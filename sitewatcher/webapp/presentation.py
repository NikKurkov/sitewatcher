"""Small presentation adapters for the bounded analytics DTOs and native forms."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from django.utils.formats import date_format
from django.utils.translation import gettext_lazy as _, ngettext

from sitewatcher.web_actions import NUMERIC_FIELDS
from sitewatcher.checks.malware_scan import VT_FAILURE_MESSAGES


_CHECK_LABELS = {
    'http_basic': _('Website availability'), 'tls_cert': _('TLS certificate'),
    'keywords': _('Required keywords'), 'deface': _('Defacement markers'),
    'ping': _('Ping reachability'), 'rkn_domain': _('RKN domain blocking'),
    'rkn_ip': _('RKN IP listing'), 'rkn_block': _('Legacy RKN blocking'), 'ports': _('TCP ports'),
    'whois': _('Domain registration'), 'ip_blacklist': _('IP blocklists'),
    'ip_change': _('IP address changes'), 'malware': _('Malware detection'),
    'traceroute': _('Network route'),
}
_CHECK_HELP = {
    'rkn_domain': _('A domain or parent-domain listing is Critical.'),
    'rkn_ip': _('An IPv4 listing is Warning; it may concern another domain on shared hosting.'),
}
_STATUS_LABELS = {'OK': _('OK'), 'WARN': _('WARN'), 'CRIT': _('CRIT'),
                  'UNKNOWN': _('UNKNOWN')}


_DIAGNOSTIC_MESSAGES = {
    'VirusTotal is not configured: API key is missing':
        _('VirusTotal is not configured: API key is missing'),
    'VirusTotal has no report for this URL': _('VirusTotal has no report for this URL'),
    'VirusTotal configuration could not be read securely':
        _('VirusTotal configuration could not be read securely'),
    'VT: not_found': _('VT: not_found'),
}
_DIAGNOSTIC_MESSAGES.update({message: _(message) for message in VT_FAILURE_MESSAGES.values()})


def diagnostic_message(value):
    return _DIAGNOSTIC_MESSAGES.get(value, value)


def status_label(value):
    return _STATUS_LABELS.get(value, value)


def check_label(name):
    return _CHECK_LABELS.get(name, name.replace('_', ' ').capitalize())


def _updated_label(age):
    if age < 0:
        return _('Timestamp is in the future')
    if age < 60:
        return _('Updated just now')
    if age < 3600:
        count = int(age // 60)
        return ngettext('Updated %(count)s minute ago', 'Updated %(count)s minutes ago', count) % {'count': count}
    if age < 86400:
        count = int(age // 3600)
        return ngettext('Updated %(count)s hour ago', 'Updated %(count)s hours ago', count) % {'count': count}
    count = int(age // 86400)
    return ngettext('Updated %(count)s day ago', 'Updated %(count)s days ago', count) % {'count': count}


def local_time(value, zone):
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        local = stamp.astimezone(ZoneInfo(zone))
        label = date_format(local, 'd M Y, H:i') + ' ' + local.tzname()
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return {'iso': stamp.isoformat(), 'label': label,
            'compact_label': local.strftime('%Y-%m-%d %H:%M'), 'value': stamp,
            'updated_label': _updated_label(age),
            'future': age < 0, 'just_now': 0 <= age < 60}


def chart_context(points, metric):
    """Position bucket starts within 120 equal intervals; gaps start a new segment."""
    maximum = max((point[metric] for point in points if point.get(metric) is not None),
                  default=0) or 1
    segments, dots, current, previous = [], [], [], None
    for point in points:
        value, index = point.get(metric), point['index']
        if value is None:
            if current:
                segments.append(' '.join(current))
            current, previous = [], None
            continue
        if previous is not None and index != previous + 1:
            segments.append(' '.join(current))
            current = []
        x, y = index * 1000 / 120, 150 - (value / maximum) * 132
        current.append(f'{x:.2f},{y:.2f}')
        dots.append({'x': x, 'y': y, 'value': value, 'label': point.get('label', '')})
        previous = index
    if current:
        segments.append(' '.join(current))
    return {'segments': segments, 'dots': dots, 'maximum': maximum}


def report_context(report):
    known = report['totals']['successful'] + report['totals']['failed']
    report['totals']['failure_percent'] = report['totals']['failed'] / known * 100 if known else None
    report['observed'] = local_time(report.get('latest_observed_at'), report['timezone'])
    report['start'] = local_time(report['window_start'], report['timezone'])
    report['end'] = local_time(report['window_end'], report['timezone'])
    report['chart'] = chart_context(report['buckets'], 'latency_ms')
    for bucket in report['buckets']:
        bucket['x'] = bucket['index'] * 10
        bucket['state'] = ('failed' if bucket['failed'] else 'successful'
                           if bucket['successful'] else 'unknown')
    return report


def domain_form_context(context, error):
    values = context['values']
    messages = {
        **dict.fromkeys(NUMERIC_FIELDS, _('Check this value.')),
        'keywords': _('Enter keywords separated by commas; quote phrases containing commas.'),
        'ports': _('Enter TCP ports (1–65535) or ranges, separated by commas.'),
        'proxy': _('Enter a supported proxy URL with a host.'),
        'http_url': _('Enter an HTTP(S) address using this domain.'),
        'http_scheme': _('Choose HTTP or HTTPS.'),
        'proxy_mode': _('Choose a valid proxy action.'),
    }
    field_errors = {key: message for key, message in messages.items()
                    if key + ':' in error or key + '.' in error}
    if error in {'Invalid domain', 'Domain already exists'}:
        field_errors['domain'] = (_('This domain is already monitored.')
                                  if error == 'Domain already exists'
                                  else _('Enter a valid hostname, such as example.com.'))
    if error == 'Enter at most 50 domains.':
        field_errors['domain'] = _('Enter at most 50 domains.')
    context['field_errors'] = field_errors
    checks = []
    for name in context['check_names']:
        key = f'check.{name}'
        checks.append({'name': key, 'label': check_label(name), 'value': values.get(key, ''),
                       'help': _CHECK_HELP.get(name, ''),
                       'default': _('On') if context['defaults']['checks'][name] else _('Off')})
    context['basic_checks'] = [c for c in checks if c['name'] in {'check.http_basic', 'check.tls_cert'}]
    context['advanced_checks'] = [c for c in checks if c not in context['basic_checks']]
    labels = [_('Check interval (minutes)'), _('Request timeout (seconds)'),
              _('Slow response warning (ms)'), _('Slow response critical (ms)'),
              _('Certificate warning (days before expiry)')]
    numeric = [{'name': key, 'label': label, 'value': values.get(key, ''),
                'minimum': 1 if key == 'http_timeout_s' else 0,
                'error': field_errors.get(key, ''),
                'default': context['defaults'].get(key)}
               for key, label in zip(NUMERIC_FIELDS, labels, strict=True)]
    context['interval'] = numeric[0]
    context['numeric_fields'] = numeric[1:]
    context['advanced_error'] = bool(error)
    return context
