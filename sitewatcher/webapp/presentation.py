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
    'no zones configured': _('IP blocklists are not configured'),
    'IP blocklists are not configured': _('IP blocklists are not configured'),
    'IP blocklists require an IPv4 address': _('IP blocklists require an IPv4 address'),
    'not listed': _('Not found in the configured IP blocklists'),
    'VirusTotal analysis is pending': _('VirusTotal analysis is pending'),
    'VirusTotal submission could not be confirmed. Try again later.':
        _('VirusTotal submission could not be confirmed. Try again later.'),
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
        display_label = date_format(local, 'd M Y, H:i')
        label = display_label + ' ' + local.tzname()
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return {'iso': stamp.isoformat(), 'label': label, 'display_label': display_label,
            'clock_label': local.strftime('%H:%M'),
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
    y_ticks = [{'value': maximum * fraction, 'y': 150 - fraction * 132,
                'position': (150 - fraction * 132) / 165 * 100,
                'short_value': format(maximum * fraction, '.3g') if maximum * fraction >= 1e6 else None}
               for fraction in [1, .75, .5, .25, 0]]
    return {'segments': segments, 'dots': dots, 'maximum': maximum, 'y_ticks': y_ticks}


def report_context(report, *, public=False):
    known = report['totals']['successful'] + report['totals']['failed']
    report['totals']['failure_percent'] = report['totals']['failed'] / known * 100 if known else None
    report['observed'] = local_time(report.get('latest_observed_at'), report['timezone'])
    report['start'] = local_time(report['window_start'], report['timezone'])
    report['end'] = local_time(report['window_end'], report['timezone'])
    if public:
        for bucket in report['buckets']:
            stamp = local_time(bucket.get('start_at'), report['timezone'])
            if stamp:
                bucket['label'] = stamp['display_label']
    report['chart'] = chart_context(report['buckets'], 'latency_ms')
    if report['start'] and report['end']:
        start, end = report['start']['value'], report['end']['value']
        ticks = []
        for index in range(5):
            value = start + (end - start) * index / 4
            stamp = local_time(value.isoformat(), report['timezone'])
            local = value.astimezone(ZoneInfo(report['timezone']))
            ticks.append({'position': index * 25, 'stamp': stamp,
                          'label': date_format(local, 'd M H:i'), 'time_label': date_format(local, 'H:i')})
        report['chart']['x_ticks'] = ticks
    for bucket in report['buckets']:
        bucket['x'] = bucket['index'] * 10
        bucket['state'] = ('failed' if bucket['failed'] else 'successful'
                           if bucket['successful'] else 'unknown')
    occupied = {bucket['index']: bucket for bucket in report['buckets']}
    report['history_buckets'] = []
    gaps, gap_start = [], None
    for index in range(120):
        bucket = occupied.get(index)
        if bucket is None:
            value = start + (end - start) * index / 120
            stamp = local_time(value.isoformat(), report['timezone'])
            bucket = {'index': index, 'x': index * 10, 'state': 'no-data',
                      'label': stamp['display_label'] if public else stamp['label']}
            if gap_start is None:
                gap_start = index
        elif gap_start is not None:
            gaps.append({'x': gap_start * 1000 / 120, 'width': (index - gap_start) * 1000 / 120})
            gap_start = None
        report['history_buckets'].append(bucket)
    if gap_start is not None:
        gaps.append({'x': gap_start * 1000 / 120, 'width': (120 - gap_start) * 1000 / 120})
    report['chart']['gaps'] = gaps
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
