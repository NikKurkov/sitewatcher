"""Small presentation adapters for the bounded analytics DTOs and native forms."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from sitewatcher.web_actions import NUMERIC_FIELDS


_CHECK_LABELS = {
    'http_basic': 'HTTP availability', 'tls_cert': 'TLS certificate',
    'keywords': 'Required keywords', 'deface': 'Defacement markers',
    'ping': 'Ping reachability', 'rkn_block': 'RKN blocking', 'ports': 'TCP ports',
    'whois': 'Domain registration', 'ip_blacklist': 'IP blocklists',
    'ip_change': 'IP address changes', 'malware': 'Malware detection',
}


def local_time(value, zone):
    if not value:
        return None
    try:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)
        label = stamp.astimezone(ZoneInfo(zone)).strftime('%d %b %Y, %H:%M %Z')
    except (ValueError, TypeError, AttributeError, OverflowError):
        return None
    age = (datetime.now(timezone.utc) - stamp).total_seconds()
    return {'iso': stamp.isoformat(), 'label': label, 'value': stamp,
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
        dots.append({'x': x, 'y': y})
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
        **dict.fromkeys(NUMERIC_FIELDS, 'Check this value.'),
        'keywords': 'Enter a valid JSON list of keywords.',
        'ports': 'Enter a valid JSON list of TCP ports (1–65535).',
        'proxy': 'Enter a supported proxy URL with a host.',
        'proxy_mode': 'Choose a valid proxy action.',
    }
    field_errors = {key: message for key, message in messages.items()
                    if key + ':' in error or key + '.' in error}
    if error in {'Invalid domain', 'Domain already exists'}:
        field_errors['domain'] = ('This domain is already monitored.'
                                  if error == 'Domain already exists'
                                  else 'Enter a valid hostname, such as example.com.')
    context['field_errors'] = field_errors
    checks = []
    for name in context['check_names']:
        key = f'check.{name}'
        checks.append({'name': key, 'label': 'Website availability' if name == 'http_basic'
                       else _CHECK_LABELS.get(name, name), 'value': values.get(key, ''),
                       'default': 'On' if context['effective']['checks'][name] else 'Off'})
    context['basic_checks'] = [c for c in checks if c['name'] in {'check.http_basic', 'check.tls_cert'}]
    context['advanced_checks'] = [c for c in checks if c not in context['basic_checks']]
    labels = ['Check interval (minutes)', 'Request timeout (seconds)',
              'Slow response warning (ms)', 'Slow response critical (ms)',
              'Certificate warning (days before expiry)']
    numeric = [{'name': key, 'label': label, 'value': values.get(key, ''),
                'minimum': 1 if key == 'http_timeout_s' else 0,
                'error': field_errors.get(key, ''),
                'default': context['effective'].get(key)}
               for key, label in zip(NUMERIC_FIELDS, labels, strict=True)]
    context['interval'] = numeric[0]
    context['numeric_fields'] = numeric[1:]
    context['advanced_error'] = bool(error)
    return context
