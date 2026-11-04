"""Check-list freshness presentation without changing saved verdicts."""
from collections import Counter
from datetime import datetime, timezone

from django.utils.translation import gettext, npgettext, pgettext


def _updated_checks(age):
    if age < 0:
        return gettext('Timestamp is in the future')
    if age < 60:
        return pgettext('check results', 'Updated just now')
    if age < 3600:
        count = int(age // 60)
        return npgettext('check results', 'Updated %(count)s minute ago',
                         'Updated %(count)s minutes ago', count) % {'count': count}
    if age < 86400:
        count = int(age // 3600)
        return npgettext('check results', 'Updated %(count)s hour ago',
                         'Updated %(count)s hours ago', count) % {'count': count}
    count = int(age // 86400)
    return npgettext('check results', 'Updated %(count)s day ago',
                     'Updated %(count)s days ago', count) % {'count': count}


def prepare_check_list(checks, *, now=None):
    """Share an identical majority timestamp; retain times for exceptions and stale results."""
    counts = Counter(check['observed']['iso'] for check in checks if check.get('observed'))
    common = None
    if counts:
        stamp, count = counts.most_common(1)[0]
        if count >= 2 and count > len(checks) / 2:
            common = dict(next(check['observed'] for check in checks
                               if check.get('observed') and check['observed']['iso'] == stamp))
            age = ((now or datetime.now(timezone.utc)) - common['value']).total_seconds()
            common['checks_updated_label'] = _updated_checks(age)
    for check in checks:
        observed = check.get('observed')
        check['show_observed'] = (common is None or observed is None
                                  or observed['iso'] != common['iso'] or check['stale'])
    return common
