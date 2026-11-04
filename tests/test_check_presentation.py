from datetime import datetime, timedelta, timezone

from django.utils import translation

from sitewatcher.webapp.check_presentation import prepare_check_list
from sitewatcher.webapp.presentation import local_time


NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)


def check(minutes, *, stale=False):
    return {'status': 'OK', 'stale': stale,
            'observed': local_time((NOW - timedelta(minutes=minutes)).isoformat(), 'Europe/Moscow')}


def test_common_timestamp_keeps_separate_stale_and_missing_times():
    checks = [check(8), check(8), check(8, stale=True), check(1), {'stale': True, 'observed': None}]
    with translation.override('ru'):
        common = prepare_check_list(checks, now=NOW)
    assert common['checks_updated_label'] == 'обновлены 8 минут назад'
    assert [item['show_observed'] for item in checks] == [False, False, True, True, True]
    assert all(item.get('status', 'OK') == 'OK' for item in checks)


def test_no_majority_or_missing_observations_never_imply_common_freshness():
    for checks in ([check(1), check(2)], [check(1), check(1), check(2), check(2)],
                   [{'stale': True, 'observed': None}], []):
        assert prepare_check_list(checks, now=NOW) is None
        assert all(item['show_observed'] for item in checks)
