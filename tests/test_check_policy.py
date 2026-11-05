from datetime import datetime,timedelta,timezone
import json

import pytest

from sitewatcher.config import AppConfig,resolve_settings
from sitewatcher.check_policy import interval_minutes,result_deadlines,expiry_assessment_due


@pytest.mark.parametrize('name',['tls_cert','whois','malware','ip_blacklist','rkn_domain','rkn_ip'])
def test_short_domain_interval_cannot_accelerate_daily_checks(name):
    assert interval_minutes(AppConfig(),name,5)==1440


def test_operational_checks_keep_domain_interval_and_pause():
    assert interval_minutes(AppConfig(),'http_basic',5)==5
    assert interval_minutes(AppConfig(),'ping',10)==10
    assert interval_minutes(AppConfig(),'tls_cert',0)==0


def test_daily_observation_remains_fresh_and_provider_retry_deadline_is_shared():
    cfg=AppConfig();now=datetime.now(timezone.utc);past=now-timedelta(hours=2)
    row={'created_at':past.isoformat(),'metrics_json':'{}'}
    _,due,stale=result_deadlines(cfg,'malware',5,row,now=now)
    assert due==past+timedelta(days=1) and stale>now
    retry=now+timedelta(minutes=15)
    row['metrics_json']=json.dumps({'observed_at':past.isoformat(),'next_refresh_at':retry.isoformat()})
    assert result_deadlines(cfg,'ip_blacklist',5,row,now=now)[1]==retry


def test_cached_certificate_expiry_transition_requires_local_assessment():
    cfg=AppConfig();now=datetime.now(timezone.utc)
    settings=resolve_settings(cfg,'example.test',{'interval_minutes':5})
    row={'status':'OK','metrics_json':json.dumps({'expires_at':(now+timedelta(days=2)).isoformat()})}
    assert expiry_assessment_due('tls_cert',row,cfg,settings,now=now)
    row['status']='CRIT'
    assert not expiry_assessment_due('tls_cert',row,cfg,settings,now=now)


def test_retained_rkn_threat_is_schedulable_but_stale_clean_is_not():
    from sitewatcher.utils.results import current_rkn_result
    old = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
    metrics = {'registry_version': '3', 'source': 'antifilter',
               'source_updated_at': old, 'source_stale': True}
    assert current_rkn_result('rkn_domain', metrics, status='CRIT')
    assert current_rkn_result('rkn_ip', metrics, status='WARN')
    assert not current_rkn_result('rkn_domain', metrics, status='OK')
    assert not current_rkn_result('rkn_domain', {**metrics, 'source': 'unknown'}, status='CRIT')
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert not current_rkn_result('rkn_domain',
                                  {**metrics, 'source_updated_at': future}, status='CRIT')
