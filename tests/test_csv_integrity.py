import csv
import io
import sqlite3
from contextlib import closing

import pytest

from sitewatcher import storage
from sitewatcher.utils.domains_csv import HEADERS, export_domains_csv, import_domains_csv


@pytest.fixture
def database(tmp_path, monkeypatch):
    path = tmp_path / "csv.db"
    monkeypatch.setattr(storage, "DEFAULT_DB", path)
    storage.add_domain(1, "example.com")
    return path


def csv_data(**values):
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=HEADERS, delimiter=";")
    writer.writeheader()
    writer.writerow({"domain": "example.com", **values})
    return stream.getvalue().encode("utf-8-sig")


def test_invalid_replacement_keeps_previous_settings(database):
    storage.set_domain_override(1, "example.com", {"keywords": ["keep"]})
    report = import_domains_csv(1, csv_data(latency_warn_ms="5000"), mode="replace")
    assert report.skipped == 1 and report.errors
    assert storage.get_domain_override(1, "example.com") == {"keywords": ["keep"]}


def test_replacement_write_failure_rolls_back_previous_settings(database):
    storage.set_domain_override(1, "example.com", {"keywords": ["keep"]})
    with closing(sqlite3.connect(database)) as conn:
        conn.execute("""
            CREATE TRIGGER reject_override BEFORE INSERT ON domain_overrides
            BEGIN SELECT RAISE(ABORT, 'reject replacement'); END
        """)
    with pytest.raises(sqlite3.IntegrityError):
        import_domains_csv(1, csv_data(keywords="new"), mode="replace")
    assert storage.get_domain_override(1, "example.com") == {"keywords": ["keep"]}


def test_advanced_port_targets_survive_export_and_import(database):
    ports = [{"port": 443, "tls": True, "host": "service.example", "read_bytes": 32}]
    storage.set_domain_override(1, "example.com", {"ports": ports})
    data = export_domains_csv(1)
    storage.unset_domain_override(1, "example.com", "ports")
    report = import_domains_csv(1, data)
    assert report.updated == 1 and report.errors == []
    assert storage.get_domain_override(1, "example.com")["ports"] == ports


def test_unicode_domain_is_normalized_consistently(database):
    report = import_domains_csv(1, csv_data(domain="ПРИМЕР.РФ.", ports="443"))
    assert report.added == 1 and report.errors == []
    assert storage.domain_exists(1, "xn--e1afmkfd.xn--p1ai")


def test_export_import_preserves_paused_schedule_and_zero_thresholds(database):
    original = {"interval_minutes": 0, "tls_warn_days": 0,
                "latency_warn_ms": 0, "latency_crit_ms": 0, "proxy": None}
    storage.set_domain_override(1, "example.com", original)
    data = export_domains_csv(1)
    storage.set_domain_override(1, "example.com", {"proxy": "http://proxy.example:3128"}, replace=True)
    report = import_domains_csv(1, data)
    assert report.updated == 1
    assert storage.get_domain_override(1, "example.com") == original


def test_invalid_nonempty_check_flag_does_not_silently_change_import(database):
    report = import_domains_csv(1, csv_data(http_timeout_s="3", **{"checks.ping": "treu"}))
    assert report.skipped == 1 and report.errors
    assert storage.get_domain_override(1, "example.com") is None
