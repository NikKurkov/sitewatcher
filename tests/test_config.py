from sitewatcher.config import AppConfig, load_config, resolve_settings, validate_config
from pathlib import Path
import os
import subprocess
import sys


def test_missing_default_yaml_uses_valid_defaults():
    validate_config(load_config())


def test_explicit_missing_yaml_fails(tmp_path):
    try:
        load_config(tmp_path / "missing.yaml")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("An explicit missing config must fail")


def test_shipped_yaml_example_is_valid():
    path = Path(__file__).resolve().parents[1] / "sitewatcher/data/config.yaml.example"
    validate_config(load_config(path))


def test_dotenv_database_path_is_used_by_cli(tmp_path):
    db = tmp_path / "chosen.db"
    (tmp_path / ".env").write_text(f"DATABASE_PATH={db}\n")
    env = os.environ.copy()
    env.pop("DATABASE_PATH", None)
    run = subprocess.run(
        [sys.executable, "-m", "sitewatcher.main", "check_all"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    assert "No users" in run.stdout
    assert db.exists()
    assert not (tmp_path / "sitewatcher.db").exists()


def test_cli_rejects_unknown_check_name_without_network(tmp_path):
    run = subprocess.run(
        [sys.executable, "-m", "sitewatcher.main", "scan", "example.com", "--only", "typo"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0
    assert "Unknown check" in run.stderr


def test_cli_rejects_invalid_domain_without_network(tmp_path):
    run = subprocess.run(
        [sys.executable, "-m", "sitewatcher.main", "scan", "bad!domain"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert run.returncode != 0
    assert "Invalid domain" in run.stderr


def test_partial_domain_checks_preserve_other_global_defaults():
    cfg = AppConfig.model_validate({
        "defaults": {"checks": {"ping": False, "deface": True}},
        "domains": [{"name": "example.com", "checks": {"keywords": True}}],
    })
    checks = resolve_settings(cfg, "example.com").checks
    assert checks.keywords is True
    assert checks.ping is False
    assert checks.deface is True
