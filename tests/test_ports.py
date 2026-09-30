from sitewatcher.checks.ports import PortsCheck
from sitewatcher.config import AppConfig


def test_default_config_ports_are_usable():
    cfg = AppConfig()
    check = PortsCheck("example.com", targets=cfg.ports.targets, defaults=cfg.ports)
    assert [target.port for target in check.targets] == [80, 443, 22, 25]
