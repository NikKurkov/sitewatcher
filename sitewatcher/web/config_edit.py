"""Validated, atomic writes for the shared YAML configuration."""

import os
import tempfile
from pathlib import Path

import yaml

from sitewatcher.config import AppConfig, validate_config


def save_config_yaml(text: str, path: str | os.PathLike[str]) -> AppConfig:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(str(exc)) from exc
    config = AppConfig.model_validate({} if data is None else data)
    validate_config(config)

    destination = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return config
