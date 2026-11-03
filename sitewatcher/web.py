"""Authenticated web command compatibility entry point."""
from .config import AppConfig


def run_web(cfg: AppConfig, owner_id: int | None = None, port: int = 8080, *,
            read_only: bool = False) -> None:
    """Compatibility entry point: every mode requires the authenticated Django workspace."""
    from .webapp.bootstrap import run_asgi

    run_asgi(cfg, port=port, read_only=read_only, owner_id=owner_id)
