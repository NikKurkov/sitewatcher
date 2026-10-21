# sitewatcher/main.py
from __future__ import annotations

import argparse
import asyncio
import logging
import json
import sqlite3
import uuid
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

# Storage reads DATABASE_PATH at import time.
load_dotenv(Path.cwd() / ".env")

from . import storage
from .bot import run_bot
from .config import AppConfig, ChecksModel, load_config, validate_config, validation_message
from .dispatcher import Dispatcher
from .logging_setup import setup_logging
from .bot.validators import DOMAIN_RE, normalize_domain
from .utils.results import (
    overall_from_results as _overall_from,
    status_text as _status_str,
    status_emoji as _status_emoji,
)

# ---------- CLI parsing ----------

def _parse_args() -> argparse.Namespace:
    """Parse monitoring, diagnostics and local dashboard arguments."""
    p = argparse.ArgumentParser(description="sitewatcher CLI")
    p.add_argument("mode", choices=["bot", "check_all", "check_domain", "scan", "doctor", "web", "setup", "password"], help="Run mode")
    p.add_argument("--json", action="store_true", help="Print doctor diagnostics as JSON")
    p.add_argument("--read-only", action="store_true", help="Disable web management; viewing only")
    p.add_argument("--port", type=int, default=8080, help="Local dashboard port (web mode)")
    p.add_argument("name", nargs="?", help="Domain for 'check_domain' or 'scan'")
    p.add_argument("--config", default=None, help="Path to config.yaml")
    p.add_argument("--force", action="store_true", help="Ignore cache and run all checks live")
    p.add_argument(
        "--only",
        default=None,
        help="Comma-separated list of checks to run (e.g. http_basic,tls_cert)",
    )
    p.add_argument(
        "--owner",
        type=int,
        default=None,
        help="Telegram user ID (required for check_domain and web; optional for check_all).",
    )
    return p.parse_args()


# ---------- Helpers ----------

def _new_run_id() -> str:
    """Create a short correlation id for this CLI invocation."""
    return uuid.uuid4().hex


async def _run_and_persist(
    cfg: AppConfig,
    owner_id: int,
    domain: str,
    *,
    only_checks: Optional[list[str]] = None,
    use_cache: bool = True,
    run_id: Optional[str] = None,
) -> list:
    """Run checks for a single domain and persist results to storage."""
    async with Dispatcher(cfg) as d:
        results = await d.run_for(
            owner_id,
            domain,
            only_checks=only_checks,
            use_cache=use_cache,
            run_id=run_id,
        )
    storage.save_histories(owner_id, domain, results)
    return results


def _parse_only(arg: Optional[str]) -> Optional[list[str]]:
    """Split comma-separated checks string into a list."""
    if not arg:
        return None
    checks = [x.strip() for x in arg.split(",") if x.strip()]
    unknown = set(checks) - ChecksModel.model_fields.keys()
    if unknown:
        raise SystemExit(f"Unknown check: {', '.join(sorted(unknown))}")
    return checks


# ---------- Commands ----------

async def _cmd_check_all(
    cfg: AppConfig,
    *,
    only: Optional[list[str]],
    use_cache: bool,
    owner_id: Optional[int],
    run_id: str,
) -> None:
    """Run checks for all domains. If owner_id is None, iterate all users."""
    log = logging.getLogger("sitewatcher.main")
    owners = [owner_id] if owner_id is not None else storage.list_users()
    if not owners:
        print("No users in database.")
        log.debug("cli.check_all.nousers", extra={"event": "cli.check_all.nousers", "run_id": run_id})
        return

    # Run sequentially per domain; Dispatcher handles internal concurrency.
    log.info(
        "cli.check_all.start",
        extra={"event": "cli.check_all.start", "run_id": run_id, "owners": len(owners), "use_cache": use_cache, "only": bool(only)},
    )
    for oid in owners:
        names = storage.list_domains(oid)
        if not names:
            continue
        for name in names:
            results = await _run_and_persist(cfg, oid, name, only_checks=only, use_cache=use_cache, run_id=run_id)
            overall = _overall_from(results)
            checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
            print(f"[{oid}] {_status_emoji(overall)} {name} — {overall} -> {checks_summary}")
    log.info("cli.check_all.done", extra={"event": "cli.check_all.done", "run_id": run_id})


async def _cmd_scan_one(
    cfg: AppConfig,
    owner_id: int,
    name: str,
    *,
    only: Optional[list[str]],
    use_cache: bool,
    run_id: str,
) -> None:
    """Run checks for a single domain WITHOUT persisting results."""
    log = logging.getLogger("sitewatcher.main")
    async with Dispatcher(cfg) as d:
        results = await d.run_for(owner_id, name, only_checks=only, use_cache=use_cache, ephemeral=True, run_id=run_id)
    overall = _overall_from(results)
    checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
    print(f"{_status_emoji(overall)} {name} — {overall} -> {checks_summary}")
    log.info(
        "cli.scan.done",
        extra={"event": "cli.scan.done", "run_id": run_id, "owner_id": owner_id, "domain": name, "overall": overall},
    )


async def _cmd_check_one(
    cfg: AppConfig,
    owner_id: int,
    name: str,
    *,
    only: Optional[list[str]],
    use_cache: bool,
    run_id: str,
) -> None:
    """Run checks for a single domain and persist results to storage."""
    log = logging.getLogger("sitewatcher.main")
    results = await _run_and_persist(cfg, owner_id, name, only_checks=only, use_cache=use_cache, run_id=run_id)
    overall = _overall_from(results)
    checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
    print(f"[{owner_id}] {_status_emoji(overall)} {name} — {overall} -> {checks_summary}")
    log.info(
        "cli.check_domain.done",
        extra={"event": "cli.check_domain.done", "run_id": run_id, "owner_id": owner_id, "domain": name, "overall": overall},
    )


# ---------- Entrypoints ----------

def main() -> None:
    """Entrypoint for `python -m sitewatcher.main`."""
    args = _parse_args()
    if args.read_only and args.mode != "web":
        raise SystemExit("--read-only is supported by web")
    if args.mode == "doctor":
        from .diagnostics import diagnose, format_diagnostics

        report = diagnose(args.config)
        print(json.dumps(report, ensure_ascii=False) if args.json else format_diagnostics(report))
        raise SystemExit(0 if report["ok"] else 1)
    if args.json:
        raise SystemExit("--json is supported by doctor")
    if args.name:
        args.name = normalize_domain(args.name)
        if not args.name or not DOMAIN_RE.fullmatch(args.name):
            raise SystemExit("Invalid domain")
    try:
        cfg = load_config(args.config)
        validate_config(cfg)
    except (OSError, ValueError) as error:
        raise SystemExit(validation_message(error)) from None
    if args.mode in {"setup", "password"}:
        from django.db import DatabaseError
        from .webapp.bootstrap import configure_web, migrate_web_database
        try:
            configure_web(cfg)
            migrate_web_database()
            from .webapp.accounts import reset_password, setup_owner
            if args.mode == "setup":
                setup_owner(owner_id=args.owner)
            else:
                if args.owner is not None:
                    raise ValueError("password does not accept --owner")
                reset_password()
        except (DatabaseError, OSError, sqlite3.Error):
            raise SystemExit("Cannot update local account; check database permissions and setup") from None
        except (ValueError, EOFError) as error:
            raise SystemExit(str(error) or "Account input was cancelled") from None
        return
    if args.mode == "web":
        if args.owner is None or args.owner <= 0:
            raise SystemExit("web requires --owner with a positive Telegram user ID")
        from .web import run_web

        try:
            run_web(cfg, args.owner, port=args.port, read_only=args.read_only)
        except (OSError, ValueError, sqlite3.Error):
            raise SystemExit("Cannot start local dashboard; check database permissions and --port") from None
        return
    setup_logging(cfg.logging)

    log = logging.getLogger("sitewatcher.main")
    log.info(
        "app.start",
        extra={
            "event": "app.start",
            "logging_destination": getattr(cfg.logging, "destination", None),
            "logging_format": getattr(cfg.logging, "format", None),
            "logging_level": getattr(cfg.logging, "level", None),
        },
    )

    use_cache = not bool(args.force)
    only = _parse_only(args.only)
    run_id = _new_run_id()

    if args.mode == "bot":
        log.info("cli.bot.start", extra={"event": "cli.bot.start", "run_id": run_id})
        run_bot(cfg)
        return

    if args.mode == "check_all":
        asyncio.run(_cmd_check_all(cfg, only=only, use_cache=use_cache, owner_id=args.owner, run_id=run_id))
        return

    if args.mode == "scan":
        if not args.name:
            raise SystemExit(
                "Usage:\n"
                "  sitewatcher scan <name> [--only a,b]\n"
                "Notes:\n"
                "  Runs checks WITHOUT saving to DB. Use this for ad-hoc diagnostics."
            )
        # scan: always live run without cache
        asyncio.run(_cmd_scan_one(cfg, args.owner or 0, args.name, only=only, use_cache=False, run_id=run_id))
        return

    # check_domain
    if not args.name or args.owner is None:
        raise SystemExit(
            "Usage:\n"
            "  sitewatcher check_domain <name> --owner <telegram_id> [--force] [--only a,b]\n"
            "Example:\n"
            "  sitewatcher check_domain example.com --owner 123456789 --only http_basic,tls_cert"
        )
    asyncio.run(_cmd_check_one(cfg, args.owner, args.name, only=only, use_cache=use_cache, run_id=run_id))


if __name__ == "__main__":
    main()
