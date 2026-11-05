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
from .config import AppConfig, ChecksModel, resolve_settings, load_config, validate_config, validation_message
from .dispatcher import Dispatcher
from .logging_setup import setup_logging
from .utils.domains import DOMAIN_RE, normalize_domain
from .utils.results import (
    overall_from_results as _overall_from,
    status_text as _status_str,
    status_emoji as _status_emoji,
)

# ---------- CLI parsing ----------

def _parse_args() -> argparse.Namespace:
    """Parse monitoring, diagnostics and local dashboard arguments."""
    p = argparse.ArgumentParser(description="sitewatcher CLI")
    p.add_argument("mode", choices=["bot", "worker", "check_all", "check_domain", "scan", "doctor", "web", "setup", "password"], help="Run mode")
    p.add_argument("--json", action="store_true", help="Print doctor diagnostics as JSON")
    p.add_argument("--no-scheduler", action="store_true",
                   help="Bot commands only; use alongside a separate worker")
    p.add_argument("--read-only", action="store_true", help="Disable owner mutations; sign-in is still required")
    p.add_argument("--port", type=int, default=8080, help="Web port (loopback by default)")
    p.add_argument("name", nargs="?", help="Domain for 'check_domain' or 'scan'")
    p.add_argument("--config", default=None, help="Path to config.yaml")
    p.add_argument("--force", action="store_true", help="Bypass operational cache; metadata keeps provider cache limits")
    p.add_argument(
        "--only",
        default=None,
        help="Comma-separated list of checks to run (e.g. http_basic,tls_cert)",
    )
    p.add_argument(
        "--owner",
        type=int,
        default=None,
        help="Owner ID (required for check_domain; optional mapping assertion for web).",
    )
    p.add_argument('--refresh-metadata', default=None,
                   help='Refresh selected TLS/WHOIS metadata for an owned check_domain')
    args = p.parse_args()
    if args.refresh_metadata is not None:
        checks = args.refresh_metadata.split(',')
        if (args.mode != 'check_domain' or not args.name or args.owner is None
                or not checks or any(check not in {'tls_cert', 'whois'} for check in checks)
                or len(set(checks)) != len(checks) or args.only):
            p.error('--refresh-metadata requires check_domain, --owner and tls_cert,whois only')
    return args


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
    refresh_checks: Optional[list[str]] = None,
) -> list:
    """Run checks for a single domain and persist results to storage."""
    async with Dispatcher(cfg) as d:
        results = await d.run_for(
            owner_id,
            domain,
            only_checks=only_checks,
            use_cache=use_cache,
            run_id=run_id,
            **({"refresh_checks": refresh_checks} if refresh_checks else {}),
        )
    storage.save_histories(
        owner_id, domain, results, source="manual",
        **({"create_missing": False} if refresh_checks else {}),
    )
    return results


def _parse_only(arg: Optional[str]) -> Optional[list[str]]:
    """Split comma-separated checks string into a list."""
    if not arg:
        return None
    checks = [x.strip() for x in arg.split(",") if x.strip()]
    checks = [name for check in checks for name in (
        ('rkn_domain', 'rkn_ip') if check == 'rkn_block' else (check,))]
    unknown = set(checks) - ChecksModel.model_fields.keys()
    if unknown:
        raise SystemExit(f"Unknown check: {', '.join(sorted(unknown))}")
    return checks


# ---------- Commands ----------

async def _cmd_worker(cfg: AppConfig) -> None:
    """Turn service-manager termination into ordinary async resource cleanup."""
    import signal
    from .worker import run_worker

    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, asyncio.current_task().cancel)
    try:
        await run_worker(cfg)
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


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
    refresh_checks: Optional[list[str]] = None,
) -> None:
    """Run checks for a single domain and persist results to storage."""
    log = logging.getLogger("sitewatcher.main")
    if refresh_checks:
        if not storage.domain_exists(owner_id, name):
            raise SystemExit('Metadata refresh requires an owned domain')
        resolved = resolve_settings(cfg, name, storage.get_domain_override(owner_id, name))
        if any(check not in {'tls_cert', 'whois'} or not getattr(resolved.checks, check)
               for check in refresh_checks):
            raise SystemExit('Metadata refresh requires enabled TLS/WHOIS checks')
        only = refresh_checks
    results = await _run_and_persist(
        cfg, owner_id, name, only_checks=only, use_cache=use_cache, run_id=run_id,
        **({'refresh_checks': refresh_checks} if refresh_checks else {}),
    )
    if refresh_checks and (not results or any(result.cached for result in results)):
        print('Cached metadata reused; refresh is limited by provider cooldown')
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
    if args.no_scheduler and args.mode != "bot":
        raise SystemExit("--no-scheduler is supported by bot")
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
        from .webapp.bootstrap import run_asgi
        from django.db import DatabaseError

        try:
            run_asgi(cfg, owner_id=args.owner, port=args.port, read_only=args.read_only)
        except ValueError as error:
            if str(error) == "Web owner does not match a configured workspace; run sitewatcher setup":
                raise SystemExit(str(error)) from None
            raise SystemExit("Cannot start local dashboard; check database permissions and --port") from None
        except (DatabaseError, OSError, sqlite3.Error):
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
        if args.no_scheduler:
            cfg.scheduler.enabled = False
        log.info("cli.bot.start", extra={"event": "cli.bot.start", "run_id": run_id})
        run_bot(cfg)
        return

    if args.mode == "worker":
        try:
            asyncio.run(_cmd_worker(cfg))
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
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
    asyncio.run(_cmd_check_one(
        cfg, args.owner, args.name, only=only, use_cache=use_cache, run_id=run_id,
        **({'refresh_checks': args.refresh_metadata.split(',')} if args.refresh_metadata else {}),
    ))


if __name__ == "__main__":
    main()
