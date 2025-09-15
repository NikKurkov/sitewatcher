# sitewatcher/main.py
from __future__ import annotations

import argparse
import asyncio
import logging
import uuid
from typing import Iterable, Optional

from dotenv import load_dotenv

from . import storage
from .bot import run_bot
from .config import AppConfig, load_config, validate_config
from .dispatcher import Dispatcher
from .logging_setup import setup_logging

# Load .env once at process start (affects config/env overrides and logging early)
load_dotenv()


# ---------- CLI parsing ----------

def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments for bot/one-shot checks."""
    p = argparse.ArgumentParser(description="sitewatcher CLI")
    p.add_argument("mode", choices=["bot", "check_all", "check_domain", "scan"], help="Run mode")
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
        help="Telegram user id to act on (required for check_domain; optional for check_all).",
    )
    return p.parse_args()


# ---------- Helpers ----------

def _new_run_id() -> str:
    """Create a short correlation id for this CLI invocation."""
    return uuid.uuid4().hex


def _status_str(x: object) -> str:
    """Get human string from Status enum or string."""
    return getattr(x, "value", str(x))


def _status_emoji(s: str) -> str:
    """Simple traffic light for CLI output."""
    s = (s or "").upper()
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(s, "⚪")


def _overall_from(results: Iterable[object]) -> str:
    """Compute overall status from individual results."""
    def weight(st: str) -> int:
        if st == "CRIT":
            return 2
        if st in ("WARN", "UNKNOWN"):
            return 1
        return 0

    worst = 0
    for r in results:
        st = _status_str(getattr(r, "status", "UNKNOWN")).upper()
        worst = max(worst, weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]


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
    for r in results:
        storage.save_history(owner_id, domain, r.check, r.status, r.message, r.metrics)
    return results


def _parse_only(arg: Optional[str]) -> Optional[list[str]]:
    """Split comma-separated checks string into a list."""
    if not arg:
        return None
    return [x.strip() for x in arg.split(",") if x.strip()]


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
        results = await d.run_for(owner_id, name, only_checks=only, use_cache=use_cache)
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
    cfg = load_config(args.config)

    # Initialize logging ASAP so validation and later steps are captured
    setup_logging(getattr(cfg, "logging", None))

    # validate config early (fail-fast with clear summary)
    try:
        validate_config(cfg)
    except ValueError as e:
        # Use logging to emit the failure as well
        logging.getLogger("sitewatcher.main").error("config.invalid: %s", e, extra={"event": "config.invalid"})
        raise SystemExit(str(e))

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


def cli() -> None:
    """Entry-point function for the console script."""
    main()


if __name__ == "__main__":
    main()
