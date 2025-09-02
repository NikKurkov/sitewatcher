# sitewatcher/main.py
from __future__ import annotations

import argparse
import asyncio
from typing import Iterable, Optional

from dotenv import load_dotenv

from .bot import run_bot
from .config import AppConfig, load_config, validate_config
from .dispatcher import Dispatcher
from . import storage

load_dotenv()  # Load .env once at process start


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
) -> list:
    """Run checks for a single domain and persist results to storage."""
    async with Dispatcher(cfg) as d:
        # pass owner_id first — актуальная сигнатура Dispatcher.run_for(owner_id, domain, ...)
        results = await d.run_for(owner_id, domain, only_checks=only_checks, use_cache=use_cache)
    for r in results:
        storage.save_history(owner_id, domain, r.check, r.status, r.message, r.metrics)
    return results


def _parse_only(arg: Optional[str]) -> Optional[list[str]]:
    """Split comma-separated checks string into a list."""
    if not arg:
        return None
    return [x.strip() for x in arg.split(",") if x.strip()]


async def _cmd_check_all(
    cfg: AppConfig,
    *,
    only: Optional[list[str]],
    use_cache: bool,
    owner_id: Optional[int],
) -> None:
    """Run checks for all domains. If owner_id is None, iterate all users."""
    owners = [owner_id] if owner_id is not None else storage.list_users()
    if not owners:
        print("No users in database.")
        return

    # Run sequentially per domain; Dispatcher handles internal concurrency.
    for oid in owners:
        names = storage.list_domains(oid)
        if not names:
            continue
        for name in names:
            results = await _run_and_persist(cfg, oid, name, only_checks=only, use_cache=use_cache)
            overall = _overall_from(results)
            checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
            print(f"[{oid}] {_status_emoji(overall)} {name} — {overall} -> {checks_summary}")


async def _cmd_scan_one(
    cfg: AppConfig,
    owner_id: int,
    name: str,
    *,
    only: Optional[list[str]],
    use_cache: bool,
) -> None:
    """Run checks for a single domain WITHOUT persisting results."""
    async with Dispatcher(cfg) as d:
        # use owner_id to resolve overrides, но ничего не сохраняем
        results = await d.run_for(owner_id, name, only_checks=only, use_cache=use_cache)
    overall = _overall_from(results)
    checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
    print(f"{_status_emoji(overall)} {name} — {overall} -> {checks_summary}")


async def _cmd_check_one(
    cfg: AppConfig,
    owner_id: int,
    name: str,
    *,
    only: Optional[list[str]],
    use_cache: bool,
) -> None:
    """Run checks for a single domain and persist results to storage."""
    results = await _run_and_persist(cfg, owner_id, name, only_checks=only, use_cache=use_cache)
    overall = _overall_from(results)
    checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
    print(f"[{owner_id}] {_status_emoji(overall)} {name} — {overall} -> {checks_summary}")


def main() -> None:
    """Entrypoint for `python -m sitewatcher.main`."""
    args = _parse_args()
    cfg = load_config(args.config)

    # validate config early (fail-fast с понятной сводкой)
    try:
        validate_config(cfg)
    except ValueError as e:
        raise SystemExit(str(e))

    use_cache = not bool(args.force)
    only = _parse_only(args.only)

    if args.mode == "bot":
        run_bot(cfg)
        return

    if args.mode == "check_all":
        asyncio.run(_cmd_check_all(cfg, only=only, use_cache=use_cache, owner_id=args.owner))
        return

    if args.mode == "scan":
        if not args.name:
            raise SystemExit(
                "Usage:\n"
                "  sitewatcher scan <name> [--only a,b]\n"
                "Notes:\n"
                "  Runs checks WITHOUT saving to DB. Use this for ad-hoc diagnostics."
            )
        # scan всегда «живой» прогон без кэша
        asyncio.run(_cmd_scan_one(cfg, args.owner or 0, args.name, only=only, use_cache=False))
        return

    # check_domain
    if not args.name or args.owner is None:
        raise SystemExit(
            "Usage:\n"
            "  sitewatcher check_domain <name> --owner <telegram_id> [--force] [--only a,b]\n"
            "Example:\n"
            "  sitewatcher check_domain example.com --owner 123456789 --only http_basic,tls_cert"
        )
    asyncio.run(_cmd_check_one(cfg, args.owner, args.name, only=only, use_cache=use_cache))


def cli() -> None:
    """Entry-point function for the console script."""
    main()


if __name__ == "__main__":
    main()
