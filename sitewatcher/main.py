# sitewatcher/main.py
from __future__ import annotations

import argparse
import asyncio
from typing import Iterable, Optional

from dotenv import load_dotenv

from .bot import run_bot
from .config import AppConfig, load_config
from .dispatcher import Dispatcher
from . import storage


load_dotenv()  # Load .env once at process start


def _parse_args() -> argparse.Namespace:
    """
    CLI parser for three simple modes:
      - bot: run Telegram bot (blocking)
      - check_all: run checks for all domains once
      - check: run checks for a single domain once

    Extra options:
      --config <path>   : path to config.yaml
      --force           : ignore cache (fresh checks only)
      --only a,b,c      : run only selected checks
    """
    p = argparse.ArgumentParser(description="sitewatcher CLI")
    p.add_argument("mode", choices=["bot", "check_all", "check_domain"], help="Run mode")
    p.add_argument("name", nargs="?", help="Domain for 'check_domain'")
    p.add_argument("--config", default=None, help="Path to config.yaml")
    p.add_argument("--force", action="store_true", help="Ignore cache and run all checks live")
    p.add_argument(
        "--only",
        default=None,
        help="Comma-separated list of checks to run (e.g. http_basic,tls_cert)",
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
    domain: str,
    *,
    only_checks: Optional[list[str]] = None,
    use_cache: bool = True,
) -> list:
    """Run checks for a single domain and persist results to storage."""
    async with Dispatcher(cfg) as d:
        results = await d.run_for(domain, only_checks=only_checks, use_cache=use_cache)
    for r in results:
        storage.save_history(domain, r.check, r.status, r.message, r.metrics)
    return results


def _parse_only(arg: Optional[str]) -> Optional[list[str]]:
    if not arg:
        return None
    return [x.strip() for x in arg.split(",") if x.strip()]


async def _cmd_check_all(cfg: AppConfig, *, only: Optional[list[str]], use_cache: bool) -> None:
    names = storage.list_domains()
    if not names:
        print("No domains in database.")
        return

    # Run sequentially: simple & predictable. Concurrency is handled *within* Dispatcher.
    for name in names:
        results = await _run_and_persist(cfg, name, only_checks=only, use_cache=use_cache)
        overall = _overall_from(results)
        checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
        print(f"{_status_emoji(overall)} {name} — {overall} -> {checks_summary}")


async def _cmd_check_one(cfg: AppConfig, name: str, *, only: Optional[list[str]], use_cache: bool) -> None:
    results = await _run_and_persist(cfg, name, only_checks=only, use_cache=use_cache)
    overall = _overall_from(results)
    checks_summary = ", ".join(f"{r.check}:{_status_str(r.status)}" for r in results)
    print(f"{_status_emoji(overall)} {name} — {overall} -> {checks_summary}")


def main() -> None:
    """Entrypoint. See _parse_args() for usage."""
    args = _parse_args()
    cfg = load_config(args.config)

    # --force disables cache, otherwise allow cache
    use_cache = not bool(args.force)
    only = _parse_only(args.only)

    if args.mode == "bot":
        # Blocking call; Application.run_polling() manages the event loop internally.
        run_bot(cfg)
        return

    if args.mode == "check_all":
        asyncio.run(_cmd_check_all(cfg, only=only, use_cache=use_cache))
        return

    # check_domain
    if not args.name:
        raise SystemExit("Usage: python -m sitewatcher.main check_domain <name> [--force] [--only a,b]")

    asyncio.run(_cmd_check_one(cfg, args.name, only=only, use_cache=use_cache))


if __name__ == "__main__":
    main()
