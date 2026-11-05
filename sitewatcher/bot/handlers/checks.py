from __future__ import annotations

import logging
from typing import Iterable

from telegram import Update
from telegram.ext import ContextTypes

from ... import storage
from ...config import AppConfig, resolve_settings
from ...dispatcher import Dispatcher
from ..formatting import _format_results, _format_results_summary
from ..utils import safe_reply_html
from ..alerts import maybe_send_alert
from ...utils.domains import DOMAIN_RE, normalize_domain

log = logging.getLogger(__name__)

# --- internal helpers ---------------------------------------------------------

def _parse_force(args: Iterable[str]) -> bool:
    """Return True if args contain any force flag."""
    tokens = {str(a).strip().lower() for a in (args or [])}
    return bool({"--force", "-f", "force"} & tokens)


# --- commands ----------------------------------------------------------------

async def cmd_check_domain(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Run checks for a single domain (ephemeral if not owned)."""
    if not context.args:
        await update.message.reply_text("Usage: /check example.com")
        return

    cfg: AppConfig = context.application.bot_data["cfg"]
    owner_id = update.effective_user.id

    force = _parse_force(context.args)
    refresh_flags = [arg for arg in context.args if arg.startswith('--refresh')]
    refresh = refresh_flags[0].removeprefix('--refresh=') if refresh_flags else None
    names = [arg for arg in context.args if not _parse_force([arg])
             and arg not in refresh_flags]
    if refresh_flags and (len(refresh_flags) != 1 or refresh not in {'tls_cert', 'whois'}
                          or len(names) != 1):
        await update.message.reply_text('Usage: /check example.com --refresh=whois (or tls_cert)')
        return
    name = normalize_domain(names[0] if names else "")
    if not name or not DOMAIN_RE.fullmatch(name):
        await update.message.reply_text("Enter a valid domain, for example /check example.com")
        return

    if refresh:
        if not storage.domain_exists(owner_id, name):
            await update.message.reply_text('Metadata refresh requires an owned domain')
            return
        resolved = resolve_settings(cfg, name, storage.get_domain_override(owner_id, name))
        if not getattr(resolved.checks, refresh):
            await update.message.reply_text('Metadata check is disabled')
            return
        async with Dispatcher(cfg) as dispatcher:
            results = await dispatcher.run_for(
                owner_id, name, only_checks=[refresh], refresh_checks=[refresh],
            )
        storage.save_histories(owner_id, name, results, create_missing=False, source='manual')
        text = await _format_results(owner_id, name, results, persist=False)
        if not results or any(result.cached for result in results):
            text += '\nCached metadata reused; refresh is limited by provider cooldown'
        await safe_reply_html(update.message, text)
        return

    log.info(
        "cmd.check.start",
        extra={"event": "cmd.check.start", "owner_id": owner_id, "domain": name, "force": bool(force)},
    )

    # Owned domain: normal mode (persist history + alerts)
    if storage.domain_exists(owner_id, name):
        log.info(
            "cmd.check.mode",
            extra={"event": "cmd.check.mode", "owner_id": owner_id, "domain": name, "mode": "owned"},
        )
        async with Dispatcher(cfg) as d:
            results = await d.run_for(owner_id, name, use_cache=not force)
            text = await _format_results(owner_id, name, results, persist=True)
        await safe_reply_html(update.message, text)
        await maybe_send_alert(update, context, owner_id, name, results)
        log.info(
            "cmd.check.done",
            extra={"event": "cmd.check.done", "owner_id": owner_id, "domain": name, "mode": "owned"},
        )
        return

    # Ephemeral mode: not owned -> no persistence, no alerts, force-disable keywords
    log.info(
        "cmd.check.mode",
        extra={"event": "cmd.check.mode", "owner_id": owner_id, "domain": name, "mode": "ephemeral"},
    )
    async with Dispatcher(cfg) as d:
        allowed = [check for check in type(cfg.defaults.checks).model_fields if check != "keywords"]
        results = await d.run_for(owner_id, name, only_checks=allowed, use_cache=False, ephemeral=True)

    text = await _format_results(owner_id, name, results, persist=False)
    await safe_reply_html(update.message, text)
    log.info(
        "cmd.check.done",
        extra={"event": "cmd.check.done", "owner_id": owner_id, "domain": name, "mode": "ephemeral"},
    )


async def cmd_check_all_detail(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Detailed check for all owned domains (per-check lines for every domain)."""
    await _check_all(update, context, _format_results, "\n\n", "check_all_detail")


async def cmd_check_all(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Summary check for all owned domains (overall line; details only for non-OK)."""
    await _check_all(update, context, _format_results_summary, "\n", "check_all")


async def _check_all(update, context, format_results, separator: str, command: str) -> None:
    msg = getattr(update, "effective_message", None)
    cfg: AppConfig = context.application.bot_data["cfg"]
    owner_id = update.effective_user.id
    if any(arg.startswith('--refresh') for arg in (context.args or [])):
        if msg:
            await msg.reply_text('Metadata refresh requires /check with one owned domain')
        return
    names = storage.list_domains(owner_id)

    if not names:
        if msg:
            await msg.reply_text("No domains in DB")
        return

    force = _parse_force(context.args)
    log.info(
        f"cmd.{command}.start",
        extra={"event": f"cmd.{command}.start", "owner_id": owner_id, "count": len(names), "force": bool(force)},
    )

    parts: list[str] = []
    async with Dispatcher(cfg) as d:
        for name in names:
            try:
                results = await d.run_for(owner_id, name, use_cache=not force)
            except Exception:
                # Keep going even if one domain fails
                log.exception(
                    f"cmd.{command}.domain_error",
                    extra={"event": f"cmd.{command}.domain_error", "owner_id": owner_id, "domain": name},
                )
                continue
            parts.append(await format_results(owner_id, name, results, persist=True))
            await maybe_send_alert(update, context, owner_id, name, results)

    text = separator.join(parts) if parts else "No results."
    await safe_reply_html(msg, text)

    log.info(
        f"cmd.{command}.done",
        extra={"event": f"cmd.{command}.done", "owner_id": owner_id, "count": len(names)},
    )
