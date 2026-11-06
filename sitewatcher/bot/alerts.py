from __future__ import annotations

from sitewatcher.check_policy import result_deadlines

import asyncio
import html
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import NamedTuple, Optional, Mapping, Any

from telegram.error import BadRequest, NetworkError, RetryAfter, TimedOut
from telegram.ext import ContextTypes  # noqa: F401

from .. import storage
from ..checks.base import CheckOutcome
from ..config import AppConfig, resolve_settings
from .utils import _resolve_alert_chat_id
from .formatting import _format_check
from .html import split_html
from ..utils.results import status_emoji as _status_emoji
from ..utils.results import (
    current_rkn_result,
    overall_from_results as _overall_from_results,
    status_text as _status_text,
    status_weight as _status_weight,
)

# Module-level logger (use consistently as 'log')
log = logging.getLogger(__name__)


class _AlertKey(NamedTuple):
    """Per-tenant dedupe key: owner + domain + overall level."""
    owner_id: int
    domain: str
    level: str  # "CRIT" | "WARN" | "OK" | "UNKNOWN"


@dataclass
class _AlertRecord:
    """State stored for each dedupe key."""
    last_sent_at: float = 0.0
    suppressed: int = 0
    last_text: str = ""


class AlertDeduper:
    """In-memory per-process deduper with a cooldown window."""

    def __init__(self, cooldown_sec: int) -> None:
        self.cooldown = max(0, int(cooldown_sec))
        self._state: dict[_AlertKey, _AlertRecord] = {}

    def peek_last_text(self, key: _AlertKey) -> Optional[str]:
        """Return last alert text for the given key (if any)."""
        rec = self._state.get(key)
        return rec.last_text if rec else None

    def should_send_now(
        self,
        key: _AlertKey,
        text: str,
        now: Optional[float] = None,
    ) -> tuple[bool, Optional[str]]:
        """Return (send_now, maybe_text).

        Policy:
          - Per-(owner_id, domain, level) cooldown window.
          - If an event repeats within the cooldown, do not send; only count it.
          - On the first send after cooldown, prefix the message with a suppression summary.
        """
        ts = time.time() if now is None else now
        rec = self._state.get(key)
        if rec is None:
            rec = _AlertRecord()
            self._state[key] = rec

        if rec.last_sent_at == 0 or (ts - rec.last_sent_at) >= self.cooldown:
            prefix = (
                f"(+{rec.suppressed} similar events in last {self.cooldown}s)\n"
                if rec.suppressed > 0
                else ""
            )
            return True, (prefix + text)

        # Within cooldown window: suppress and count
        rec.suppressed += 1
        return False, None

    def mark_sent(self, key: _AlertKey, text: str) -> None:
        """Commit dedupe state only after a successful delivery."""
        self._state[key] = _AlertRecord(last_sent_at=time.time(), last_text=text)

    def pending_summaries(self) -> list[_AlertKey]:
        """Return all ready keys so undeliverable owners cannot starve later summaries."""
        return [key for key in self._state if self.pending_summary(key) is not None]

    def discard(self, key: _AlertKey) -> None:
        """Forget counters for a domain that is no longer monitored."""
        self._state.pop(key, None)

    def pending_summary(self, key: _AlertKey) -> tuple[str, int] | None:
        """Prepare a summary; the returned count is acknowledged only after delivery."""
        rec = self._state.get(key)
        if rec is None or rec.suppressed <= 0 or time.time() - rec.last_sent_at < self.cooldown:
            return None
        return (
            f"{rec.suppressed} repetition(s) in last {self.cooldown}s "
            f"for owner {key.owner_id}, {key.domain} [{key.level}]",
            rec.suppressed,
        )

    def acknowledge_summary(self, key: _AlertKey, delivered_count: int) -> None:
        """Retain repetitions that arrived while the summary was being delivered."""
        rec = self._state.get(key)
        if rec is not None:
            rec.suppressed = max(0, rec.suppressed - delivered_count)
            rec.last_sent_at = time.time()


def _parse_bad_checks_from_alert(text: str) -> set[str]:
    """Extract check names that were non-OK from a previously sent alert (HTML)."""
    bad: set[str] = set()
    if not text:
        return bad
    # Skip header (first line), parse subsequent lines:
    for line in text.splitlines()[1:]:
        m = re.search(r"<code>([^<]+)</code>\s+—\s+<b>([^<]+)</b>", line)
        if not m:
            continue
        check = html.unescape(m.group(1)).strip()
        status = m.group(2).strip().upper()
        if status in {"WARN", "CRIT", "UNKNOWN"}:
            bad.add(check)
    return bad


def _compose_message(domain: str, overall: str, prev_overall: Optional[str], results) -> str:
    """Build alert message body with header and per-check lines."""
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"
    if prev_overall:
        head += f" (was {prev_overall})"

    return "\n".join([head] + [_format_check(result) for result in results])


def _enabled_checks_for(cfg: AppConfig, owner_id: int, domain: str) -> list[str]:
    """Return names of enabled checks (respecting per-domain overrides from storage)."""
    settings = resolve_settings(cfg, domain, storage.get_domain_override(owner_id, domain))
    return [name for name, enabled in settings.checks.model_dump().items() if enabled]


def _complete_results(cfg: AppConfig, owner_id: int, domain: str, current: list) -> list:
    """Include earlier results for checks not due in this tick."""
    by_check = {result.check: result for result in current}
    enabled = set(_enabled_checks_for(cfg, owner_id, domain))
    for name, row in storage.latest_check_results(owner_id, domain).items():
        if not current_rkn_result(name, row['metrics_json'], cfg.rkn.max_source_age_hours,
                                  status=row['status']):
            continue
        if name not in by_check and name in enabled:
            by_check[name] = CheckOutcome(name, row["status"], row["message"], {}, cached=True)
    for name in enabled - by_check.keys():
        by_check[name] = CheckOutcome(name, "UNKNOWN", "not checked yet", {})
    return list(by_check.values())


def _is_fresh_ok_for_all(
    cfg: AppConfig,
    owner_id: int,
    domain: str,
    enabled_checks: list[str],
    current_results: list,
) -> bool:
    """Return True if all enabled checks are confirmed OK.

    A check is considered confirmed OK if:
      - it was run in the current tick and is OK; or
      - its latest stored result is OK and fresh (no older than its interval).
    Otherwise, recovery to OK is not confirmed.
    """
    # Current statuses from this tick
    current_map: dict[str, str] = {
        getattr(r, "check", ""): _status_text(getattr(r, "status", ""))
        for r in current_results if not getattr(r, "cached", False)
        or getattr(r, "assessment_changed", False)
    }

    # A failed settings read cannot confirm that a recovery is fresh.
    try:
        override = storage.get_domain_override(owner_id, domain) or {}
        domain_iv = resolve_settings(cfg, domain, override).interval_minutes
    except Exception:
        return False

    # Check all enabled checks
    for check in enabled_checks:
        # If present in the current tick, it must be OK
        if check in current_map:
            if _status_weight(current_map[check]) > 0:
                return False
            continue

        # Otherwise check the latest stored result and its freshness
        row = storage.last_history_for_check(owner_id, domain, check)
        if not row:
            return False  # no data -> not confirmed

        # Same evidence deadline as scheduling/reporting, including daily caches.
        _, due_at, _ = result_deadlines(cfg, check, domain_iv, row)
        if datetime.now(timezone.utc) >= due_at:
            return False

        # Stored status must be OK
        st = str((row.get("status") if isinstance(row, dict) else row["status"])).upper()
        if _status_weight(st) > 0:
            return False

    return True


async def safe_send_message(
    bot,
    *,
    chat_id: int,
    text: str,
    parse_mode: Optional[str] = None,
    disable_web_page_preview: bool = True,
    max_attempts: int = 3,
):
    """Send a message with tiny retry logic (RetryAfter/TimedOut/NetworkError).

    - Honors RetryAfter from Telegram (sleeps and retries).
    - Retries once or twice on transient network timeouts.
    - On success returns telegram.Message; on final failure re-raises the error.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    chunks = split_html(text) if parse_mode == "HTML" else [text[i:i + 1900] for i in range(0, len(text), 1900)]
    message = None
    for chunk in chunks:
        for attempt in range(1, max_attempts + 1):
            try:
                message = await bot.send_message(
                    chat_id=chat_id,
                    text=chunk,
                    parse_mode=parse_mode,
                    disable_web_page_preview=disable_web_page_preview,
                )
                break
            except BadRequest:
                raise
            except RetryAfter as error:
                if attempt == max_attempts:
                    raise
                delay = error.retry_after
                if isinstance(delay, timedelta):
                    delay = delay.total_seconds()
                await asyncio.sleep(max(1.0, float(delay)))
            except (TimedOut, NetworkError):
                if attempt == max_attempts:
                    raise
                await asyncio.sleep(float(attempt))
    return message


def _log_alert_skipped(
    reason: str,
    *,
    owner_id: int,
    domain: str,
    level: str,
    run_id: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> None:
    """Helper to log a skipped alert with a consistent schema."""
    xtra = dict(extra or {})
    xtra.update({"event": "alert.skipped", "reason": reason, "owner_id": owner_id, "domain": domain, "level": level})
    if run_id:
        xtra["run_id"] = run_id
    log.info("alert.skipped", extra=xtra)


async def maybe_send_alert(update, context, owner_id: int, domain: str, results, *, run_id=None) -> None:
    """Serialize delivery decisions for one owner's domain."""
    locks = context.application.bot_data.setdefault("alert_locks", {})
    lock = locks.setdefault((owner_id, domain), asyncio.Lock())
    async with lock:
        if not storage.domain_exists(owner_id, domain):
            return
        cfg = context.application.bot_data['cfg']
        preferences = storage.domain_notifications(cfg, owner_id, domain)
        errors = []
        for channel in ('telegram', 'email'):
            if not preferences[channel]:
                continue
            try:
                await _maybe_send_alert(update, context, owner_id, domain, results,
                                        run_id=run_id, channel=channel)
            except Exception as error:
                errors.append(error)
        if errors:
            raise errors[0]


def _channel_deduper(context, channel: str):
    key = 'alert_deduper' if channel == 'telegram' else 'email_alert_deduper'
    if channel == 'email' and key not in context.application.bot_data:
        cfg = context.application.bot_data['cfg']
        context.application.bot_data[key] = AlertDeduper(cfg.alerts.effective_cooldown)
    return context.application.bot_data.get(key)


def _channel_available(update, context, cfg, owner_id: int, channel: str) -> bool:
    if channel == 'email':
        from ..email_settings import email_ready
        return email_ready(owner_id)
    return bool(context.bot and _resolve_alert_chat_id(context, update, cfg, owner_id))


async def _deliver_channel(update, context, cfg, owner_id: int, domain: str,
                           channel: str, text: str) -> None:
    if channel == 'email':
        from ..email_delivery import send_notification_email
        await send_notification_email(owner_id, f'SiteWatcher: {domain}', text)
    else:
        await safe_send_message(
            context.bot, chat_id=_resolve_alert_chat_id(context, update, cfg, owner_id),
            text=text, parse_mode='HTML', disable_web_page_preview=True,
        )


async def _maybe_send_alert(
    update,
    context,
    owner_id: int,
    domain: str,
    results,
    *,
    run_id: Optional[str] = None,
    channel: str = "telegram",
) -> None:
    """Send problem alerts (WARN/CRIT) and a recovery alert when status returns to OK.

    Rules:
      - Respect cfg.alerts.enabled and per-user toggle.
      - Recovery (prev in {WARN,CRIT} -> now OK): send immediately, bypassing cooldown & deduper,
        but only when all enabled checks are confirmed OK (fresh/OK).
      - Policy (cfg.alerts.policy): "worsen_only" | "overall_change" | "all" (default: "overall_change").
      - Cooldown (cfg.alerts.cooldown_sec or cfg.alerts.debounce_sec) applies to repeating problem states.
      - An unavailable destination does not consume a pending transition.
    """
    cfg: AppConfig = context.application.bot_data["cfg"]
    if not results:
        return
    if not getattr(cfg.alerts, "enabled", True):
        _log_alert_skipped("alerts_disabled", owner_id=owner_id, domain=domain, level="-", run_id=run_id)
        return

    # The workspace Telegram switch is independent of email subscriptions.
    if channel == "telegram" and not storage.is_user_alerts_enabled(owner_id):
        _log_alert_skipped("user_alerts_disabled", owner_id=owner_id, domain=domain, level="-", run_id=run_id)
        return

    current_results = results
    results = _complete_results(cfg, owner_id, domain, results)
    now = datetime.now(timezone.utc)
    overall = _overall_from_results(results)
    overall_txt = _status_text(overall)

    row = storage.get_alert_state(owner_id, domain, channel=channel)
    prev_overall = (row["last_overall"] if row else None)
    prev_overall_txt = _status_text(prev_overall) if prev_overall else None

    # Parse last_sent_at (may be None)
    last_sent_iso = (row["last_sent_at"] if row else None)
    last_sent_at_dt: Optional[datetime] = None
    if last_sent_iso:
        try:
            last_sent_at_dt = datetime.fromisoformat(last_sent_iso)
        except Exception:
            last_sent_at_dt = None

    # First observation: just persist baseline without sending
    if prev_overall is None:
        storage.upsert_alert_state(owner_id, domain, overall_txt, None, channel=channel)
        _log_alert_skipped("baseline", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
        return

    # Recovery path: previous was bad and now OK -> notify only if ALL enabled checks are confirmed OK
    if overall_txt == "OK" and prev_overall_txt in {"WARN", "CRIT"}:
        enabled = _enabled_checks_for(cfg, owner_id, domain)
        if not _is_fresh_ok_for_all(cfg, owner_id, domain, enabled, current_results):
            _log_alert_skipped("recovery_not_confirmed", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
            return

        text = _compose_message(domain, overall_txt, prev_overall_txt, results)

        # Add a list of checks that recovered (based on last problem text, if available)
        recovered: list[str] = []
        deduper = _channel_deduper(context, channel)
        if deduper is not None:
            prev_key = _AlertKey(owner_id=owner_id, domain=domain, level=prev_overall_txt)
            last_problem_text = deduper.peek_last_text(prev_key)  # may be None (after restart)
            bad_before = _parse_bad_checks_from_alert(last_problem_text or "")
            if bad_before:
                for r in results:
                    if _status_text(r.status) == "OK" and str(r.check) in bad_before:
                        recovered.append(str(r.check))
        if recovered:
            text += "\n\nRecovered checks: " + ", ".join(
                f"<code>{html.escape(c)}</code>" for c in recovered
            )

        if not _channel_available(update, context, cfg, owner_id, channel):
            _log_alert_skipped("no_chat_id", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
            return
        try:
            await _deliver_channel(update, context, cfg, owner_id, domain, channel, text)
            storage.upsert_alert_state(owner_id, domain, overall_txt, now.isoformat(), channel=channel)
            log.info(
                "alert.sent",
                extra={"event": "alert.sent", "owner_id": owner_id, "domain": domain, "level": overall_txt, "run_id": run_id, "type": "recovery"},
            )
        except Exception as e:
            log.error(
                "alert.error",
                exc_info=e,
                extra={"event": "alert.error", "owner_id": owner_id, "domain": domain, "level": overall_txt, "run_id": run_id, "type": "recovery"},
            )
            raise
        return

    # Policy gate (for problem states and other transitions)
    policy = getattr(cfg.alerts, "policy", "overall_change")
    if policy == "worsen_only":
        # Only notify when the overall severity increases
        if _status_weight(overall_txt) <= _status_weight(prev_overall_txt or "OK"):
            storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_iso, channel=channel)
            _log_alert_skipped("not_worsened", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
            return
    elif policy == "overall_change":
        if overall_txt == prev_overall_txt:
            # Nothing changed
            _log_alert_skipped("no_change", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
            return
    elif policy == "all":
        pass
    else:
        # Default to change-only if policy is unknown
        if overall_txt == prev_overall_txt:
            _log_alert_skipped("unknown_policy_no_change", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id, extra={"policy": policy})
            return

    # Cooldown for repeating alerts (applies to problem states)
    cooldown = cfg.alerts.effective_cooldown
    if overall_txt == prev_overall_txt and last_sent_at_dt is not None and (now - last_sent_at_dt) < timedelta(seconds=cooldown):
        _log_alert_skipped("cooldown_active", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
        return

    # Resolve destination chat
    if not _channel_available(update, context, cfg, owner_id, channel):
        _log_alert_skipped("no_chat_id", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
        return

    # Build message body
    text = _compose_message(domain, overall_txt, prev_overall_txt, results)

    # Optional in-process deduper (per (owner, domain, level))
    deduper: Optional[AlertDeduper] = _channel_deduper(context, channel)  # type: ignore[assignment]
    key = _AlertKey(owner_id=owner_id, domain=domain, level=overall_txt)
    if deduper is not None and overall_txt == prev_overall_txt:
        send_now, maybe_text = deduper.should_send_now(key, text)
        if not send_now:
            storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_iso, channel=channel)
            _log_alert_skipped("suppressed_by_deduper", owner_id=owner_id, domain=domain, level=overall_txt, run_id=run_id)
            return
        if maybe_text:
            text = maybe_text

    # Send and persist
    try:
        await _deliver_channel(update, context, cfg, owner_id, domain, channel, text)
        storage.upsert_alert_state(owner_id, domain, overall_txt, now.isoformat(), channel=channel)
        if deduper is not None:
            deduper.mark_sent(key, text)
        log.info(
            "alert.sent",
            extra={"event": "alert.sent", "owner_id": owner_id, "domain": domain, "level": overall_txt, "run_id": run_id, "type": "problem"},
        )
    except Exception as e:
        log.exception(
            "alert send failed for %s: %s", domain, e,
            extra={"event": "alert.error", "owner_id": owner_id, "domain": domain, "level": overall_txt, "run_id": run_id, "type": "problem"},
        )
        raise
