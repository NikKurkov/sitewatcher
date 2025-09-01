# sitewatcher/bot/alerts.py
from __future__ import annotations

import html
import logging
import time
import re
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import NamedTuple, Optional

from telegram.ext import ContextTypes  # noqa: F401

from .. import storage
from ..config import AppConfig, resolve_settings
from .utils import _resolve_alert_chat_id

logger = logging.getLogger("sitewatcher.bot")


class _AlertKey(NamedTuple):
    domain: str
    level: str  # "CRIT" | "WARN" | "OK" | "UNKNOWN"


@dataclass
class _AlertRecord:
    last_sent_at: float = 0.0
    suppressed: int = 0
    last_text: str = ""


class AlertDeduper:
    """In-memory per-process deduper with cooldown window."""
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
        """Return (send_now, maybe_text). Applies per-key cooldown with jitter-free counting."""
        ts = time.time() if now is None else now
        rec = self._state.get(key)
        if rec is None:
            rec = _AlertRecord()
            self._state[key] = rec

        if rec.last_sent_at == 0 or (ts - rec.last_sent_at) >= self.cooldown:
            prefix = f"(+{rec.suppressed} similar events in last {self.cooldown}s)\n" if rec.suppressed > 0 else ""
            rec.last_sent_at = ts
            rec.last_text = text
            rec.suppressed = 0
            return True, (prefix + text)

        # Within cooldown window: suppress and count
        rec.suppressed += 1
        rec.last_text = text
        return False, None

    def flush_summaries(self, max_batch: int = 20) -> list[tuple[_AlertKey, str]]:
        """Flush summary lines for keys that had suppressions and whose cooldown has elapsed."""
        out: list[tuple[_AlertKey, str]] = []
        ts = time.time()
        for key, rec in list(self._state.items()):
            if rec.suppressed > 0 and (ts - rec.last_sent_at) >= self.cooldown:
                msg = f"{rec.suppressed} repetition(s) in last {self.cooldown}s for {key.domain} [{key.level}]"
                rec.suppressed = 0
                rec.last_sent_at = ts
                out.append((key, msg))
                if len(out) >= max_batch:
                    break
        return out


def _status_text(s) -> str:
    """Normalize status (enum or str) to uppercased string."""
    return getattr(s, "value", str(s)).upper()


def _status_weight(s) -> int:
    """Map status to numeric severity for comparisons."""
    u = _status_text(s)
    if u == "CRIT":
        return 2
    if u in ("WARN", "UNKNOWN"):
        return 1
    return 0


def _status_emoji(s) -> str:
    u = _status_text(s)
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(u, "⚪")


def _status_bullet(s) -> str:
    u = _status_text(s)
    if u == "CRIT":
        return "🔺"
    if u == "WARN":
        return "🔸"
    return "•"


def _overall_from_results(results) -> str:
    """Compute overall status from individual check results."""
    worst = 0
    for r in results:
        worst = max(worst, _status_weight(getattr(r.status, "value", str(r.status))))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]

def _parse_bad_checks_from_alert(text: str) -> set[str]:
    """Extract checks that were non-OK from previously sent alert HTML text."""
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

    lines = [head]
    for r in results:
        st = _status_text(r.status)
        bullet = _status_bullet(st)
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(str(r.check)),
                status=html.escape(st),
                msg=html.escape(str(r.message)),
            )
        )
    return "\n".join(lines)


def _enabled_checks_for(cfg: AppConfig, owner_id: int, domain: str) -> list[str]:
    """
    Вернёт список имён включённых проверок (с учётом доменных override из storage).
    Логика совпадает по сути с Dispatcher._resolve() для checks.*.
    """
    settings = resolve_settings(cfg, domain)
    try:
        patch = storage.get_domain_override(owner_id, domain) or {}
    except Exception:
        patch = {}

    if isinstance(patch.get("checks"), dict):
        for k, v in patch["checks"].items():
            if hasattr(settings.checks, k):
                setattr(settings.checks, k, bool(v))

    enabled: list[str] = []
    for name in dir(settings.checks):
        if name.startswith("_"):
            continue
        try:
            val = getattr(settings.checks, name)
        except Exception:
            continue
        if isinstance(val, bool) and val:
            enabled.append(name)
    return enabled


def _is_fresh_ok_for_all(
    cfg: AppConfig,
    owner_id: int,
    domain: str,
    enabled_checks: list[str],
    current_results: list,
) -> bool:
    """
    Для recovery в OK: проверяем, что все включённые проверки имеют OK:
      - или прямо в текущем запуске,
      - или по последнему свежему результату из БД (не старше своего интервала).
    Если чего-то нет/протухло/не OK — считаем, что recovery неподтверждён.
    """
    # Текущие статусы из этого тика
    current_map: dict[str, str] = {
        getattr(r, "check", ""): getattr(getattr(r, "status", None), "value", str(getattr(r, "status", ""))).upper()
        for r in current_results
    }

    # В доменном override может быть общий interval_minutes
    try:
        override = storage.get_domain_override(owner_id, domain) or {}
    except Exception:
        override = {}

    domain_iv = None
    if isinstance(override.get("interval_minutes"), int) and override["interval_minutes"] > 0:
        domain_iv = int(override["interval_minutes"])

    # Проходим по всем включённым проверкам
    for check in enabled_checks:
        # Если в текущем запуске была эта проверка — она должна быть OK
        if check in current_map:
            if _status_weight(current_map[check]) > 0:
                return False
            continue

        # Иначе — смотрим последний результат в БД и его «свежесть»
        row = storage.last_history_for_check(owner_id, domain, check)
        if not row:
            return False  # нет информации — восстановления не подтверждаем

        # Свежесть: берём доменный общий интервал, иначе индивидуальный из schedules
        if domain_iv is not None:
            ttl_min = domain_iv
        else:
            sched = getattr(cfg.schedules, check, None)
            ttl_min = int(getattr(sched, "interval_minutes", 0) or 0)
            if ttl_min <= 0:
                # если вдруг нет интервала в конфиге — считаем несвежим
                return False

        mins = storage.minutes_since_last(owner_id, domain, check)
        if mins is None or mins > ttl_min:
            return False  # протухло — не подтверждаем

        # Сам статус должен быть OK
        if isinstance(row, dict):
            st = str(row.get("status", "")).upper()
        else:
            st = str(row["status"]).upper()
            
        if _status_weight(st) > 0:
            return False

    return True


async def maybe_send_alert(update, context, owner_id: int, domain: str, results) -> None:
    """Send problem alerts (WARN/CRIT) and a recovery alert when status returns to OK.

    Rules:
    - Respect cfg.alerts.enabled.
    - Recovery (prev in {WARN,CRIT} -> now OK): send immediately, bypass cooldown and deduper.
    - Policy (cfg.alerts.policy): "worsen_only" | "overall_change" | "all" (default "overall_change").
    - Cooldown (cfg.alerts.cooldown_sec or cfg.alerts.debounce_sec): applied to repeating problem states.
    - If chat_id cannot be resolved, just persist state without sending.
    """
    cfg: AppConfig = context.application.bot_data["cfg"]
    if not getattr(cfg.alerts, "enabled", True):
        return

    now = datetime.now(timezone.utc)
    overall = _overall_from_results(results)
    overall_txt = _status_text(overall)

    row = storage.get_alert_state(owner_id, domain)
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
        storage.upsert_alert_state(owner_id, domain, overall_txt, None)
        return

    # Recovery path: previous was bad and now OK -> notify только если ВСЕ включённые проверки подтверждённо OK
    if overall_txt == "OK" and prev_overall_txt in {"WARN", "CRIT"}:
        enabled = _enabled_checks_for(cfg, owner_id, domain)
        if not _is_fresh_ok_for_all(cfg, owner_id, domain, enabled, results):
            logger.debug("alert: suppress recovery OK for %s (not all enabled checks are fresh/OK)", domain)
            return

        text = _compose_message(domain, overall_txt, prev_overall_txt, results)

        # Дополнительно: показать, какие именно проверки «выздоровели»
        recovered: list[str] = []
        deduper = context.application.bot_data.get("alert_deduper")
        if deduper is not None:
            prev_key = _AlertKey(domain=domain, level=prev_overall_txt)
            last_problem_text = deduper.peek_last_text(prev_key)  # may be None (после рестарта)
            bad_before = _parse_bad_checks_from_alert(last_problem_text or "")
            if bad_before:
                for r in results:
                    if _status_text(r.status) == "OK" and str(r.check) in bad_before:
                        recovered.append(str(r.check))
        if recovered:
            text += "\n\nRecovered checks: " + ", ".join(f"<code>{html.escape(c)}</code>" for c in recovered)

        chat_id = _resolve_alert_chat_id(context, update, cfg, owner_id)
        if not chat_id:
            storage.upsert_alert_state(owner_id, domain, overall_txt, None)
            return
        try:
            await context.bot.send_message(chat_id=chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)
            storage.upsert_alert_state(owner_id, domain, overall_txt, now.isoformat())
        except Exception:
            storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_at_dt.isoformat() if last_sent_at_dt else None)
            raise
        return

    # Policy gate (for problem states and other transitions)
    policy = getattr(cfg.alerts, "policy", "overall_change")
    if policy == "worsen_only":
        # Only notify when the overall severity increases
        if _status_weight(overall_txt) <= _status_weight(prev_overall_txt or "OK"):
            storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_iso)
            return

    elif policy == "overall_change":
        if overall_txt == prev_overall_txt:
            # Nothing changed
            return
    elif policy == "all":
        pass
    else:
        # Default to change-only if policy is unknown
        if overall_txt == prev_overall_txt:
            return

    # Cooldown for repeating alerts (applies to problem states)
    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 0)) or 0)
    if last_sent_at_dt is not None and (now - last_sent_at_dt) < timedelta(seconds=cooldown):
        storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_iso)
        return

    # Resolve destination chat
    alert_chat_id = _resolve_alert_chat_id(context, update, cfg, owner_id)
    if not alert_chat_id:
        storage.upsert_alert_state(owner_id, domain, overall_txt, None)
        return

    # Build message body
    text = _compose_message(domain, overall_txt, prev_overall_txt, results)

    # Optional in-process deduper (per (domain, level))
    deduper: Optional[AlertDeduper] = context.application.bot_data.get("alert_deduper")  # type: ignore[assignment]
    if deduper is not None:
        key = _AlertKey(domain=domain, level=overall_txt)
        send_now, maybe_text = deduper.should_send_now(key, text)
        if not send_now:
            storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_iso)
            return
        if maybe_text:
            text = maybe_text

    # Send and persist
    try:
        await context.bot.send_message(chat_id=alert_chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)
        storage.upsert_alert_state(owner_id, domain, overall_txt, now.isoformat())
    except Exception as e:
        logger.exception("alert send failed for %s: %s", domain, e)
        # Preserve previous timestamp on failure
        storage.upsert_alert_state(owner_id, domain, overall_txt, last_sent_at_dt.isoformat() if last_sent_at_dt else None)
