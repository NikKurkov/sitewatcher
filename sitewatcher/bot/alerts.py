# /bot/alerts.py
from __future__ import annotations

import html
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import NamedTuple, Optional

from telegram.ext import ContextTypes

from .. import storage
from ..config import AppConfig
from .utils import _resolve_alert_chat_id

logger = logging.getLogger("sitewatcher.bot")


class _AlertKey(NamedTuple):
    domain: str
    level: str   # "CRIT" | "WARN" | "OK" | "UNKNOWN"


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

    def should_send_now(self, key: _AlertKey, text: str, now: Optional[float] = None) -> tuple[bool, Optional[str]]:
        now = now or time.time()
        rec = self._state.get(key)
        if rec is None:
            rec = _AlertRecord()
            self._state[key] = rec
        if rec.last_sent_at == 0 or (now - rec.last_sent_at) >= self.cooldown:
            prefix = f"(+{rec.suppressed} similar events in last {self.cooldown}s)\n" if rec.suppressed > 0 else ""
            rec.last_sent_at = now
            rec.last_text = text
            rec.suppressed = 0
            return True, (prefix + text)
        rec.suppressed += 1
        rec.last_text = text
        return False, None

    def flush_summaries(self, max_batch: int = 20) -> list[tuple[_AlertKey, str]]:
        out: list[tuple[_AlertKey, str]] = []
        now = time.time()
        for key, rec in list(self._state.items()):
            if rec.suppressed > 0 and (now - rec.last_sent_at) >= self.cooldown:
                msg = f"{rec.suppressed} repetition(s) in last {self.cooldown}s for {key.domain} [{key.level}]"
                rec.suppressed = 0
                rec.last_sent_at = now
                out.append((key, msg))
                if len(out) >= max_batch:
                    break
        return out


def _status_weight(s: str) -> int:
    s = (s or "").upper()
    if s == "CRIT":
        return 2
    if s in ("WARN", "UNKNOWN"):
        return 1
    return 0


def _status_emoji(s: str) -> str:
    s = (s or "").upper()
    return {"CRIT": "🔴", "WARN": "🟡", "OK": "🟢", "UNKNOWN": "⚪"}.get(s, "⚪")


def _status_bullet(s: str) -> str:
    s = (s or "").upper()
    if s == "CRIT":
        return "🔺"
    if s == "WARN":
        return "🔸"
    return "•"


def _overall_from_results(results) -> str:
    worst = 0
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        worst = max(worst, _status_weight(st))
    return {2: "CRIT", 1: "WARN", 0: "OK"}[worst]


async def maybe_send_alert(update, context, owner_id: int, domain: str, results) -> None:
    """Decide whether to send an alert and deliver it (respect policy + cooldown)."""
    cfg: AppConfig = context.application.bot_data["cfg"]
    if not getattr(cfg.alerts, "enabled", True):
        return

    now = datetime.now(timezone.utc)
    overall = _overall_from_results(results)

    row = storage.get_alert_state(owner_id, domain)
    prev_overall = row["last_overall"] if row else None
    policy = getattr(cfg.alerts, "policy", "overall_change")

    last_sent_at_dt = None
    if row:
        raw_last = row["last_sent_at"]
        if raw_last:
            try:
                last_sent_at_dt = datetime.fromisoformat(raw_last)
            except Exception:
                last_sent_at_dt = None

    # baseline
    if prev_overall is None:
        storage.upsert_alert_state(owner_id, domain, overall, None)  # ⟵ исправлено
        return

    # policy
    if policy == "worsen_only":
        if _status_weight(overall) <= _status_weight(prev_overall):
            storage.upsert_alert_state(
                owner_id, domain, overall, row["last_sent_at"] if row else None
            )
            return
    elif policy == "overall_change":
        if overall == prev_overall:
            return
    elif policy == "all":
        pass
    else:
        if overall == prev_overall:
            return

    cooldown = int(getattr(cfg.alerts, "cooldown_sec", getattr(cfg.alerts, "debounce_sec", 0)) or 0)
    if last_sent_at_dt is not None and (now - last_sent_at_dt) < timedelta(seconds=cooldown):
        storage.upsert_alert_state(owner_id, domain, overall, row["last_sent_at"])  # ⟵ исправлено
        return

    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall} (was {prev_overall})"
    lines = [head]
    for r in results:
        st = getattr(r.status, "value", str(r.status))
        bullet = _status_bullet(st)
        lines.append(
            "{bullet} <code>{check}</code> — <b>{status}</b> — {msg}".format(
                bullet=bullet,
                check=html.escape(str(r.check)),
                status=html.escape(st),
                msg=html.escape(str(r.message)),
            )
        )
    text = "\n".join(lines)

    alert_chat_id = _resolve_alert_chat_id(context, update, cfg, owner_id)
    if not alert_chat_id:
        storage.upsert_alert_state(owner_id, domain, overall, None)  # ⟵ уже корректно
        return

    # dedupe via instance stored in bot_data
    deduper: AlertDeduper | None = context.application.bot_data.get("alert_deduper")
    if deduper is not None:
        key = _AlertKey(domain=domain, level=overall)
        send_now, maybe_text = deduper.should_send_now(key, text)
        if not send_now:
            storage.upsert_alert_state(owner_id, domain, overall, row["last_sent_at"] if row else None)  # ⟵ исправлено
            return
        if maybe_text:
            text = maybe_text

    try:
        await context.bot.send_message(chat_id=alert_chat_id, text=text, parse_mode="HTML", disable_web_page_preview=True)
        storage.upsert_alert_state(owner_id, domain, overall, now.isoformat())
    except Exception as e:
        logger.exception("alert send failed for %s: %s", domain, e)
        if last_sent_at_dt is not None:
                    storage.upsert_alert_state(owner_id, domain, overall, last_sent_at_dt.isoformat())

