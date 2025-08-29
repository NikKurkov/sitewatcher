# sitewatcher/bot/formatting.py
from __future__ import annotations

import html
from typing import Iterable

from .. import storage
from .alerts import _status_bullet, _status_emoji, _overall_from_results
from .utils import _strip_cached_suffix


async def _format_results(owner_id: int, domain: str, results: Iterable, persist: bool = True) -> str:
    """Store clean history (optionally) and format a compact result text with emojis."""
    if persist:
        for r in results:
            storage.save_history(owner_id, domain, r.check, r.status, _strip_cached_suffix(r.message), r.metrics)

    overall = _overall_from_results(results)
    head = f"{_status_emoji(overall)} <b>{html.escape(domain)}</b> — {overall}"

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
    return "\n".join(lines)
