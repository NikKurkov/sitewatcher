# sitewatcher/bot/handlers/backup_csv.py
from __future__ import annotations

import asyncio
import io
import logging
from typing import Optional, Tuple

from telegram import Update, InputFile
from telegram.ext import Application, ContextTypes, CommandHandler, MessageHandler, filters

from ... import storage
from ...utils import domains_csv as csvutil  # required: export_domains_csv / import_domains_csv
from ..utils import requires_auth, safe_reply_html

log = logging.getLogger(__name__)

# Keys for a tiny, per-user import "FSM"
KEY_AWAIT_IMPORT = "await_import_csv"
KEY_IMPORT_MODE = "import_mode"  # "merge" | "replace"


# -----------------------------
# Registration
# -----------------------------
def register_backup_csv_handlers(app: Application) -> None:
    """
    Register handlers for CSV backup/restore:
      - /export_csv
      - /import_csv [replace]
      - document upload hook for import flow
    """
    app.add_handler(CommandHandler("export_csv", cmd_export_csv))
    app.add_handler(CommandHandler("import_csv", cmd_import_csv))

    # Any non-command document goes here; we'll check user_data flag inside.
    app.add_handler(
        MessageHandler(filters.Document.ALL & (~filters.COMMAND), on_document_uploaded_for_import)
    )


# -----------------------------
# /export_csv
# -----------------------------
@requires_auth(allow_while_busy=True)
async def cmd_export_csv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Export current user's domains and overrides as a semicolon-separated CSV.
    Uses utils.domains_csv.export_domains_csv (UTF-8-SIG bytes).
    """
    user = update.effective_user
    chat = update.effective_chat
    owner_id = user.id

    try:
        csv_bytes, count = await _export_owner_to_csv(owner_id)
    except Exception as e:
        log.exception("export_csv.failed user=%s: %s", owner_id, e, extra={"event": "export_csv.failed", "owner": owner_id})
        await safe_reply_html(update.effective_message, f"❌ Export failed: <code>{e}</code>")
        return

    if not csv_bytes:
        await safe_reply_html(update.effective_message, "No data to export.")
        return

    filename = f"sitewatcher_{owner_id}_domains.csv".replace(" ", "_")
    bio = io.BytesIO(csv_bytes)
    bio.name = filename  # set filename for Telegram

    try:
        await context.bot.send_document(
            chat_id=chat.id,
            document=InputFile(bio),
            caption=f"Exported {count} domain(s). Encoding: UTF-8 (BOM); delimiter: semicolon (;).",
        )
    except Exception as e:
        log.exception("export_csv.send.failed user=%s: %s", owner_id, e, extra={"event": "export_csv.send.failed", "owner": owner_id})
        await safe_reply_html(update.effective_message, f"❌ Failed to send file: <code>{e}</code>")


async def _export_owner_to_csv(owner_id: int) -> Tuple[bytes, int]:
    """
    Export via utils.domains_csv.export_domains_csv -> bytes (UTF-8-SIG).
    Returns (csv_bytes, domains_count).
    """
    if not hasattr(csvutil, "export_domains_csv"):
        raise RuntimeError("utils.domains_csv.export_domains_csv not found")

    data: bytes = csvutil.export_domains_csv(owner_id)  # UTF-8-SIG bytes for Excel compatibility
    count = len(storage.list_domains(owner_id))
    return data, count


# -----------------------------
# /import_csv
# -----------------------------
@requires_auth()
async def cmd_import_csv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Start CSV import.
    Usage: /import_csv [replace]
      - replace: overwrite existing overrides / settings for listed domains
      - merge (default): upsert/patch overrides; domains not present remain untouched
    Then user should upload a CSV document in reply.
    """
    msg = update.effective_message
    args = context.args or []
    mode = "replace" if (args and args[0].lower() == "replace") else "merge"

    # If user already attached a document in the same message (rare), process it immediately
    doc = getattr(msg, "document", None)
    if doc:
        await _process_import_document(update, context, mode)
        return

    # Otherwise, set waiting flags and prompt for upload
    context.user_data[KEY_AWAIT_IMPORT] = True
    context.user_data[KEY_IMPORT_MODE] = mode

    await safe_reply_html(
        msg,
        "Please upload a CSV file (semicolon-separated, UTF-8). "
        f"Mode: <b>{mode}</b>.\n"
        "The header must start with <code>domain</code>. "
        "Tip: use /export_csv to get a template.",
    )


@requires_auth()
async def on_document_uploaded_for_import(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Hook for document uploads. Only acts if the user previously issued /import_csv.
    """
    if not context.user_data.get(KEY_AWAIT_IMPORT):
        return  # Not in import mode; ignore

    mode = context.user_data.get(KEY_IMPORT_MODE, "merge")
    await _process_import_document(update, context, mode)


async def _process_import_document(update: Update, context: ContextTypes.DEFAULT_TYPE, mode: str) -> None:
    """
    Download, decode, and import the CSV file using utils.domains_csv.import_domains_csv.
    """
    user = update.effective_user
    owner_id = user.id
    msg = update.effective_message
    doc = getattr(msg, "document", None)

    if not doc:
        await safe_reply_html(msg, "❌ No document attached.")
        return

    # Download the file contents
    try:
        file = await context.bot.get_file(doc.file_id)
        blob = await file.download_as_bytearray()
        data = bytes(blob)  # pass bytes to the importer
    except Exception as e:
        log.exception("import_csv.download.failed user=%s: %s", owner_id, e, extra={"event": "import_csv.download.failed", "owner": owner_id})
        await safe_reply_html(msg, f"❌ Failed to download file: <code>{e}</code>")
        return
    finally:
        # Reset FSM regardless of outcome to avoid being stuck in busy state
        context.user_data.pop(KEY_AWAIT_IMPORT, None)
        context.user_data.pop(KEY_IMPORT_MODE, None)

    # Import via utility
    try:
        report = await _import_csv_bytes(owner_id, data, replace=(mode == "replace"))
    except Exception as e:
        log.exception("import_csv.failed user=%s: %s", owner_id, e, extra={"event": "import_csv.failed", "owner": owner_id})
        await safe_reply_html(msg, f"❌ Import failed: <code>{e}</code>")
        return

    # Summarize result
    added = getattr(report, "added", 0)
    updated = getattr(report, "updated", 0)
    skipped = getattr(report, "skipped", 0)
    errors = getattr(report, "errors", []) or []

    lines = [
        f"✅ Import finished. Mode: <b>{mode}</b>",
        f"Added: <b>{added}</b>",
        f"Updated: <b>{updated}</b>",
        f"Skipped: <b>{skipped}</b>",
    ]
    if errors:
        lines.append("\n<b>Errors (first 5):</b>")
        lines.extend(f"• {e}" for e in errors[:5])

    await safe_reply_html(msg, "\n".join(lines))


async def _import_csv_bytes(owner_id: int, data: bytes, *, replace: bool) -> object:
    """
    Call utils.domains_csv.import_domains_csv(owner_id, data, mode='merge'|'replace').
    Returns an ImportReport-like object with attributes: added, updated, skipped, errors (list[str]).
    """
    if not hasattr(csvutil, "import_domains_csv"):
        raise RuntimeError("utils.domains_csv.import_domains_csv not found")

    mode = "replace" if replace else "merge"
    report = csvutil.import_domains_csv(owner_id, data, mode=mode)
    return report


# -----------------------------
# Small helpers
# -----------------------------
async def _maybe_await(obj):
    """Await coroutine values, pass-through otherwise."""
    if asyncio.iscoroutine(obj):
        return await obj
    return obj
