# sitewatcher/bot/handlers/backup_csv.py
from __future__ import annotations

<<<<<<< HEAD
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
        await safe_reply_html(update, context, f"❌ Export failed: <code>{e}</code>")
        return

    if not csv_bytes:
        await safe_reply_html(update, context, "No data to export.")
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
        await safe_reply_html(update, context, f"❌ Failed to send file: <code>{e}</code>")


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
        update,
        context,
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
        await safe_reply_html(update, context, "❌ No document attached.")
        return

    # Download the file contents
    try:
        file = await context.bot.get_file(doc.file_id)
        blob = await file.download_as_bytearray()
        data = bytes(blob)  # pass bytes to the importer
    except Exception as e:
        log.exception("import_csv.download.failed user=%s: %s", owner_id, e, extra={"event": "import_csv.download.failed", "owner": owner_id})
        await safe_reply_html(update, context, f"❌ Failed to download file: <code>{e}</code>")
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
        await safe_reply_html(update, context, f"❌ Import failed: <code>{e}</code>")
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

    await safe_reply_html(update, context, "\n".join(lines))


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
=======
import logging
from io import BytesIO
from datetime import datetime, timezone
from typing import Optional

from telegram import Update, Document
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    ConversationHandler,
    filters,
)

from ..utils import requires_auth, safe_reply_html
from ...utils.domains_csv import export_domains_csv, import_domains_csv, ImportReport

log = logging.getLogger(__name__)

# Conversation states
WAIT_CSV = 1


# ------------------------------ export ---------------------------------


@requires_auth()
async def cmd_export_csv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Export user's domains and overrides as a CSV file."""
    owner_id = update.effective_user.id
    log.info("export_csv.start", extra={"event": "export_csv.start", "owner_id": owner_id})

    data = export_domains_csv(owner_id)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M")
    filename = f"sitewatcher_export_{ts}.csv"

    bio = BytesIO(data)
    bio.name = filename
    bio.seek(0)

    await update.effective_message.reply_document(
        document=bio,
        filename=filename,
        caption="Export of domains and overrides (CSV).",
    )
    log.info("export_csv.done", extra={"event": "export_csv.done", "owner_id": owner_id, "bytes": len(data)})


# ------------------------------ import ---------------------------------


@requires_auth(allow_while_busy=True)
async def cmd_import_csv_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start a short conversation to receive a CSV file or text."""
    args = context.args or []
    mode = "merge"
    if args and args[0].strip().lower() == "replace":
        mode = "replace"
    context.user_data["import_mode"] = mode

    log.info(
        "import_csv.start",
        extra={"event": "import_csv.start", "owner_id": update.effective_user.id, "mode": mode},
    )

    await safe_reply_html(
        update.effective_message,
        "Send CSV file (<b>semicolon</b> separated) with the required header, "
        "or paste CSV text directly. Send <code>/cancel</code> to abort.",
    )
    return WAIT_CSV


@requires_auth(allow_while_busy=True)
async def on_import_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Receive CSV as a document."""
    doc: Optional[Document] = getattr(update.effective_message, "document", None)
    if not doc:
        await safe_reply_html(update.effective_message, "Please send a CSV file.")
        return WAIT_CSV

    log.info(
        "import_csv.file",
        extra={
            "event": "import_csv.file",
            "owner_id": update.effective_user.id,
            "file_name": getattr(doc, "file_name", None),
            "mime": getattr(doc, "mime_type", None),
            "size": getattr(doc, "file_size", None),
        },
    )
    tgfile = await context.bot.get_file(doc.file_id)
    data = await tgfile.download_as_bytearray()
    return await _handle_import_data(update, context, bytes(data))


@requires_auth(allow_while_busy=True)
async def on_import_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Receive CSV as plain text."""
    txt = (update.effective_message.text or "").strip()
    if not txt:
        await safe_reply_html(update.effective_message, "Please paste CSV text or send a CSV file.")
        return WAIT_CSV

    log.info(
        "import_csv.text",
        extra={"event": "import_csv.text", "owner_id": update.effective_user.id, "chars": len(txt)},
    )
    return await _handle_import_data(update, context, txt.encode("utf-8"))


@requires_auth(allow_while_busy=True)
async def import_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Cancel the import conversation."""
    context.user_data.pop("import_mode", None)
    await safe_reply_html(update.effective_message, "Cancelled.")
    return ConversationHandler.END


# ------------------------------ internals -------------------------------


async def _handle_import_data(update: Update, context: ContextTypes.DEFAULT_TYPE, data: bytes) -> int:
    """Run the import and report a compact summary."""
    mode = context.user_data.get("import_mode", "merge")
    owner_id = update.effective_user.id
    try:
        report: ImportReport = import_domains_csv(owner_id, data, mode=mode)
    except Exception as e:
        log.exception("import_csv.failed", extra={"event": "import_csv.failed", "owner_id": owner_id, "mode": mode})
        await safe_reply_html(update.effective_message, f"Import failed: <code>{e}</code>")
        return ConversationHandler.END

    log.info(
        "import_csv.done",
        extra={
            "event": "import_csv.done",
            "owner_id": owner_id,
            "mode": mode,
            "added": report.added,
            "updated": report.updated,
            "skipped": report.skipped,
            "errors": len(report.errors),
        },
    )

    lines = [
        f"✅ Import done (mode=<b>{mode}</b>).",
        f"Added: <b>{report.added}</b>, Updated: <b>{report.updated}</b>, Skipped: <b>{report.skipped}</b>.",
    ]
    if report.errors:
        head = "\n".join(["Errors (first 10):"] + [f"• {e}" for e in report.errors[:10]])
        lines.append(head)

    await safe_reply_html(update.effective_message, "\n".join(lines))
    context.user_data.pop("import_mode", None)
    return ConversationHandler.END


# ------------------------------ registry --------------------------------


def register_handlers(app: Application) -> None:
    """Register export/import handlers on the application/router."""
    # Export: simple command
    app.add_handler(CommandHandler("export_csv", cmd_export_csv, block=False), group=0)

    # Import: short conversation
    conv = ConversationHandler(
        entry_points=[CommandHandler("import_csv", cmd_import_csv_start, block=False)],
        states={
            WAIT_CSV: [
                MessageHandler(filters.Document.ALL, on_import_document, block=False),
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_import_text, block=False),
            ]
        },
        fallbacks=[CommandHandler("cancel", import_cancel, block=False)],
        name="sitewatcher:import_csv",
        persistent=False,
        allow_reentry=True,
    )
    app.add_handler(conv, group=0)


def register_backup_csv_handlers(app: Application) -> None:
    """Backward-compatible alias expected by router.py."""
    register_handlers(app)
>>>>>>> fbb85f0e808f8e62eb1ab2a505f698bb82d7d2ca
