# sitewatcher/bot/handlers/backup_csv.py
from __future__ import annotations

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
