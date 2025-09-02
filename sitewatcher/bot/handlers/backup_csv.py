# sitewatcher/bot/handlers/backup_csv.py
from __future__ import annotations

from io import BytesIO
from datetime import datetime, timezone
from typing import Optional

from telegram import Update, Document
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, ConversationHandler, filters

from ..utils import requires_auth
from ...utils.domains_csv import export_domains_csv, import_domains_csv, ImportReport

# Conversation state for /import_csv
WAIT_CSV = 9201


@requires_auth()
async def cmd_export_csv(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Export user's domains and overrides as a CSV file."""
    owner_id = update.effective_user.id
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


@requires_auth()
async def cmd_import_csv_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Start a short conversation to receive a CSV file or text."""
    args = context.args or []
    mode = "merge"
    if args and args[0].strip().lower() == "replace":
        mode = "replace"
    context.user_data["import_mode"] = mode

    await update.effective_message.reply_text(
        "Send CSV file (semicolon separated) with the required header, "
        "or paste CSV text directly. Send /cancel to abort."
    )
    return WAIT_CSV


async def _handle_import_data(update: Update, context: ContextTypes.DEFAULT_TYPE, data: bytes) -> int:
    mode = context.user_data.get("import_mode", "merge")
    try:
        report: ImportReport = import_domains_csv(update.effective_user.id, data, mode=mode)
    except Exception as e:
        await update.effective_message.reply_text(f"Import failed: {e}")
        return ConversationHandler.END

    # Build compact summary
    lines = [
        f"✅ Import done (mode={mode}).",
        f"Added: {report.added}, Updated: {report.updated}, Skipped: {report.skipped}.",
    ]
    if report.errors:
        head = "\n".join(["Errors (first 10):"] + [f"• {e}" for e in report.errors[:10]])
        lines.append(head)

    await update.effective_message.reply_text("\n".join(lines))
    context.user_data.pop("import_mode", None)
    return ConversationHandler.END


@requires_auth()
async def on_import_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Receive CSV as a document."""
    doc: Optional[Document] = getattr(update.effective_message, "document", None)
    if not doc:
        await update.effective_message.reply_text("Please send a CSV file.")
        return WAIT_CSV
    tgfile = await context.bot.get_file(doc.file_id)
    data = await tgfile.download_as_bytearray()
    return await _handle_import_data(update, context, bytes(data))


@requires_auth()
async def on_import_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Receive CSV as plain text."""
    txt = (update.effective_message.text or "").strip()
    if not txt:
        await update.effective_message.reply_text("Please paste CSV text or send a CSV file.")
        return WAIT_CSV
    return await _handle_import_data(update, context, txt.encode("utf-8"))


@requires_auth()
async def import_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    context.user_data.pop("import_mode", None)
    await update.effective_message.reply_text("Cancelled.")
    return ConversationHandler.END


def register_backup_csv_handlers(app: Application) -> None:
    """Wire up /export_csv and /import_csv conversation."""
    app.add_handler(CommandHandler("export_csv", cmd_export_csv))

    import_conv = ConversationHandler(
        entry_points=[CommandHandler("import_csv", cmd_import_csv_start)],
        states={
            WAIT_CSV: [
                MessageHandler(filters.Document.ALL, on_import_document),
                MessageHandler(filters.TEXT & ~filters.COMMAND, on_import_text),
            ],
        },
        fallbacks=[CommandHandler("cancel", import_cancel)],
        name="sitewatcher:import_csv",
        persistent=False,
    )
    app.add_handler(import_conv)
