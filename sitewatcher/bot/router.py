# sitewatcher/bot/router.py
from __future__ import annotations

from telegram.ext import Application, CommandHandler, ConversationHandler, MessageHandler, filters

from .constants import ADD_WAIT_INTERVAL, ADD_WAIT_KEYWORDS
from .utils import on_error
from .handlers.help import cmd_help
from .handlers.domains import cmd_add_domain, cmd_remove_domain, cmd_list_domain
from .handlers.checks import cmd_check_domain, cmd_check_all
from .handlers.cfg import cmd_cfg, cmd_cfg_set, cmd_cfg_unset
from .handlers.cache import cmd_clear_cache
from .handlers.add_wizard import (
    cmd_add_start,
    cmd_add_keywords_text,
    cmd_add_keywords_none,
    cmd_add_interval_text,
    cmd_add_interval_none,
    cmd_add_cancel,
)


def register_handlers(app: Application) -> None:
    """Wire up all handlers on the given Application."""
    # Conversation for /add (quick wizard)
    add_conv = ConversationHandler(
        entry_points=[CommandHandler("add", cmd_add_start)],
        states={
            ADD_WAIT_KEYWORDS: [
                CommandHandler("none", cmd_add_keywords_none),
                MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_add_keywords_text),
            ],
            ADD_WAIT_INTERVAL: [
                CommandHandler("none", cmd_add_interval_none),
                MessageHandler(filters.TEXT & ~filters.COMMAND, cmd_add_interval_text),
            ],
        },
        fallbacks=[CommandHandler("cancel", cmd_add_cancel)],
        name="sitewatcher:add_wizard",
        persistent=False,
    )
    app.add_handler(add_conv)

    # Other handlers (aligned with your latest mapping)
    app.add_handler(CommandHandler(["start", "help"], cmd_help))
    app.add_handler(CommandHandler("add_domain", cmd_add_domain))
    app.add_handler(CommandHandler("remove", cmd_remove_domain))
    app.add_handler(CommandHandler("list", cmd_list_domain))
    app.add_handler(CommandHandler("check", cmd_check_domain))
    app.add_handler(CommandHandler("check_all", cmd_check_all))
    app.add_handler(CommandHandler("clear_cache", cmd_clear_cache))
    app.add_handler(CommandHandler("cfg", cmd_cfg))
    app.add_handler(CommandHandler("cfg_set", cmd_cfg_set))
    app.add_handler(CommandHandler("cfg_unset", cmd_cfg_unset))

    # Global error handler
    app.add_error_handler(on_error)
