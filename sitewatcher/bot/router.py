# sitewatcher/bot/router.py
from __future__ import annotations

import logging
from telegram.ext import Application, CommandHandler, ConversationHandler, MessageHandler, filters

from .constants import ADD_WAIT_INTERVAL, ADD_WAIT_KEYWORDS
from .utils import on_error, requires_auth

# Module-level logger
log = logging.getLogger(__name__)

from .handlers.help import cmd_help
from .handlers.domains import (
    cmd_add_domain, cmd_remove_domain, cmd_list_domain,
    cmd_remove_all_start, cmd_remove_all_confirm, cmd_remove_all_cancel,
    REMOVE_ALL_CONFIRM
)
from .handlers.checks import cmd_check_domain, cmd_check_all, cmd_check_all_detail
from .handlers.status import cmd_status
from .handlers.history import cmd_history
from .handlers.user_prefs import cmd_stop_alerts, cmd_start_alerts
from .handlers.cfg import cmd_cfg, cmd_cfg_set, cmd_cfg_unset
from .handlers.backup_csv import register_backup_csv_handlers
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
        entry_points=[CommandHandler("add", requires_auth(cmd_add_start))],
        states={
            ADD_WAIT_KEYWORDS: [
                CommandHandler("none", requires_auth(cmd_add_keywords_none)),
                MessageHandler(filters.TEXT & ~filters.COMMAND, requires_auth(cmd_add_keywords_text)),
            ],
            ADD_WAIT_INTERVAL: [
                CommandHandler("none", requires_auth(cmd_add_interval_none)),
                MessageHandler(filters.TEXT & ~filters.COMMAND, requires_auth(cmd_add_interval_text)),
            ],
        },
        fallbacks=[CommandHandler("cancel", requires_auth(cmd_add_cancel))],
        name="sitewatcher:add_wizard",
        persistent=False,
    )
    app.add_handler(add_conv)

    # Conversation for /remove_all (bulk delete with confirmation)
    remove_all_conv = ConversationHandler(
        entry_points=[CommandHandler("remove_all", requires_auth(cmd_remove_all_start))],
        states={
            REMOVE_ALL_CONFIRM: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, requires_auth(cmd_remove_all_confirm)),
                CommandHandler("none", requires_auth(cmd_remove_all_cancel)),
            ],
        },
        fallbacks=[CommandHandler("cancel", requires_auth(cmd_remove_all_cancel))],
        name="sitewatcher:remove_all_confirm",
        persistent=False,
    )
    app.add_handler(remove_all_conv)

    # Other handlers (aligned with your latest mapping)
    app.add_handler(CommandHandler(["start", "help"], requires_auth(cmd_help)))
    app.add_handler(CommandHandler("add_domain", requires_auth(cmd_add_domain)))
    app.add_handler(CommandHandler("remove", requires_auth(cmd_remove_domain)))
    app.add_handler(CommandHandler("list", requires_auth(cmd_list_domain)))
    app.add_handler(CommandHandler("check", requires_auth(cmd_check_domain)))
    app.add_handler(CommandHandler("check_all", requires_auth(cmd_check_all)))
    app.add_handler(CommandHandler("check_all_detail", requires_auth(cmd_check_all_detail)))
    app.add_handler(CommandHandler("clear_cache", requires_auth(cmd_clear_cache)))
    app.add_handler(CommandHandler("cfg", requires_auth(cmd_cfg)))
    app.add_handler(CommandHandler("cfg_set", requires_auth(cmd_cfg_set)))
    app.add_handler(CommandHandler("cfg_unset", requires_auth(cmd_cfg_unset)))
    app.add_handler(CommandHandler("status", requires_auth(cmd_status)))
    app.add_handler(CommandHandler("history", requires_auth(cmd_history)))
    app.add_handler(CommandHandler("stop_alerts", requires_auth(cmd_stop_alerts)))
    app.add_handler(CommandHandler("start_alerts", requires_auth(cmd_start_alerts)))
    register_backup_csv_handlers(app)

    # Global error handler
    app.add_error_handler(on_error)

    # Trace handlers registration
    log.info("router.handlers_registered", extra={"event": "router.handlers_registered"})
