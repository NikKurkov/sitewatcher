import asyncio
from types import SimpleNamespace

from sitewatcher.bot.handlers.cfg import cmd_cfg_set


def test_unknown_check_name_is_rejected():
    replies = []

    class Message:
        async def reply_text(self, text):
            replies.append(text)

    update = SimpleNamespace(effective_message=Message(), effective_user=SimpleNamespace(id=7))
    context = SimpleNamespace(args=["example.com", "checks.typo", "true"])
    asyncio.run(cmd_cfg_set(update, context))

    assert "Unknown check" in replies[0]
