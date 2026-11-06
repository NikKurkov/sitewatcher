"""Bounded standard-library SMTP delivery; transport failures never expose secrets."""
from __future__ import annotations

import asyncio
from email.message import EmailMessage
from html import unescape
import re
import smtplib
import ssl

from .email_settings import get_notification_email, load_smtp_config


class EmailDeliveryError(ValueError):
    """Safe diagnostics suitable for owner settings and worker logs."""


def _send(config: dict, recipient: str, subject: str, html: str) -> None:
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = config['from_email']
    message['To'] = recipient
    plain = re.sub(r'<(?:br\s*/?|/p|/div)>', '\n', html, flags=re.IGNORECASE)
    plain = unescape(re.sub(r'<[^>]*>', '', plain)).strip()
    message.set_content(plain or 'SiteWatcher notification')
    message.add_alternative(html, subtype='html')
    context = ssl.create_default_context()
    client = smtplib.SMTP_SSL if config['security'] == 'tls' else smtplib.SMTP
    kwargs = {'timeout': 10}
    if config['security'] == 'tls':
        kwargs['context'] = context
    with client(config['host'], config['port'], **kwargs) as smtp:
        if config['security'] == 'starttls':
            smtp.starttls(context=context)
        if config['username']:
            smtp.login(config['username'], config['password'])
        smtp.send_message(message)


async def send_notification_email(owner_id: int, subject: str, html: str) -> None:
    try:
        recipient = get_notification_email(owner_id)
        config = load_smtp_config()
        if not recipient or config is None:
            raise EmailDeliveryError('Configure an email recipient and SMTP connection in Settings.')
        # Wait for the actual SMTP result: cancelling to_thread cannot stop a send.
        # Each socket operation has a 10-second timeout; there is no total deadline.
        await asyncio.to_thread(_send, config, recipient, subject, html)
    except EmailDeliveryError:
        raise
    except Exception:
        raise EmailDeliveryError('Email delivery failed. Check your SMTP connection and recipient.') from None
