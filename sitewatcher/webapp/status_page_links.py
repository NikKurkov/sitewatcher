"""Recoverable bearer links without storing the bearer token in the database."""
from base64 import urlsafe_b64encode
import hashlib

from django.utils.crypto import constant_time_compare, salted_hmac
from django.views.decorators.debug import sensitive_variables


def private_token(workspace_id, nonce):
    digest = salted_hmac('sitewatcher.status_page.private_link', f'{workspace_id}:{nonce}',
                         algorithm='sha256').digest()
    return urlsafe_b64encode(digest).decode('ascii').rstrip('=')


@sensitive_variables('token')
def private_path(page):
    if page.access_mode != 'private' or not page.public_enabled or not page.private_token_nonce:
        return ''
    token = private_token(page.workspace_id, page.private_token_nonce)
    if not constant_time_compare(hashlib.sha256(token.encode()).hexdigest(), page.public_token_hash):
        return ''
    return '/status/' + token + '/'
