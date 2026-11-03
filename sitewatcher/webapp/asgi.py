"""ASGI application; production launch must disable server/proxy access logs."""
from django.core.asgi import get_asgi_application

from sitewatcher.config import load_config
from .bootstrap import configure_web

configure_web(load_config())
application = get_asgi_application()
