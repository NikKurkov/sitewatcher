"""Private-by-default Django settings; runtime secrets are loaded by bootstrap."""
from sitewatcher import storage

DEBUG = False
SECRET_KEY = ''  # configure_web() loads a deployment key or the persistent secret file.
ALLOWED_HOSTS = ['127.0.0.1', 'localhost', '[::1]']
ROOT_URLCONF = 'sitewatcher.webapp.urls'
ASGI_APPLICATION = 'sitewatcher.webapp.asgi.application'
INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'sitewatcher.webapp.apps.WebappConfig',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'sitewatcher.webapp.middleware.SecurityHeadersMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': str(storage.DEFAULT_DB.resolve()),
        'OPTIONS': {'timeout': 30},
    },
}
TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.request',
        'django.contrib.auth.context_processors.auth',
    ]},
}]
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
USE_TZ = True
TIME_ZONE = 'Europe/Moscow'
LANGUAGE_CODE = 'en-us'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 12 * 60 * 60
SESSION_COOKIE_SECURE = False  # Explicit HTTPS deployment configuration in configure_web().
CSRF_COOKIE_SECURE = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'
