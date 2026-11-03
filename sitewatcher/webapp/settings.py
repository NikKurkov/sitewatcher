"""Private-by-default Django settings; runtime secrets are loaded by bootstrap."""
from datetime import timedelta
from pathlib import Path

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
    'axes',
    'sitewatcher.webapp.apps.WebappConfig',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'sitewatcher.webapp.middleware.SecurityHeadersMiddleware',
    'sitewatcher.webapp.middleware.PublicStatusMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'sitewatcher.webapp.middleware.ManagementBodyMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'sitewatcher.webapp.middleware.WorkspaceLanguageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'axes.middleware.AxesMiddleware',
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
LANGUAGE_CODE = 'en'
LANGUAGES = [('en', 'English'), ('ru', 'Русский')]
USE_I18N = True
LOCALE_PATHS = [Path(__file__).resolve().parent / 'locale']
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 12 * 60 * 60
SESSION_COOKIE_SECURE = False  # Explicit HTTPS deployment configuration in configure_web().
CSRF_COOKIE_SECURE = False
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = 'same-origin'
X_FRAME_OPTIONS = 'DENY'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
AUTHENTICATION_BACKENDS = [
    'axes.backends.AxesStandaloneBackend',
    'django.contrib.auth.backends.ModelBackend',
]
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
AXES_HANDLER = 'axes.handlers.database.AxesDatabaseHandler'
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCKOUT_PARAMETERS = [['username', 'ip_address']]
AXES_IPWARE_META_PRECEDENCE_ORDER = ('REMOTE_ADDR',)
AXES_RESET_ON_SUCCESS = True
AXES_LOCKOUT_CALLABLE = 'sitewatcher.webapp.accounts.locked_out'
AXES_SENSITIVE_PARAMETERS = ['username', 'ip_address', 'password', 'csrfmiddlewaretoken']
AXES_VERBOSE = False
AXES_DISABLE_ACCESS_LOG = True
