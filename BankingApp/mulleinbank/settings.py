import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# V1 (CWE-321): Hardcoded secret key — never rotated, committed to version control
SECRET_KEY = 'django-insecure-mullein-bank-2024-hardcoded-secret-key-do-not-use'

# V2 (CWE-215): Debug mode left on in production — exposes stack traces,
# environment variables, installed apps, and Django version to any visitor
DEBUG = True

# V3: Wildcard ALLOWED_HOSTS — accepts requests from any hostname (Host header injection)
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'banking',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # V3 (CWE-352): CsrfViewMiddleware removed — all POST endpoints are CSRF-vulnerable
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # V4 (CWE-1021): XFrameOptionsMiddleware removed — clickjacking possible
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'mulleinbank.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'mulleinbank.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
MONGODB_DB = 'mulleinbank'

# V14 (CWE-521): All password validators disabled — any password accepted (e.g. "1", "a")
AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'America/Winnipeg'
USE_I18N = True
USE_L10N = True
USE_TZ = True

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

# V13 (CWE-614 / CWE-1004): Insecure cookie configuration
# SESSION_COOKIE_SECURE=False → session cookie sent over plain HTTP
# SESSION_COOKIE_HTTPONLY=False → JavaScript can read the session cookie (XSS escalation)
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = False
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False

# Missing security headers — no HSTS, no content-type sniffing protection,
# no XSS filter enforcement
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
SECURE_HSTS_SECONDS = 0

import logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {'format': '[%(levelname)s] %(asctime)s %(name)s: %(message)s'},
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'DEBUG',
    },
}
