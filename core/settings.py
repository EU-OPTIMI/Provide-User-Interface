import os
from decouple import config, Csv
from pathlib import Path
from django.conf import global_settings

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config('DJANGO_SECRET_KEY', 'django-insecure-default-key')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config('DEBUG', default=True, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='', cast=Csv())
CSRF_TRUSTED_ORIGINS = config('CSRF_TRUSTED_ORIGINS', default='', cast=Csv())

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'survey',
    'corsheaders',
    'rest_framework',
    #'provide',
    'provide.apps.ProvideConfig' # keeping only the full path
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # 'django.middleware.csrf.CsrfViewMiddleware',  # CSRF middleware disabled - DO NOT DO THIS IN PRODUCTION
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'core.middleware.auth_service.AuthServiceMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'core.urls'

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

WSGI_APPLICATION = 'core.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.getenv('DJANGO_DB_PATH', BASE_DIR / 'db.sqlite3'),
    }
}

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS settings
CORS_ORIGIN_ALLOW_ALL = True  # For development only
CORS_ALLOW_CREDENTIALS = True

# CSRF settings
CSRF_USE_SESSIONS = False
CSRF_COOKIE_HTTPONLY = False  # Allow JavaScript to read the cookie
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', cast=bool, default=False)
_csrf_samesite = config('CSRF_COOKIE_SAMESITE', default=None)
CSRF_COOKIE_SAMESITE = None if _csrf_samesite in (None, '', 'None') else _csrf_samesite
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:8000',
    'http://localhost:8001',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:8000',
    'http://127.0.0.1:8001',
]

# Custom settings
DATA_UPLOAD_SERVICE_URL = config('DATA_UPLOAD_SERVICE_URL','')
DATA_SPACE_CONSUMER_SERVICE_URL = config('DATA_SPACE_CONSUMER_SERVICE_URL','')
CONNECTOR_URL = config('CONNECTOR_URL', '')
ACCESS_POLICY_GENERATOR_URL = config('ACCESS_POLICY_GENERATOR_URL', '')
DOMAIN_URL = config('DOMAIN_URL', '')


ENFORCE_CONNECTOR_SSL = config('REQUESTS_VERIFY_SSL', cast=bool)

BROKER_URL = config('BROKER_URL', '')

# Provider UI extra metadata choices
DATA_MODEL_OPTIONS = config(
    'DATA_MODEL_OPTIONS',
    default='Common Information Model (CIM),Open Field Message Bus (OpenFMB),Custom / Other',
    cast=Csv()
)
PURPOSE_OF_USE_OPTIONS = config(
    'PURPOSE_OF_USE_OPTIONS',
    default='Analytics,Operations,Research,Regulatory Reporting',
    cast=Csv()
)

# External authentication service (shared across microservices)
AUTH_SERVICE_BASE_URL = config('AUTH_SERVICE_BASE_URL', default='')
AUTH_SERVICE_PROFILE_ENDPOINT = config(
    'AUTH_SERVICE_PROFILE_ENDPOINT', default='/api/auth/me/'
)
AUTH_SERVICE_LOGIN_PAGE = config(
    'AUTH_SERVICE_LOGIN_PAGE', default='/api/auth/login-page/'
)
DEFAULT_SESSION_COOKIE_NAME = globals().get(
    'SESSION_COOKIE_NAME', getattr(global_settings, 'SESSION_COOKIE_NAME', 'sessionid')
)
AUTH_SERVICE_SESSION_COOKIE = config(
    'AUTH_SERVICE_SESSION_COOKIE', default=DEFAULT_SESSION_COOKIE_NAME
)
AUTH_SERVICE_TIMEOUT = config('AUTH_SERVICE_TIMEOUT', cast=int, default=3)
AUTH_SERVICE_VERIFY_SSL = config('AUTH_SERVICE_VERIFY_SSL', cast=bool, default=True)
AUTH_SERVICE_ALLOWLIST = config('AUTH_SERVICE_ALLOWLIST', default='/health,/metrics', cast=Csv())
AUTH_SERVICE_ENFORCE = config('AUTH_SERVICE_ENFORCE', cast=bool, default=False)

# Provider app session cookie (keep distinct from auth service cookie)
SESSION_COOKIE_NAME = config('SESSION_COOKIE_NAME', default='provider_sessionid')
# Session / cookie tuning (for local cross-origin between ports)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', cast=bool, default=False)
_session_samesite = config('SESSION_COOKIE_SAMESITE', default=None)
SESSION_COOKIE_SAMESITE = None if _session_samesite in (None, '', 'None') else _session_samesite

# For the file upload
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
