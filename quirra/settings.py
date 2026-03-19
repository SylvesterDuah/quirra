# quirra/settings.py
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

import dj_database_url

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------ Core
SECRET_KEY    = os.environ.get("SECRET_KEY", "dev-insecure-change-me")
DEBUG         = os.environ.get("DEBUG", "0") in ("1", "true", "True")
ALLOWED_HOSTS = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "*").split(",") if h.strip()] or ["*"]

# ------------------------------------------------------------------ Apps
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_filters",
    "corsheaders",
    "whitenoise.runserver_nostatic",
    "events",
    "analysis",
    "flags",
    "api",
    "detectors",
]

# ------------------------------------------------------------------ Middleware
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF     = "quirra.urls"
WSGI_APPLICATION = "quirra.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    }
]

# ------------------------------------------------------------------ Database
_raw_db_url = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}")

# Render internal URLs use postgres:// but psycopg2 requires postgresql://
if _raw_db_url.startswith("postgres://"):
    _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)

# Only require SSL for PostgreSQL — SQLite doesn't support sslmode and crashes
_is_postgres = _raw_db_url.startswith("postgresql://")

DATABASES = {
    "default": dj_database_url.parse(
        _raw_db_url,
        conn_max_age=0,
        conn_health_checks=True,
        ssl_require=_is_postgres,  # FIX: was always True — kills SQLite locally
    )
}

# ------------------------------------------------------------------ I18N
LANGUAGE_CODE = "en-us"
TIME_ZONE     = "UTC"
USE_I18N      = True
USE_TZ        = True

# ------------------------------------------------------------------ Static
STATIC_URL          = "/static/"
STATIC_ROOT         = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ------------------------------------------------------------------ DRF
REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
}

# ------------------------------------------------------------------ CORS
CORS_ALLOW_ALL_ORIGINS  = True
CORS_ALLOW_CREDENTIALS  = False

CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
    "x-ingest-secret",
    "x-quirra-secret",
]

# ------------------------------------------------------------------ CSRF
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") in ("1", "true", "True")
CSRF_COOKIE_SECURE    = os.environ.get("CSRF_COOKIE_SECURE",    "0") in ("1", "true", "True")

_csrf = [s.strip() for s in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if s.strip()]
if _csrf:
    CSRF_TRUSTED_ORIGINS = _csrf

# ------------------------------------------------------------------ Security
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROXY", "https")

# ------------------------------------------------------------------ Quirra knobs
QUIRRA_DEFAULTS = {
    "STORE_RAW":            False,
    "SIMHASH_THRESHOLD":    int(os.environ.get("SIMHASH_THRESHOLD",    "6")),
    "STYLE_SAME_THRESHOLD": float(os.environ.get("STYLE_SAME_THRESHOLD", "0.7")),
    "RISK_THRESHOLD":       float(os.environ.get("RISK_THRESHOLD",     "0.75")),
}

INGEST_SECRET    = os.environ.get("INGEST_SECRET",    "")
QUIRRA_USER_SALT = os.environ.get("QUIRRA_USER_SALT", "")

# ------------------------------------------------------------------ Celery
CELERY_BROKER_URL     = os.environ.get("CELERY_BROKER_URL",     "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# ------------------------------------------------------------------ Debug endpoint gate
QUIRRA_EXPOSE_DEBUG_ENDPOINT = os.environ.get(
    "QUIRRA_EXPOSE_DEBUG_ENDPOINT", "1" if DEBUG else "0"
) in ("1", "true", "True")