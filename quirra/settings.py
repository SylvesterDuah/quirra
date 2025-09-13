# quirra/settings.py
import os
from pathlib import Path

# Optional but handy if you keep a .env locally
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass

import dj_database_url  # type: ignore

BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------------------------------------------------------
# Core
# ------------------------------------------------------------------------------
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-insecure")
DEBUG = os.environ.get("DEBUG", "0") in ("1", "true", "True")

# In Render, the service URL is dynamic. For testing, allow all; tighten later.
ALLOWED_HOSTS = os.environ.get("ALLOWED_HOSTS", "*").split(",")

# ------------------------------------------------------------------------------
# Apps
# ------------------------------------------------------------------------------
INSTALLED_APPS = [
    # Django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party
    "rest_framework",
    "django_filters",
    "corsheaders",
    "whitenoise.runserver_nostatic",

    # Project apps
    "events",
    "analysis",
    "flags",
    "api",
    "detectors",
]

# ------------------------------------------------------------------------------
# Middleware
# ------------------------------------------------------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",

    # WhiteNoise for static files on Render
    "whitenoise.middleware.WhiteNoiseMiddleware",

    # CORS *before* CommonMiddleware
    "corsheaders.middleware.CorsMiddleware",

    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "quirra.urls"

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

WSGI_APPLICATION = "quirra.wsgi.application"

# ------------------------------------------------------------------------------
# Database
# ------------------------------------------------------------------------------
# Use Postgres in production. If DATABASE_URL is not set, fall back to SQLite for dev.
DATABASES = {
    "default": dj_database_url.parse(
        os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
        conn_max_age=600,
    )
}

# ------------------------------------------------------------------------------
# Internationalization
# ------------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# ------------------------------------------------------------------------------
# Static files (WhiteNoise)
# ------------------------------------------------------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ------------------------------------------------------------------------------
# DRF
# ------------------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
}

# ------------------------------------------------------------------------------
# CORS & CSRF (configure from env; permissive defaults for first tests)
# ------------------------------------------------------------------------------
# For early testing: allow all. For production, set CORS_ALLOWED_ORIGINS.
CORS_ALLOW_ALL_ORIGINS = os.environ.get("CORS_ALLOW_ALL_ORIGINS", "1") in ("1", "true", "True")

# Optional comma-separated allowlist (overrides allow-all when provided)
_allowed = [o.strip() for o in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if o.strip()]
if _allowed:
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS = _allowed

# CSRF Trusted Origins (comma-separated)
_csrf = [o.strip() for o in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if o.strip()]
if _csrf:
    CSRF_TRUSTED_ORIGINS = _csrf

# ------------------------------------------------------------------------------
# Quirra-specific knobs
# ------------------------------------------------------------------------------
QUIRRA_DEFAULTS = {
    "STORE_RAW": False,
    "SIMHASH_THRESHOLD": int(os.environ.get("SIMHASH_THRESHOLD", "6")),
    "STYLE_SAME_THRESHOLD": float(os.environ.get("STYLE_SAME_THRESHOLD", "0.7")),
    "RISK_THRESHOLD": float(os.environ.get("RISK_THRESHOLD", "0.75")),
}

# Ingestion shared secret (if empty, your guarded ingest view only allows localhost)
INGEST_SECRET = os.environ.get("INGEST_SECRET", "")

# Salt for server-side user hashing
QUIRRA_USER_SALT = os.environ.get("QUIRRA_USER_SALT", "")

# ------------------------------------------------------------------------------
# Celery (optional; not required for the sync compute path)
# ------------------------------------------------------------------------------
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# ------------------------------------------------------------------------------
# Security (toggle as you harden)
# ------------------------------------------------------------------------------
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") in ("1", "true", "True")
CSRF_COOKIE_SECURE = os.environ.get("CSRF_COOKIE_SECURE", "1") in ("1", "true", "True")
