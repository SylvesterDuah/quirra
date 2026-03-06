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
SECRET_KEY   = os.environ.get("SECRET_KEY", "dev-insecure")
DEBUG        = os.environ.get("DEBUG", "0") in ("1", "true", "True")
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

ROOT_URLCONF      = "quirra.urls"
WSGI_APPLICATION  = "quirra.wsgi.application"

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
DATABASES = {
    "default": dj_database_url.parse(
        os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
        conn_max_age=0,
        conn_health_checks=True,
    )
}

# ------------------------------------------------------------------ I18N
LANGUAGE_CODE = "en-us"
TIME_ZONE     = "UTC"
USE_I18N      = True
USE_TZ        = True

# ------------------------------------------------------------------ Static
STATIC_URL         = "/static/"
STATIC_ROOT        = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ------------------------------------------------------------------ DRF
REST_FRAMEWORK = {
    "DEFAULT_FILTER_BACKENDS": ["django_filters.rest_framework.DjangoFilterBackend"],
}

# ------------------------------------------------------------------ CORS / CSRF
CORS_ALLOW_ALL_ORIGINS = os.environ.get("CORS_ALLOW_ALL_ORIGINS", "1") in ("1", "true", "True")

_allowed = [s.strip() for s in os.environ.get("CORS_ALLOWED_ORIGINS", "").split(",") if s.strip()]
if _allowed:
    CORS_ALLOW_ALL_ORIGINS = False
    CORS_ALLOWED_ORIGINS   = _allowed

_csrf = [s.strip() for s in os.environ.get("CSRF_TRUSTED_ORIGINS", "").split(",") if s.strip()]
if _csrf:
    CSRF_TRUSTED_ORIGINS = _csrf

# ------------------------------------------------------------------ Quirra knobs
QUIRRA_DEFAULTS = {
    "STORE_RAW":             False,
    "SIMHASH_THRESHOLD":     int(os.environ.get("SIMHASH_THRESHOLD",   "6")),
    "STYLE_SAME_THRESHOLD":  float(os.environ.get("STYLE_SAME_THRESHOLD", "0.7")),
    "RISK_THRESHOLD":        float(os.environ.get("RISK_THRESHOLD",    "0.75")),
}

INGEST_SECRET    = os.environ.get("INGEST_SECRET",    "")
QUIRRA_USER_SALT = os.environ.get("QUIRRA_USER_SALT", "")

# ------------------------------------------------------------------ Celery
CELERY_BROKER_URL     = os.environ.get("CELERY_BROKER_URL",     "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

# ------------------------------------------------------------------ Security
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") in ("1", "true", "True")
CSRF_COOKIE_SECURE    = os.environ.get("CSRF_COOKIE_SECURE",    "0") in ("1", "true", "True")

# ------------------------------------------------------------------ Debug endpoint gate
QUIRRA_EXPOSE_DEBUG_ENDPOINT = os.environ.get(
    "QUIRRA_EXPOSE_DEBUG_ENDPOINT", "1" if DEBUG else "0"
) in ("1", "true", "True")