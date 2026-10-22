"""The smallest Django configuration the tests need: the auth models (groups and permissions), the admin, in an
in-memory database, with Django REST framework when it's installed (the tox env `nodrf` runs without). This is the
library's own test setup, not a recommendation for an app."""

from django_action_permissions.utils import drf_installed

SECRET_KEY = "tests-only"
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    *(["rest_framework"] if drf_installed() else []),
    "django_action_permissions",
    "tests",  # its rules module holds the tests' predicates (discovered as an app's)
]
MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.contrib.auth.middleware.LoginRequiredMiddleware",  # DenyAll without DRF (check W005)
]
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]
ROOT_URLCONF = "tests.urls"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
# A test that wants the cache turns it on (tests/test_cache.py): with it, a table changed inside a test's
# transaction would be read from the cache, which is dropped only on commit.
ACTION_PERMISSIONS = {"CACHE": None}
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["django_action_permissions.permissions.DenyAll"]}  # check W004
