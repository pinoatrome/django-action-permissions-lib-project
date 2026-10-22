"""The smallest Django configuration the tests need: the auth models (groups and permissions)
in an in-memory database. This is the library's own test setup, not a recommendation for an app."""

SECRET_KEY = "tests-only"
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
]
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
