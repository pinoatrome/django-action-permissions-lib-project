"""The library's settings: `ACTION_PERMISSIONS` in the project's settings, a dict whose keys override `DEFAULTS`."""

from django.conf import settings
from django.utils.module_loading import import_string

DEFAULTS = {
    # The DRF permission class a project sets as REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"], and that the rules
    # backend goes with: DenyAll (look for an allowance) or rest_framework.permissions.AllowAny (look for a block).
    # Without DRF, the name of one of these two policies.
    "DEFAULT_PERMISSION": "django_action_permissions.permissions.DenyAll",
    "RULES_BACKEND": "django_action_permissions.backends.DenyUnlessAllowedRulesBackend",
    # An alias of CACHES holding the table between checks; None reads the database on each check. The cache must be
    # shared by every process of the project (Redis, Memcached, the database cache), not a LocMemCache.
    "CACHE": "default",
    "CACHE_TIMEOUT": 300,
    # The dotted path of a function (user) -> manager, the user a `staff` group acts as, for the checks that have no
    # view to ask (the auth backend `ActionPermissionBackend`); None: a staff group allows nothing there.
    "MANAGER_USER": None,
}


def get(name: str):
    return {**DEFAULTS, **getattr(settings, "ACTION_PERMISSIONS", {})}[name]


def manager_user():
    """The function `MANAGER_USER` names, or None."""
    path = get("MANAGER_USER")
    return import_string(path) if path else None
