"""System checks: the settings (every `manage.py` command) and the stored action permissions (`manage.py check
--database default`, and the admin's Check configuration).

The default permission is checked against what runs: with DRF, the views' default permission classes (W004);
without it, Django has no permission classes, and `DEFAULT_PERMISSION` only names the policy of the built-in
backends (`DenyAll` or `AllowAny`, E001), the views being closed by `LoginRequiredMiddleware` (W005)."""

from django.conf import settings
from django.core import checks
from django.db import DatabaseError
from django.utils.module_loading import import_string

from . import conf
from .backends import BaseRulesBackend, backend_error
from .predicates import NamedPredicate, discover, parse
from .utils import drf_installed, rule_error

ID = "django_action_permissions"


DENY_ALL = "django_action_permissions.permissions.DenyAll"
ALLOW_ANY = "rest_framework.permissions.AllowAny"
# The policies of the built-in backends: without DRF, the only default permissions that can be told apart.
KNOWN_DEFAULT_PERMISSIONS = {DENY_ALL, ALLOW_ANY}
LOGIN_REQUIRED_MIDDLEWARE = "django.contrib.auth.middleware.LoginRequiredMiddleware"


def _dotted_path(cls) -> str:
    return f"{cls.__module__}.{cls.__qualname__}"


def _check_default_permission(default_permission: str) -> list[checks.CheckMessage]:
    """E001, and W004 (with DRF) or W005 (without): the default permission against what runs."""
    if not drf_installed():
        if default_permission not in KNOWN_DEFAULT_PERMISSIONS:
            return [
                checks.Error(
                    f"DEFAULT_PERMISSION {default_permission!r} isn't one of "
                    f"{', '.join(sorted(KNOWN_DEFAULT_PERMISSIONS))}",
                    hint="Without Django REST framework, a custom default permission can't be checked.",
                    id=f"{ID}.E001",
                )
            ]
        if default_permission == DENY_ALL and LOGIN_REQUIRED_MIDDLEWARE not in settings.MIDDLEWARE:
            return [
                checks.Warning(
                    "DEFAULT_PERMISSION is DenyAll, but no view is closed by default",
                    hint=f"Add {LOGIN_REQUIRED_MIDDLEWARE} to MIDDLEWARE. It requires only a login: the pages "
                    "still check allowed() / unrestricted().",
                    id=f"{ID}.W005",
                )
            ]
        return []

    from rest_framework.permissions import BasePermission
    from rest_framework.settings import api_settings

    try:
        permission_class = import_string(default_permission)
    except ImportError as e:
        return [checks.Error(f"DEFAULT_PERMISSION {default_permission!r} can't be imported: {e}", id=f"{ID}.E001")]
    if not (isinstance(permission_class, type) and issubclass(permission_class, BasePermission)):
        message = f"DEFAULT_PERMISSION {default_permission!r} isn't a DRF permission class"
        return [checks.Error(message, id=f"{ID}.E001")]
    if default_permission not in {_dotted_path(cls) for cls in api_settings.DEFAULT_PERMISSION_CLASSES}:
        return [
            checks.Warning(
                f"DEFAULT_PERMISSION {default_permission!r} isn't in REST_FRAMEWORK['DEFAULT_PERMISSION_CLASSES'], "
                "which the views without their own permission_classes get",
                hint=f'REST_FRAMEWORK = {{"DEFAULT_PERMISSION_CLASSES": ["{default_permission}"]}}',
                id=f"{ID}.W004",
            )
        ]
    return []


@checks.register()
def check_settings(app_configs=None, **kwargs) -> list[checks.CheckMessage]:
    issues = _check_default_permission(conf.get("DEFAULT_PERMISSION"))
    path = conf.get("RULES_BACKEND")
    try:
        backend_class = import_string(path)
    except ImportError as e:
        issues.append(checks.Error(f"RULES_BACKEND {path!r} can't be imported: {e}", id=f"{ID}.E002"))
    else:
        if not (isinstance(backend_class, type) and issubclass(backend_class, BaseRulesBackend)):
            issues.append(checks.Error(f"RULES_BACKEND {path!r} isn't a BaseRulesBackend", id=f"{ID}.E002"))
        elif error := backend_error():
            issues.append(
                checks.Error(
                    error,
                    hint="DenyAll goes with DenyUnlessAllowedRulesBackend, "
                    "AllowAny with AllowUnlessBlockedRulesBackend.",
                    id=f"{ID}.E003",
                )
            )
    manager_user = conf.get("MANAGER_USER")
    if manager_user is not None:
        try:
            function = import_string(manager_user)
        except ImportError as e:
            issues.append(checks.Error(f"MANAGER_USER {manager_user!r} can't be imported: {e}", id=f"{ID}.E007"))
        else:
            if not callable(function):
                issues.append(checks.Error(f"MANAGER_USER {manager_user!r} isn't callable", id=f"{ID}.E007"))
    alias = conf.get("CACHE")
    if alias is not None:
        if alias not in settings.CACHES:
            issues.append(checks.Error(f"CACHE {alias!r} isn't an alias of CACHES", id=f"{ID}.E004"))
        elif settings.CACHES[alias].get("BACKEND", "").endswith("LocMemCache"):
            issues.append(
                checks.Warning(
                    f"CACHE {alias!r} is a LocMemCache, which every process keeps on its own",
                    hint="With several processes, configure a shared cache (Redis, Memcached, the database) or set "
                    "ACTION_PERMISSIONS['CACHE'] to None.",
                    id=f"{ID}.W001",
                )
            )
    return issues


@checks.register(checks.Tags.database)
def check_table(app_configs=None, databases=None, **kwargs) -> list[checks.CheckMessage]:
    from django.contrib.auth.models import Group

    from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule

    issues = []
    for alias in databases or ():
        try:
            for rule in ActionPermissionRule.objects.using(alias):
                if error := rule_error(rule.fqn):
                    issues.append(checks.Error(f"rule {rule.code!r}: {error}", obj=rule, id=f"{ID}.E005"))
            held = set(Group.permissions.through.objects.using(alias).values_list("group_id", "permission_id"))
            stored = {
                rule.code: NamedPredicate(rule.code, rule.fqn) for rule in ActionPermissionRule.objects.using(alias)
            }
            rows = ActionPermissionGroup.objects.using(alias).select_related(
                "action_permission__permission__content_type", "group"
            )
            for row in rows:
                if (row.group_id, row.action_permission.permission_id) not in held:
                    issues.append(
                        checks.Error(
                            f"{row.action_permission}: {row.group.name} has the ruleset {row.ruleset!r} "
                            f"but doesn't hold the permission",
                            hint="Grant it the permission (rbac) or remove the ruleset.",
                            obj=row,
                            id=f"{ID}.E006",
                        )
                    )
                try:
                    parse(row.ruleset, stored.__getitem__)
                except ValueError as e:
                    issues.append(
                        checks.Error(
                            f"{row.action_permission}: {row.group.name}'s ruleset can't be used: {e}",
                            hint="A predicate it names must be stored: run the setup, or correct the ruleset.",
                            obj=row,
                            id=f"{ID}.E008",
                        )
                    )
            if not ActionPermission.objects.using(alias).exists():
                issues.append(
                    checks.Warning(
                        "There is no action permission: no group holds a permission on any object.",
                        hint="Run the setup (setup_rbac_permissions, or the django_action_permissions_load command).",
                        id=f"{ID}.W002",
                    )
                )
            registered = discover()
            for rule in ActionPermissionRule.objects.using(alias).filter(usages__isnull=True):
                if rule.code not in registered:
                    issues.append(
                        checks.Warning(
                            f"rule {rule.code!r} isn't used, and no @predicate defines it any more",
                            hint="Run the setup without keep, or delete it.",
                            obj=rule,
                            id=f"{ID}.W003",
                        )
                    )
            for code in sorted(set(registered) - set(stored)) if stored else ():  # none stored: W002 says it
                issues.append(
                    checks.Warning(
                        f"predicate {code!r} ({registered[code].fqn}) isn't stored: "
                        "setup hasn't run since it was added",
                        hint="Run the setup to store it, so that rulesets can use it.",
                        id=f"{ID}.W006",
                    )
                )
        except DatabaseError:  # not migrated yet: the migrations' own checks tell
            continue
    return issues


def run_all(databases=("default",)) -> list[checks.CheckMessage]:
    """Every check of the library, the database ones included."""
    return check_settings() + check_table(databases=list(databases))
