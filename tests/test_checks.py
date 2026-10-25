"""The system checks: the settings, and the stored action permissions (database checks)."""

import pytest
from django.contrib.auth.models import Group
from django.core import checks as django_checks

from django_action_permissions import checks
from django_action_permissions.backends import DenyUnlessAllowedRulesBackend
from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from django_action_permissions.utils import drf_installed

LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
REDIS = {"default": {"BACKEND": "django.core.cache.backends.redis.RedisCache", "LOCATION": "redis://localhost"}}


def ids(issues) -> list[str]:
    return sorted(issue.id.removeprefix("django_action_permissions.") for issue in issues)


def test_the_test_settings_are_clean():
    assert checks.check_settings() == []


@pytest.mark.parametrize(
    "configuration, expected",
    [
        ({"CACHE": None, "DEFAULT_PERMISSION": "tests.nowhere.Permission"}, ["E001", "E003"]),
        ({"CACHE": None, "DEFAULT_PERMISSION": "tests.rules.always"}, ["E001", "E003"]),
        ({"CACHE": None, "RULES_BACKEND": "tests.nowhere.Backend"}, ["E002"]),
        ({"CACHE": None, "RULES_BACKEND": "tests.rules.always"}, ["E002"]),
        (
            {"CACHE": None, "RULES_BACKEND": "django_action_permissions.backends.AllowUnlessBlockedRulesBackend"},
            ["E003"],
        ),
        ({"CACHE": "permissions"}, ["E004"]),
    ],
)
def test_bad_settings_are_errors(settings, configuration, expected):
    settings.ACTION_PERMISSIONS = configuration

    assert ids(checks.check_settings()) == expected


def test_a_cache_kept_by_each_process_is_a_warning(settings):
    settings.ACTION_PERMISSIONS = {}
    settings.CACHES = LOCMEM
    assert ids(checks.check_settings()) == ["W001"]

    settings.CACHES = REDIS
    assert checks.check_settings() == []


def test_the_checks_run_with_djangos():
    assert not [issue for issue in django_checks.run_checks() if issue.id.startswith("django_action_permissions.")]


def test_database_checks_need_a_database():
    assert checks.check_table() == []


@pytest.mark.django_db
def test_an_empty_table_is_a_warning():
    assert ids(checks.check_table(databases=["default"])) == ["W002"]


@pytest.mark.django_db
def test_a_consistent_table_is_clean(setup):
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}}})

    assert checks.check_table(databases=["default"]) == []
    assert checks.run_all() == []


@pytest.mark.django_db
def test_a_broken_table_is_reported(setup):
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}}})
    ActionPermissionRule.objects.filter(code="owner").update(fqn="tests.rules.gone")  # E005
    entry = ActionPermission.objects.get()
    ActionPermissionGroup.objects.create(  # E006: CLERKS doesn't hold auth.change_user
        action_permission=entry, group=Group.objects.get(name="CLERKS"), ruleset="yes"
    )
    ActionPermissionGroup.objects.create(  # E008: doesn't parse
        action_permission=entry, group=Group.objects.create(name="X"), ruleset="yes &"
    )
    ActionPermissionRule.objects.create(code="legacy", fqn="tests.rules.yes")  # W003: unused, not registered

    issues = checks.check_table(databases=["default"])

    assert ids(issues) == ["E005", "E006", "E006", "E008", "W003"]
    assert "CLERKS has the ruleset 'yes' but doesn't hold the permission" in str(issues)
    assert "X's ruleset can't be used: 'yes &': unexpected the end" in str(issues)


@pytest.mark.django_db
def test_a_ruleset_naming_a_predicate_not_stored_is_reported(setup):
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}}})
    ActionPermissionGroup.objects.filter(group__name="CUSTOMERS").update(ruleset="owner | gone")

    assert ids(checks.check_table(databases=["default"])) == ["E008"]


@pytest.mark.django_db
def test_a_predicate_registered_since_the_setup_is_a_warning(setup, registry):
    setup({"auth.view_user": {"rbac": {"CLERKS"}}})
    from django_action_permissions.predicates import predicate

    predicate(code="newcomer")(lambda user, obj: True)

    issues = checks.check_table(databases=["default"])
    assert ids(issues) == ["W006"] and "'newcomer'" in issues[0].msg


@pytest.mark.django_db
def test_a_database_not_migrated_is_left_to_the_migrations_checks(monkeypatch):
    from django.db import DatabaseError

    def fail(*args, **kwargs):
        raise DatabaseError("no such table")

    monkeypatch.setattr(ActionPermissionRule.objects, "using", fail)

    assert checks.check_table(databases=["default"]) == []


# ── the default permission against what runs ─────────────────────────────────

DENY_ALL = "django_action_permissions.permissions.DenyAll"
ALLOW_ANY = {
    "CACHE": None,
    "DEFAULT_PERMISSION": "rest_framework.permissions.AllowAny",
    "RULES_BACKEND": "django_action_permissions.backends.AllowUnlessBlockedRulesBackend",
}
needs_drf = pytest.mark.skipif(not drf_installed(), reason="Django REST framework isn't installed")


@needs_drf
def test_a_default_permission_drf_doesnt_apply_is_a_warning(settings):
    settings.REST_FRAMEWORK = {}  # DRF's default: AllowAny

    assert ids(checks.check_settings()) == ["W004"]
    assert DENY_ALL in checks.check_settings()[0].hint

    settings.REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated", DENY_ALL]}
    assert checks.check_settings() == []


@needs_drf
def test_allow_any_is_drfs_own_default(settings):
    settings.REST_FRAMEWORK = {}
    settings.ACTION_PERMISSIONS = ALLOW_ANY

    assert checks.check_settings() == []


@pytest.fixture
def without_drf(monkeypatch):
    monkeypatch.setattr(checks, "drf_installed", lambda: False)


@pytest.mark.parametrize("configuration", [{"CACHE": None}, ALLOW_ANY])
def test_without_drf_the_default_permission_is_one_of_the_two_policies(settings, without_drf, configuration):
    settings.ACTION_PERMISSIONS = configuration

    assert checks.check_settings() == []


def test_without_drf_another_default_permission_cant_be_checked(settings, without_drf):
    settings.ACTION_PERMISSIONS = {
        "CACHE": None,
        "DEFAULT_PERMISSION": "myapp.permissions.Custom",
        "RULES_BACKEND": "tests.test_checks.CustomBackend",
    }

    assert ids(checks.check_settings()) == ["E001"]
    assert "can't be checked" in checks.check_settings()[0].hint


def test_without_drf_deny_all_wants_the_views_closed_by_login(settings, monkeypatch, without_drf):
    monkeypatch.setattr(checks, "LOGIN_REQUIRED_AVAILABLE", True)
    settings.MIDDLEWARE = [m for m in settings.MIDDLEWARE if not m.endswith("LoginRequiredMiddleware")]

    assert ids(checks.check_settings()) == ["W005"]

    settings.ACTION_PERMISSIONS = ALLOW_ANY
    assert checks.check_settings() == []


def test_before_django_5_1_there_is_no_middleware_to_want(settings, monkeypatch, without_drf):
    monkeypatch.setattr(checks, "LOGIN_REQUIRED_AVAILABLE", False)
    settings.MIDDLEWARE = [m for m in settings.MIDDLEWARE if not m.endswith("LoginRequiredMiddleware")]

    assert checks.check_settings() == []


class CustomBackend(DenyUnlessAllowedRulesBackend):
    default_permission = "myapp.permissions.Custom"


@pytest.mark.parametrize(
    "manager_user, expected",
    [
        (None, []),
        ("tests.auth.manager_of", []),
        ("tests.nowhere.manager", ["E007"]),
        ("tests.rules.NOT_CALLABLE", ["E007"]),
    ],
)
def test_the_manager_user_function_must_import(settings, manager_user, expected):
    settings.ACTION_PERMISSIONS = {"CACHE": None, "MANAGER_USER": manager_user}

    assert ids(checks.check_settings()) == expected
