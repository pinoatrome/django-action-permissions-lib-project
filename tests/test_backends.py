"""The rules backends: a stored ruleset evaluated, and each backend's policy when it decides nothing."""

from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured, PermissionDenied

from django_action_permissions.backends import (
    AllowUnlessBlockedRulesBackend,
    DenyUnlessAllowedRulesBackend,
    get_rules_backend,
)

USER = SimpleNamespace(username="ann")
DENY_UNLESS_ALLOWED = DenyUnlessAllowedRulesBackend()
ALLOW_UNLESS_BLOCKED = AllowUnlessBlockedRulesBackend()
ALLOW_ANY_SETTINGS = {
    "DEFAULT_PERMISSION": "rest_framework.permissions.AllowAny",
    "RULES_BACKEND": "django_action_permissions.backends.AllowUnlessBlockedRulesBackend",
}
PREDICATES = {code: f"tests.rules.{code}" for code in ("owner", "yes", "no", "abstain", "block")}


@pytest.mark.parametrize("backend", [DENY_UNLESS_ALLOWED, ALLOW_UNLESS_BLOCKED])
@pytest.mark.parametrize(
    "expression, expected",
    [("yes", True), ("no", False), ("abstain", None), ("no | yes", True), ("yes & abstain", True), ("~abstain", None)],
)
def test_a_ruleset_is_evaluated_as_written(backend, expression, expected):
    assert backend.evaluate(expression, PREDICATES, USER, None) is expected


@pytest.mark.parametrize("backend", [DENY_UNLESS_ALLOWED, ALLOW_UNLESS_BLOCKED])
def test_a_block_goes_through(backend, calls):
    with pytest.raises(PermissionDenied):
        backend.evaluate("abstain | block | yes", PREDICATES, USER, None)
    assert calls == ["abstain", "block"]


def test_the_policies_on_a_ruleset_that_decides_nothing():
    assert DENY_UNLESS_ALLOWED.default_allows is False
    assert ALLOW_UNLESS_BLOCKED.default_allows is True


def test_a_ruleset_that_cant_be_parsed_doesnt_allow(caplog):
    assert DENY_UNLESS_ALLOWED.evaluate("yes &", PREDICATES, USER, None) is False
    assert DENY_UNLESS_ALLOWED.evaluate("unknown", PREDICATES, USER, None) is False
    assert "ruleset 'yes &' can't be used" in caplog.text


def test_a_predicate_that_stopped_importing_doesnt_allow():
    assert (
        DENY_UNLESS_ALLOWED.evaluate("gone | no", {"gone": "tests.rules.gone", "no": "tests.rules.no"}, USER, None)
        is False
    )


def test_the_same_ruleset_is_parsed_once():
    assert DENY_UNLESS_ALLOWED.ruleset("owner & yes", PREDICATES) is ALLOW_UNLESS_BLOCKED.ruleset(
        "owner & yes", PREDICATES
    )


# ── configuration ────────────────────────────────────────────────────────────


def test_the_default_backend_denies_unless_allowed():
    assert type(get_rules_backend()) is DenyUnlessAllowedRulesBackend


def test_allow_unless_blocked_goes_with_its_backend(settings):
    settings.ACTION_PERMISSIONS = ALLOW_ANY_SETTINGS

    assert type(get_rules_backend()) is AllowUnlessBlockedRulesBackend


@pytest.mark.parametrize(
    "configuration, message",
    [
        ({"RULES_BACKEND": "django_action_permissions.backends.AllowUnlessBlockedRulesBackend"}, "goes with"),
        ({"DEFAULT_PERMISSION": "rest_framework.permissions.AllowAny"}, "goes with"),
        ({"RULES_BACKEND": "tests.nowhere.Backend"}, "can't be imported"),
        ({"RULES_BACKEND": "tests.rules.yes"}, "isn't a BaseRulesBackend"),
    ],
)
def test_a_backend_that_doesnt_fit_is_improperly_configured(settings, configuration, message):
    settings.ACTION_PERMISSIONS = configuration

    with pytest.raises(ImproperlyConfigured, match=message):
        get_rules_backend()
