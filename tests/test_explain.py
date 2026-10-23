"""`explain`: `abac.allowed`'s answer step by step, each ruleset traced; with a draft ruleset (`draft_info`)."""

import pytest
from django.contrib.auth.models import AnonymousUser, Permission
from django.core.exceptions import PermissionDenied

from django_action_permissions import abac
from django_action_permissions.abac import allowed
from django_action_permissions.backends import BaseRulesBackend
from django_action_permissions.explain import draft_info, explain
from django_action_permissions.models import ActionPermissionRule
from django_action_permissions.predicates import RulesetSyntaxError
from tests.conftest import thing
from tests.test_backends import ALLOW_ANY_SETTINGS

pytestmark = pytest.mark.django_db

CHANGE = "auth.change_user"


def table(ruleset="owner", **entry):
    return {
        CHANGE: {"rbac": {"CLERKS", "CUSTOMERS", "BOSSES"}, "abac": {"CUSTOMERS": ruleset}, **entry},
        "auth.view_user": {"rbac": {"CLERKS"}},
    }


def same_as_allowed(user, perm, obj=None, **kwargs):
    explanation = explain(user, perm, obj, **kwargs)
    assert explanation.allowed == allowed(user, perm, obj, manager_user=kwargs.get("manager_user"))
    return explanation


@pytest.mark.parametrize("backend", [{}, ALLOW_ANY_SETTINGS])
@pytest.mark.parametrize("ruleset", ["owner", "no", "abstain", "block", "yes & ~no", "abstain | no", "~owner"])
@pytest.mark.parametrize("owner", ["ann", "bob", None])
def test_it_answers_as_allowed(setup, member, settings, backend, ruleset, owner):
    settings.ACTION_PERMISSIONS = {"CACHE": None, **backend}
    setup(table(ruleset))
    customer = member("CUSTOMERS")
    obj = None if owner is None else thing(owner)

    explanation = same_as_allowed(customer, CHANGE, obj)

    [row] = explanation.groups
    assert row.group == "CUSTOMERS" and row.expression == ruleset
    if obj is None:
        assert row.skipped == "no object" and row.trace is None
    else:
        assert row.trace is not None and (row.blocked is not None) == (ruleset == "block")
        assert explanation.refusal == (None if explanation.allowed else 403)  # not a model instance: 403


def test_the_way_to_the_answer_is_listed(setup, member, django_user_model):
    setup(table())
    root = member(username="root", is_superuser=True)
    direct = member(username="dan")
    direct.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="change_user"))
    clerk = member("CLERKS", username="cid")
    nobody = member(username="nat")
    inactive = member("CLERKS", username="ivy", is_active=False)

    assert same_as_allowed(AnonymousUser(), CHANGE, thing()).reason.startswith("The user isn't authenticated")
    assert "doesn't hold" in same_as_allowed(nobody, CHANGE).reason
    assert "doesn't hold" in same_as_allowed(inactive, CHANGE).reason
    assert "superuser" in same_as_allowed(root, CHANGE).reason
    assert "directly" in same_as_allowed(direct, CHANGE, thing("bob")).reason
    explanation = same_as_allowed(clerk, CHANGE, thing("bob"))
    assert "CLERKS holds it without a ruleset" in explanation.reason
    assert [(step.label, step.passed) for step in explanation.steps] == [
        ("authenticated", True),
        (f"holds {CHANGE} (has_perm)", True),
        ("superuser", False),
        ("given to the user directly", False),
        ("an action permission", True),
    ]
    assert explanation.steps[1].detail == "through CLERKS"


def test_a_permission_that_isnt_an_action_permission_is_left_to_has_perm(setup, member):
    setup(table())
    user = member(username="dan")
    user.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="delete_user"))
    clerk = member("CLERKS", username="cid")
    clerk.groups.get().permissions.add(Permission.objects.get(codename="delete_user"))

    assert same_as_allowed(user, "auth.delete_user", thing()).allowed  # directly
    explanation = same_as_allowed(member("CLERKS", username="cal"), "auth.delete_user", thing())
    assert not explanation.allowed and "has_perm(perm, obj)" in explanation.reason
    assert "no group holds it on any object" in same_as_allowed(clerk, "auth.delete_user").reason


def test_a_block_in_any_group_refuses_and_stops_the_check(setup, member, calls):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "yes", "CUSTOMERS": "block | owner"}}})
    user = member("BOSSES", "CUSTOMERS")

    explanation = same_as_allowed(user, CHANGE, thing("ann"))

    bosses, customers = explanation.groups
    assert bosses.answer is True and customers.blocked == "blocked"
    assert [node.evaluated for node in customers.trace.children] == [True, False]
    assert explanation.reason == "Blocked by CUSTOMERS's ruleset: blocked."


def test_a_later_group_isnt_run_after_a_block(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "block", "CUSTOMERS": "yes"}}})

    explanation = same_as_allowed(member("BOSSES", "CUSTOMERS"), CHANGE, thing())

    assert explanation.groups[1].skipped.startswith("not evaluated") and explanation.groups[1].trace is None


def test_the_default_of_the_backend_decides_when_no_group_does(setup, member, settings):
    setup(table("abstain"))
    customer = member("CUSTOMERS")

    assert "denies then" in same_as_allowed(customer, CHANGE, thing()).reason
    settings.ACTION_PERMISSIONS = {"CACHE": None, **ALLOW_ANY_SETTINGS}
    explanation = same_as_allowed(customer, CHANGE, thing())
    assert "allows then" in explanation.reason and explanation.default_allows
    assert explanation.backend.endswith("AllowUnlessBlockedRulesBackend")


def test_a_staff_group_runs_with_its_managers_rights(setup, member, django_user_model):
    setup(table(staff=["CUSTOMERS"]))
    assistant = member("CUSTOMERS")
    manager = django_user_model.objects.create_user(username="meg")

    explanation = same_as_allowed(assistant, CHANGE, thing("meg"), manager_user=lambda user: manager)
    assert explanation.allowed and explanation.groups[0].checked_user == "meg"
    explanation = same_as_allowed(assistant, CHANGE, thing("meg"))
    assert "no manager_user" in explanation.groups[0].skipped and not explanation.allowed


def test_a_predicate_raising_is_reported_not_raised(setup, member, monkeypatch):
    setup(table())

    class Crashing:
        def trace(self, user, obj, blocks=()):
            raise RuntimeError("boom")

    monkeypatch.setattr(BaseRulesBackend, "ruleset", lambda self, expression, predicates: Crashing())

    explanation = explain(member("CUSTOMERS"), CHANGE, thing())

    assert not explanation.allowed and explanation.raises == "a predicate raises RuntimeError: boom"
    assert explanation.refusal is None and "500" in explanation.reason


def test_a_custom_evaluate_is_noted(setup, member, monkeypatch):
    setup(table())

    class Custom(BaseRulesBackend):
        def evaluate(self, expression, predicates, user, obj):
            return True

    monkeypatch.setattr("django_action_permissions.explain.get_rules_backend", Custom)

    assert "overrides evaluate()" in explain(member("CUSTOMERS"), CHANGE, thing()).notes[0]


def test_the_trace_has_the_stored_descriptions(setup, member):
    setup(table("yes & owner"))
    ActionPermissionRule.objects.filter(code="yes").update(description="Says yes.")

    [row] = explain(member("CUSTOMERS"), CHANGE, thing()).groups

    assert [child.description for child in row.trace.children] == ["Says yes.", "The object's owner is the user."]


def test_a_model_instance_nobody_may_read_is_a_404(setup, member, django_user_model):
    setup(table())
    customer = member("CUSTOMERS")
    other = django_user_model.objects.create_user(username="bob")

    explanation = same_as_allowed(customer, CHANGE, other)

    assert explanation.refusal == 404  # the user can't read it (view_user) either: as abac.refusal
    assert abac.refusal(customer, CHANGE, other) is not PermissionDenied


def test_the_groups_without_detail_access_are_listed(setup, member):
    setup(table(no_detail=["CUSTOMERS"]))

    assert explain(member("CUSTOMERS"), CHANGE, thing()).no_detail == ["CUSTOMERS"]


# ── a draft ──────────────────────────────────────────────────────────────────


def test_a_draft_replaces_one_groups_ruleset(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "no", "CUSTOMERS": "owner"}}})
    customer = member("CUSTOMERS")

    info = draft_info(CHANGE, "CUSTOMERS", "yes|no")
    assert info["abac"] == {"BOSSES": "no", "CUSTOMERS": "yes | no"}
    assert info["predicates"] == {"no": "tests.rules.no", "yes": "tests.rules.yes"}
    assert allowed(customer, CHANGE, thing("bob"), perm_info=info)

    explanation = explain(customer, CHANGE, thing("bob"), draft=("CUSTOMERS", "yes|no"))
    assert explanation.allowed and explanation.groups[0].draft and explanation.draft == ("CUSTOMERS", "yes|no")
    assert not explain(customer, CHANGE, thing("bob")).allowed  # nothing saved


def test_a_blank_draft_holds_it_on_any_object(setup, member):
    setup(table())

    explanation = explain(member("CUSTOMERS"), CHANGE, draft=("CUSTOMERS", " "))

    assert explanation.allowed and "CUSTOMERS holds it without a ruleset" in explanation.reason


def test_a_draft_for_a_group_not_holding_it_is_noted(setup, member):
    setup(table())

    explanation = explain(member("CUSTOMERS"), CHANGE, thing(), draft=("CLERKS", "no"))

    assert "CLERKS doesn't hold auth.change_user" in explanation.notes[0]


def test_a_bad_draft_or_permission_is_a_value_error(setup):
    setup(table())

    with pytest.raises(RulesetSyntaxError, match="unknown predicate 'nobody'"):
        draft_info(CHANGE, "CUSTOMERS", "nobody")
    with pytest.raises(ValueError, match="isn't an action permission"):
        draft_info("auth.delete_user", "CUSTOMERS", "yes")
