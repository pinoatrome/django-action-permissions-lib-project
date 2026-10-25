"""`unrestricted`, `allowed` and `held_permissions`: the object checks of the action permissions, outside a view."""

import pytest
from django.contrib.auth.models import AnonymousUser, Group, Permission
from django.core.exceptions import PermissionDenied
from django.http import Http404

from django_action_permissions import abac
from django_action_permissions.abac import allowed, granting_groups, held_permissions, unrestricted
from django_action_permissions.utils import drf_installed
from tests.conftest import thing
from tests.test_backends import ALLOW_ANY_SETTINGS

pytestmark = pytest.mark.django_db

CHANGE = "auth.change_user"
TABLE = {
    CHANGE: {
        "rbac": {"CLERKS", "CUSTOMERS", "BOSSES"},
        "abac": {"CUSTOMERS": "owner", "BOSSES": "owner"},
    },
    "auth.view_user": {"rbac": {"CLERKS"}},
}


@pytest.fixture(autouse=True)
def table(setup):
    setup(TABLE)


def test_a_group_without_rules_holds_the_permission_on_any_object(member):
    clerk = member("CLERKS")

    assert unrestricted(clerk, CHANGE)
    assert allowed(clerk, CHANGE, thing("bob")) and allowed(clerk, CHANGE)


def test_a_group_with_abac_holds_it_on_the_objects_its_rules_allow(member):
    customer = member("CUSTOMERS")

    assert not unrestricted(customer, CHANGE)
    assert allowed(customer, CHANGE, thing("ann")) and not allowed(customer, CHANGE, thing("bob"))
    assert not allowed(customer, CHANGE)  # no object: only an unrestricted user


def test_a_group_with_rules_holds_it_on_the_objects_they_all_allow(member):
    boss = member("BOSSES")

    assert not unrestricted(boss, CHANGE)
    assert allowed(boss, CHANGE, thing("ann")) and not allowed(boss, CHANGE, thing("bob"))


def test_superusers_and_permissions_given_directly_are_unrestricted(member):
    superuser = member(username="root", is_superuser=True)
    direct = member(username="dan")
    direct.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="change_user"))

    assert unrestricted(superuser, CHANGE) and unrestricted(direct, CHANGE)


def test_without_the_permission_nothing_is_allowed(member):
    nobody = member()

    assert not unrestricted(nobody, CHANGE) and not allowed(nobody, CHANGE, thing("ann"))
    assert not unrestricted(AnonymousUser(), CHANGE)


def test_a_permission_the_table_doesnt_list_is_held_on_no_object_through_a_group(member):
    Group.objects.get(name="CLERKS").permissions.add(
        Permission.objects.get(content_type__app_label="auth", codename="delete_user")
    )
    clerk = member("CLERKS")

    assert clerk.has_perm("auth.delete_user")
    assert not unrestricted(clerk, "auth.delete_user")
    assert not allowed(clerk, "auth.delete_user", thing("ann"))  # Django's ModelBackend has no object permissions


def test_a_group_without_rules_isnt_overruled_by_another_s_false(member):
    """v0.1.0 let the last group evaluated decide: CUSTOMERS' False denied a clerk who is also a customer."""
    clerk_and_customer = member("CUSTOMERS", "CLERKS")

    assert allowed(clerk_and_customer, CHANGE, thing("bob"))


def test_the_groups_are_evaluated_by_name_whatever_the_users_order(member):
    first = member("CUSTOMERS", "BOSSES", username="ann")
    second = member("BOSSES", "CUSTOMERS", username="bob")

    assert granting_groups(first, CHANGE) == granting_groups(second, CHANGE) == ["BOSSES", "CUSTOMERS"]


def test_a_block_in_one_group_denies_though_another_group_allows(setup, member, calls):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "yes", "CUSTOMERS": "block"}}})
    user = member("BOSSES", "CUSTOMERS")

    assert not allowed(user, CHANGE, thing("ann"))
    assert calls == ["yes", "block"]


def test_one_group_allowing_is_enough(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "owner", "CUSTOMERS": "yes"}}})

    assert allowed(member("BOSSES", "CUSTOMERS"), CHANGE, thing("bob"))


def test_a_staff_group_is_checked_as_its_manager(setup, member, django_user_model):
    setup({CHANGE: {"rbac": {"BOSSES"}, "abac": {"BOSSES": "owner"}, "staff": ["BOSSES"]}})
    assistant = member("BOSSES", username="ann")
    manager = django_user_model.objects.create_user(username="meg")

    assert allowed(assistant, CHANGE, thing("meg"), manager_user=lambda user: manager)
    assert not allowed(assistant, CHANGE, thing("ann"), manager_user=lambda user: manager)
    assert not allowed(assistant, CHANGE, thing("meg"))  # no manager: the staff group allows nothing


def test_rules_that_dont_apply_deny_under_deny_all(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES"}, "abac": {"BOSSES": "abstain"}}})

    assert not allowed(member("BOSSES"), CHANGE, thing("ann"))


def test_under_allow_all_only_a_block_denies(setup, member, settings):
    settings.ACTION_PERMISSIONS = {**ALLOW_ANY_SETTINGS, "CACHE": None}
    setup(
        {
            CHANGE: {
                "rbac": {"BOSSES", "CUSTOMERS"},
                "abac": {"CUSTOMERS": "abstain & owner", "BOSSES": "abstain"},
            }
        }
    )

    assert allowed(member("CUSTOMERS", username="ann"), CHANGE, thing("bob")) is False  # owner: False blocks
    assert allowed(member("CUSTOMERS", username="cid"), CHANGE, thing("cid")) is True
    assert allowed(member("BOSSES", username="bea"), CHANGE, thing("x")) is True  # no rule applies: allowed


def test_the_table_given_is_used_instead_of_the_stored_one(member):
    customer = member("CUSTOMERS")
    entry = {"abac": {}, "predicates": {}, "no_detail": [], "staff": []}

    assert unrestricted(customer, CHANGE, perm_info=entry)
    assert not unrestricted(customer, CHANGE, perm_info=None)


@pytest.mark.skipif(not drf_installed(), reason="Django REST framework isn't installed")
def test_drfs_permission_denied_blocks_too(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "yes", "CUSTOMERS": "block_drf"}}})

    assert not allowed(member("BOSSES", "CUSTOMERS"), CHANGE, thing("ann"))


@pytest.mark.skipif(drf_installed(), reason="without Django REST framework only")
def test_without_drf_djangos_permission_denied_is_the_block():
    assert abac.BLOCKS == (PermissionDenied,)


# ── 404 for an object the user can't read ────────────────────────────────────

VIEW = "auth.view_user"
SELF_ONLY = {
    VIEW: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
    CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
}


def test_the_read_permission_is_the_models_view_permission(django_user_model):
    assert abac.read_permission(django_user_model(username="x")) == "auth.view_user"
    assert abac.read_permission(thing()) is None


def test_an_object_the_user_cant_read_is_not_found(setup, member, django_user_model):
    setup(SELF_ONLY)
    customer, other = member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")

    assert abac.refusal(customer, CHANGE, other) is Http404


def test_an_object_the_user_can_read_is_forbidden(setup, member, django_user_model):
    setup({**SELF_ONLY, VIEW: {"rbac": {"CUSTOMERS"}}})
    customer, other = member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")

    assert abac.refusal(customer, CHANGE, other) is PermissionDenied


def test_a_refused_read_is_not_found_without_asking_again(setup, member, django_user_model, monkeypatch):
    setup(SELF_ONLY)
    customer, other = member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")

    def not_asked(*args, **kwargs):
        raise AssertionError("allowed() asked again")

    monkeypatch.setattr(abac, "allowed", not_asked)
    assert abac.refusal(customer, VIEW, other) is Http404


def test_an_object_to_be_created_is_forbidden_not_hidden(setup, member, django_user_model):
    setup(SELF_ONLY)

    assert abac.refusal(member("CUSTOMERS"), CHANGE, django_user_model(username="unsaved")) is PermissionDenied
    assert abac.refusal(member("CUSTOMERS", username="bob"), VIEW, django_user_model(username="x")) is PermissionDenied


def test_an_object_that_isnt_a_model_instance_is_forbidden(member):
    assert abac.refusal(member("CUSTOMERS"), CHANGE, thing("bob")) is PermissionDenied


# ── held_permissions: what the user holds, filtered in the database ──────────


def direct(user, codename):
    user.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename=codename))


def test_a_group_without_a_ruleset_holds_on_any_object_one_with_on_its_own(member):
    assert held_permissions(member("CLERKS")) == {CHANGE: True, "auth.view_user": True}
    assert held_permissions(member("CUSTOMERS", username="cid")) == {CHANGE: False}


def test_one_unrestricted_group_is_enough(member):
    assert held_permissions(member("CUSTOMERS", "CLERKS")) == {CHANGE: True, "auth.view_user": True}
    assert held_permissions(member("CUSTOMERS", "BOSSES", username="bea")) == {CHANGE: False}


def test_a_superuser_holds_every_action_permission_and_a_direct_grant_is_on_any_object(member):
    superuser = member(username="root", is_superuser=True)
    given = member("CUSTOMERS", username="dan")
    direct(given, "change_user")
    direct(given, "delete_user")  # not an action permission: not held as one

    assert held_permissions(superuser) == {CHANGE: True, "auth.view_user": True}
    assert held_permissions(given) == {CHANGE: True}


def test_nobody_holds_nothing(member):
    inactive = member("CLERKS", username="old", is_active=False)

    assert held_permissions(AnonymousUser()) == {} and held_permissions(inactive) == {}
    assert held_permissions(member(username="nobody")) == {}


def test_held_permissions_agree_with_unrestricted(member):
    from django_action_permissions.entries import entry_codes
    from django_action_permissions.models import ActionPermission

    users = [member("CLERKS"), member("CUSTOMERS", username="cid"), member("CUSTOMERS", "BOSSES", username="bea")]
    for user in users:
        held = held_permissions(user)
        for perm in entry_codes(ActionPermission.objects.all()):
            assert held.get(perm) == (unrestricted(user, perm) if user.has_perm(perm) else None), (user, perm)


def test_held_permissions_take_two_queries_however_many_action_permissions(setup, member, django_assert_num_queries):
    setup({**TABLE, "auth.delete_user": {"rbac": {"CLERKS"}}, "auth.add_user": {"rbac": {"CLERKS"}}})
    clerk = member("CLERKS", "CUSTOMERS")

    with django_assert_num_queries(2):
        held = held_permissions(clerk)
    assert len(held) == 4
