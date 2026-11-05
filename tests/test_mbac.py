"""`mbac`: the groups a user must belong to (at least one, or all) to use an action permission, however they hold it
(through a group, directly, as a superuser)."""

import pytest
from django.contrib.auth.models import Group, Permission
from django.core.exceptions import PermissionDenied

from django_action_permissions import entries
from django_action_permissions.abac import allowed, held_permissions, holds, unrestricted
from django_action_permissions.auth import ActionPermissionBackend
from django_action_permissions.explain import explain
from django_action_permissions.models import ActionPermission
from django_action_permissions.utils import drf_installed
from django_action_permissions.yaml_io import export_document, parse_document
from tests.conftest import stored_entries, thing

pytestmark = pytest.mark.django_db

CHANGE = "auth.change_user"
VIEW = "auth.view_user"


def table(match=None, groups=("CUSTOMERS", "BOSSES")):
    mbac = {"groups": list(groups), **({"match": match} if match else {})}
    return {
        CHANGE: {"rbac": {"CLERKS"}, "abac": {"CLERKS": "owner"}, "mbac": mbac},
        VIEW: {"rbac": {"CLERKS"}},
    }


def give(user, perm_code):
    app_label, _, codename = perm_code.partition(".")
    user.user_permissions.add(Permission.objects.get(content_type__app_label=app_label, codename=codename))
    return type(user).objects.get(pk=user.pk)


def test_setup_stores_the_requirement(setup):
    setup(table("all"))

    assert stored_entries()[CHANGE]["mbac"] == {"groups": ["BOSSES", "CUSTOMERS"], "match": "all"}
    assert stored_entries()[VIEW]["mbac"] is None


def test_match_is_any_by_default(setup):
    setup(table())

    assert stored_entries()[CHANGE]["mbac"]["match"] == "any"


def test_setup_again_without_it_removes_it(setup):
    setup(table("all"))
    setup({CHANGE: {"rbac": {"CLERKS"}}})

    entry = ActionPermission.objects.get(permission__codename="change_user")
    assert entry.mbac.count() == 0 and entry.mbac_match == "any"


@pytest.mark.parametrize(
    "mbac, message",
    [
        (["CUSTOMERS"], "isn't"),
        ({"groups": ["NOBODY"]}, "isn't one of the groups"),
        ({"groups": "CUSTOMERS"}, "list of group names"),
        ({"groups": ["CUSTOMERS"], "match": "some"}, "match 'some'"),
        ({"groups": ["CUSTOMERS"], "every": True}, "unknown keys every"),
    ],
)
def test_setup_refuses_a_bad_requirement(setup, mbac, message):
    with pytest.raises(ValueError, match=message):
        setup({CHANGE: {"rbac": {"CLERKS"}, "mbac": mbac}})


def test_a_holder_outside_the_groups_is_refused(setup, member):
    setup(table())
    clerk = member("CLERKS")

    assert not holds(clerk, CHANGE) and not allowed(clerk, CHANGE, thing("ann"))
    assert holds(clerk, VIEW) and unrestricted(clerk, VIEW)  # no requirement there
    assert held_permissions(clerk) == {VIEW: True}


def test_any_one_group_is_enough(setup, member):
    setup(table("any"))
    clerk = member("CLERKS", "CUSTOMERS")

    assert holds(clerk, CHANGE) and allowed(clerk, CHANGE, thing("ann"))
    assert not allowed(clerk, CHANGE, thing("bob"))  # the ruleset still runs
    assert held_permissions(clerk) == {CHANGE: False, VIEW: True}


def test_all_requires_every_group(setup, member):
    setup(table("all"))

    assert not holds(member("CLERKS", "CUSTOMERS"), CHANGE)
    assert holds(member("CLERKS", "CUSTOMERS", "BOSSES", username="bob"), CHANGE)


def test_a_superuser_outside_the_groups_is_refused(setup, member):
    setup(table())
    root = member(username="root", is_superuser=True)

    assert not holds(root, CHANGE) and not unrestricted(root, CHANGE) and not allowed(root, CHANGE, thing("bob"))
    assert held_permissions(root) == {VIEW: True}


def test_a_superuser_in_the_groups_holds_it_on_any_object(setup, member):
    setup(table())
    root = member("BOSSES", username="root", is_superuser=True)

    assert unrestricted(root, CHANGE) and allowed(root, CHANGE, thing("bob"))


def test_a_direct_grant_outside_the_groups_is_refused(setup, member):
    setup(table())
    ann = give(member(), CHANGE)

    assert not holds(ann, CHANGE) and not unrestricted(ann, CHANGE)
    assert unrestricted(give(member("CUSTOMERS", username="bob"), CHANGE), CHANGE)


def test_joining_a_group_is_seen_at_once(setup, member):
    setup(table())
    clerk = member("CLERKS")
    assert not holds(clerk, CHANGE)

    clerk.groups.add(Group.objects.get(name="CUSTOMERS"))

    assert holds(clerk, CHANGE)


def test_changing_the_groups_drops_the_cached_entry(setup, settings, django_capture_on_commit_callbacks):
    settings.ACTION_PERMISSIONS = {}  # the tests' cache
    setup(table())
    assert entries.perm_info(CHANGE)["mbac"]["groups"] == ["BOSSES", "CUSTOMERS"]

    with django_capture_on_commit_callbacks(execute=True):
        ActionPermission.objects.get(permission__codename="change_user").mbac.remove(Group.objects.get(name="BOSSES"))

    assert entries.perm_info(CHANGE)["mbac"]["groups"] == ["CUSTOMERS"]


def test_the_auth_backend_blocks_a_holder_outside_the_groups(setup, member):
    setup(table())
    clerk = member("CLERKS")
    backend = ActionPermissionBackend()

    with pytest.raises(PermissionDenied):
        backend.has_perm(clerk, CHANGE, thing("ann"))
    with pytest.raises(PermissionDenied):
        backend.has_perm(clerk, CHANGE)
    assert backend.has_perm(member("CLERKS", "CUSTOMERS", username="bob"), CHANGE) is False  # ModelBackend's answer


def test_explain_shows_the_requirement(setup, member):
    setup(table("all"))

    explanation = explain(member("CLERKS", "CUSTOMERS"), CHANGE, thing("ann"))

    assert explanation.allowed is False
    assert explanation.steps[-1].label == "a member of all of BOSSES, CUSTOMERS (mbac)"
    assert explanation.steps[-1].passed is False


def test_yaml_round_trips_the_requirement(setup):
    setup(table("all"))

    document = export_document()
    assert document["permissions"][CHANGE]["mbac"] == {"groups": ["BOSSES", "CUSTOMERS"], "match": "all"}
    assert "mbac" not in document["permissions"][VIEW]
    assert {"BOSSES", "CUSTOMERS"} <= set(document["groups"])
    definitions, _groups, _rules = parse_document(document)
    assert definitions[CHANGE]["mbac"]["match"] == "all"


def test_yaml_refuses_a_requirement_of_the_wrong_shape():
    with pytest.raises(ValueError, match="mbac"):
        parse_document({"permissions": {CHANGE: {"mbac": ["CUSTOMERS"]}}})


def test_the_view_mixin_refuses_a_holder_outside_the_groups(setup, member, rf):
    from django.views import View

    from django_action_permissions.views import PermissionRequiredMixin

    class Page(PermissionRequiredMixin, View):
        permission_required = CHANGE

    setup(table())
    page = Page()
    page.request = rf.get("/")
    page.request.user = member("CLERKS")
    assert page.has_permission() is False
    page.request.user = member("CLERKS", "BOSSES", username="bob")
    assert page.has_permission() is True


@pytest.mark.skipif(not drf_installed(), reason="DRF not installed")
def test_the_drf_permission_refuses_a_holder_outside_the_groups(setup, member):
    from django_action_permissions.permissions import BaseActionModelPermission
    from tests.test_permissions import request_of, view_of

    setup(table())
    permission = BaseActionModelPermission()

    assert permission.has_permission(request_of(member(username="root", is_superuser=True)), view_of("update")) is False
    assert permission.has_permission(request_of(member("CLERKS", "CUSTOMERS")), view_of("update")) is True


def test_the_admin_shows_and_edits_the_requirement(admin_client, setup):
    from django.urls import reverse

    setup(table("all"))
    entry = ActionPermission.objects.get(permission__codename="change_user")

    for name, args in [("changelist", []), ("change", [entry.pk]), ("overview", [])]:
        response = admin_client.get(reverse(f"admin:django_action_permissions_actionpermission_{name}", args=args))
        assert response.status_code == 200, name
        assert "BOSSES" in response.content.decode(), name
    changelist = admin_client.get(reverse("admin:django_action_permissions_actionpermission_changelist"))
    assert "all: BOSSES, CUSTOMERS" in changelist.content.decode()
