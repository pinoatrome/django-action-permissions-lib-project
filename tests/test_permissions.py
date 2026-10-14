from types import SimpleNamespace

import pytest
from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from django_action_permissions.permissions import BaseActionModelPermission, DenyAll, parse_view_action


def test_deny_all_denies_every_request():
    factory = APIRequestFactory()

    for request in (factory.get("/"), factory.post("/", data=b"<Document/>", content_type="application/xml")):
        assert DenyAll().has_permission(request, view=None) is False


@pytest.mark.parametrize(
    "action, operation",
    [
        ("create", "add"),
        ("update", "change"),
        ("partial_update", "change"),
        ("destroy", "delete"),
        ("list", "view"),
        ("retrieve", "view"),
        ("upload", "upload"),  # a custom action is its own operation: <app_label>.upload_<model_name>
    ],
)
def test_view_action_maps_to_permission_operation(action, operation):
    assert parse_view_action(SimpleNamespace(action=action, detail=False)) == operation


def test_view_without_action_is_denied():
    """A request method the viewset doesn't route has no action."""
    with pytest.raises(exceptions.PermissionDenied):
        parse_view_action(SimpleNamespace(action=None, detail=False))


@pytest.mark.parametrize("method, operation", [("OPTIONS", "view"), ("POST", "add"), ("PUT", "change")])
def test_metadata_maps_to_the_described_operation(method, operation):
    """OPTIONS takes the view permission; to describe the POST and PUT input, DRF checks
    them on a copy of the request, still under `metadata`."""
    view = SimpleNamespace(action="metadata", detail=False, request=SimpleNamespace(method=method))

    assert parse_view_action(view) == operation


def request_by(is_authenticated, method="get"):
    request = getattr(APIRequestFactory(), method)("/")
    request.user = SimpleNamespace(is_authenticated=is_authenticated)
    return request


def test_unrouted_method_is_not_allowed_to_authenticated_users():
    with pytest.raises(exceptions.MethodNotAllowed):
        BaseActionModelPermission().has_permission(request_by(True, "delete"), SimpleNamespace(action=None))


def test_unrouted_method_is_denied_to_anonymous_users():
    """Denied, not 405: DRF asks for credentials without telling which methods exist."""
    view = SimpleNamespace(action=None)

    assert BaseActionModelPermission().has_permission(request_by(False, "delete"), view) is False


# ── Checking a request against the RBAC table ────────────────────────────────


class FakeGroups:
    def __init__(self, names):
        self.names = names

    def all(self):
        return [SimpleNamespace(name=name) for name in self.names]


def user_with(perms=(), groups=(), authenticated=True):
    return SimpleNamespace(
        is_authenticated=authenticated, groups=FakeGroups(groups), has_perm=lambda code, obj=None: code in perms)


def view_of(action, detail=False):
    return SimpleNamespace(action=action, detail=detail, get_queryset=lambda: User.objects)


def request_of(user):
    request = APIRequestFactory().get("/")
    request.user = user
    return request


class TablePermission(BaseActionModelPermission):
    table = {}

    def get_perm_info(self, perm_code):
        return self.table.get(perm_code)

    def apply_rule(self, br_code, user, obj):
        return br_code == "owner" and obj == "mine"


def permission_with(table):
    return type("Permission", (TablePermission,), {"table": table})()


def test_the_permission_is_the_viewsets_model_and_the_actions_operation():
    permission = permission_with({})
    assert permission.get_perm_code(request_of(None), view_of("list")) == "auth.view_user"
    assert permission.get_perm_code(request_of(None), view_of("create")) == "auth.add_user"
    assert permission.get_perm_code(request_of(None), view_of("approve")) == "auth.approve_user"


def test_a_user_holding_the_permission_is_allowed():
    permission = permission_with({"auth.view_user": {"rbac": {"CLERKS"}}})
    assert permission.has_permission(request_of(user_with({"auth.view_user"})), view_of("list")) is True
    assert permission.has_permission(request_of(user_with(set())), view_of("list")) is False


def test_a_group_without_detail_access_may_not_retrieve_one():
    permission = permission_with({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    clerk = user_with({"auth.view_user"}, ["CLERKS"])

    assert permission.has_permission(request_of(clerk), view_of("retrieve", detail=True)) is False
    assert permission.has_permission(request_of(clerk), view_of("list")) is True


def test_skipping_detail_access_lets_a_group_retrieve():
    permission = permission_with({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    permission.skip_detail_access(["retrieve", "info"])

    assert permission.has_permission(request_of(user_with({"auth.view_user"}, ["CLERKS"])),
                                     view_of("retrieve", detail=True)) is True


def test_without_a_table_entry_the_django_permission_decides_for_an_object_too():
    permission = permission_with({})
    request = request_of(user_with({"auth.change_user"}))

    assert permission.has_object_permission(request, view_of("update"), "any") is True
    assert permission.has_object_permission(request_of(user_with(set())), view_of("update"), "any") is False


def test_an_entry_without_abac_or_rules_is_the_model_permission_alone():
    permission = permission_with({"auth.change_user": {"rbac": {"CLERKS"}, "abac": {}}})

    assert permission.has_object_permission(
        request_of(user_with({"auth.change_user"}, ["CLERKS"])), view_of("update"), "any") is True


def test_an_abac_rule_allows_its_group_on_the_objects_it_accepts():
    permission = permission_with({"auth.change_user": {"rbac": {"CLERKS"}, "abac": {"CLERKS": ["owner"]}}})
    clerk = request_of(user_with({"auth.change_user"}, ["CLERKS"]))

    assert permission.has_object_permission(clerk, view_of("update"), "mine") is True
    assert permission.has_object_permission(clerk, view_of("update"), "yours") is False


def test_business_rules_must_all_allow():
    table = {"auth.change_user": {"rbac": {"CLERKS"}, "rules": [{"code": "owner", "for": ["CLERKS"]}]}}
    permission = permission_with(table)
    clerk = request_of(user_with({"auth.change_user"}, ["CLERKS"]))

    assert permission.has_object_permission(clerk, view_of("update"), "mine") is True
    assert permission.has_object_permission(clerk, view_of("update"), "yours") is False


def test_the_base_class_needs_a_table():
    with pytest.raises(NotImplementedError, match="get_perm_info"):
        BaseActionModelPermission().get_perm_info("auth.view_user")
