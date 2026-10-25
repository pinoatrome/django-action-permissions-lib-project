from types import SimpleNamespace

import pytest

pytest.importorskip("rest_framework")  # the `drf` extra

from django.contrib.auth.models import User
from rest_framework import exceptions
from rest_framework.test import APIRequestFactory

from django_action_permissions import entries
from django_action_permissions.permissions import BaseActionModelPermission, DenyAll, parse_view_action
from tests.conftest import thing
from tests.test_backends import ALLOW_ANY_SETTINGS


def test_deny_unless_allowed_denies_every_request():
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


# ── Checking a request against the stored action permissions ─────────────────

CHANGE = "auth.change_user"


def view_of(action, detail=False):
    return SimpleNamespace(action=action, detail=detail, get_queryset=lambda: User.objects)


def request_of(user):
    request = APIRequestFactory().get("/")
    request.user = user
    return request


def update(permission, user, obj):
    return permission.has_object_permission(request_of(user), view_of("update", detail=True), obj)


def test_the_permission_is_the_viewsets_model_and_the_actions_operation():
    permission = BaseActionModelPermission()
    assert permission.get_perm_code(request_of(None), view_of("list")) == "auth.view_user"
    assert permission.get_perm_code(request_of(None), view_of("create")) == "auth.add_user"
    assert permission.get_perm_code(request_of(None), view_of("approve")) == "auth.approve_user"


@pytest.mark.django_db
def test_the_entry_is_the_stored_one(setup):
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}}})

    assert BaseActionModelPermission().get_perm_info(CHANGE) == entries.perm_info(CHANGE)
    assert BaseActionModelPermission().get_perm_info("auth.view_user") is None


@pytest.mark.django_db
def test_a_user_holding_the_permission_is_allowed(setup, member):
    setup({"auth.view_user": {"rbac": {"CLERKS"}}})

    assert BaseActionModelPermission().has_permission(request_of(member("CLERKS")), view_of("list")) is True
    assert BaseActionModelPermission().has_permission(request_of(member(username="bob")), view_of("list")) is False


@pytest.mark.django_db
def test_a_group_without_detail_access_may_not_retrieve_one(setup, member):
    setup({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    clerk, permission = member("CLERKS"), BaseActionModelPermission()

    assert permission.has_permission(request_of(clerk), view_of("retrieve", detail=True)) is False
    assert permission.has_object_permission(request_of(clerk), view_of("retrieve", detail=True), thing()) is False
    assert permission.has_permission(request_of(clerk), view_of("list")) is True


@pytest.mark.django_db
def test_skipping_detail_access_lets_a_group_retrieve(setup, member):
    setup({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    permission = BaseActionModelPermission()
    permission.skip_detail_access(["retrieve", "info"])

    assert permission.has_permission(request_of(member("CLERKS")), view_of("retrieve", detail=True)) is True


@pytest.mark.django_db
def test_without_skipped_actions_every_action_has_detail_access(setup, member):
    setup({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    permission = BaseActionModelPermission()
    permission.skip_detail_access()

    assert permission.has_permission(request_of(member("CLERKS")), view_of("retrieve", detail=True)) is True


@pytest.mark.django_db
def test_detail_access_reads_the_entry_itself_when_not_given(setup, member):
    setup({"auth.view_user": {"rbac": {"CLERKS"}, "no_detail": ["CLERKS"]}})
    clerk = member("CLERKS")

    assert (
        BaseActionModelPermission().has_detail_access_permission(request_of(clerk), view_of("retrieve", True)) is False
    )
    assert BaseActionModelPermission().has_detail_access_permission(request_of(clerk), None) is True


@pytest.mark.django_db
def test_without_a_table_entry_the_django_permission_decides_for_an_object(member):
    superuser = member(username="root", is_superuser=True)

    assert update(BaseActionModelPermission(), superuser, thing()) is True
    assert update(BaseActionModelPermission(), member(), thing()) is False


@pytest.mark.django_db
def test_an_entry_without_abac_or_rules_is_the_model_permission_alone(setup, member):
    setup({CHANGE: {"rbac": {"CLERKS"}}})

    assert update(BaseActionModelPermission(), member("CLERKS"), thing("bob")) is True


@pytest.mark.django_db
def test_an_abac_rule_allows_its_group_on_the_objects_it_accepts(setup, member):
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}}})
    customer = member("CUSTOMERS")

    assert update(BaseActionModelPermission(), customer, thing("ann")) is True
    assert update(BaseActionModelPermission(), customer, thing("bob")) is False


@pytest.mark.django_db
def test_a_ruleset_of_predicates_that_must_all_allow(setup, member):
    setup({CHANGE: {"rbac": {"CLERKS"}, "abac": {"CLERKS": "owner & yes"}}})
    clerk = member("CLERKS")

    assert update(BaseActionModelPermission(), clerk, thing("ann")) is True
    assert update(BaseActionModelPermission(), clerk, thing("bob")) is False


@pytest.mark.django_db
def test_a_ruleset_runs_as_written(setup, member, calls):
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "yes | no"}}})

    assert update(BaseActionModelPermission(), member("CUSTOMERS"), thing()) is True
    assert calls == ["yes"]


@pytest.mark.django_db
def test_a_block_in_one_group_denies_though_another_allows(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "yes", "CUSTOMERS": "block_drf"}}})

    assert update(BaseActionModelPermission(), member("BOSSES", "CUSTOMERS"), thing()) is False


@pytest.mark.django_db
def test_the_answer_doesnt_depend_on_the_order_of_the_users_groups(setup, member):
    setup({CHANGE: {"rbac": {"BOSSES", "CUSTOMERS"}, "abac": {"BOSSES": "no", "CUSTOMERS": "owner"}}})

    for user in (member("BOSSES", "CUSTOMERS", username="ann"), member("CUSTOMERS", "BOSSES", username="bob")):
        assert update(BaseActionModelPermission(), user, thing(user.username)) is True
        assert update(BaseActionModelPermission(), user, thing("cid")) is False


@pytest.mark.django_db
def test_a_staff_group_acts_with_its_managers_rights(setup, member, django_user_model):
    setup({CHANGE: {"rbac": {"BOSSES"}, "abac": {"BOSSES": "owner"}, "staff": ["BOSSES"]}})
    manager = django_user_model.objects.create_user(username="meg")

    class StaffPermission(BaseActionModelPermission):
        def manager_user(self, user):
            return manager

    assistant = member("BOSSES")
    assert update(StaffPermission(), assistant, thing("meg")) is True
    assert update(StaffPermission(), assistant, thing("ann")) is False
    with pytest.raises(NotImplementedError, match="manager_user"):
        update(BaseActionModelPermission(), assistant, thing("meg"))


@pytest.mark.django_db
def test_under_allow_all_an_object_is_allowed_unless_a_rule_blocks(setup, member, settings):
    settings.ACTION_PERMISSIONS = {**ALLOW_ANY_SETTINGS, "CACHE": None}
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "abstain & owner"}}})
    customer = member("CUSTOMERS")

    assert update(BaseActionModelPermission(), customer, thing("ann")) is True
    assert update(BaseActionModelPermission(), customer, thing("bob")) is False


# ── 404 for an object the user can't read ────────────────────────────────────

from django.http import Http404  # noqa: E402
from django.urls import reverse  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402

VIEW = "auth.view_user"
SELF_ONLY = {
    VIEW: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
    CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
}
READ_ALL = {**SELF_ONLY, VIEW: {"rbac": {"CUSTOMERS"}}}


@pytest.fixture
def customer_and_other(member, django_user_model):
    return member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")


@pytest.mark.django_db
def test_an_object_the_user_cant_read_is_not_found(setup, customer_and_other):
    setup(SELF_ONLY)
    customer, other = customer_and_other

    with pytest.raises(Http404):
        BaseActionModelPermission().has_object_permission(request_of(customer), view_of("retrieve", True), other)
    with pytest.raises(Http404):
        update(BaseActionModelPermission(), customer, other)
    assert update(BaseActionModelPermission(), customer, customer) is True


@pytest.mark.django_db
def test_an_object_the_user_can_read_is_forbidden(setup, customer_and_other):
    setup(READ_ALL)
    customer, other = customer_and_other

    assert update(BaseActionModelPermission(), customer, other) is False


@pytest.mark.django_db
def test_a_creation_refused_is_forbidden_not_hidden(setup, customer_and_other, django_user_model):
    """The object a creation is checked on isn't saved yet: refused, it's a 403, there's nothing to hide."""
    setup(SELF_ONLY)
    customer, _other = customer_and_other

    assert update(BaseActionModelPermission(), customer, django_user_model(username="new")) is False


@pytest.mark.django_db
def test_403_everywhere_when_asked(setup, customer_and_other):
    setup(SELF_ONLY)
    customer, other = customer_and_other

    class Forbidding(BaseActionModelPermission):
        not_found_when_unreadable = False

    assert update(Forbidding(), customer, other) is False


@pytest.mark.django_db
def test_no_detail_stays_forbidden(setup, customer_and_other):
    setup({**SELF_ONLY, VIEW: {**SELF_ONLY[VIEW], "no_detail": ["CUSTOMERS"]}})
    customer, other = customer_and_other

    permission = BaseActionModelPermission()
    assert permission.has_object_permission(request_of(customer), view_of("retrieve", True), other) is False


@pytest.mark.django_db
def test_a_permission_the_table_doesnt_list_follows_the_same_rule(setup, customer_and_other):
    setup({VIEW: SELF_ONLY[VIEW]})  # change_user isn't listed: has_perm(perm, obj) refuses
    customer, other = customer_and_other

    with pytest.raises(Http404):
        update(BaseActionModelPermission(), customer, other)


@pytest.mark.django_db
@pytest.mark.parametrize("table, other_status", [(SELF_ONLY, 404), (READ_ALL, 403)])
def test_over_http(setup, customer_and_other, table, other_status):
    setup(table)
    customer, other = customer_and_other
    client = APIClient()
    client.force_authenticate(customer)

    assert client.get(reverse("user-detail", args=[customer.pk])).status_code == 200
    response = client.put(reverse("user-detail", args=[other.pk]), {"username": "bob2"}, format="json")
    assert response.status_code == other_status
    assert client.get(reverse("user-detail", args=[other.pk])).status_code == {404: 404, 403: 200}[other_status]
