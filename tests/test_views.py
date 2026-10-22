"""The plain Django views' guards (`views`): no Django REST framework needed."""

import pytest
from asgiref.sync import async_to_sync
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.http import Http404, HttpResponse
from django.test import RequestFactory
from django.views import View
from django.views.generic.detail import SingleObjectMixin

from django_action_permissions.views import PermissionRequiredMixin, permission_required
from tests.conftest import thing

pytestmark = pytest.mark.django_db

CHANGE = "auth.change_user"
VIEW = "auth.view_user"
DELETE = "auth.delete_user"
TABLE = {
    CHANGE: {"rbac": {"CLERKS", "CUSTOMERS", "BOSSES"}, "abac": {"CUSTOMERS": "owner", "BOSSES": "owner"}},
    VIEW: {"rbac": {"CLERKS", "CUSTOMERS"}},
}


@pytest.fixture(autouse=True)
def table(setup):
    setup({**TABLE, CHANGE: {**TABLE[CHANGE], "staff": ["BOSSES"]}})


def request_by(user, path="/things/1/?tab=history"):
    request = RequestFactory().get(path)
    request.user = user
    return request


def page(request, owner="ann"):
    return HttpResponse(f"page of {owner}")


def owners_thing(request, owner="ann"):
    return thing(owner)


# ── permission_required ──────────────────────────────────────────────────────


def test_an_anonymous_visitor_is_sent_to_the_login_page():
    response = permission_required(CHANGE)(page)(request_by(AnonymousUser()))

    assert response.status_code == 302
    assert response.url == "/accounts/login/?next=/things/1/%3Ftab%3Dhistory"


def test_the_login_page_and_the_field_can_be_chosen():
    guarded = permission_required(CHANGE, login_url="https://sso.example.com/login", redirect_field_name="back")(page)

    response = guarded(request_by(AnonymousUser()))

    assert response.url == "https://sso.example.com/login?back=http%3A//testserver/things/1/%3Ftab%3Dhistory"


def test_without_an_object_the_permission_is_needed_on_any_object(member):
    guarded = permission_required(CHANGE)(page)

    assert guarded(request_by(member("CLERKS", username="cid"))).status_code == 200
    with pytest.raises(PermissionDenied):
        guarded(request_by(member("CUSTOMERS")))  # held on their own objects only
    with pytest.raises(PermissionDenied):
        guarded(request_by(member(username="nobody")))


def test_with_an_object_the_table_decides_on_it(member):
    guarded = permission_required(CHANGE, get_object=owners_thing)(page)
    customer = member("CUSTOMERS")

    assert guarded(request_by(customer), owner="ann").content == b"page of ann"
    with pytest.raises(PermissionDenied):
        guarded(request_by(customer), owner="bob")


def test_get_object_may_answer_404(member):
    def missing(request, **kwargs):
        raise Http404

    with pytest.raises(Http404):
        permission_required(CHANGE, get_object=missing)(page)(request_by(member("CUSTOMERS")))


def test_several_permissions_are_all_required(member):
    guarded = permission_required([CHANGE, VIEW])(page)

    assert guarded(request_by(member("CLERKS", username="cid"))).status_code == 200
    with pytest.raises(PermissionDenied):
        permission_required([CHANGE, "auth.delete_user"])(page)(request_by(member("CLERKS", username="dan")))


def test_a_staff_group_acts_as_its_manager(member, django_user_model):
    manager = django_user_model.objects.create_user(username="meg")
    assistant = member("BOSSES")

    guarded = permission_required(CHANGE, get_object=owners_thing, manager_user=lambda user: manager)(page)

    assert guarded(request_by(assistant), owner="meg").status_code == 200
    with pytest.raises(PermissionDenied):
        guarded(request_by(assistant), owner="ann")


def test_an_async_view_is_guarded_too(member):
    async def async_page(request, owner="ann"):
        return HttpResponse(f"async page of {owner}")

    guarded = permission_required(CHANGE, get_object=owners_thing)(async_page)
    customer = member("CUSTOMERS")

    assert async_to_sync(guarded)(request_by(customer), owner="ann").content == b"async page of ann"
    with pytest.raises(PermissionDenied):
        async_to_sync(guarded)(request_by(customer), owner="bob")
    assert async_to_sync(guarded)(request_by(AnonymousUser())).status_code == 302


def test_the_view_keeps_its_name():
    assert permission_required(CHANGE)(page).__name__ == "page"


# ── PermissionRequiredMixin ──────────────────────────────────────────────────


class ThingView(SingleObjectMixin, View):
    """A detail view of a thing, its owner in the URL."""

    def get_object(self, queryset=None):
        return thing(self.kwargs["owner"])

    def get(self, request, *args, **kwargs):
        return HttpResponse(f"thing of {self.get_object().owner}")


class GuardedThing(PermissionRequiredMixin, ThingView):
    permission_required = CHANGE


def get(view_class, user, owner="ann", **attributes):
    return view_class.as_view(**attributes)(request_by(user), owner=owner)


def test_the_mixin_sends_an_anonymous_visitor_to_the_login_page():
    response = get(GuardedThing, AnonymousUser())

    assert response.status_code == 302 and response.url.startswith("/accounts/login/?next=")


def test_the_mixin_lets_in_a_user_restricted_to_their_objects_and_checks_the_object(member):
    customer = member("CUSTOMERS")

    assert get(GuardedThing, customer, "ann").content == b"thing of ann"
    with pytest.raises(PermissionDenied):
        get(GuardedThing, customer, "bob")


def test_the_mixin_refuses_a_user_without_the_permission(member):
    with pytest.raises(PermissionDenied):
        get(GuardedThing, member(username="nobody"))


def test_the_mixin_may_ask_for_the_permission_on_any_object(member):
    class Portal(GuardedThing):
        permission_unrestricted = True

    assert get(Portal, member("CLERKS", username="cid"), "bob").status_code == 200
    with pytest.raises(PermissionDenied):
        get(Portal, member("CUSTOMERS"), "ann")


def test_the_mixin_asks_all_the_permissions(member):
    class Both(GuardedThing):
        permission_required = (CHANGE, VIEW)

    assert get(Both, member("CUSTOMERS"), "ann").status_code == 200
    with pytest.raises(PermissionDenied):
        get(Both, member("CUSTOMERS", username="bob"), "ann")


def test_the_mixin_acts_as_the_manager_for_a_staff_group(member, django_user_model):
    manager = django_user_model.objects.create_user(username="meg")

    class StaffThing(GuardedThing):
        def manager_user(self, user):
            return manager

    assistant = member("BOSSES")
    assert get(StaffThing, assistant, "meg").status_code == 200
    with pytest.raises(PermissionDenied):
        get(StaffThing, assistant, "ann")


def test_the_mixin_needs_a_permission(member):
    class Unguarded(PermissionRequiredMixin, ThingView):
        pass

    with pytest.raises(ImproperlyConfigured, match="permission_required"):
        get(Unguarded, member("CLERKS"))


def test_the_mixin_works_with_djangos_generic_views(setup, member, django_user_model):
    """A DetailView of users: a customer may delete their own account only (the `is_self` rule)."""
    from django.views.generic import DetailView

    setup({**TABLE, DELETE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}}})

    class UserPage(PermissionRequiredMixin, DetailView):
        model = django_user_model
        permission_required = DELETE

        def render_to_response(self, context, **kwargs):
            return HttpResponse(context["object"].username)

    customer = member("CUSTOMERS")
    other = django_user_model.objects.create_user(username="bob")

    assert UserPage.as_view()(request_by(customer), pk=customer.pk).content == b"ann"
    with pytest.raises(PermissionDenied):
        UserPage.as_view()(request_by(customer), pk=other.pk)


# ── 404 for an object the user can't read ────────────────────────────────────

SELF_ONLY = {
    VIEW: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
    CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
}
READ_ALL = {**SELF_ONLY, VIEW: {"rbac": {"CUSTOMERS"}}}


@pytest.fixture
def customer_and_other(member, django_user_model):
    return member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")


def user_page(request, pk):
    return HttpResponse(f"user {pk}")


def user_by_pk(request, pk):
    from django.contrib.auth import get_user_model

    return get_user_model().objects.get(pk=pk)


@pytest.mark.parametrize(
    "not_found, table, expected",
    [(True, SELF_ONLY, Http404), (True, READ_ALL, PermissionDenied), (False, SELF_ONLY, PermissionDenied)],
)
def test_the_decorator_answers_404_for_an_object_the_user_cant_read(
    setup, customer_and_other, not_found, table, expected
):
    setup(table)
    customer, other = customer_and_other
    guarded = permission_required(CHANGE, get_object=user_by_pk, not_found_when_unreadable=not_found)(user_page)

    with pytest.raises(expected):
        guarded(request_by(customer), pk=other.pk)
    assert guarded(request_by(customer), pk=customer.pk).status_code == 200


@pytest.mark.parametrize(
    "not_found, table, expected",
    [(True, SELF_ONLY, Http404), (True, READ_ALL, PermissionDenied), (False, SELF_ONLY, PermissionDenied)],
)
def test_the_mixin_answers_404_for_an_object_the_user_cant_read(
    setup, customer_and_other, django_user_model, not_found, table, expected
):
    from django.views.generic import DetailView

    setup(table)
    customer, other = customer_and_other

    class UserPage(PermissionRequiredMixin, DetailView):
        model = django_user_model
        permission_required = CHANGE
        not_found_when_unreadable = not_found

        def render_to_response(self, context, **kwargs):
            return HttpResponse(context["object"].username)

    with pytest.raises(expected):
        UserPage.as_view()(request_by(customer), pk=other.pk)
    assert UserPage.as_view()(request_by(customer), pk=customer.pk).content == b"ann"


def test_the_mixin_answers_for_an_object_without_raising(setup, customer_and_other):
    setup(SELF_ONLY)
    customer, other = customer_and_other
    view = GuardedThing()
    view.setup(request_by(customer), owner="ann")

    assert view.has_object_permission(customer) is True
    assert view.has_object_permission(other) is False
