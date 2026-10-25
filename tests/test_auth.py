"""The optional auth backend: `user.has_perm(perm, obj)` answered by the rulesets."""

import pytest
from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied
from django.urls import reverse

from django_action_permissions.abac import allowed
from django_action_permissions.utils import drf_installed

pytestmark = pytest.mark.django_db

VIEW = "auth.view_user"
CHANGE = "auth.change_user"
MODEL_BACKEND = "django.contrib.auth.backends.ModelBackend"
TABLE_BACKEND = "django_action_permissions.auth.ActionPermissionBackend"
SELF_ONLY = {
    VIEW: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
    CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "is_self"}},
}


@pytest.fixture(autouse=True)
def backends(settings):
    settings.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, TABLE_BACKEND]
    return settings


@pytest.fixture
def customer_and_other(setup, member, django_user_model):
    setup(SELF_ONLY)
    return member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")


def test_with_an_object_the_table_answers(customer_and_other):
    customer, other = customer_and_other

    assert customer.has_perm(CHANGE, customer) is True
    assert customer.has_perm(CHANGE, other) is False


def test_without_an_object_the_model_backend_answers(customer_and_other, member):
    customer, _ = customer_and_other

    assert customer.has_perm(CHANGE) is True
    assert member(username="nobody").has_perm(CHANGE) is False


def test_an_inactive_user_is_refused(customer_and_other):
    customer, _ = customer_and_other
    customer.is_active = False

    assert customer.has_perm(CHANGE, customer) is False


def test_a_permission_the_table_doesnt_list_is_left_to_the_other_backends(customer_and_other, member):
    customer, other = customer_and_other
    customer.user_permissions.add(Permission.objects.get(content_type__app_label="auth", codename="delete_user"))

    assert customer.has_perm("auth.delete_user") is True
    assert customer.has_perm("auth.delete_user", other) is False  # ModelBackend has no object permissions


def test_another_backend_may_allow_over_a_plain_refusal(customer_and_other, backends):
    backends.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, TABLE_BACKEND, "tests.auth.GrantObjects"]
    customer, other = customer_and_other

    assert customer.has_perm(CHANGE, other) is True


def test_a_rule_blocking_stops_the_backends_after(setup, member, django_user_model, backends):
    backends.AUTHENTICATION_BACKENDS = [MODEL_BACKEND, TABLE_BACKEND, "tests.auth.GrantObjects"]
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "block"}}})
    customer = member("CUSTOMERS")

    assert customer.has_perm(CHANGE, django_user_model.objects.create_user(username="bob")) is False


def test_allowed_raises_a_block_when_asked(setup, member, django_user_model):
    setup({CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "block"}}})
    customer, other = member("CUSTOMERS"), django_user_model.objects.create_user(username="bob")

    assert allowed(customer, CHANGE, other) is False
    with pytest.raises(PermissionDenied, match="blocked"):
        allowed(customer, CHANGE, other, raise_blocks=True)


def test_a_staff_group_acts_as_the_manager_user_setting_names(setup, member, django_user_model, settings):
    setup({CHANGE: {"rbac": {"BOSSES"}, "abac": {"BOSSES": "is_self"}, "staff": ["BOSSES"]}})
    assistant = member("BOSSES")
    manager = django_user_model.objects.create_user(username="meg")

    assert assistant.has_perm(CHANGE, manager) is False  # MANAGER_USER is None: a staff group allows nothing

    settings.ACTION_PERMISSIONS = {"CACHE": None, "MANAGER_USER": "tests.auth.manager_of"}
    assert django_user_model.objects.get(pk=assistant.pk).has_perm(CHANGE, manager) is True


@pytest.mark.skipif(not drf_installed(), reason="Django REST framework isn't installed")
def test_drfs_own_object_permissions_follow_the_table(customer_and_other, setup):
    from rest_framework.test import APIClient

    customer, other = customer_and_other
    client = APIClient()
    client.force_authenticate(customer)

    assert client.get(reverse("object-user-detail", args=[customer.pk])).status_code == 200
    assert client.get(reverse("object-user-detail", args=[other.pk])).status_code == 404
    setup({**SELF_ONLY, VIEW: {"rbac": {"CUSTOMERS"}}})  # every user readable, only oneself changeable
    response = client.put(reverse("object-user-detail", args=[other.pk]), {"username": "bob2"}, format="json")
    assert response.status_code == 403
