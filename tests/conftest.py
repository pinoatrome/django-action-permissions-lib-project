from types import SimpleNamespace

import pytest
from django.contrib.auth.models import Group

from django_action_permissions import predicates
from django_action_permissions.rbac import setup_rbac_permissions
from tests import rules

GROUPS = ["BOSSES", "CLERKS", "CUSTOMERS"]


def stored_entries() -> dict:
    """Every action permission's entry, read from the database (the library itself reads one at a time)."""
    from django_action_permissions.entries import entry_codes, read_entry
    from django_action_permissions.models import ActionPermission

    return {code: read_entry(code) for code in sorted(entry_codes(ActionPermission.objects.all()))}


def thing(owner="ann"):
    """An object with an owner, for the `owner` predicate."""
    return SimpleNamespace(owner=owner)


@pytest.fixture(autouse=True)
def calls():
    rules.CALLS.clear()
    return rules.CALLS


@pytest.fixture(autouse=True)
def registry():
    """The predicates a test registers don't outlive it."""
    predicates.discover()
    saved = dict(predicates.REGISTRY)
    yield predicates.REGISTRY
    predicates.REGISTRY.clear()
    predicates.REGISTRY.update(saved)


@pytest.fixture
def setup(db):
    """Run setup with the test groups (the predicates are the discovered ones)."""

    def run(table, rules=None, groups=GROUPS, keep=False):
        return setup_rbac_permissions(table, groups, rules=rules, keep=keep)

    return run


@pytest.fixture
def member(db, django_user_model):
    """A user in the given groups (created if missing)."""

    def make(*groups, username="ann", **fields):
        user = django_user_model.objects.create_user(username=username, **fields)
        user.groups.add(*(Group.objects.get_or_create(name=name)[0] for name in groups))
        return django_user_model.objects.get(pk=user.pk)  # no permission cached on the instance

    return make
