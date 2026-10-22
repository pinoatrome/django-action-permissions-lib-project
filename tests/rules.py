"""The tests' predicates, discovered as an installed app's (`tests` is one in the test settings). `CALLS` records
which ran, in order (cleared before each test)."""

from django.core.exceptions import PermissionDenied

from django_action_permissions.predicates import predicate
from django_action_permissions.utils import drf_installed

CALLS = []

NOT_CALLABLE = 42


@predicate
def owner(user, obj):
    """The object's owner is the user."""
    CALLS.append("owner")
    return getattr(obj, "owner", None) == user.username


@predicate
def yes(user, obj):
    CALLS.append("yes")
    return True


@predicate
def no(user, obj):
    CALLS.append("no")
    return False


@predicate
def abstain(user, obj):
    CALLS.append("abstain")
    return None


@predicate
def block(user, obj):
    CALLS.append("block")
    raise PermissionDenied("blocked")


if drf_installed():
    from rest_framework import exceptions

    @predicate
    def block_drf(user, obj):
        CALLS.append("block_drf")
        raise exceptions.PermissionDenied("blocked")
