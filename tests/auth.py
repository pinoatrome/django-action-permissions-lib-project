"""Helpers of the auth backend's tests: another object-permission backend, and a staff manager."""

from django.contrib.auth import get_user_model


class GrantObjects:
    """A backend granting every object permission (as a django-guardian grant would)."""

    def has_perm(self, user_obj, perm, obj=None):
        return obj is not None

    def authenticate(self, request, **credentials):
        return None

    def get_user(self, user_id):
        return None


def manager_of(user):
    return get_user_model().objects.get(username="meg")
