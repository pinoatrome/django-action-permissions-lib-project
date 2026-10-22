"""An authentication backend answering `user.has_perm(perm, obj)` by the permissions table (no DRF needed).

Opt-in, after Django's `ModelBackend`:

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "django_action_permissions.auth.ActionPermissionBackend",
    ]

Without an object, `ModelBackend` answers (`Group.permissions`, which setup writes). With one, for a permission
the table lists, this backend answers `abac.allowed`: Django's own API then asks the table, so templates, services,
guardian-style code and DRF's `DjangoObjectPermissions` follow it. A rule raising `PermissionDenied` stops the
backends after this one (Django's `_user_has_perm`), so a table block also stops another backend's grant; a plain
refusal leaves them free to allow. A permission the table doesn't list is left to the other backends.
"""

from django.contrib.auth.backends import BaseBackend

from . import conf, table
from .abac import allowed


class ActionPermissionBackend(BaseBackend):
    def has_perm(self, user_obj, perm, obj=None):
        if obj is None or not user_obj.is_active:
            return False  # without an object: ModelBackend's answer
        info = table.perm_info(perm)
        if info is None:
            return False  # not in the table: the other backends' (never has_perm(perm, obj) here: no recursion)
        return allowed(user_obj, perm, obj, manager_user=conf.manager_user(), perm_info=info, raise_blocks=True)
