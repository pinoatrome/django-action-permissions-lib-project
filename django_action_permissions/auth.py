"""An authentication backend answering `user.has_perm(perm, obj)` by the action permissions (no DRF needed).

Opt-in, after Django's `ModelBackend`:

    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "django_action_permissions.auth.ActionPermissionBackend",
    ]

Without an object, `ModelBackend` answers (`Group.permissions`, which setup writes). With one, for an action
permission, this backend answers `abac.allowed`: Django's own API then asks its rulesets, so templates, services,
guardian-style code and DRF's `DjangoObjectPermissions` follow them. A rule raising `PermissionDenied` stops the
backends after this one (Django's `_user_has_perm`), so a ruleset's block also stops another backend's grant; a plain
refusal leaves them free to allow. A permission that isn't an action permission is left to the other backends.
"""

from django.contrib.auth.backends import BaseBackend

from . import conf, entries
from .abac import allowed


class ActionPermissionBackend(BaseBackend):
    def has_perm(self, user_obj, perm, obj=None):
        if obj is None or not user_obj.is_active:
            return False  # without an object: ModelBackend's answer
        info = entries.perm_info(perm)
        if info is None:
            return False  # not an action permission: the other backends' (never has_perm(perm, obj) here: no recursion)
        return allowed(user_obj, perm, obj, manager_user=conf.manager_user(), perm_info=info, raise_blocks=True)
