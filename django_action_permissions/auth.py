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

A user who doesn't meet an entry's membership requirement (`mbac`) is refused with `PermissionDenied`, which stops
the other backends. With an object, `ModelBackend` answers False first, so this backend decides; without one,
`ModelBackend` answers True first if it's listed first: list this backend first to enforce `mbac` there too. Django's
`User.has_perm` answers True for an active superuser before asking any backend: a superuser's requirement is
enforced by `abac`, the library's views and permission classes, not `user.has_perm`.
"""

from django.contrib.auth.backends import BaseBackend
from django.core.exceptions import PermissionDenied

from . import conf, entries
from .abac import allowed, meets


class ActionPermissionBackend(BaseBackend):
    def has_perm(self, user_obj, perm, obj=None):
        if not user_obj.is_active:
            return False
        info = entries.perm_info(perm)
        if info is None:
            return False  # not an action permission: the other backends' (never has_perm(perm, obj) here: no recursion)
        if not meets(user_obj, info):
            raise PermissionDenied(f"{perm}: not a member of the required groups")
        if obj is None:
            return False  # without an object: ModelBackend's answer
        return allowed(user_obj, perm, obj, manager_user=conf.manager_user(), perm_info=info, raise_blocks=True)
