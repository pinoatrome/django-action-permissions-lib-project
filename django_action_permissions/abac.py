"""The object checks of the action permissions, in a view (`BaseActionModelPermission.has_object_permission`) or
outside one (pages, filters).

- `unrestricted(user, perm_code)`: the user holds the permission on any object.
- `allowed(user, perm_code, obj)`: the user may use the permission on `obj`.
- `held_permissions(user)`: every action permission the user holds, and whether on any object, in two queries
  (what a profile or a menu asks; the checks above read only their own permission's entry).

A user holds a permission through their groups (`rbac`); a group that has a ruleset for it (`abac`) holds it only
on the objects the ruleset allows. Every group holding the permission is evaluated (in name order): a rule raising
`PermissionDenied` in any of them blocks, else one group allowing is enough, so the answer doesn't depend on the
order of `user.groups`. Django's `PermissionDenied` blocks, and DRF's too when DRF is installed; nothing here needs
DRF.
"""

import logging

from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from django.http import Http404

from . import entries
from .backends import get_rules_backend

logger = logging.getLogger(__name__)

# What a rule raises to block. DRF's PermissionDenied isn't Django's: with DRF installed, a rule may raise either.
BLOCKS = (DjangoPermissionDenied,)
try:
    from rest_framework.exceptions import PermissionDenied as DRFPermissionDenied
except ImportError:
    pass
else:
    BLOCKS += (DRFPermissionDenied,)

_LOAD = object()  # `perm_info` not given: read the permission's entry


def granting_groups(user, perm_code: str) -> list[str]:
    """The names of the user's groups holding `perm_code`, in name order."""
    app_label, _, codename = perm_code.partition(".")
    return list(
        user.groups.filter(permissions__content_type__app_label=app_label, permissions__codename=codename)
        .order_by("name")
        .values_list("name", flat=True)
    )


def _restricted(info: dict, group: str) -> bool:
    return bool(info["abac"].get(group))


def unrestricted(user, perm_code: str, perm_info=_LOAD) -> bool:
    """Whether `user` holds `perm_code` on any object: a superuser, a permission given to the user directly, or a
    group of theirs holding it without a ruleset for it. A permission that isn't an action permission is held on no
    object through a group (until setup has run, no group is unrestricted)."""
    if not user.is_authenticated or not user.has_perm(perm_code):
        return False
    if user.is_superuser:
        return True
    app_label, _, codename = perm_code.partition(".")
    if user.user_permissions.filter(content_type__app_label=app_label, codename=codename).exists():
        return True
    info = entries.perm_info(perm_code) if perm_info is _LOAD else perm_info
    if info is None:
        logger.warning(f"{perm_code}: not an action permission, no group holds it on any object")
        return False
    return any(not _restricted(info, group) for group in granting_groups(user, perm_code))


def held_permissions(user) -> dict[str, bool]:
    """The action permissions `user` holds, each with whether they hold it on any object (as `unrestricted`
    answers), filtered in the database: the grants of the user's groups, each with whether that group has a ruleset
    for the permission, and the permissions given to the user directly. An anonymous or inactive user holds none, a
    superuser every action permission on any object."""
    from django.contrib.auth.models import Group, Permission
    from django.db.models import Exists, OuterRef

    from .models import ActionPermissionGroup

    if not user.is_authenticated or not user.is_active:
        return {}
    code = ("permission__content_type__app_label", "permission__codename")
    if user.is_superuser:
        rows = Permission.objects.filter(action_permission__isnull=False)
        return {
            f"{app_label}.{codename}": True
            for app_label, codename in rows.values_list("content_type__app_label", "codename")
        }
    grants = (
        Group.permissions.through.objects.filter(
            group__in=user.groups.all(), permission__action_permission__isnull=False
        )
        .annotate(
            restricted=Exists(
                ActionPermissionGroup.objects.filter(
                    action_permission__permission=OuterRef("permission"), group=OuterRef("group")
                )
            )
        )
        .values_list(*code, "restricted")
    )
    held = {}
    for app_label, codename, restricted in grants:
        perm_code = f"{app_label}.{codename}"
        held[perm_code] = held.get(perm_code, False) or not restricted
    direct = user.user_permissions.filter(action_permission__isnull=False)
    held.update(
        {
            f"{app_label}.{codename}": True
            for app_label, codename in direct.values_list("content_type__app_label", "codename")
        }
    )
    return held


def allowed(user, perm_code: str, obj=None, *, manager_user=None, perm_info=_LOAD, raise_blocks=False) -> bool:
    """Whether `user` may use `perm_code` on `obj` (on any object when None).

    Unrestricted, or else each group holding the permission evaluates its ruleset through the rules backend: a
    `PermissionDenied` blocks, else one group allowing is enough, else the backend's `default_allows` decides when a
    group's ruleset didn't (`None`). A `staff` group's ruleset is run for `manager_user(user)`; without
    `manager_user`, a staff group allows nothing. A permission that isn't an action permission is left to
    `user.has_perm(perm_code, obj)` (Django's object permission backends). With
    `raise_blocks`, a block is raised as Django's `PermissionDenied` instead of answered `False` (the auth backend's
    way of stopping the backends after it)."""
    info = entries.perm_info(perm_code) if perm_info is _LOAD else perm_info
    if unrestricted(user, perm_code, perm_info=info):
        return True
    if obj is None or not user.has_perm(perm_code):
        return False
    if info is None:
        return user.has_perm(perm_code, obj=obj)
    backend = get_rules_backend()
    answers = []
    for group in granting_groups(user, perm_code):
        checked = user
        if group in info["staff"]:
            if manager_user is None:
                logger.warning(f"{perm_code}: {group} is a staff group, but no manager_user is given")
                continue
            checked = manager_user(user)
        try:
            answer = backend.evaluate(info["abac"][group], info["predicates"], checked, obj)
        except BLOCKS as e:
            logger.info(f"{perm_code} on {obj!r} for {user}: blocked by {group}'s rules ({e})")
            if raise_blocks:
                raise DjangoPermissionDenied(str(e)) from e
            return False
        logger.debug(f"{perm_code} on {obj!r} for {user}: {group} answers {answer}")
        answers.append(answer)
    if any(answers):
        return True
    return None in answers and backend.default_allows


def read_permission(obj) -> str | None:
    """The permission to read `obj`, `<app_label>.view_<model_name>`, or None when `obj` isn't a model instance."""
    meta = getattr(obj, "_meta", None)
    return f"{meta.app_label}.view_{meta.model_name}" if meta is not None else None


def refusal(user, perm_code: str, obj, *, manager_user=None) -> type[Exception]:
    """What to raise when `user` may not use `perm_code` on `obj`: `Http404` when they can't read it either, so
    that its existence isn't revealed (as DRF's `DjangoObjectPermissions`), else `PermissionDenied` (403). An
    unsaved instance, the object a creation is checked on, is always `PermissionDenied`: there's nothing to hide."""
    read = read_permission(obj)
    if read is None or obj.pk is None:
        return DjangoPermissionDenied
    if read == perm_code or not allowed(user, read, obj, manager_user=manager_user):
        return Http404
    return DjangoPermissionDenied
