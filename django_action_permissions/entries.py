"""The action permissions as the checks read them, one at a time: each permission's entry, from the database,
through the cache `ACTION_PERMISSIONS["CACHE"]` names (if any).

An action permission is a Django permission setup stored with an `ActionPermission` row. Its entry is
`{"abac": {group: ruleset}, "predicates": {code: fqn}, "no_detail": [group], "staff": [group]}`: each group's ruleset
as its expression (see the module `predicates`), and the definitions of the predicates they name. Who holds a
permission (`rbac`) isn't in it: that is always read live from `Group.permissions` / `user.has_perm()`.

Each entry is cached under its own key, and a change of what it's made of (its rows, a predicate it uses, a group it
names) deletes that key once the change commits: see `signals`. No copy is kept in the memory of the process: a
project runs several, and only a shared cache (or the database) is seen by all of them. A cache that fails is logged
and the database answers.
"""

import logging

from django.core.cache import caches
from django.db import transaction

from . import conf

logger = logging.getLogger(__name__)

KEY_PREFIX = "django_action_permissions:perm:"
UNLISTED = {"listed": False}  # cached for a permission that isn't an action permission


def _cache():
    alias = conf.get("CACHE")
    return caches[alias] if alias else None


def _key(perm_code: str) -> str:
    return f"{KEY_PREFIX}{perm_code}"


def entry_codes(queryset) -> set[str]:
    """The permission strings of a queryset of `ActionPermission`."""
    rows = queryset.values_list("permission__content_type__app_label", "permission__codename")
    return {f"{app_label}.{codename}" for app_label, codename in rows}


def read_entry(perm_code: str) -> dict | None:
    """The entry of `perm_code`, from the database; None when it isn't an action permission."""
    from django.db.models import Prefetch

    from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
    from .predicates import codes_of

    app_label, _, codename = perm_code.partition(".")
    entry = (
        ActionPermission.objects.filter(permission__content_type__app_label=app_label, permission__codename=codename)
        .prefetch_related(
            "no_detail",
            "staff",
            Prefetch("group_rules", queryset=ActionPermissionGroup.objects.select_related("group")),
        )
        .first()
    )
    if entry is None:
        return None
    abac = {row.group.name: row.ruleset for row in entry.group_rules.all()}
    codes = set().union(*(codes_of(ruleset) for ruleset in abac.values()))
    predicates = dict(ActionPermissionRule.objects.filter(code__in=codes).values_list("code", "fqn")) if codes else {}
    return {
        "abac": abac,
        "predicates": predicates,
        "no_detail": sorted(group.name for group in entry.no_detail.all()),
        "staff": sorted(group.name for group in entry.staff.all()),
    }


def perm_info(perm_code: str) -> dict | None:
    """The entry of `perm_code`, from the cache when one is configured and holds it, else from the database (and
    then cached); None when it isn't an action permission (that answer is cached too)."""
    cache = _cache()
    if cache is None:
        return read_entry(perm_code)
    try:
        cached = cache.get(_key(perm_code))
    except Exception:
        logger.warning(f"{perm_code}: the cache can't be read, reading the database", exc_info=True)
        return read_entry(perm_code)
    if cached is not None:
        return None if cached == UNLISTED else cached
    entry = read_entry(perm_code)
    try:
        cache.set(_key(perm_code), UNLISTED if entry is None else entry, conf.get("CACHE_TIMEOUT"))
    except Exception:
        logger.warning(f"{perm_code}: the cache can't be written", exc_info=True)
    return entry


def invalidate(perm_codes, strict: bool = False) -> None:
    """Drop the cached entries of `perm_codes` (only theirs: the cache may be shared with the rest of the project).
    When the cache can't be reached, `strict` raises (setup), else the failure is logged (the entries expire after
    `CACHE_TIMEOUT` anyway)."""
    cache = _cache()
    keys = [_key(perm_code) for perm_code in perm_codes]
    if cache is None or not keys:
        return
    try:
        cache.delete_many(keys)
    except Exception:
        if strict:
            raise
        logger.error(f"the cached entries of {', '.join(sorted(perm_codes))} couldn't be dropped", exc_info=True)


def invalidate_on_commit(perm_codes, strict: bool = False) -> None:
    """`invalidate` once the current transaction commits (at once outside one), so that no reader caches an entry
    the transaction is about to change."""
    codes = frozenset(perm_codes)
    if codes:
        transaction.on_commit(lambda: invalidate(codes, strict=strict))
