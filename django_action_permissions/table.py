"""The permissions table as the checks read it: from the database, through the cache `ACTION_PERMISSIONS["CACHE"]`
names (if any).

`load_table()` is `{perm_code: entry}`, an entry being
`{"abac": {group: ruleset}, "predicates": {code: fqn}, "no_detail": [group], "staff": [group]}`: each group's
ruleset as its expression (see the module `predicates`), and the definitions of the predicates they name. Who holds
a permission (`rbac`) isn't in it: that is always read live from `Group.permissions` / `user.has_perm()`.

No copy is kept in the memory of the process: a project runs several, and only a shared cache (or the database)
is seen by all of them. A cache that fails is logged and the database answers.
"""

import logging

from django.core.cache import caches
from django.db import transaction

from . import conf

logger = logging.getLogger(__name__)

CACHE_KEY = "django_action_permissions:table"


def _cache():
    alias = conf.get("CACHE")
    return caches[alias] if alias else None


def read_table() -> dict:
    """The table, from the database."""
    from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
    from .predicates import codes_of

    table = {}
    entries = ActionPermission.objects.select_related("permission__content_type").prefetch_related("no_detail", "staff")
    for entry in entries:
        table[entry.perm_code] = {
            "abac": {},
            "predicates": {},
            "no_detail": sorted(group.name for group in entry.no_detail.all()),
            "staff": sorted(group.name for group in entry.staff.all()),
        }
    definitions = dict(ActionPermissionRule.objects.values_list("code", "fqn"))
    rows = ActionPermissionGroup.objects.select_related("action_permission__permission__content_type", "group")
    for row in rows:
        entry = table[row.action_permission.perm_code]
        entry["abac"][row.group.name] = row.ruleset
        entry["predicates"].update({code: definitions[code] for code in codes_of(row.ruleset) if code in definitions})
    return table


def load_table() -> dict:
    """The table, from the cache when one is configured and holds it, else from the database (and then cached)."""
    cache = _cache()
    if cache is None:
        return read_table()
    try:
        table = cache.get(CACHE_KEY)
    except Exception:
        logger.warning("permissions table: the cache can't be read, reading the database", exc_info=True)
        return read_table()
    if table is not None:
        return table
    table = read_table()
    try:
        cache.set(CACHE_KEY, table, conf.get("CACHE_TIMEOUT"))
    except Exception:
        logger.warning("permissions table: the cache can't be written", exc_info=True)
    return table


def perm_info(perm_code: str) -> dict | None:
    """The table's entry of `perm_code`, or None when the table doesn't list it."""
    return load_table().get(perm_code)


def invalidate_table(strict: bool = False) -> None:
    """Drop the cached table (only the library's key: the cache may be shared with the rest of the project).
    When the cache can't be reached, `strict` raises (setup), else the failure is logged (the table expires
    after `CACHE_TIMEOUT` anyway)."""
    cache = _cache()
    if cache is None:
        return
    try:
        cache.delete(CACHE_KEY)
    except Exception:
        if strict:
            raise
        logger.error("permissions table: the cached table couldn't be dropped", exc_info=True)


def invalidate_on_commit(strict: bool = False) -> None:
    """`invalidate_table` once the current transaction commits (at once outside one), so that no reader caches
    the table the transaction is about to change."""
    transaction.on_commit(lambda: invalidate_table(strict=strict))
