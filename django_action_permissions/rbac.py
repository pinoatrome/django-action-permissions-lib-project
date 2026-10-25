"""Setup: the permission definitions and their predicates, written to the database.

The definitions map a Django permission string as `user.has_perm()` takes it ("app_label.codename") to its entry:

- `rbac`: the groups granted the permission (`Group.permissions`);
- `abac`: `{group: ruleset}`, the predicates the group's objects must pass, composed with `&`, `|`, `~` (see
  `predicates`): an expression (`"own_order & ~archived"`), or the composition itself in Python;
- `no_detail`: groups that may list but not retrieve a single object;
- `staff`: groups that act with the rights of their manager.

The predicates are the ones registered with `@predicate` in the installed apps' `rules` modules (`discover()`),
and the definitions given as `rules` (`{code: {"fqn", "description"?}}`, e.g. a YAML document's).
"""

from django.db import transaction

from .entries import entry_codes, invalidate_on_commit
from .predicates import NamedPredicate, Ruleset, canonical, discover
from .utils import rule_error

SECTIONS = ("rbac", "abac", "no_detail", "staff")
MERGED = (
    'a group\'s predicates are one ruleset: write {group: "a | b"} (any allows) or {group: "a & b"} (all must pass)'
)


def _check_groups(names, groups: set[str], where: str) -> None:
    for name in names:
        if name not in groups:
            raise ValueError(f"{where}: '{name}' isn't one of the groups to set up: {', '.join(sorted(groups))}")


def _definitions(rules: dict) -> dict[str, dict]:
    """The predicates to store: the registered ones and `rules`, each importable, a code meaning one function."""
    definitions = {
        code: {"fqn": registered.fqn, "description": registered.description} for code, registered in discover().items()
    }
    for code, definition in rules.items():
        if not isinstance(definition, dict) or not isinstance(definition.get("fqn"), str):
            raise ValueError(f"rule '{code}': {definition!r} has no 'fqn'")
        unknown = set(definition) - {"fqn", "description"}
        if unknown:
            raise ValueError(f"rule '{code}': unknown keys {', '.join(sorted(unknown))}")
        if code in definitions and definitions[code]["fqn"] != definition["fqn"]:
            raise ValueError(
                f"rule '{code}' is the registered predicate {definitions[code]['fqn']}, not {definition['fqn']}"
            )
        definitions[code] = {
            "fqn": definition["fqn"],
            "description": definition.get("description") or definitions.get(code, {}).get("description", ""),
        }
    for code, definition in definitions.items():
        error = rule_error(definition["fqn"])
        if error:
            raise ValueError(f"rule '{code}': {error} (a predicate must be defined at a module's top level)")
    return definitions


def _ruleset(value, resolve, where: str) -> str:
    """The canonical expression of a group's ruleset."""
    if isinstance(value, (list, tuple, set)):
        raise ValueError(f"{where}: {value!r} is a list; {MERGED}")
    if isinstance(value, dict):
        raise ValueError(f"{where}: {value!r}: positions are gone, the expression's order is the execution order")
    if not isinstance(value, (str, Ruleset)):
        raise ValueError(f"{where}: {value!r} isn't a ruleset (an expression or a composition of predicates)")
    try:
        return str(canonical(value, resolve))
    except ValueError as e:
        raise ValueError(f"{where}: {e}") from None


def _validate_entry(perm_code: str, item: dict, groups: set[str], resolve) -> dict:
    """The entry as setup writes it: rbac, the rulesets `{group: expression}`, no_detail, staff."""
    if "rules" in item:
        raise ValueError(f"'{perm_code}': 'rules' merged into 'abac': {MERGED}")
    unknown = set(item) - set(SECTIONS)
    if unknown:
        raise ValueError(f"'{perm_code}': unknown keys {', '.join(sorted(unknown))} (allowed: {', '.join(SECTIONS)})")
    rbac = set(item.get("rbac") or ())
    for name in rbac:
        if name not in groups:
            raise ValueError(
                f"'{perm_code}' is granted to '{name}', which isn't one of the groups "
                f"to set up: {', '.join(sorted(groups))}"
            )
    abac = {}
    for group, value in (item.get("abac") or {}).items():
        where = f"'{perm_code}' abac {group}"
        _check_groups([group], groups, where)
        if group not in rbac:
            raise ValueError(f"{where}: '{group}' has a ruleset but rbac doesn't grant it '{perm_code}'")
        abac[group] = _ruleset(value, resolve, where)
    no_detail, staff = list(item.get("no_detail") or ()), list(item.get("staff") or ())
    _check_groups(no_detail, groups, f"'{perm_code}' no_detail")
    _check_groups(staff, groups, f"'{perm_code}' staff")
    return {"rbac": rbac, "abac": abac, "no_detail": no_detail, "staff": staff}


def _write_predicates(definitions: dict[str, dict]) -> None:
    from .models import ActionPermissionRule

    for code, definition in definitions.items():
        ActionPermissionRule.objects.update_or_create(code=code, defaults=definition)


def store_predicates(rules=None) -> int:
    """Store the predicates registered in the installed apps' `rules` modules, and those `rules` defines, without
    touching the entries (what setup does first). A definition whose function doesn't import is a `ValueError`,
    raised before anything is written. The cached entries using a predicate it updates are dropped once it commits.

    Returns the number of predicates written."""
    from .models import ActionPermission

    definitions = _definitions(rules or {})
    with transaction.atomic():
        _write_predicates(definitions)
        invalidate_on_commit(entry_codes(ActionPermission.objects.filter(group_rules__rules__code__in=definitions)))
    return len(definitions)


def setup_rbac_permissions(definitions, group_names, rules=None, keep=False) -> dict:
    """Write the permission definitions and their predicates to the database, in one transaction: each permission
    they list becomes an action permission.

    The predicates registered in the installed apps' `rules` modules, and those `rules` defines, are stored. The
    groups in `group_names` are created if missing and get the permissions the definitions grant them; each entry's
    rulesets, `no_detail` and `staff` replace what the database had for it, the rulesets in their canonical form.
    Unless `keep`, the groups lose any other permission, and the entries the definitions no longer list, and the
    predicates no longer defined and unused, are removed. Definitions that name a group not in `group_names`, gives a
    ruleset to a group its `rbac` doesn't grant, or has a ruleset that doesn't parse or names an unknown predicate,
    or a predicate whose function doesn't import, is a `ValueError`, raised before anything is written. The cached
    entries it may have changed are dropped once the transaction commits.

    Returns the counts written: `{"permissions", "rules", "groups"}`.
    """
    # Imported here, not at module level: an AppConfig module may import this one before the app registry is ready.
    from django.contrib.auth.models import Group, Permission

    from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule

    groups = set(group_names)
    predicate_definitions = _definitions(rules or {})
    known = dict(ActionPermissionRule.objects.values_list("code", "fqn"))
    known.update({code: definition["fqn"] for code, definition in predicate_definitions.items()})
    references = {code: NamedPredicate(code, fqn) for code, fqn in known.items()}
    entries = {}
    for perm_code, item in definitions.items():
        app_label, _, codename = perm_code.partition(".")
        try:
            permission = Permission.objects.get(content_type__app_label=app_label, codename=codename)
        except Permission.DoesNotExist:
            raise ValueError(f"Invalid permission code: '{perm_code}'. Hint: run migration for '{app_label}'") from None
        entries[perm_code] = (permission, _validate_entry(perm_code, item, groups, references.__getitem__))

    with transaction.atomic():
        # the entries setup may change: those it writes, and those already stored (removed, or using a predicate
        # whose definition it updates); their cached copies are dropped once it commits
        touched = set(entries) | entry_codes(ActionPermission.objects.all())
        group_objects = {}
        for name in group_names:
            group_objects[name], _created = Group.objects.get_or_create(name=name)
            if not keep:
                group_objects[name].permissions.clear()
        _write_predicates(predicate_definitions)

        for permission, entry in entries.values():
            for name in entry["rbac"]:
                group_objects[name].permissions.add(permission)
            action_permission, _created = ActionPermission.objects.get_or_create(permission=permission)
            action_permission.no_detail.set([group_objects[name] for name in entry["no_detail"]])
            action_permission.staff.set([group_objects[name] for name in entry["staff"]])
            action_permission.group_rules.all().delete()
            for group, expression in entry["abac"].items():
                ActionPermissionGroup.objects.create(
                    action_permission=action_permission, group=group_objects[group], ruleset=expression
                )
        if not keep:
            listed = [permission for permission, _entry in entries.values()]
            ActionPermission.objects.exclude(permission__in=listed).delete()
            ActionPermissionRule.objects.exclude(code__in=predicate_definitions).filter(usages__isnull=True).delete()
        invalidate_on_commit(touched, strict=True)
    return {"permissions": len(entries), "rules": len(predicate_definitions), "groups": len(group_objects)}
