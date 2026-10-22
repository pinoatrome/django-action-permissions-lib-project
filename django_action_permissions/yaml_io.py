"""The permissions table and its predicates as one YAML document, loaded by setup and exported from the database:

    groups: [CLERKS, CUSTOMERS]
    rules:  # optional: the registered predicates (@predicate) are stored anyway
      own_order: {fqn: shop.rules.own_order, description: The order is the user's}
    permissions:
      shop.view_order:
        rbac: [CLERKS, CUSTOMERS]
        abac: {CUSTOMERS: own_order & ~is_blocked}
        no_detail: [CLERKS]
        staff: []

Needs PyYAML (the `yaml` extra: `pip install django-action-permissions[yaml]`).
"""

from .rbac import MERGED, SECTIONS, setup_rbac_permissions


class YAMLNotInstalled(ImportError):
    def __init__(self):
        super().__init__("PyYAML isn't installed: pip install 'django-action-permissions[yaml]'")


def _yaml():
    try:
        import yaml
    except ImportError:
        raise YAMLNotInstalled() from None
    return yaml


def yaml_available() -> bool:
    try:
        _yaml()
    except YAMLNotInstalled:
        return False
    return True


def _expect(value, kind, path: str):
    if not isinstance(value, kind):
        names = " or ".join(k.__name__ for k in kind) if isinstance(kind, tuple) else kind.__name__
        raise ValueError(f"{path}: expected a {names}, got {type(value).__name__}")
    return value


def _get(mapping: dict, key: str, default):
    """`mapping[key]`, or `default` when it's missing or null (an empty value of the wrong type is still wrong)."""
    value = mapping.get(key)
    return default if value is None else value


def _strings(value, path: str) -> list[str]:
    for i, item in enumerate(_expect(value, list, path)):
        _expect(item, str, f"{path}[{i}]")
    return value


def parse_document(document) -> tuple[dict, list[str], dict]:
    """(table, group names, rules) of a parsed YAML document, as `setup_rbac_permissions` takes them. A document of
    the wrong shape is a `ValueError` naming where (e.g. `permissions.shop.view_order.abac`)."""
    document = _expect(document if document is not None else {}, dict, "document")
    unknown = set(document) - {"groups", "rules", "permissions"}
    if unknown:
        raise ValueError(f"document: unknown keys {', '.join(sorted(unknown))} (allowed: groups, rules, permissions)")
    groups = _strings(_get(document, "groups", []), "groups")
    rules = {}
    for code, definition in _expect(_get(document, "rules", {}), dict, "rules").items():
        rules[code] = _expect(definition, dict, f"rules.{code}")
    table = {}
    for perm_code, entry in _expect(_get(document, "permissions", {}), dict, "permissions").items():
        path = f"permissions.{perm_code}"
        entry = dict(_expect(entry if entry is not None else {}, dict, path))
        if "rules" in entry:
            raise ValueError(f"{path}: 'rules' merged into 'abac': {MERGED}")
        unknown = set(entry) - set(SECTIONS)
        if unknown:
            raise ValueError(f"{path}: unknown keys {', '.join(sorted(unknown))} (allowed: {', '.join(SECTIONS)})")
        entry["rbac"] = set(_strings(_get(entry, "rbac", []), f"{path}.rbac"))
        for group, ruleset in _expect(_get(entry, "abac", {}), dict, f"{path}.abac").items():
            if isinstance(ruleset, list):
                raise ValueError(f"{path}.abac.{group}: a list; {MERGED}")
            if isinstance(ruleset, dict):
                raise ValueError(
                    f"{path}.abac.{group}: positions are gone, the expression's order is the execution order"
                )
            _expect(ruleset, str, f"{path}.abac.{group}")
        for section in ("no_detail", "staff"):
            _strings(_get(entry, section, []), f"{path}.{section}")
        table[perm_code] = entry
    return table, groups, rules


def load_yaml(stream, keep: bool = False) -> dict:
    """Set up the table and the rules of the YAML document in `stream` (a string or a file); see
    `setup_rbac_permissions`, whose counts it returns. A YAML error or a document of the wrong shape is a
    `ValueError`, and nothing is written."""
    yaml = _yaml()
    try:
        document = yaml.safe_load(stream)
    except yaml.YAMLError as e:
        raise ValueError(f"not a YAML document: {e}") from None
    table, groups, rules = parse_document(document)
    return setup_rbac_permissions(table, groups, rules=rules, keep=keep)


def export_document(queryset=None) -> dict:
    """The stored table as a document: the entries of `queryset` (all when None), their rulesets in the canonical
    form, the definitions of the predicates they use, and the groups they name. Groups the table doesn't touch are
    left out."""
    from .models import ActionPermission, ActionPermissionRule
    from .predicates import codes_of

    entries = (queryset if queryset is not None else ActionPermission.objects.all()).select_related(
        "permission__content_type"
    )
    entries = entries.prefetch_related("permission__group_set", "no_detail", "staff", "group_rules__group")
    permissions, groups, used = {}, set(), set()
    for entry in entries:
        item = {"rbac": sorted(group.name for group in entry.permission.group_set.all())}
        abac = {row.group.name: row.ruleset for row in entry.group_rules.all()}
        for ruleset in abac.values():
            used.update(codes_of(ruleset))
        if abac:
            item["abac"] = abac
        for section in ("no_detail", "staff"):
            names = sorted(group.name for group in getattr(entry, section).all())
            if names:
                item[section] = names
        groups.update(item["rbac"], abac, item.get("no_detail", ()), item.get("staff", ()))
        permissions[entry.perm_code] = item
    rules = {}
    for rule in ActionPermissionRule.objects.filter(code__in=used):
        rules[rule.code] = {"fqn": rule.fqn, **({"description": rule.description} if rule.description else {})}
    return {"groups": sorted(groups), "rules": rules, "permissions": permissions}


def dump_yaml(stream=None, queryset=None) -> str | None:
    """The stored table as YAML (see `export_document`): written to `stream`, or returned when None. Keys are
    sorted and the rulesets canonical, so two exports of the same table are identical."""
    yaml = _yaml()
    return yaml.safe_dump(
        export_document(queryset), stream, sort_keys=True, allow_unicode=True, default_flow_style=False
    )
