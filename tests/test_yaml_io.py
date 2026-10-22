"""The YAML document: loaded by setup, exported from the database, and the two management commands."""

import sys
from io import StringIO
from textwrap import dedent

import pytest
import yaml
from django.contrib.auth.models import Group, Permission
from django.core.management import CommandError, call_command

from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from django_action_permissions.predicates import discover
from django_action_permissions.table import read_table
from django_action_permissions.yaml_io import (
    YAMLNotInstalled,
    dump_yaml,
    export_document,
    load_yaml,
    parse_document,
    yaml_available,
)

pytestmark = pytest.mark.django_db

DOCUMENT = dedent(
    """\
    groups: [BOSSES, CLERKS, CUSTOMERS]
    rules:
      owner: {fqn: tests.rules.owner, description: The object is the user's}
    permissions:
      auth.change_user:
        rbac: [BOSSES, CUSTOMERS]
        abac: {CUSTOMERS: owner & ~no | is_staff, BOSSES: ( yes|abstain )}
        no_detail: [CLERKS]
        staff: [BOSSES]
      auth.view_user:
        rbac: [CLERKS]
    """
)
PREDICATES = len(discover())


def clear_database():
    ActionPermissionGroup.objects.all().delete()
    ActionPermission.objects.all().delete()
    ActionPermissionRule.objects.all().delete()
    Group.objects.all().delete()


def test_a_document_is_set_up_as_setup_would():
    counts = load_yaml(DOCUMENT)

    assert counts == {"permissions": 2, "rules": PREDICATES, "groups": 3}
    entry = read_table()["auth.change_user"]
    assert entry["abac"] == {"CUSTOMERS": "owner & ~no | is_staff", "BOSSES": "yes | abstain"}
    assert (entry["no_detail"], entry["staff"]) == (["CLERKS"], ["BOSSES"])
    assert ActionPermissionRule.objects.get(code="owner").description == "The object is the user's"
    assert set(Group.objects.get(name="CLERKS").permissions.values_list("codename", flat=True)) == {"view_user"}


def test_the_rules_section_is_optional():
    rules_section = "rules:\n  owner: {fqn: tests.rules.owner, description: The object is the user's}\n"
    load_yaml(DOCUMENT.replace(rules_section, ""))

    assert ActionPermissionRule.objects.get(code="owner").description == "The object's owner is the user."


def test_keep_is_passed_to_setup():
    clerks = Group.objects.create(name="CLERKS")
    clerks.permissions.add(Permission.objects.get(content_type__app_label="auth", codename="add_group"))

    load_yaml(DOCUMENT, keep=True)
    assert clerks.permissions.filter(codename="add_group").exists()

    load_yaml(DOCUMENT)
    assert not clerks.permissions.filter(codename="add_group").exists()


def test_an_empty_document_stores_the_predicates_only():
    assert load_yaml("") == {"permissions": 0, "rules": PREDICATES, "groups": 0}


@pytest.mark.parametrize(
    "document, message",
    [
        ("[1, 2]", "document: expected a dict, got list"),
        ("acl: {}", "document: unknown keys acl"),
        ("groups: CLERKS", "groups: expected a list, got str"),
        ("groups: [1]", r"groups\[0\]: expected a str"),
        ("rules: {owner: tests.rules.owner}", "rules.owner: expected a dict"),
        ("permissions: []", "permissions: expected a dict"),
        ("permissions: {auth.view_user: [CLERKS]}", "permissions.auth.view_user: expected a dict"),
        ("permissions: {auth.view_user: {acl: []}}", "permissions.auth.view_user: unknown keys acl"),
        ("permissions: {auth.view_user: {rbac: CLERKS}}", "permissions.auth.view_user.rbac: expected a list"),
        ("permissions: {auth.view_user: {abac: [owner]}}", "permissions.auth.view_user.abac: expected a dict"),
        ("permissions: {auth.view_user: {abac: {CLERKS: [owner]}}}", "abac.CLERKS: a list; a group's predicates"),
        ("permissions: {auth.view_user: {abac: {CLERKS: {code: owner}}}}", "abac.CLERKS: positions are gone"),
        ("permissions: {auth.view_user: {abac: {CLERKS: 1}}}", "abac.CLERKS: expected a str, got int"),
        ("permissions: {auth.view_user: {rules: []}}", "permissions.auth.view_user: 'rules' merged into 'abac'"),
        ("permissions: {auth.view_user: {staff: X}}", "permissions.auth.view_user.staff: expected a list"),
        ("groups: [", "not a YAML document"),
    ],
)
def test_a_document_of_the_wrong_shape_names_where(document, message):
    with pytest.raises(ValueError, match=message):
        load_yaml(document)
    assert not Group.objects.exists()


def test_setups_errors_surface_and_nothing_is_written():
    with pytest.raises(ValueError, match="unknown predicate 'nobody_knows'"):
        load_yaml(DOCUMENT.replace("owner & ~no", "nobody_knows & ~no"))
    assert not Group.objects.exists() and not ActionPermissionRule.objects.exists()


def test_an_entry_may_be_empty():
    table, groups, rules = parse_document({"permissions": {"auth.view_user": None}})

    assert (table, groups, rules) == ({"auth.view_user": {"rbac": set()}}, [], {})


# ── export ───────────────────────────────────────────────────────────────────


def test_the_export_writes_the_canonical_rulesets_and_the_predicates_they_use():
    load_yaml(DOCUMENT)

    document = export_document()

    assert document["permissions"]["auth.change_user"] == {
        "rbac": ["BOSSES", "CUSTOMERS"],
        "abac": {"BOSSES": "yes | abstain", "CUSTOMERS": "owner & ~no | is_staff"},
        "no_detail": ["CLERKS"],
        "staff": ["BOSSES"],
    }
    assert document["permissions"]["auth.view_user"] == {"rbac": ["CLERKS"]}
    assert set(document["rules"]) == {"owner", "no", "is_staff", "yes", "abstain"}
    assert document["rules"]["owner"] == {"fqn": "tests.rules.owner", "description": "The object is the user's"}
    assert document["rules"]["yes"] == {"fqn": "tests.rules.yes"}


def test_the_export_leaves_out_the_groups_the_table_doesnt_touch():
    load_yaml(DOCUMENT)
    Group.objects.create(name="EDITORS")

    assert export_document()["groups"] == ["BOSSES", "CLERKS", "CUSTOMERS"]


def test_the_export_is_sorted_and_stable():
    load_yaml(DOCUMENT)

    exported = dump_yaml()

    assert exported == dump_yaml()
    assert list(yaml.safe_load(exported)) == ["groups", "permissions", "rules"]
    assert list(yaml.safe_load(exported)["permissions"]) == ["auth.change_user", "auth.view_user"]


def test_load_export_load_export_gives_the_same_document():
    load_yaml(DOCUMENT)
    exported = dump_yaml()
    clear_database()

    load_yaml(exported)

    assert dump_yaml() == exported


def test_exporting_a_selection_takes_the_rules_and_groups_it_uses():
    load_yaml(DOCUMENT)

    document = export_document(ActionPermission.objects.filter(permission__codename="view_user"))

    assert document == {"groups": ["CLERKS"], "rules": {}, "permissions": {"auth.view_user": {"rbac": ["CLERKS"]}}}


def test_the_export_writes_to_a_stream():
    load_yaml(DOCUMENT)
    stream = StringIO()

    assert dump_yaml(stream) is None
    assert stream.getvalue() == dump_yaml()


# ── the commands ─────────────────────────────────────────────────────────────


def test_the_load_command_sets_up_a_file(tmp_path):
    path = tmp_path / "permissions.yaml"
    path.write_text(DOCUMENT, encoding="utf-8")
    out = StringIO()

    call_command("django_action_permissions_load", str(path), stdout=out)
    assert out.getvalue().strip() == f"2 permissions, {PREDICATES} rules, 3 groups set up"
    assert set(read_table()) == {"auth.change_user", "auth.view_user"}

    call_command("django_action_permissions_load", str(path), "--keep", stdout=out)
    assert "(keep)" in out.getvalue()


@pytest.mark.parametrize("content, message", [(None, "No such file"), ("groups: [", "not a YAML document")])
def test_the_load_command_reports_errors(tmp_path, content, message):
    path = tmp_path / "permissions.yaml"
    if content is not None:
        path.write_text(content, encoding="utf-8")

    with pytest.raises(CommandError, match=message):
        call_command("django_action_permissions_load", str(path))


def test_the_export_command_writes_a_file_or_the_standard_output(tmp_path):
    load_yaml(DOCUMENT)
    path = tmp_path / "out.yaml"
    out = StringIO()

    call_command("django_action_permissions_export", "-o", str(path))
    call_command("django_action_permissions_export", stdout=out)

    assert path.read_text(encoding="utf-8") == out.getvalue() == dump_yaml()


def test_without_pyyaml_the_commands_name_the_extra(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "yaml", None)  # `import yaml` then raises ImportError
    path = tmp_path / "permissions.yaml"
    path.write_text(DOCUMENT, encoding="utf-8")

    assert not yaml_available()
    with pytest.raises(YAMLNotInstalled):
        dump_yaml()
    with pytest.raises(CommandError, match=r"django-action-permissions\[yaml\]"):
        call_command("django_action_permissions_load", str(path))
    with pytest.raises(CommandError, match=r"django-action-permissions\[yaml\]"):
        call_command("django_action_permissions_export")
