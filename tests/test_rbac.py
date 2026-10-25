import pytest
from django.contrib.auth.models import Group, Permission

from django_action_permissions import rules as builtin
from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from django_action_permissions.predicates import discover
from django_action_permissions.rbac import setup_rbac_permissions, store_predicates
from tests import rules
from tests.conftest import GROUPS, stored_entries

pytestmark = pytest.mark.django_db

TABLE = {
    "auth.view_user": {"rbac": {"CLERKS", "BOSSES"}},
    "auth.change_user": {"rbac": {"BOSSES"}},
    "auth.delete_user": {"rbac": set()},
}

FULL = {
    "auth.change_user": {
        "rbac": {"BOSSES", "CUSTOMERS"},
        "abac": {"CUSTOMERS": "owner & ~block | is_staff", "BOSSES": rules.yes & (rules.abstain | builtin.is_self)},
        "no_detail": ["CLERKS"],
        "staff": ["BOSSES"],
    },
    "auth.view_user": {"rbac": {"CLERKS"}},
}


def granted(group_name):
    return {f"{p.content_type.app_label}.{p.codename}" for p in Group.objects.get(name=group_name).permissions.all()}


def nothing_written():
    return not (
        Group.objects.exists()
        or ActionPermission.objects.exists()
        or ActionPermissionRule.objects.exists()
        or ActionPermissionGroup.objects.exists()
    )


def stored_codes():
    return set(ActionPermissionRule.objects.values_list("code", flat=True))


# ── rbac: the groups' permissions ────────────────────────────────────────────


def test_each_group_gets_the_permissions_the_table_lists_for_it():
    setup_rbac_permissions(TABLE, ["CLERKS", "BOSSES"])

    assert granted("CLERKS") == {"auth.view_user"}
    assert granted("BOSSES") == {"auth.view_user", "auth.change_user"}


def test_missing_groups_are_created_and_existing_ones_kept():
    existing = Group.objects.create(name="CLERKS")

    setup_rbac_permissions(TABLE, ["CLERKS", "BOSSES"])

    assert Group.objects.get(name="CLERKS").pk == existing.pk
    assert Group.objects.filter(name="BOSSES").exists()


def test_other_permissions_are_removed_unless_kept():
    group = Group.objects.create(name="CLERKS")
    group.permissions.add(Permission.objects.get(content_type__app_label="auth", codename="add_group"))

    setup_rbac_permissions(TABLE, ["CLERKS", "BOSSES"], keep=True)
    assert granted("CLERKS") == {"auth.add_group", "auth.view_user"}

    setup_rbac_permissions(TABLE, ["CLERKS", "BOSSES"])
    assert granted("CLERKS") == {"auth.view_user"}


def test_an_unknown_permission_is_refused_with_a_hint():
    with pytest.raises(ValueError, match=r"Invalid permission code: 'nowhere.view_thing'.*migration for 'nowhere'"):
        setup_rbac_permissions({"nowhere.view_thing": {"rbac": {"CLERKS"}}}, ["CLERKS"])


def test_a_table_granting_to_a_group_not_set_up_is_refused():
    table = {"auth.change_user": {"rbac": {"BOSSES"}}}

    with pytest.raises(
        ValueError, match=r"'auth.change_user' is granted to 'BOSSES', which isn't one of the groups.*CLERKS"
    ):
        setup_rbac_permissions(table, ["CLERKS"])
    assert nothing_written()


# ── the predicates and the rulesets, stored ──────────────────────────────────


def test_setup_stores_the_discovered_predicates(setup):
    counts = setup(TABLE)

    assert stored_codes() == set(discover())
    assert counts == {"permissions": 3, "rules": len(discover()), "groups": len(GROUPS)}
    owner = ActionPermissionRule.objects.get(code="owner")
    assert (owner.fqn, owner.description) == ("tests.rules.owner", "The object's owner is the user.")
    assert ActionPermissionRule.objects.get(code="is_self").fqn == "django_action_permissions.rules.is_self"


def test_setup_stores_the_rulesets_in_their_canonical_form(setup):
    setup(FULL)

    assert stored_entries() == {
        "auth.change_user": {
            "abac": {"CUSTOMERS": "owner & ~block | is_staff", "BOSSES": "yes & (abstain | is_self)"},
            "predicates": {
                "owner": "tests.rules.owner",
                "block": "tests.rules.block",
                "is_staff": "django_action_permissions.rules.is_staff",
                "yes": "tests.rules.yes",
                "abstain": "tests.rules.abstain",
                "is_self": "django_action_permissions.rules.is_self",
            },
            "no_detail": ["CLERKS"],
            "staff": ["BOSSES"],
        },
        "auth.view_user": {"abac": {}, "predicates": {}, "no_detail": [], "staff": []},
    }


def test_a_ruleset_is_stored_canonical_whatever_its_spacing(setup):
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": " ( owner|yes )&no "}}})

    assert ActionPermissionGroup.objects.get().ruleset == "(owner | yes) & no"


def test_the_predicates_a_ruleset_uses_are_linked(setup):
    setup(FULL)

    rows = {row.group.name: {rule.code for rule in row.rules.all()} for row in ActionPermissionGroup.objects.all()}
    assert rows == {"CUSTOMERS": {"owner", "block", "is_staff"}, "BOSSES": {"yes", "abstain", "is_self"}}


def test_a_rerun_replaces_an_entry(setup):
    setup(FULL)
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "yes"}, "staff": ["CLERKS"]}})

    entry = stored_entries()["auth.change_user"]
    assert (entry["abac"], entry["no_detail"], entry["staff"]) == ({"CUSTOMERS": "yes"}, [], ["CLERKS"])


def test_entries_left_out_are_removed_unless_kept(setup):
    setup(FULL)

    setup({"auth.view_user": {"rbac": {"CLERKS"}}}, keep=True)
    assert set(stored_entries()) == {"auth.change_user", "auth.view_user"}

    setup({"auth.view_user": {"rbac": {"CLERKS"}}})
    assert set(stored_entries()) == {"auth.view_user"}


def test_a_definition_no_predicate_registers_any_more_is_removed_unless_kept_or_used(setup):
    setup(TABLE, rules={"legacy": {"fqn": "tests.rules.owner", "description": "an old name"}})
    assert "legacy" in stored_codes()

    setup(TABLE, keep=True)
    assert "legacy" in stored_codes()

    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "legacy"}}}, keep=True)
    setup({"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "legacy"}}})
    assert "legacy" in stored_codes()  # still used

    setup(TABLE)
    assert "legacy" not in stored_codes()


def test_a_given_definition_may_describe_a_registered_predicate(setup):
    setup(TABLE, rules={"owner": {"fqn": "tests.rules.owner", "description": "Said otherwise"}})

    assert ActionPermissionRule.objects.get(code="owner").description == "Said otherwise"


@pytest.mark.parametrize(
    "entry, message",
    [
        ({"rbac": {"CLERKS"}, "acl": {}}, "unknown keys acl"),
        ({"rbac": {"CLERKS"}, "rules": [{"code": "owner", "for": ["CLERKS"]}]}, "'rules' merged into 'abac'"),
        ({"rbac": {"CLERKS"}, "abac": {"NOBODY": "owner"}}, "'NOBODY' isn't one of the groups"),
        ({"rbac": {"CLERKS"}, "abac": {"CUSTOMERS": "owner"}}, "rbac doesn't grant it"),
        ({"rbac": {"CLERKS"}, "abac": {"CLERKS": ["owner", "yes"]}}, "is a list; a group's predicates are one ruleset"),
        ({"rbac": {"CLERKS"}, "abac": {"CLERKS": {"code": "owner", "position": "HIGH"}}}, "positions are gone"),
        ({"rbac": {"CLERKS"}, "abac": {"CLERKS": 42}}, "isn't a ruleset"),
        ({"rbac": {"CLERKS"}, "abac": {"CLERKS": "owner & nobody"}}, "unknown predicate 'nobody' at 8"),
        ({"rbac": {"CLERKS"}, "abac": {"CLERKS": "owner &"}}, "unexpected the end"),
        ({"rbac": {"CLERKS"}, "no_detail": ["NOBODY"]}, "no_detail: 'NOBODY'"),
        ({"rbac": {"CLERKS"}, "staff": ["NOBODY"]}, "staff: 'NOBODY'"),
    ],
)
def test_a_bad_table_is_refused_before_anything_is_written(setup, entry, message):
    with pytest.raises(ValueError, match=message.replace("(", r"\(").replace(")", r"\)")):
        setup({"auth.view_user": {"rbac": {"CLERKS"}}, "auth.change_user": entry})
    assert nothing_written()


@pytest.mark.parametrize(
    "rules, message",
    [
        ({"x": {"fqn": "tests.nowhere.x"}}, "rule 'x'"),
        ({"x": {"fqn": "tests.rules.NOT_CALLABLE"}}, "isn't callable"),
        ({"x": {"description": "no function"}}, "has no 'fqn'"),
        ({"x": {"fqn": "tests.rules.owner", "author": "me"}}, "unknown keys author"),
        ({"owner": {"fqn": "tests.rules.yes"}}, "'owner' is the registered predicate tests.rules.owner"),
    ],
)
def test_bad_definitions_are_refused_before_anything_is_written(setup, rules, message):
    with pytest.raises(ValueError, match=message):
        setup(TABLE, rules=rules)
    assert nothing_written()


def test_a_predicate_defined_where_it_cant_be_imported_is_refused(setup, registry):
    from django_action_permissions.predicates import predicate

    @predicate
    def local(user, obj):
        return True

    with pytest.raises(ValueError, match="rule 'local'.*top level"):
        setup(TABLE)
    assert nothing_written()


def test_storing_the_predicates_leaves_the_entries_alone(setup):
    setup(FULL)
    entries = stored_entries()
    ActionPermissionRule.objects.filter(code="yes").update(fqn="tests.rules.no", description="")
    ActionPermissionRule.objects.filter(code="always").delete()

    assert store_predicates() == len(discover())

    assert ActionPermissionRule.objects.get(code="yes").fqn == "tests.rules.yes"
    assert ActionPermissionRule.objects.filter(code="always").exists()
    assert stored_entries() == entries


def test_storing_a_predicate_that_doesnt_import_writes_nothing(db):
    with pytest.raises(ValueError, match="rule 'gone'"):
        store_predicates({"gone": {"fqn": "tests.rules.gone"}})

    assert not ActionPermissionRule.objects.exists()
