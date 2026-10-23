import pytest
from django.contrib.auth.models import Group
from django.core.exceptions import ValidationError
from django.db.models import ProtectedError

from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from tests.conftest import stored_entries

pytestmark = pytest.mark.django_db

TABLE = {
    "auth.change_user": {
        "rbac": {"CUSTOMERS", "BOSSES"},
        "abac": {"CUSTOMERS": "owner | is_staff", "BOSSES": "owner & yes"},
        "no_detail": ["CLERKS"],
    }
}


@pytest.mark.parametrize("fqn, message", [("tests.rules.gone", "gone"), ("tests.rules.NOT_CALLABLE", "isn't callable")])
def test_a_rule_whose_function_cant_be_used_isnt_valid(fqn, message):
    with pytest.raises(ValidationError, match=message):
        ActionPermissionRule(code="x", fqn=fqn).full_clean()
    ActionPermissionRule(code="x", fqn="tests.rules.owner").full_clean()


def test_a_predicate_in_use_cant_be_deleted(setup):
    setup(TABLE)

    with pytest.raises(ProtectedError):
        ActionPermissionRule.objects.get(code="owner").delete()
    ActionPermissionRule.objects.get(code="never").delete()


def test_the_same_predicate_serves_several_groups(setup):
    setup(TABLE)

    rows = ActionPermissionRule.objects.get(code="owner").usages.order_by("group__name")
    assert [row.group.name for row in rows] == ["BOSSES", "CUSTOMERS"]


def test_a_ruleset_is_checked_and_made_canonical(setup):
    setup(TABLE)
    row = ActionPermissionGroup.objects.get(group__name="CUSTOMERS")

    row.ruleset = "( yes|no )& owner"
    row.full_clean()
    assert row.ruleset == "(yes | no) & owner"

    row.ruleset = "yes & nobody"
    with pytest.raises(ValidationError, match="unknown predicate 'nobody'.*the predicates: "):
        row.full_clean()


def test_saving_links_the_predicates_the_ruleset_uses(setup):
    setup(TABLE)
    row = ActionPermissionGroup.objects.get(group__name="CUSTOMERS")

    row.ruleset = "yes & ~no"
    row.save()
    assert {rule.code for rule in row.rules.all()} == {"yes", "no"}

    row.ruleset = "yes &"  # saved as it is (the checks report it), linked to nothing
    row.save()
    assert not row.rules.exists()


def test_deleting_a_group_removes_it_from_the_table(setup):
    setup(TABLE)

    Group.objects.filter(name__in=["CLERKS", "CUSTOMERS"]).delete()

    entry = stored_entries()["auth.change_user"]
    assert (entry["no_detail"], entry["abac"]) == ([], {"BOSSES": "owner & yes"})


def test_the_models_read_as_the_table_does(setup):
    setup(TABLE)

    entry = ActionPermission.objects.get()
    row = ActionPermissionGroup.objects.get(group__name="CUSTOMERS")
    assert (str(entry), entry.perm_code) == ("auth.change_user", "auth.change_user")
    assert str(row) == "auth.change_user CUSTOMERS: owner | is_staff"
    assert str(ActionPermissionRule.objects.get(code="owner")) == "owner"
