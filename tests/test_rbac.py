import pytest
from django.contrib.auth.models import Group, Permission

from django_action_permissions.rbac import setup_rbac_permissions

pytestmark = pytest.mark.django_db

TABLE = {
    "auth.view_user": {"rbac": {"CLERKS", "BOSSES"}},
    "auth.change_user": {"rbac": {"BOSSES"}},
    "auth.delete_user": {"rbac": set()},
}


def granted(group_name):
    return {f"{p.content_type.app_label}.{p.codename}" for p in Group.objects.get(name=group_name).permissions.all()}


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
