"""The admin: every model editable, and the configuration tools (Load YAML, Export YAML, Check configuration)."""

import pytest
from django.contrib.auth.models import Group, Permission
from django.core.cache import caches
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse

from django_action_permissions import admin as action_admin
from django_action_permissions import entries
from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from django_action_permissions.predicates import discover
from django_action_permissions.yaml_io import dump_yaml
from tests.conftest import stored_entries
from tests.test_yaml_io import DOCUMENT

pytestmark = pytest.mark.django_db

CHANGELIST = "admin:django_action_permissions_actionpermission_changelist"


def url(name, *args):
    return reverse(f"admin:django_action_permissions_{name}", args=args)


def upload(content: str) -> SimpleUploadedFile:
    return SimpleUploadedFile("permissions.yaml", content.encode("utf-8"), content_type="application/yaml")


@pytest.fixture
def loaded(setup):
    setup(
        {
            "auth.change_user": {
                "rbac": {"CUSTOMERS", "BOSSES"},
                "abac": {"CUSTOMERS": "owner"},
                "no_detail": ["CLERKS"],
            },
            "auth.view_user": {"rbac": {"CLERKS"}, "abac": {"CLERKS": "yes & ~no"}},
        }
    )


@pytest.fixture
def staff_user(django_user_model):
    """Staff, not a superuser, with the view permissions of the three models."""
    user = django_user_model.objects.create_user(username="sam", password="pw", is_staff=True)
    user.user_permissions.add(
        *Permission.objects.filter(content_type__app_label="django_action_permissions", codename__startswith="view_")
    )
    return user


@pytest.mark.parametrize("model", ["actionpermission", "actionpermissionrule", "actionpermissiongroup"])
def test_every_model_is_listed_added_and_changed(admin_client, loaded, model):
    obj = {"actionpermission": ActionPermission, "actionpermissionrule": ActionPermissionRule}.get(
        model, ActionPermissionGroup
    ).objects.first()

    assert admin_client.get(url(f"{model}_changelist")).status_code == 200
    assert admin_client.get(url(f"{model}_add")).status_code == 200
    assert admin_client.get(url(f"{model}_change", obj.pk)).status_code == 200


def test_the_entries_list_shows_rbac_rules_and_groups(admin_client, loaded):
    content = admin_client.get(url("actionpermission_changelist")).content.decode()

    assert "auth.change_user" in content and "BOSSES, CUSTOMERS" in content
    assert "Load YAML" in content and "Export YAML" in content and "Check configuration" in content


def test_an_entry_is_edited_on_one_page_rbac_and_rules_included(
    admin_client, loaded, django_capture_on_commit_callbacks, settings
):
    settings.ACTION_PERMISSIONS = {}  # the cached table, dropped by the admin's save
    caches["default"].clear()
    entries.perm_info("auth.view_user")
    entries.perm_info("auth.change_user")
    entry = ActionPermission.objects.get(permission__codename="view_user")
    bosses, clerks = Group.objects.get(name="BOSSES"), Group.objects.get(name="CLERKS")
    row = entry.group_rules.get()

    with django_capture_on_commit_callbacks(execute=True):
        response = admin_client.post(
            url("actionpermission_change", entry.pk),
            {
                "permission": entry.permission_id,
                "rbac": [bosses.pk, clerks.pk],
                "no_detail": [],
                "staff": [bosses.pk],
                "group_rules-TOTAL_FORMS": "2",
                "group_rules-INITIAL_FORMS": "1",
                "group_rules-0-id": row.pk,
                "group_rules-0-action_permission": entry.pk,
                "group_rules-0-group": clerks.pk,
                "group_rules-0-ruleset": "yes",
                "group_rules-1-action_permission": entry.pk,
                "group_rules-1-group": bosses.pk,
                "group_rules-1-ruleset": " owner|is_staff ",
            },
        )

    assert response.status_code == 302, response.content.decode()
    assert set(entry.permission.group_set.values_list("name", flat=True)) == {"BOSSES", "CLERKS"}
    assert caches["default"].get(entries._key("auth.view_user")) is None  # the entry edited is dropped ...
    assert caches["default"].get(entries._key("auth.change_user")) is not None  # ... and only that one
    info = entries.perm_info("auth.view_user")
    assert info["abac"] == {"CLERKS": "yes", "BOSSES": "owner | is_staff"}  # canonical
    assert info["staff"] == ["BOSSES"]
    assert {rule.code for rule in ActionPermissionGroup.objects.get(group=bosses).rules.all()} == {"owner", "is_staff"}
    caches["default"].clear()


def test_a_rule_is_added_with_its_function_checked(admin_client, db):
    response = admin_client.post(
        url("actionpermissionrule_add"), {"code": "x", "fqn": "tests.rules.gone", "description": ""}
    )
    assert response.status_code == 200 and "gone" in response.content.decode()

    response = admin_client.post(
        url("actionpermissionrule_add"), {"code": "x", "fqn": "tests.rules.owner", "description": "d"}
    )
    assert response.status_code == 302 and ActionPermissionRule.objects.filter(code="x").exists()


def test_a_ruleset_naming_an_unknown_predicate_is_refused(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")
    row = entry.group_rules.get()

    response = admin_client.post(
        url("actionpermission_change", entry.pk),
        {
            "permission": entry.permission_id,
            "rbac": [Group.objects.get(name="CLERKS").pk],
            "no_detail": [],
            "staff": [],
            "group_rules-TOTAL_FORMS": "1",
            "group_rules-INITIAL_FORMS": "1",
            "group_rules-0-id": row.pk,
            "group_rules-0-action_permission": entry.pk,
            "group_rules-0-group": row.group_id,
            "group_rules-0-ruleset": "yes & nobody",
        },
    )

    content = response.content.decode()
    assert response.status_code == 200 and "unknown predicate &#x27;nobody&#x27; at 6" in content
    assert "the predicates: abstain, always" in content
    assert ActionPermissionGroup.objects.get(pk=row.pk).ruleset == "yes & ~no"


def test_the_rules_list_counts_their_uses(admin_client, loaded):
    content = admin_client.get(url("actionpermissionrule_changelist")).content.decode()

    assert "owner" in content and "The object&#x27;s owner is the user." in content
    rows = admin_client.get(url("actionpermissiongroup_changelist")).content.decode()
    assert "yes &amp; ~no" in rows and "no, yes" in rows


def test_a_rule_in_use_isnt_deleted(admin_client, loaded):
    owner = ActionPermissionRule.objects.get(code="owner")

    response = admin_client.post(url("actionpermissionrule_delete", owner.pk), {"post": "yes"})

    assert "protected" in response.content.decode().lower()
    assert ActionPermissionRule.objects.filter(code="owner").exists()


# ── Load YAML ────────────────────────────────────────────────────────────────


def test_loading_a_document_sets_it_up(admin_client, db):
    assert admin_client.get(url("actionpermission_load")).status_code == 200

    response = admin_client.post(url("actionpermission_load"), {"file": upload(DOCUMENT)}, follow=True)

    assert response.redirect_chain[-1][0] == reverse(CHANGELIST)
    assert f"2 permissions, {len(discover())} rules, 3 groups set up." in response.content.decode()
    assert set(stored_entries()) == {"auth.change_user", "auth.view_user"}


def test_a_bad_document_is_shown_and_nothing_is_written(admin_client, db):
    response = admin_client.post(url("actionpermission_load"), {"file": upload("permissions: []")})

    assert response.status_code == 200
    assert "permissions: expected a dict" in response.content.decode()
    assert not ActionPermission.objects.exists() and not Group.objects.exists()


def test_a_file_that_isnt_text_is_refused(admin_client, db):
    file = SimpleUploadedFile("permissions.yaml", b"\xff\xfe\x00", content_type="application/yaml")

    response = admin_client.post(url("actionpermission_load"), {"file": file})

    assert response.status_code == 200 and not ActionPermission.objects.exists()


def test_only_superusers_load(client, staff_user):
    client.force_login(staff_user)

    assert client.get(url("actionpermission_load")).status_code == 403
    assert "Load YAML" not in client.get(url("actionpermission_changelist")).content.decode()


# ── Export YAML ──────────────────────────────────────────────────────────────


def test_the_export_downloads_the_stored_table(client, staff_user, loaded):
    client.force_login(staff_user)

    response = client.get(url("actionpermission_export"))

    assert response["Content-Disposition"] == 'attachment; filename="action_permissions.yaml"'
    assert response.content.decode() == dump_yaml()


def test_exporting_the_selected_entries(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")

    response = admin_client.post(
        url("actionpermission_changelist"), {"action": "export_selected", "_selected_action": [entry.pk]}
    )

    assert response.content.decode() == dump_yaml(queryset=ActionPermission.objects.filter(pk=entry.pk))
    assert "auth.change_user" not in response.content.decode()


def test_exporting_needs_the_view_permissions(client, django_user_model, loaded):
    user = django_user_model.objects.create_user(username="vic", is_staff=True)
    user.user_permissions.add(Permission.objects.get(codename="view_actionpermission"))
    client.force_login(user)

    assert client.get(url("actionpermission_export")).status_code == 403
    entry = ActionPermission.objects.first()
    response = client.post(
        url("actionpermission_changelist"), {"action": "export_selected", "_selected_action": [entry.pk]}
    )
    assert "Content-Disposition" not in response  # the action isn't offered: no export
    assert "export_selected" not in client.get(url("actionpermission_changelist")).content.decode()


# ── Check configuration ──────────────────────────────────────────────────────


def test_the_check_page_lists_the_issues(admin_client, loaded):
    ActionPermissionGroup.objects.create(
        action_permission=ActionPermission.objects.get(permission__codename="view_user"),
        group=Group.objects.get(name="CUSTOMERS"),
        ruleset="owner",
    )

    content = admin_client.get(url("actionpermission_check")).content.decode()

    assert "django_action_permissions.E006" in content
    assert "CUSTOMERS has the ruleset &#x27;owner&#x27; but doesn&#x27;t hold the permission" in content


def test_the_check_page_says_when_all_is_consistent(admin_client, setup):
    setup({"auth.view_user": {"rbac": {"CLERKS"}}}, rules={})

    assert "No issues" in admin_client.get(url("actionpermission_check")).content.decode()


def test_checking_needs_the_view_permission(client, django_user_model):
    client.force_login(django_user_model.objects.create_user(username="vic", is_staff=True))

    assert client.get(url("actionpermission_check")).status_code == 403


# ── without PyYAML ───────────────────────────────────────────────────────────


def test_without_pyyaml_loading_and_exporting_are_off(admin_client, loaded, monkeypatch):
    monkeypatch.setattr(action_admin, "yaml_available", lambda: False)

    content = admin_client.get(url("actionpermission_changelist")).content.decode()
    assert "Load YAML" not in content and "Export YAML" not in content and "export_selected" not in content
    for view in ("actionpermission_load", "actionpermission_export"):
        response = admin_client.get(url(view), follow=True)
        assert "PyYAML isn" in response.content.decode()
