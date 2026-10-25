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


def test_the_check_page_links_the_objects(admin_client, loaded):
    row = ActionPermissionGroup.objects.create(
        action_permission=ActionPermission.objects.get(permission__codename="view_user"),
        group=Group.objects.get(name="CUSTOMERS"),
        ruleset="owner",
    )

    content = admin_client.get(url("actionpermission_check")).content.decode()

    assert f'href="{url("actionpermissiongroup_change", row.pk)}"' in content


# ── the ruleset editor ───────────────────────────────────────────────────────


def test_the_ruleset_inputs_are_checked_as_typed(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")

    content = admin_client.get(url("actionpermission_change", entry.pk)).content.decode()

    assert "django_action_permissions/ruleset.js" in content
    assert f'data-validate-url="{url("actionpermission_validate")}"' in content
    assert f'data-verify-url="{url("actionpermission_verify")}"' in content  # a superuser
    assert 'data-perm="auth.view_user"' in content and "&quot;code&quot;: &quot;owner&quot;" in content
    for operation in ("and", "or", "not", "group", "predicates"):  # the toolbar, shown by ruleset.js
        assert f'<button type="button" data-op="{operation}"' in content
    assert '<span class="dap-tools" role="toolbar" aria-label="Ruleset operators" hidden>' in content
    assert SETUP_NOTE_START in content


SETUP_NOTE_START = "A setup, or a Load YAML without keep, replaces"


def test_verify_isnt_offered_to_who_may_not_use_it(client, staff_user, loaded):
    staff_user.user_permissions.add(*Permission.objects.filter(codename="change_actionpermissiongroup"))
    client.force_login(staff_user)
    row = ActionPermissionGroup.objects.first()

    content = client.get(url("actionpermissiongroup_change", row.pk)).content.decode()

    assert 'data-verify-url=""' in content
    assert "Verify" not in client.get(url("actionpermission_changelist")).content.decode()


@pytest.mark.parametrize(
    "expression, expected",
    [
        (" owner|yes ", {"valid": True, "canonical": "owner | yes", "codes": ["owner", "yes"], "position": None}),
        ("owner &", {"valid": False, "position": 7, "unknown": []}),
        ("nobody | yes & ghost", {"valid": False, "position": 0, "unknown": ["ghost", "nobody"]}),
        ("", {"valid": False, "error": "an empty ruleset"}),
    ],
)
def test_the_validate_endpoint(admin_client, loaded, expression, expected):
    response = admin_client.get(url("actionpermission_validate"), {"expression": expression})

    assert response.status_code == 200
    assert expected.items() <= response.json().items()


def test_validating_needs_the_rulesets_view_permission(client, django_user_model, staff_user, loaded):
    assert client.get(url("actionpermission_validate")).status_code == 302  # signed out: the login page
    client.force_login(django_user_model.objects.create_user(username="vic", is_staff=True))
    assert client.get(url("actionpermission_validate")).status_code == 403
    client.force_login(staff_user)
    assert client.get(url("actionpermission_validate"), {"expression": "yes"}).json()["valid"]
    assert client.post(url("actionpermission_validate")).status_code == 405


def test_a_ruleset_for_a_group_not_in_rbac_is_refused(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")
    row = entry.group_rules.get()
    data = {
        "permission": entry.permission_id,
        "rbac": [],  # CLERKS taken out, its ruleset kept
        "no_detail": [],
        "staff": [],
        "group_rules-TOTAL_FORMS": "1",
        "group_rules-INITIAL_FORMS": "1",
        "group_rules-0-id": row.pk,
        "group_rules-0-action_permission": entry.pk,
        "group_rules-0-group": row.group_id,
        "group_rules-0-ruleset": "yes",
    }

    response = admin_client.post(url("actionpermission_change", entry.pk), data)

    assert response.status_code == 200
    assert "CLERKS has a ruleset but isn&#x27;t granted the permission" in response.content.decode()
    assert entry.permission.group_set.filter(name="CLERKS").exists()

    response = admin_client.post(url("actionpermission_change", entry.pk), {**data, "group_rules-0-DELETE": "on"})
    assert response.status_code == 302 and not entry.group_rules.exists()


def test_a_ruleset_on_its_own_page_is_for_a_group_holding_the_permission(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")
    customers = Group.objects.get(name="CUSTOMERS")

    response = admin_client.post(
        url("actionpermissiongroup_add"), {"action_permission": entry.pk, "group": customers.pk, "ruleset": "yes"}
    )

    assert response.status_code == 200
    assert "CUSTOMERS isn&#x27;t granted auth.view_user" in response.content.decode()


# ── the predicates ───────────────────────────────────────────────────────────


def test_the_predicates_status_in_the_code(admin_client, loaded):
    ActionPermissionRule.objects.create(code="old", fqn="tests.rules.owner")
    ActionPermissionRule.objects.create(code="gone", fqn="tests.rules.gone")
    ActionPermissionRule.objects.filter(code="yes").update(fqn="tests.rules.no")

    content = admin_client.get(url("actionpermissionrule_changelist")).content.decode()

    assert "stored only: no @predicate defines it" in content
    assert "doesn't import" in content
    assert "registered as tests.rules.yes" in content
    assert '<span class="dap-good">registered</span>' in content


def test_a_predicate_shows_the_rulesets_using_it(admin_client, loaded):
    owner = ActionPermissionRule.objects.get(code="owner")
    row = ActionPermissionGroup.objects.get(ruleset="owner")

    content = admin_client.get(url("actionpermissionrule_change", owner.pk)).content.decode()

    assert f'href="{url("actionpermissiongroup_change", row.pk)}"' in content
    assert "auth.change_user CUSTOMERS" in content
    assert admin_client.get(url("actionpermissionrule_add")).status_code == 200


def test_syncing_the_predicates(admin_client, loaded):
    ActionPermissionRule.objects.filter(code="always").delete()
    ActionPermissionRule.objects.filter(code="never").update(description="")

    content = admin_client.get(url("actionpermissionrule_sync")).content.decode()
    assert "Store 2 new or changed predicates" in content

    response = admin_client.post(url("actionpermissionrule_sync"), follow=True)

    assert f"{len(discover())} registered predicates stored." in response.content.decode()
    assert ActionPermissionRule.objects.filter(code="always").exists()
    assert "Sync predicates" in admin_client.get(url("actionpermissionrule_changelist")).content.decode()


def test_syncing_a_predicate_that_doesnt_import_is_reported(admin_client, loaded, monkeypatch):
    def store_predicates():
        raise ValueError("rule 'x': no")

    monkeypatch.setattr(action_admin, "store_predicates", store_predicates)

    response = admin_client.post(url("actionpermissionrule_sync"), follow=True)

    assert "Rule &#x27;x&#x27;: no" in response.content.decode()
    assert ActionPermissionRule.objects.count() == len(discover())


def test_syncing_needs_the_add_and_change_permissions(client, staff_user, loaded):
    client.force_login(staff_user)

    assert client.get(url("actionpermissionrule_sync")).status_code == 403
    assert "Sync predicates" not in client.get(url("actionpermissionrule_changelist")).content.decode()


# ── the overview ─────────────────────────────────────────────────────────────


def test_the_overview_shows_the_entries_against_the_groups(client, staff_user, loaded):
    client.force_login(staff_user)

    content = client.get(url("actionpermission_overview")).content.decode()

    assert "auth.change_user" in content and "auth.view_user" in content
    for group in ("BOSSES", "CLERKS", "CUSTOMERS"):
        assert f">{group}</a></th>" in content
    assert "<code>owner</code>" in content and "<code>yes &amp; ~no</code>" in content
    assert "any object" in content and "no detail" in content
    assert "+ ruleset" not in content and "verify</a>" not in content  # neither may add rulesets nor verify


def test_the_overview_is_filtered(admin_client, loaded):
    def get(**params):
        return admin_client.get(url("actionpermission_overview"), params).content.decode()

    assert "auth.change_user" not in get(predicate="yes")
    assert "auth.view_user" not in get(q="change")
    content = get(group="CUSTOMERS")
    assert "auth.view_user" not in content and ">BOSSES</a></th>" not in content
    assert '<a href="?app=auth&amp;group=BOSSES" title="Only BOSSES">' in get(app="auth")
    assert "No action permission matches." in get(app="django_action_permissions")
    content = get(app="auth")
    assert "Not yet action permissions in auth" in content and "auth.delete_user" in content
    add = Permission.objects.get(content_type__app_label="auth", codename="delete_user").pk
    assert f"{url('actionpermission_add')}?permission={add}" in content
    bosses = Group.objects.get(name="BOSSES")
    entry = ActionPermission.objects.get(permission__codename="change_user")
    assert f"{url('actionpermissiongroup_add')}?action_permission={entry.pk}&amp;group={bosses.pk}" in content


def test_the_overview_needs_the_view_permission(client, django_user_model):
    client.force_login(django_user_model.objects.create_user(username="vic", is_staff=True))

    assert client.get(url("actionpermission_overview")).status_code == 403


# ── verify ───────────────────────────────────────────────────────────────────


def verify(client, **params):
    response = client.get(url("actionpermission_verify"), params)
    assert response.status_code == 200
    return response.content.decode()


def test_verify_lists_what_a_user_holds(admin_client, loaded, member):
    member("CUSTOMERS", "CLERKS")

    content = verify(admin_client, user="ann")

    assert "The action permissions ann holds" in content
    assert "<code>auth.change_user</code>" in content and "the objects a ruleset allows" in content
    assert "<code>auth.view_user</code>" in content
    assert "?user=ann&amp;perm=auth.view_user" in content
    assert "<code>auth.view_user</code>" in verify(admin_client, user="admin")  # a superuser: every one
    member(username="nat")
    assert "<p>None.</p>" in verify(admin_client, user="nat")


def test_verify_explains_a_check_on_an_object(admin_client, loaded, member, django_user_model):
    member("CUSTOMERS")
    bob = django_user_model.objects.create_user(username="bob")

    content = verify(admin_client, user="ann", perm="auth.change_user", obj=bob.pk)

    assert "<strong>Refused</strong>" in content and f"on {bob}" in content
    assert "A view answers\n            404" in content
    assert '<span class="dap-chip false">false</span>' in content and "<code>owner</code>" in content
    assert "denies when no group" in content


def test_verify_tries_a_draft(admin_client, loaded, member, django_user_model):
    member("CUSTOMERS")
    bob = django_user_model.objects.create_user(username="bob")

    content = verify(
        admin_client, user="ann", perm="auth.change_user", obj=bob.pk, draft_group="CUSTOMERS", draft_ruleset="yes"
    )

    assert "<strong>Allowed</strong>" in content and "with the draft for CUSTOMERS" in content
    assert '<span class="dap-badge">draft</span>' in content
    assert ActionPermissionGroup.objects.get(group__name="CUSTOMERS").ruleset == "owner"


@pytest.mark.parametrize(
    "params, error",
    [
        ({"user": "nobody"}, "No user &#x27;nobody&#x27;."),
        ({"user": "ann", "obj": "1"}, "An object or a draft needs a permission."),
        ({"user": "ann", "perm": "auth.nothing", "obj": "1"}, "No permission &#x27;auth.nothing&#x27;"),
        ({"user": "ann", "perm": "auth.change_user", "obj": "999"}, "No user &#x27;999&#x27;."),
        ({"user": "ann", "perm": "auth.change_user", "draft_group": "NOBODY"}, "No group &#x27;NOBODY&#x27;."),
        (
            {"user": "ann", "perm": "auth.change_user", "draft_group": "CUSTOMERS", "draft_ruleset": "own"},
            "unknown predicate &#x27;own&#x27;",
        ),
        (
            {"user": "ann", "perm": "auth.delete_user", "draft_group": "CUSTOMERS", "draft_ruleset": "yes"},
            "auth.delete_user isn&#x27;t an action permission",
        ),
    ],
)
def test_verify_says_what_it_cant_check(admin_client, loaded, member, params, error):
    member("CUSTOMERS")

    content = verify(admin_client, **params)

    assert error in content and "<strong>" not in content.split("Verify</h1>")[-1].split('<div id="footer"')[0]


def test_verify_without_a_query_shows_the_form_prefilled(admin_client, loaded):
    content = verify(admin_client, perm="auth.change_user", draft_group="CUSTOMERS")

    assert 'value="auth.change_user"' in content and 'value="CUSTOMERS"' in content
    assert "This field is required" not in content
    assert '<option value="auth.view_user">' in content


def test_verify_reports_a_manager_user_that_doesnt_import(admin_client, loaded, member, settings):
    settings.ACTION_PERMISSIONS = {"CACHE": None, "MANAGER_USER": "tests.nowhere.manager"}
    member("CUSTOMERS")

    response = admin_client.get(url("actionpermission_verify"), {"user": "ann", "perm": "auth.change_user"})

    assert "MANAGER_USER can&#x27;t be imported" in response.content.decode()


def test_verify_reports_a_misconfigured_backend(admin_client, loaded, member, settings):
    settings.ACTION_PERMISSIONS = {"CACHE": None, **{"RULES_BACKEND": "tests.nowhere.Backend"}}
    member("CUSTOMERS")

    content = verify(admin_client, user="ann", perm="auth.change_user", obj="1")

    assert "RULES_BACKEND" in content


def test_only_superusers_verify(client, staff_user):
    client.force_login(staff_user)

    assert client.get(url("actionpermission_verify")).status_code == 403


# ── the rows selected in the list ────────────────────────────────────────────


def test_the_tools_carry_the_rows_selected(admin_client, loaded):
    content = admin_client.get(url("actionpermission_changelist")).content.decode()

    assert "django_action_permissions/changelist.js" in content
    assert f'<a href="{url("actionpermission_verify")}" data-selection="entry" data-selection-max="1"' in content
    assert f'<a href="{url("actionpermission_overview")}" data-selection="entry"' in content


def test_verify_takes_the_permission_of_the_row_selected(admin_client, loaded, member):
    member("CUSTOMERS")
    entry = ActionPermission.objects.get(permission__codename="change_user")

    assert 'value="auth.change_user"' in verify(admin_client, entry=entry.pk)  # the form, prefilled
    content = verify(admin_client, user="ann", entry=entry.pk)
    assert "<strong>Refused</strong>" in content and "<code>auth.change_user</code> for ann" in content
    assert 'value="auth.view_user"' in verify(admin_client, entry=entry.pk, perm="auth.view_user")  # typed: kept
    for other in ("999", "x"):
        content = verify(admin_client, entry=other)
        assert 'name="perm" value=' not in content and "This field is required" not in content


def test_the_overview_of_the_rows_selected(admin_client, loaded):
    entry = ActionPermission.objects.get(permission__codename="view_user")

    content = admin_client.get(url("actionpermission_overview"), {"entry": [entry.pk, "x"]}).content.decode()

    assert "auth.view_user" in content and "auth.change_user" not in content
    assert "The 1 action permission selected in the list." in content
    assert f'<input type="hidden" name="entry" value="{entry.pk}">' in content
