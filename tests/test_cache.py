"""Each action permission's entry read through the cache `ACTION_PERMISSIONS["CACHE"]` names, under its own key, and
dropped from it when what it's made of changes."""

import pytest
from django.contrib.auth.models import Group, Permission
from django.core.cache import caches
from django.db import connection
from django.test.utils import CaptureQueriesContext

from django_action_permissions import entries
from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule

pytestmark = pytest.mark.django_db

CHANGE, VIEW, DELETE = "auth.change_user", "auth.view_user", "auth.delete_user"
TABLE = {
    CHANGE: {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}, "no_detail": ["CLERKS"]},
    VIEW: {"rbac": {"CLERKS", "BOSSES"}, "abac": {"BOSSES": "yes"}},
}


@pytest.fixture(autouse=True)
def cached(settings):
    """The default configuration: the entries cached in `default`."""
    settings.ACTION_PERMISSIONS = {}
    caches["default"].clear()
    yield
    caches["default"].clear()


def queries(function) -> int:
    with CaptureQueriesContext(connection) as captured:
        function()
    return len(captured)


def cached_codes() -> set[str]:
    return {code for code in (CHANGE, VIEW, DELETE) if caches["default"].get(entries._key(code)) is not None}


def read_both():
    entries.perm_info(CHANGE)
    entries.perm_info(VIEW)


def rename(name, new_name):
    group = Group.objects.get(name=name)
    group.name = new_name
    group.save()


def test_a_check_caches_its_own_permissions_entry_only(setup):
    setup(TABLE)

    first = entries.perm_info(CHANGE)

    assert cached_codes() == {CHANGE}
    assert (
        first
        == entries.read_entry(CHANGE)
        == {
            "abac": {"CUSTOMERS": "owner"},
            "predicates": {"owner": "tests.rules.owner"},
            "no_detail": ["CLERKS"],
            "staff": [],
        }
    )
    assert queries(lambda: entries.perm_info(CHANGE)) == 0


def test_a_permission_that_isnt_an_action_permission_is_cached_too(setup):
    setup(TABLE)

    assert entries.perm_info(DELETE) is None
    assert caches["default"].get(entries._key(DELETE)) == entries.UNLISTED
    assert queries(lambda: entries.perm_info(DELETE)) == 0
    assert entries.perm_info("nowhere.nothing") is None


def test_without_a_cache_every_check_reads_the_database(setup, settings):
    setup(TABLE)
    settings.ACTION_PERMISSIONS = {"CACHE": None}

    assert queries(lambda: entries.perm_info(CHANGE)) > 0 and queries(lambda: entries.perm_info(CHANGE)) > 0
    entries.invalidate({CHANGE}, strict=True)  # nothing to drop


def test_invalidation_drops_only_the_entries_named(setup):
    setup(TABLE)
    read_both()
    caches["default"].set("someone-elses", 1)

    entries.invalidate({CHANGE})
    entries.invalidate(set())

    assert cached_codes() == {VIEW} and caches["default"].get("someone-elses") == 1


def test_setup_drops_the_entries_it_writes_and_removes(setup, django_capture_on_commit_callbacks):
    setup({**TABLE, DELETE: {"rbac": {"CLERKS"}}})
    read_both()
    entries.perm_info(DELETE)

    with django_capture_on_commit_callbacks(execute=True):
        setup({VIEW: TABLE[VIEW], CHANGE: {"rbac": {"CUSTOMERS"}}})  # DELETE removed, CHANGE without ruleset

    assert cached_codes() == set()
    assert entries.perm_info(CHANGE)["abac"] == {} and entries.perm_info(DELETE) is None


@pytest.mark.parametrize(
    "change, dropped",
    [
        (lambda: ActionPermission.objects.get(permission__codename="change_user").save(), {CHANGE}),
        (lambda: ActionPermission.objects.get(permission__codename="change_user").no_detail.clear(), {CHANGE}),
        (
            lambda: ActionPermission.objects.get(permission__codename="view_user").staff.add(
                Group.objects.get(name="CLERKS")
            ),
            {VIEW},
        ),
        (lambda: ActionPermission.objects.get(permission__codename="view_user").delete(), {VIEW}),
        (lambda: ActionPermissionGroup.objects.get(group__name="CUSTOMERS").save(), {CHANGE}),
        (lambda: ActionPermissionGroup.objects.get(group__name="BOSSES").delete(), {VIEW}),
        (lambda: ActionPermissionRule.objects.get(code="owner").save(), {CHANGE}),
        (lambda: ActionPermissionRule.objects.get(code="yes").save(), {VIEW}),
        (lambda: ActionPermissionRule.objects.get(code="never").save(), set()),  # used by no entry
        (lambda: rename("CLERKS", "CLERKS-2"), {CHANGE}),  # CHANGE's no_detail; VIEW only grants it (rbac)
        (lambda: rename("BOSSES", "BOSSES-2"), {VIEW}),
        (lambda: Group.objects.get(name="CUSTOMERS").delete(), {CHANGE}),
        (lambda: Group.objects.create(name="NEWCOMERS"), set()),
        (lambda: Permission.objects.get(content_type__app_label="auth", codename="view_user").delete(), {VIEW}),
    ],
)
def test_a_change_drops_the_entries_it_affects_and_no_other(setup, change, dropped, django_capture_on_commit_callbacks):
    setup(TABLE)
    read_both()

    with django_capture_on_commit_callbacks(execute=True):
        change()

    assert cached_codes() == {CHANGE, VIEW} - dropped


def test_a_cache_that_cant_be_read_or_written_leaves_the_database_to_answer(setup, monkeypatch, caplog):
    setup(TABLE)

    def fail(*args, **kwargs):
        raise ConnectionError("cache down")

    monkeypatch.setattr(caches["default"], "get", fail)
    assert entries.perm_info(CHANGE)["abac"] == {"CUSTOMERS": "owner"}
    assert "the cache can't be read" in caplog.text

    monkeypatch.undo()
    monkeypatch.setattr(caches["default"], "set", fail)
    assert entries.perm_info(VIEW)["abac"] == {"BOSSES": "yes"}
    assert "the cache can't be written" in caplog.text


def test_a_failed_invalidation_is_logged_but_raises_for_setup(
    setup, monkeypatch, caplog, django_capture_on_commit_callbacks
):
    setup(TABLE)

    def fail(*args, **kwargs):
        raise ConnectionError("cache down")

    monkeypatch.setattr(caches["default"], "delete_many", fail)
    entries.invalidate({CHANGE})
    assert "couldn't be dropped" in caplog.text

    with pytest.raises(ConnectionError), django_capture_on_commit_callbacks(execute=True):
        setup(TABLE)
