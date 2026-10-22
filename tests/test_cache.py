"""The table read through the cache `ACTION_PERMISSIONS["CACHE"]` names, and dropped from it on every change."""

import pytest
from django.contrib.auth.models import Group
from django.core.cache import caches
from django.db import connection
from django.test.utils import CaptureQueriesContext

from django_action_permissions import table
from django_action_permissions.models import ActionPermission, ActionPermissionGroup, ActionPermissionRule

pytestmark = pytest.mark.django_db

TABLE = {"auth.change_user": {"rbac": {"CUSTOMERS"}, "abac": {"CUSTOMERS": "owner"}, "no_detail": ["CLERKS"]}}


@pytest.fixture(autouse=True)
def cached(settings):
    """The default configuration: the table cached in `default`."""
    settings.ACTION_PERMISSIONS = {}
    caches["default"].clear()
    yield
    caches["default"].clear()


def queries(function) -> int:
    with CaptureQueriesContext(connection) as captured:
        function()
    return len(captured)


def rename(name, new_name):
    group = Group.objects.get(name=name)
    group.name = new_name
    group.save()


def is_cached() -> bool:
    return caches["default"].get(table.CACHE_KEY) is not None


def test_the_default_configuration_caches_the_table_in_default(setup):
    setup(TABLE)

    first = table.load_table()

    assert caches["default"].get(table.CACHE_KEY) == first
    assert queries(table.load_table) == 0
    assert table.perm_info("auth.change_user") == first["auth.change_user"]


def test_without_a_cache_every_read_goes_to_the_database(setup, settings):
    setup(TABLE)
    settings.ACTION_PERMISSIONS = {"CACHE": None}

    assert queries(table.load_table) > 0 and queries(table.load_table) > 0
    table.invalidate_table(strict=True)  # nothing to drop


def test_invalidation_drops_only_the_librarys_key(setup):
    setup(TABLE)
    table.load_table()
    caches["default"].set("someone-elses", 1)

    table.invalidate_table()

    assert not is_cached() and caches["default"].get("someone-elses") == 1


def test_setup_drops_the_cached_table_once_committed(setup, django_capture_on_commit_callbacks):
    setup(TABLE)
    table.load_table()

    with django_capture_on_commit_callbacks(execute=True):
        setup({**TABLE, "auth.view_user": {"rbac": {"CLERKS"}}})

    assert not is_cached()
    assert set(table.load_table()) == {"auth.change_user", "auth.view_user"}


@pytest.mark.parametrize(
    "change",
    [
        lambda: ActionPermissionRule.objects.get(code="owner").save(),
        lambda: ActionPermissionGroup.objects.get().save(),
        lambda: ActionPermissionGroup.objects.get().delete(),
        lambda: ActionPermission.objects.get().save(),
        lambda: ActionPermission.objects.get().no_detail.clear(),
        lambda: ActionPermission.objects.get().staff.add(Group.objects.get(name="CLERKS")),
        lambda: ActionPermission.objects.get().delete(),
        lambda: rename("CLERKS", "CLERKS-2"),
        lambda: Group.objects.get(name="BOSSES").delete(),
    ],
)
def test_a_change_to_the_stored_table_drops_the_cached_one(setup, change, django_capture_on_commit_callbacks):
    setup(TABLE)
    table.load_table()

    with django_capture_on_commit_callbacks(execute=True):
        change()

    assert not is_cached()


def test_a_cache_that_cant_be_read_or_written_leaves_the_database_to_answer(setup, monkeypatch, caplog):
    setup(TABLE)

    def fail(*args, **kwargs):
        raise ConnectionError("cache down")

    monkeypatch.setattr(caches["default"], "get", fail)
    assert set(table.load_table()) == {"auth.change_user"}
    assert "the cache can't be read" in caplog.text

    monkeypatch.undo()
    monkeypatch.setattr(caches["default"], "set", fail)
    assert set(table.load_table()) == {"auth.change_user"}
    assert "the cache can't be written" in caplog.text


def test_a_failed_invalidation_is_logged_but_raises_for_setup(
    setup, monkeypatch, caplog, django_capture_on_commit_callbacks
):
    setup(TABLE)

    def fail(*args, **kwargs):
        raise ConnectionError("cache down")

    monkeypatch.setattr(caches["default"], "delete", fail)
    table.invalidate_table()
    assert "couldn't be dropped" in caplog.text

    with pytest.raises(ConnectionError), django_capture_on_commit_callbacks(execute=True):
        setup(TABLE)
