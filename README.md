# django-action-permissions-lib-project

Action-based permissions for Django REST framework viewsets, driven by an RBAC
table. A viewset action is checked against the Django model permission it
stands for, and the table says which groups hold each permission. Nothing here
knows about a particular project: the table and the group names are passed in
by the app that uses it.

- `permissions`: `BaseActionModelPermission`, which maps a viewset action to the
  model permission it needs (`list` and `retrieve` -> `view_<model>`, `create` ->
  `add_<model>`, `update` and `partial_update` -> `change_<model>`, `destroy` ->
  `delete_<model>`, a custom action -> `<action>_<model>`, e.g. `upload_document`),
  and `DenyAll`.
- `mixins`: `OperationInfoPermissionMixin` and `CodeInfoPermissionMixin` fix a
  permission class's operation or whole permission code, for one action.
- `rbac`: `setup_rbac_permissions`, which grants groups the permissions the table
  lists for them.

## Install

```bash
pip install -e .          # or: pip install "django-action-permissions @ git+https://github.com/pinoatrome/django-action-permissions-lib-project@v0.1.0"
```

## Usage

The RBAC table maps a Django permission string (`app_label.codename`, as
`user.has_perm()` takes it) to the groups granted it:

```python
# permissions_table.py
table = {
    "shop.view_order": {"rbac": {"CLERKS", "MANAGERS"}, "abac": {}},
    "shop.change_order": {"rbac": {"MANAGERS"}, "abac": {"MANAGERS": ["own_branch"]}},
    "shop.approve_order": {"rbac": {"MANAGERS"}, "abac": {}},  # a custom action `approve`
}
```

Bind a permission class to the table and set it on a viewset:

```python
import copy

from django_action_permissions.permissions import BaseActionModelPermission

from .permissions_table import table


class ShopPermission(BaseActionModelPermission):
    def get_perm_info(self, perm_code):
        return copy.deepcopy(table.get(perm_code))

    def apply_rule(self, br_code, user, obj):  # ABAC rules, per object
        return br_code == "own_branch" and obj.branch_id == user.branch_id


class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [ShopPermission]
```

Close every view that doesn't set its own permissions:

```python
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["django_action_permissions.permissions.DenyAll"]}
```

Grant the groups what the table says (after `migrate`, so the permissions exist):

```python
from django_action_permissions.rbac import setup_rbac_permissions

setup_rbac_permissions(table, ["CLERKS", "MANAGERS"])  # groups created if missing;
setup_rbac_permissions(table, ["CLERKS", "MANAGERS"], keep=True)  # keep=True: don't remove other permissions
```

A table entry can also carry:

- `abac`: `{group: [rule codes]}`; for an object (`has_object_permission`) the user's group is
  allowed if one of its rules accepts the object (`apply_rule`);
- `rules`: `[{"code": ..., "for": [groups]}]`; all the rules of the user's group must accept it;
- `staff`: groups that act with the rights of their manager (`manager_user`);
- `no_detail`: groups that may list but not retrieve a single object.

An action the viewset doesn't route is a 405 for an authenticated user and a refusal (so a request for
credentials) for an anonymous one. OPTIONS takes the `view` permission.

## Supported versions

Tested on Django 5.2 LTS (Python 3.13) and Django 6.1 (Python 3.14), with Django REST framework 3.16+.

## Development

```bash
pip install -e ".[dev,test]"
pre-commit install          # ruff on commit, the tests (tox, Django 6.1) on push
tox                         # lint, both Django versions, combined coverage
tox -e lint                 # ruff check and ruff format --check only
tox -e py314-django61       # one Django version
```

`tox` combines the coverage of both Django versions (`tox -e coverage`): the report is printed, with the
details in `htmlcov/index.html` and `coverage.xml` for CI.

The tests use the auth models in an in-memory SQLite database (`tests/settings.py`): that is the library's
own test setup, not a requirement on the app.
