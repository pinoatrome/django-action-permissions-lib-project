# django-action-permissions-lib-project

Action-based permissions for Django REST framework viewsets and plain Django views, driven by a permissions table.
A viewset action is checked against the Django model permission it stands for. The table says which groups hold each permission
(RBAC) and which objects they may use it on (ABAC rules). Setup writes the table to the database; at runtime it is
read from there, through a Django cache. Nothing here knows about a particular project: the table, its rules and
the group names are passed in by the app that uses it.

- `permissions`: `BaseActionModelPermission`, which maps a viewset action to the model permission it needs (`list`
  and `retrieve` -> `view_<model>`, `create` -> `add_<model>`, `update` and `partial_update` -> `change_<model>`,
  `destroy` -> `delete_<model>`, a custom action -> `<action>_<model>`, e.g. `upload_document`) and checks objects
  against the table; `DenyAll`. The one module that needs Django REST framework (the `drf` extra).
- `mixins`: `OperationInfoPermissionMixin` and `CodeInfoPermissionMixin` fix a permission class's operation or
  whole permission code, for one action.
- `predicates`: the `Predicate` protocol, `@predicate`, and rulesets (predicates composed with `&`, `|`, `~`);
  `rules`: the built-in predicates.
- `rbac`: `setup_rbac_permissions`, which writes the table and its predicates to the database.
- `views`: `permission_required` and `PermissionRequiredMixin`, for plain Django views (no DRF needed).
- `abac`: `unrestricted(user, perm)` and `allowed(user, perm, obj)`, the same checks in any code.
- `backends`: the rules backends, which run the rules and read their answers.
- `yaml_io` and the commands `django_action_permissions_load` / `django_action_permissions_export`: the table as a
  YAML document.
- `auth`: `ActionPermissionBackend`, an optional authentication backend: `user.has_perm(perm, obj)` by the table.
- `admin`: every part of the table editable, and the Load, Export and Check tools.
- `checks`: system checks of the settings and of the stored table.

## Install

```bash
pip install "django-action-permissions[drf,yaml] @ git+https://github.com/pinoatrome/django-action-permissions-lib-project@v0.2.0"
```

The extras: `drf` (Django REST framework) for the viewset permission classes, `yaml` (PyYAML) for the YAML loader
and exporter. Without them the rest works in plain Django (see Usage).

```python
INSTALLED_APPS = [
    ...,
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",  # with the drf extra
    "django_action_permissions",
]
```

Then `python manage.py migrate`, and set up the table (below).

## Predicates

A predicate is a function `(user, obj) -> bool | None` (the `predicates.Predicate` protocol): `True`, `False`, or
`None` when it doesn't apply; or it raises `PermissionDenied` (Django's, or DRF's when DRF is installed), which
blocks the whole check. `@predicate` makes a function one, under a code (its name, or `code=`) and a description
(its docstring's first paragraph, or `description=`). Define them in your apps' `rules.py`, at a module's top level:

```python
# shop/rules.py
from django_action_permissions.predicates import predicate


@predicate
def own_order(user, obj):
    """The order is the user's."""
    return obj.customer_id == user.pk


@predicate(code="archived")
def is_archived(user, obj):
    """The order is archived."""
    return obj.archived_at is not None
```

Setup imports every installed app's `rules` module (as the admin does its `admin` modules) and stores each
registered predicate's definition (code, dotted path, description) in the database; a code taken by two functions
is `ImproperlyConfigured`. The library's own `rules` module ships these, whose codes are reserved:

| code | allows when |
|---|---|
| `always` / `never` | always / never |
| `is_authenticated`, `is_active`, `is_staff`, `is_superuser` | the user is (Django's flags) |
| `is_self` | the object is the user themselves |

## Rulesets

Predicates compose into a ruleset with `&` (and), `|` (or), `~` (not) and parentheses; `~` binds tighter than
`&`, and `&` tighter than `|`. `None` ("doesn't apply") is skipped:

| | evaluates | answers |
|---|---|---|
| `a & b & ...` | left to right, up to the first `False` | `False` if one is; else `True` if one is; else `None` |
| `a \| b \| ...` | left to right, up to the first `True` | `True` if one is; else `False` if one is; else `None` |
| `~a` | `a` | `True` and `False` swapped; `None` stays `None` |

The order is the execution order: `~is_blocked & own_order` checks the block first. A `PermissionDenied` goes
through every operator and blocks.

## The table

The table maps a Django permission string (`app_label.codename`, as `user.has_perm()` takes it) to its entry:

```python
from django_action_permissions.rules import is_staff
from shop.rules import is_archived, own_order

TABLE = {
    "shop.view_order": {
        "rbac": {"CLERKS", "CUSTOMERS"},  # the groups granted the permission
        "abac": {"CUSTOMERS": "own_order | is_staff"},  # a group's ruleset, as an expression ...
        "no_detail": [],  # groups that may list but not retrieve a single object
        "staff": [],  # groups that act with the rights of their manager (`manager_user`)
    },
    "shop.change_order": {
        "rbac": {"CLERKS", "CUSTOMERS"},
        "abac": {"CUSTOMERS": own_order & ~is_archived},  # ... or composed in Python
    },
    "shop.approve_order": {"rbac": {"CLERKS"}},  # a custom action `approve`
}
```

`abac` gives a group one ruleset: the group holds the permission on the objects it allows. A group holding the
permission without a ruleset holds it on any object. Set it up (after `migrate`, so the permissions exist):

```python
from django_action_permissions.rbac import setup_rbac_permissions

setup_rbac_permissions(TABLE, ["CLERKS", "CUSTOMERS"])  # groups created if missing
setup_rbac_permissions(TABLE, ["CLERKS", "CUSTOMERS"], keep=True)
```

Setup runs in one transaction. It stores the registered predicates (and the definitions `rules=` gives,
`{code: {"fqn", "description"}}`, e.g. a YAML document's), replaces each entry it lists, the rulesets in their
canonical form (`(own_order | is_staff) & ~archived`), and gives the groups the permissions it grants. Without
`keep`, the groups lose any other permission, and the entries the table no longer lists, and the predicates no
longer defined and unused, are removed. A table that names a group not set up, gives a ruleset to a group its
`rbac` doesn't grant, has a ruleset that doesn't parse or names an unknown predicate, or a predicate that doesn't
import, is a `ValueError`, raised before anything is written; so is a list of rules (write `a | b`, or `a & b`).

## The answer on an object

On an object, every group of the user holding the permission evaluates its ruleset, in name order. A
`PermissionDenied` in any of them blocks; otherwise one group allowing is enough, so the order of `user.groups`
doesn't matter. When no group decides (`None`), the rules backend's policy does, which goes with the project's
default permission:

| | `DenyUnlessAllowedRulesBackend` (default, with `DenyAll`) | `AllowUnlessBlockedRulesBackend` (with DRF's `AllowAny`) |
|---|---|---|
| a ruleset answers `None` | deny | allow |

A permission the table doesn't list is left to `user.has_perm(perm, obj)` (Django's object permission backends),
and no group holds it on any object (`unrestricted` is false until setup has run).

## Settings

```python
ACTION_PERMISSIONS = {
    "DEFAULT_PERMISSION": "django_action_permissions.permissions.DenyAll",  # or rest_framework.permissions.AllowAny
    # or django_action_permissions.backends.AllowUnlessBlockedRulesBackend
    "RULES_BACKEND": "django_action_permissions.backends.DenyUnlessAllowedRulesBackend",
    "CACHE": "default",  # an alias of CACHES; None: read the database on each check
    "CACHE_TIMEOUT": 300,
    "MANAGER_USER": None,  # "myapp.staff.manager_of": (user) -> manager, for staff groups in the auth backend
}
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["django_action_permissions.permissions.DenyAll"]}
```

These are the defaults. `DenyAll` goes with `DenyUnlessAllowedRulesBackend`, DRF's `AllowAny` with
`AllowUnlessBlockedRulesBackend` (DRF has no class that denies everything, hence `DenyAll`), and the same class is
the project's `DEFAULT_PERMISSION_CLASSES` (the check `W004` says when it isn't): with `DenyAll`, a view that
doesn't set its own `permission_classes` is closed. A custom backend subclasses `BaseRulesBackend` (e.g. to override
`order`).

The table is cached under one key (`django_action_permissions:table`) of the `CACHE` alias, and dropped from it
when setup commits and on any change of the stored table, the admin's included. The cache must be shared by every
process of the project (Redis, Memcached, the database cache): a `LocMemCache` is kept by each process on its own
(the check `W001` says so). A cache that fails is logged, and the database answers.

## Usage

What to use depends on whether Django REST framework is installed (the `drf` extra):

| | with DRF | without DRF |
|---|---|---|
| DRF viewsets and `APIView`s | `permissions.BaseActionModelPermission` | — |
| views closed by default | `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`: `DenyAll` (or `AllowAny`) | `LoginRequiredMiddleware` |
| function views | `views.permission_required` | `views.permission_required` |
| class-based views | `views.PermissionRequiredMixin` | `views.PermissionRequiredMixin` |
| any other code (filters, templates, tasks) | `abac.unrestricted`, `abac.allowed` | `abac.unrestricted`, `abac.allowed` |
| Django's `user.has_perm(perm, obj)` (optional) | `auth.ActionPermissionBackend` | `auth.ActionPermissionBackend` |
| a rule blocks by raising | Django's or DRF's `PermissionDenied` | Django's `PermissionDenied` |
| `DEFAULT_PERMISSION` | a DRF permission class, in `DEFAULT_PERMISSION_CLASSES` (check `W004`) | `DenyAll` or `AllowAny`, by name only (check `E001`) |

Setup, the stored table and its cache, the rules backends, the YAML tools, the commands and the admin are the same
in both.

### With DRF: viewsets

```python
from django_action_permissions.permissions import BaseActionModelPermission


class OrderViewSet(viewsets.ModelViewSet):
    permission_classes = [BaseActionModelPermission]
```

`has_permission` checks the action's permission (and `no_detail`), `has_object_permission` the object against the
table: call `self.check_object_permissions(request, obj)` on an object to be created, too. A project with `staff`
groups subclasses it to implement `manager_user(user)`. An action the viewset doesn't route is a 405 for an
authenticated user and a refusal (so a request for credentials) for an anonymous one. OPTIONS takes the `view`
permission.

An object the user may not use is a 403, or a 404 when they can't read it either (`view_<model>` on it), as DRF's
`DjangoObjectPermissions` does: another user's objects aren't revealed. A creation refused (the unsaved object
passed to `check_object_permissions`) is always a 403: there's nothing to hide. `not_found_when_unreadable = False`
on a subclass gives 403 for every refusal.

```python
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["django_action_permissions.permissions.DenyAll"]}
```

closes the views that don't set their own `permission_classes`; it is the class `ACTION_PERMISSIONS["DEFAULT_PERMISSION"]`
names (the check `W004` says when they differ).

### Plain Django views, with or without DRF

`django_action_permissions.views` holds the counterparts of Django's `permission_required` and
`PermissionRequiredMixin`, built on the table. As Django's, an anonymous visitor is sent to the login page
(`LOGIN_URL`), and a signed-in user who may not gets a 403 rather than a login page to come back from; an object
they may not use is a 404 when they can't read it either, as in the DRF class (`not_found_when_unreadable=False`
on the decorator, or as the mixin's attribute, for 403 everywhere). Several permissions must all be held.

```python
from django.shortcuts import get_object_or_404
from django_action_permissions.views import permission_required


@permission_required("shop.view_order")  # on any object: e.g. the back office's list of every order
def all_orders(request): ...


@permission_required("shop.change_order", get_object=lambda request, pk: get_object_or_404(Order, pk=pk))
def edit_order(request, pk): ...  # on this order: the group's ruleset decides
```

Without `get_object`, the decorator asks for the permission on any object (`unrestricted`): a user who holds it on
their own objects only is refused. With `get_object(request, *args, **kwargs)`, it asks for it on the object
returned (`allowed`). Async views are guarded too; `manager_user=` gives the manager of a `staff` group.

```python
from django.views.generic import DetailView, ListView
from django_action_permissions.abac import unrestricted
from django_action_permissions.views import PermissionRequiredMixin


class OrderDetail(PermissionRequiredMixin, DetailView):
    model = Order
    permission_required = "shop.view_order"  # get_object() refuses an order the table doesn't allow (403)


class OrderList(PermissionRequiredMixin, ListView):
    model = Order
    permission_required = "shop.view_order"  # a customer gets in: the list shows their orders

    def get_queryset(self):
        orders, user = super().get_queryset(), self.request.user
        return orders if unrestricted(user, "shop.view_order") else orders.filter(customer=user)


class BackOffice(PermissionRequiredMixin, ListView):
    model = Order
    permission_required = "shop.view_order"
    permission_unrestricted = True  # on any object only
```

The mixin lets in a user holding the permission, maybe on their own objects only (`has_perm`), or on any object
with `permission_unrestricted = True`, and `get_object()` checks the object (`allowed`): put the mixin first, before
`DetailView`, `UpdateView`, `DeleteView`. Define `manager_user(self, user)` for `staff` groups.

### Without DRF

Django has no permission classes, so nothing closes a view by default but
`django.contrib.auth.middleware.LoginRequiredMiddleware` (Django 5.1+; the check `W005` says when it's missing with
`DenyAll`). It requires a login only: the views still ask the table, with `views` or `abac`.

`DEFAULT_PERMISSION` then only names the policy of the rules backend: `django_action_permissions.permissions.DenyAll`
or `rest_framework.permissions.AllowAny`, by name, as neither can be imported (the check `E001` refuses anything
else, which it couldn't verify). `BaseActionModelPermission` and `DenyAll` themselves need DRF.

### Compared with DRF's `DjangoModelPermissions` / `DjangoObjectPermissions`

Both map a request to a Django model permission of the view's queryset model and check it with `has_perm(s)`.
DRF's map the HTTP method: reads ask for nothing, and a POST to a custom action asks for `add_<model>`. This
library maps the viewset action: reads ask for `view_<model>`, a custom action for `<action>_<model>`. On an object,
`DjangoObjectPermissions` asks `user.has_perms(perms, obj)`, per-object grants stored by an authentication backend
such as django-guardian; this library runs the table's rules on the object's attributes, and stores nothing per
object. The two meet where the table is silent: for a permission it doesn't list, the object check is
`user.has_perm(perm, obj)`, so guardian's grants apply. Both answer 404 rather than 403 for an object the user can't
read. With the auth backend below, DRF's own `DjangoObjectPermissions` asks the table too.

### Django's `user.has_perm(perm, obj)`: the optional auth backend

```python
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "django_action_permissions.auth.ActionPermissionBackend",
]
```

Without an object, `ModelBackend` answers (`Group.permissions`, which setup writes). With one, for a permission the
table lists, `ActionPermissionBackend` answers as `abac.allowed`: Django's own API then asks the table, so templates,
services, guardian-style code and DRF's `DjangoObjectPermissions` follow it, unchanged. As any Django backend, it
answers among the others: one allowing is enough, so another object-permission backend (django-guardian) may allow
what the table refuses, but a rule raising `PermissionDenied` stops the backends after it (Django's
`_user_has_perm`). A permission the table doesn't list is left to the other backends. The backend has no view to ask
for a `staff` group's manager: `ACTION_PERMISSIONS["MANAGER_USER"]` names the function (`user -> manager`; the check
`E007` says when it doesn't import), and without it a staff group allows nothing there.

`BaseActionModelPermission`, `views` and `abac` don't need the backend: they ask the table directly.

### In any code

```python
from django_action_permissions.abac import allowed, unrestricted

unrestricted(user, "shop.view_order")  # on any object: e.g. a list shows every order, or the user's own
allowed(user, "shop.view_order", order)
```

## YAML

The table as one document, the rulesets as expressions:

```yaml
groups: [CLERKS, CUSTOMERS]
rules:  # optional: the registered predicates are stored anyway; a definition here may add or describe one
  own_order: {fqn: shop.rules.own_order, description: The order is the user's}
permissions:
  shop.view_order:
    rbac: [CLERKS, CUSTOMERS]
    abac: {CUSTOMERS: own_order & ~archived | is_staff}
```

```bash
python manage.py django_action_permissions_load permissions.yaml [--keep]
python manage.py django_action_permissions_export [-o permissions.yaml]
```

Loading is setup (`load_yaml`); a document of the wrong shape is refused, naming where. The export
(`dump_yaml`) is what the database holds: sorted, the rulesets canonical, the definitions of the predicates they
use, the groups the table names (others are left out, so loading the export can't strip them of their
permissions). Load, export, load and export again
gives the same document.

## Admin

Every model is editable: an entry on one page (its permission, its `rbac` groups, `no_detail`, `staff`, and its
groups' rulesets, checked and made canonical as they're saved), the predicates' definitions (code, function,
description, and their uses; one in use can't be deleted; setup syncs the registered ones from the code), and the
groups' rulesets on their own, with the predicates each uses. The entries' list has the configuration tools:

- **Load YAML**: superusers only, as it rewrites the groups' permissions; nothing is written if the document has
  an error.
- **Export YAML**, and the action **Export selected as YAML**: users who may view the three models.
- **Check configuration**: the system checks below, the database ones included.

Load and Export need the `yaml` extra; without it they aren't offered.

## Checks

`python manage.py check` checks the settings; `python manage.py check --database default` the stored table too.

- `E001` `DEFAULT_PERMISSION` isn't a DRF permission class (without DRF: isn't `DenyAll` or `AllowAny`);
  `E002` `RULES_BACKEND` isn't a `BaseRulesBackend`; `E003` they don't go together; `E004` `CACHE` isn't an alias
  of `CACHES`; `W001` `CACHE` is a `LocMemCache`.
- `E007` `MANAGER_USER` doesn't import or isn't callable.
- `W004` (with DRF) `DEFAULT_PERMISSION` isn't in `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]`; `W005` (without
  DRF) `DenyAll` without `LoginRequiredMiddleware`.
- `E005` a predicate's function doesn't import; `E006` a group has a ruleset for a permission it doesn't hold;
  `E008` a ruleset doesn't parse, or names a predicate not stored; `W002` the table is empty (setup not run);
  `W003` a stored predicate isn't used and no `@predicate` defines it any more; `W006` a registered predicate isn't
  stored (setup hasn't run since it was added).

## Upgrading from 0.1.0

1. Add `"django_action_permissions"` to `INSTALLED_APPS` and run `migrate`.
2. Move the rule functions out of `apply_rule` into `@predicate` functions `(user, obj)` in your apps' `rules.py`,
   and write each group's `abac` list as one ruleset: `[a, b]` read as "any allows" is `a | b`, a `rules` list
   ("all must pass") is `a & b`.
3. Run setup again: until then no group holds a permission on any object.
4. Drop the overrides of `get_perm_info` and `apply_rule`: the table is the database's.

## Supported versions

Tested on Django 5.2 LTS (Python 3.13) and Django 6.1 (Python 3.14), with Django REST framework 3.16+, and on
Django 6.1 without DRF.

## Development

```bash
pip install -e ".[dev,test,drf,yaml]"
pre-commit install          # ruff on commit, the tests (tox, Django 6.1) on push
tox                         # lint, both Django versions, combined coverage
tox -e lint                 # ruff check and ruff format --check only
tox -e py314-django61       # one Django version
tox -e py314-django61-nodrf # without Django REST framework
```

`tox` combines the coverage of every env (`tox -e coverage`, at least 90%): the report is printed, with
the details in `htmlcov/index.html` and `coverage.xml` for CI.

The tests use an in-memory SQLite database (`tests/settings.py`): that is the library's own test setup, not a
requirement on the app.
