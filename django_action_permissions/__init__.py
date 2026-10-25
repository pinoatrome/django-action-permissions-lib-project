"""Action-based permissions for Django REST framework viewsets, driven by action permissions (RBAC and ABAC)
that setup stores in the database.

- `permissions`: `BaseActionModelPermission`, which maps a viewset action to the
  model permission it needs (`list` -> `view_<model>`, `create` -> `add_<model>`,
  a custom action -> `<action>_<model>`) and checks objects against the rulesets;
  `DenyAll`. The one module that needs Django REST framework (the `drf` extra).
- `mixins`: fix a permission class's operation or whole permission code.
- `rbac`: `setup_rbac_permissions`, which writes the permission definitions and their predicates to the database.
- `models`: the action permissions as stored (`ActionPermission`, `ActionPermissionGroup`, `ActionPermissionRule`).
- `predicates`: the `Predicate` protocol, `@predicate`, and the rulesets composed with `&`, `|`, `~`.
- `rules`: the built-in predicates.
- `entries`: each action permission's entry as the checks read it, cached under its own key.
- `backends`: the rules backends (`DenyUnlessAllowedRulesBackend`, `AllowUnlessBlockedRulesBackend`).
- `views`: `permission_required` and `PermissionRequiredMixin`, for plain Django views (no DRF needed).
- `abac`: `unrestricted` and `allowed`, the object checks in any code.
- `auth`: `ActionPermissionBackend`, an optional authentication backend: `user.has_perm(perm, obj)` by the rulesets.
- `yaml_io`: the permission definitions as a YAML document (load and export); `checks`: the system checks; `admin`.

Nothing here knows about a particular project: the definitions, their predicates and the group
names are passed in by the app that uses it.
"""
