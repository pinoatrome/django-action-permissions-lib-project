"""Action-based permissions for Django REST framework viewsets, driven by an RBAC table.

- `permissions`: `BaseActionModelPermission`, which maps a viewset action to the
  model permission it needs (`list` -> `view_<model>`, `create` -> `add_<model>`,
  a custom action -> `<action>_<model>`), and `DenyAll`.
- `mixins`: fix a permission class's operation or whole permission code.
- `rbac`: `setup_rbac_permissions`, which grants groups the permissions an RBAC
  table lists for them.

Nothing here knows about a particular project: the RBAC table and the group
names are passed in by the app that uses it.
"""
