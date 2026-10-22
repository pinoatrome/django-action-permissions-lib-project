def setup_rbac_permissions(permissions_table, group_names, keep=False):
    """Grant each group the permissions the RBAC table lists for it.

    Table keys are Django permission strings as `user.has_perm()` takes them
    ("app_label.codename"), e.g. "shop.view_order"; each entry's 'rbac' holds the
    names of the groups granted it. The groups in `group_names` are created if
    missing and, unless `keep`, lose any permission the table doesn't grant them. A table
    that grants a permission to a group not in `group_names` is a `ValueError`.
    """
    # Imported here, not at module level: an AppConfig module may import this one
    # before the app registry is ready.
    from django.contrib.auth import models as contrib_auth_models

    groups = {}
    for group_name in group_names:
        group, _created = contrib_auth_models.Group.objects.get_or_create(name=group_name)
        groups[group.name] = group
        if not keep:
            group.permissions.clear()

    for perm_code, item in permissions_table.items():
        app_label, _, codename = perm_code.partition(".")
        try:
            permission = contrib_auth_models.Permission.objects.get(
                content_type__app_label=app_label,
                codename=codename,
            )
        except contrib_auth_models.Permission.DoesNotExist:
            raise ValueError(f"Invalid permission code: '{perm_code}'. Hint: run migration for '{app_label}'") from None

        for group_name in item["rbac"]:
            if group_name not in groups:
                raise ValueError(
                    f"'{perm_code}' is granted to '{group_name}', which isn't one of the groups "
                    f"to set up: {', '.join(sorted(groups))}"
                )
            groups[group_name].permissions.add(permission)
