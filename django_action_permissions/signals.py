"""Any change to the stored table (the admin, a shell, setup) drops the cached table once its transaction commits.
A group's rename or deletion too: the cached table holds group names."""

from django.contrib.auth.models import Group
from django.db.models.signals import m2m_changed, post_delete, post_save
from django.dispatch import receiver

from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from .table import invalidate_on_commit

UID = "django_action_permissions.invalidate_table"


@receiver(post_save, sender=ActionPermission, dispatch_uid=f"{UID}.permission.save")
@receiver(post_delete, sender=ActionPermission, dispatch_uid=f"{UID}.permission.delete")
@receiver(post_save, sender=ActionPermissionGroup, dispatch_uid=f"{UID}.group_rule.save")
@receiver(post_delete, sender=ActionPermissionGroup, dispatch_uid=f"{UID}.group_rule.delete")
@receiver(post_save, sender=ActionPermissionRule, dispatch_uid=f"{UID}.rule.save")
@receiver(post_delete, sender=ActionPermissionRule, dispatch_uid=f"{UID}.rule.delete")
@receiver(post_save, sender=Group, dispatch_uid=f"{UID}.group.save")
@receiver(post_delete, sender=Group, dispatch_uid=f"{UID}.group.delete")
@receiver(m2m_changed, sender=ActionPermission.no_detail.through, dispatch_uid=f"{UID}.no_detail")
@receiver(m2m_changed, sender=ActionPermission.staff.through, dispatch_uid=f"{UID}.staff")
def table_changed(sender, **kwargs):
    if kwargs.get("action", "post_").startswith("post_"):
        invalidate_on_commit()
