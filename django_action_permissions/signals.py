"""A change in the database drops, once its transaction commits, the cached entries it affects (see `entries`):

- an `ActionPermission` saved or deleted, or its `no_detail` / `staff` changed: its own;
- a group's ruleset (`ActionPermissionGroup`) saved or deleted: its entry's;
- a predicate's definition (`ActionPermissionRule`) saved: the entries whose rulesets use it;
- a group renamed or deleted: the entries naming it (a ruleset, `no_detail`, `staff`), collected before the
  deletion's cascade removes their rows.
"""

from django.contrib.auth.models import Group
from django.db.models import Q
from django.db.models.signals import m2m_changed, post_delete, post_save, pre_delete
from django.dispatch import receiver

from .entries import entry_codes, invalidate_on_commit
from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule

UID = "django_action_permissions.invalidate"


def _naming(group) -> set[str]:
    return entry_codes(
        ActionPermission.objects.filter(Q(group_rules__group=group) | Q(no_detail=group) | Q(staff=group)).distinct()
    )


@receiver(post_save, sender=ActionPermission, dispatch_uid=f"{UID}.permission.save")
@receiver(post_delete, sender=ActionPermission, dispatch_uid=f"{UID}.permission.delete")
def entry_changed(sender, instance, **kwargs):
    invalidate_on_commit({instance.perm_code})


@receiver(m2m_changed, sender=ActionPermission.no_detail.through, dispatch_uid=f"{UID}.no_detail")
@receiver(m2m_changed, sender=ActionPermission.staff.through, dispatch_uid=f"{UID}.staff")
def entry_groups_changed(sender, instance, action, **kwargs):
    if action.startswith("post_") and isinstance(instance, ActionPermission):
        invalidate_on_commit({instance.perm_code})


@receiver(post_save, sender=ActionPermissionGroup, dispatch_uid=f"{UID}.group_rule.save")
@receiver(post_delete, sender=ActionPermissionGroup, dispatch_uid=f"{UID}.group_rule.delete")
def ruleset_changed(sender, instance, **kwargs):
    # in a cascade, Django deletes (and signals) the rows before their entry: the entry is still there to read
    invalidate_on_commit({instance.action_permission.perm_code})


@receiver(post_save, sender=ActionPermissionRule, dispatch_uid=f"{UID}.rule.save")
def predicate_changed(sender, instance, **kwargs):
    invalidate_on_commit(entry_codes(ActionPermission.objects.filter(group_rules__rules=instance).distinct()))


@receiver(post_save, sender=Group, dispatch_uid=f"{UID}.group.save")
def group_renamed(sender, instance, created, **kwargs):
    if not created:
        invalidate_on_commit(_naming(instance))


@receiver(pre_delete, sender=Group, dispatch_uid=f"{UID}.group.delete")
def group_deleted(sender, instance, **kwargs):
    invalidate_on_commit(_naming(instance))
