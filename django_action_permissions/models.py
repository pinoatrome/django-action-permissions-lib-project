"""The permissions table as setup last applied it. Its `rbac` part is `Group.permissions`; the rest is here: the
entries, the groups' rulesets, and the predicates' definitions."""

from django.contrib.auth.models import Group, Permission
from django.core.exceptions import ValidationError
from django.db import models

from .predicates import NamedPredicate, parse
from .utils import rule_error


class ActionPermissionRule(models.Model):
    """A predicate's definition: a function `(user, obj) -> bool | None`, which may raise `PermissionDenied`.
    Setup stores the registered predicates (`@predicate`); usable in any group's ruleset."""

    code = models.CharField(max_length=100, unique=True)
    fqn = models.CharField(
        "function", max_length=255, help_text="Dotted path of the function, e.g. shop.rules.own_order"
    )
    description = models.TextField(blank=True)

    class Meta:
        ordering = ["code"]
        verbose_name = "rule"

    def __str__(self):
        return self.code

    def clean(self):
        error = rule_error(self.fqn)
        if error:
            raise ValidationError({"fqn": error})


class ActionPermission(models.Model):
    """A permission the table lists. The groups it's granted to (`rbac`) are `Group.permissions`."""

    permission = models.OneToOneField(Permission, on_delete=models.CASCADE, related_name="action_permission")
    no_detail = models.ManyToManyField(
        Group, blank=True, related_name="+", help_text="Groups that may list but not retrieve a single object."
    )
    staff = models.ManyToManyField(
        Group, blank=True, related_name="+", help_text="Groups that act with the rights of their manager."
    )

    class Meta:
        ordering = ["permission__content_type__app_label", "permission__codename"]
        verbose_name = "action permission"

    def __str__(self):
        return self.perm_code

    @property
    def perm_code(self) -> str:
        return f"{self.permission.content_type.app_label}.{self.permission.codename}"


class ActionPermissionGroup(models.Model):
    """A group's ruleset for an entry: predicates composed with `&`, `|`, `~` (`predicates`), which the group's
    objects must pass. The predicates it uses are linked (`rules`), so that one in use can't be deleted."""

    action_permission = models.ForeignKey(ActionPermission, on_delete=models.CASCADE, related_name="group_rules")
    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name="+")
    ruleset = models.TextField(
        help_text="Predicate codes composed with & (and), | (or), ~ (not) and parentheses, "
        "e.g. own_order & ~archived | is_staff."
    )
    rules = models.ManyToManyField(
        ActionPermissionRule, through="ActionPermissionGroupRule", related_name="usages", blank=True, editable=False
    )

    class Meta:
        ordering = ["action_permission", "group__name"]
        constraints = [
            models.UniqueConstraint(fields=["action_permission", "group"], name="django_action_permissions_group_rule")
        ]
        verbose_name = "group ruleset"

    def __str__(self):
        return f"{self.action_permission} {self.group.name}: {self.ruleset}"

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self.sync_rules()

    def parsed(self):
        """The ruleset, parsed against the stored predicates (`ValueError` when it can't be)."""
        stored = {rule.code: NamedPredicate(rule.code, rule.fqn) for rule in ActionPermissionRule.objects.all()}
        return parse(self.ruleset, stored.__getitem__)

    def clean(self):
        try:
            self.ruleset = str(self.parsed())
        except ValueError as e:
            known = ", ".join(ActionPermissionRule.objects.values_list("code", flat=True)) or "none"
            raise ValidationError({"ruleset": f"{e} (the predicates: {known})"}) from None

    def sync_rules(self):
        """Link the predicates the ruleset uses (none when it doesn't parse: the checks report it)."""
        try:
            codes = self.parsed().codes()
        except ValueError:
            codes = set()
        self.rules.set(ActionPermissionRule.objects.filter(code__in=codes))


class ActionPermissionGroupRule(models.Model):
    """A predicate a group's ruleset uses."""

    group_rule = models.ForeignKey(ActionPermissionGroup, on_delete=models.CASCADE, related_name="+")
    rule = models.ForeignKey(ActionPermissionRule, on_delete=models.PROTECT, related_name="+")

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["group_rule", "rule"], name="django_action_permissions_group_rule_use")
        ]

    def __str__(self):
        return f"{self.group_rule}: {self.rule}"
