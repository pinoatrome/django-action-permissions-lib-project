"""The admin: every model of the table editable (an entry on one page, with its rbac groups and its group rules),
and on the entries' list the configuration tools: Load YAML (superusers), Export YAML, Check configuration."""

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.db import models
from django.db.models import Count
from django.http import HttpResponse
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse

from . import checks
from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule
from .yaml_io import dump_yaml, load_yaml, yaml_available

TEMPLATES = "admin/django_action_permissions/actionpermission"
EXPORT_FILENAME = "action_permissions.yaml"


def _searchable(admin_site, model) -> bool:
    """Whether `model` is registered in `admin_site` with search fields, so that an autocomplete can use it."""
    model_admin = admin_site._registry.get(model)
    return bool(model_admin and model_admin.search_fields)


def _yaml_response(document: str) -> HttpResponse:
    response = HttpResponse(document, content_type="application/yaml; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{EXPORT_FILENAME}"'
    return response


@admin.register(ActionPermissionRule)
class ActionPermissionRuleAdmin(admin.ModelAdmin):
    list_display = ["code", "fqn", "description", "uses"]
    search_fields = ["code", "fqn", "description"]

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(uses_count=Count("usages"))

    @admin.display(ordering="uses_count")
    def uses(self, rule):
        return rule.uses_count


RULESET_WIDGET = {models.TextField: {"widget": forms.TextInput(attrs={"size": 80})}}


class ActionPermissionGroupInline(admin.TabularInline):
    model = ActionPermissionGroup
    fields = ["group", "ruleset"]
    extra = 0
    formfield_overrides = RULESET_WIDGET

    def get_autocomplete_fields(self, request):
        return ["group"] if _searchable(self.admin_site, Group) else []


class ActionPermissionForm(forms.ModelForm):
    rbac = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=FilteredSelectMultiple("groups", is_stacked=False),
        help_text="The groups granted the permission.",
    )

    class Meta:
        model = ActionPermission
        fields = ["permission", "rbac", "no_detail", "staff"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["rbac"].initial = self.instance.permission.group_set.all()


class LoadForm(forms.Form):
    file = forms.FileField(help_text="A YAML document: groups, rules, permissions.")
    keep = forms.BooleanField(
        required=False,
        help_text="Keep the groups' other permissions, and the entries and rules the document doesn't list.",
    )


@admin.register(ActionPermission)
class ActionPermissionAdmin(admin.ModelAdmin):
    form = ActionPermissionForm
    filter_horizontal = ["no_detail", "staff"]
    inlines = [ActionPermissionGroupInline]
    list_display = ["perm_code", "rbac", "rulesets", "no_detail_groups", "staff_groups"]
    list_filter = ["permission__content_type__app_label", "group_rules__group", "group_rules__rules"]
    search_fields = ["permission__codename", "permission__content_type__app_label", "permission__name"]
    actions = ["export_selected"]
    change_list_template = f"{TEMPLATES}/change_list.html"

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("permission__content_type")
            .prefetch_related("permission__group_set", "no_detail", "staff", "group_rules__group")
        )

    def get_autocomplete_fields(self, request):
        return ["permission"] if _searchable(self.admin_site, ActionPermission.permission.field.related_model) else []

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "permission":
            kwargs["queryset"] = db_field.related_model.objects.select_related("content_type")
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_related(self, request, form, formsets, change):
        super().save_related(request, form, formsets, change)
        form.instance.permission.group_set.set(form.cleaned_data["rbac"])

    @admin.display(description="permission", ordering="permission__codename")
    def perm_code(self, entry):
        return entry.perm_code

    @admin.display(description="rbac")
    def rbac(self, entry):
        return ", ".join(sorted(group.name for group in entry.permission.group_set.all()))

    @admin.display(description="abac rulesets")
    def rulesets(self, entry):
        return "; ".join(f"{row.group.name}: {row.ruleset}" for row in entry.group_rules.all())

    @admin.display(description="no detail")
    def no_detail_groups(self, entry):
        return ", ".join(sorted(group.name for group in entry.no_detail.all()))

    @admin.display(description="staff")
    def staff_groups(self, entry):
        return ", ".join(sorted(group.name for group in entry.staff.all()))

    # ── the configuration tools ──────────────────────────────────────────────

    def get_urls(self):
        info = self.opts.app_label, self.opts.model_name
        return [
            path("load/", self.admin_site.admin_view(self.load_view), name="{}_{}_load".format(*info)),
            path("export/", self.admin_site.admin_view(self.export_view), name="{}_{}_export".format(*info)),
            path("check/", self.admin_site.admin_view(self.check_view), name="{}_{}_check".format(*info)),
        ] + super().get_urls()

    def changelist_view(self, request, extra_context=None):
        extra_context = {**(extra_context or {}), "yaml_available": yaml_available()}
        return super().changelist_view(request, extra_context=extra_context)

    def _changelist_url(self):
        return reverse(f"admin:{self.opts.app_label}_{self.opts.model_name}_changelist")

    def _context(self, request, title, **context):
        return {**self.admin_site.each_context(request), "opts": self.opts, "title": title, **context}

    def _may_export(self, request) -> bool:
        return request.user.has_perms(
            [
                f"{self.opts.app_label}.view_{model._meta.model_name}"
                for model in (ActionPermission, ActionPermissionGroup, ActionPermissionRule)
            ]
        )

    def _yaml_missing(self, request):
        messages.error(request, "PyYAML isn't installed: pip install 'django-action-permissions[yaml]'")
        return redirect(self._changelist_url())

    def load_view(self, request):
        """Set up the table from an uploaded YAML document. Superusers only: it rewrites the groups' permissions."""
        if not request.user.is_superuser:
            raise PermissionDenied
        if not yaml_available():
            return self._yaml_missing(request)
        form = LoadForm(request.POST or None, request.FILES or None)
        if request.method == "POST" and form.is_valid():
            try:
                counts = load_yaml(form.cleaned_data["file"].read().decode("utf-8"), keep=form.cleaned_data["keep"])
            except (ValueError, UnicodeDecodeError) as e:
                form.add_error("file", str(e))
            else:
                messages.success(
                    request,
                    f"{counts['permissions']} permissions, {counts['rules']} rules, {counts['groups']} groups set up.",
                )
                return redirect(self._changelist_url())
        return TemplateResponse(request, f"{TEMPLATES}/load.html", self._context(request, "Load YAML", form=form))

    def export_view(self, request):
        if not self._may_export(request):
            raise PermissionDenied
        if not yaml_available():
            return self._yaml_missing(request)
        return _yaml_response(dump_yaml())

    def has_export_permission(self, request) -> bool:
        """The `export` permission of the `export_selected` action: without it the action isn't offered."""
        return yaml_available() and self._may_export(request)

    @admin.action(description="Export selected as YAML", permissions=["export"])
    def export_selected(self, request, queryset):
        return _yaml_response(dump_yaml(queryset=queryset))

    def check_view(self, request):
        if not self.has_view_permission(request):
            raise PermissionDenied
        issues = sorted(checks.run_all(), key=lambda issue: (-issue.level, issue.id))
        return TemplateResponse(
            request, f"{TEMPLATES}/check.html", self._context(request, "Check configuration", issues=issues)
        )


@admin.register(ActionPermissionGroup)
class ActionPermissionGroupAdmin(admin.ModelAdmin):
    fields = ["action_permission", "group", "ruleset"]
    list_display = ["action_permission", "group", "ruleset", "predicates"]
    list_filter = ["group", "rules"]
    search_fields = ["ruleset", "group__name", "action_permission__permission__codename"]
    formfield_overrides = RULESET_WIDGET

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("action_permission__permission__content_type", "group")
            .prefetch_related("rules")
        )

    def get_autocomplete_fields(self, request):
        return ["group"] if _searchable(self.admin_site, Group) else []

    @admin.display(description="predicates")
    def predicates(self, row):
        return ", ".join(sorted(rule.code for rule in row.rules.all()))
