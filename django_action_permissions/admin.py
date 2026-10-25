"""The admin: every model of the action permissions editable (an entry on one page, with its rbac groups and its
groups' rulesets, each ruleset checked as it's typed), and on the entries' list the tools:

- Overview: the entries against the groups, as a matrix, filtered;
- Verify (superusers): why a user may or may not use a permission, on an object, with a draft ruleset (`explain`);
- Load YAML (superusers), Export YAML, Check configuration;

and on the predicates' list, their status in the code and Sync predicates (`rbac.store_predicates`)."""

import json

from django import forms
from django.contrib import admin, messages
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ImproperlyConfigured, PermissionDenied, ValidationError
from django.db import models
from django.db.models import Count, Q
from django.forms.models import BaseInlineFormSet
from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import NoReverseMatch, path, reverse
from django.utils.html import format_html, format_html_join

from . import checks, conf
from .abac import held_permissions
from .entries import entry_codes
from .explain import draft_info, explain
from .models import ActionPermission, ActionPermissionGroup, ActionPermissionRule, stored_resolver
from .predicates import RulesetSyntaxError, codes_of, discover, parse
from .rbac import store_predicates
from .utils import rule_error
from .yaml_io import dump_yaml, load_yaml, yaml_available

TEMPLATES = "admin/django_action_permissions/actionpermission"
RULE_TEMPLATES = "admin/django_action_permissions/actionpermissionrule"
EXPORT_FILENAME = "action_permissions.yaml"
SETUP_NOTE = (
    "A setup, or a Load YAML without keep, replaces what is edited here: export the YAML to keep the definitions "
    "in the code in step."
)


def _searchable(admin_site, model) -> bool:
    """Whether `model` is registered in `admin_site` with search fields, so that an autocomplete can use it."""
    model_admin = admin_site._registry.get(model)
    return bool(model_admin and model_admin.search_fields)


def _yaml_response(document: str) -> HttpResponse:
    response = HttpResponse(document, content_type="application/yaml; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{EXPORT_FILENAME}"'
    return response


def _url(admin_site, opts, name: str, *args) -> str | None:
    """The admin URL `name` of a model, or None when `admin_site` doesn't register it."""
    try:
        return reverse(f"{admin_site.name}:{opts.app_label}_{opts.model_name}_{name}", args=args)
    except NoReverseMatch:
        return None


def check_ruleset(expression: str) -> dict:
    """A ruleset as the editor shows it: whether it parses against the stored predicates (else where it doesn't),
    its canonical form, the codes it names, and those not stored."""
    stored = set(ActionPermissionRule.objects.values_list("code", flat=True))
    codes = codes_of(expression)
    result = {"valid": False, "canonical": "", "codes": sorted(codes), "unknown": sorted(codes - stored)}
    try:
        ruleset = parse(expression, stored_resolver())
    except RulesetSyntaxError as e:
        return {**result, "error": str(e), "position": e.position}
    return {**result, "valid": True, "canonical": str(ruleset), "error": "", "position": None}


# ── the rulesets ─────────────────────────────────────────────────────────────


class RulesetWidget(forms.TextInput):
    """A ruleset's input, checked as it's typed against the stored predicates (the entries' `ruleset/validate/`),
    their codes offered as completions, with a link to try it in Verify (`ruleset.js`). Without JS, a text input."""

    template_name = "django_action_permissions/widgets/ruleset.html"

    class Media:
        css = {"all": ["django_action_permissions/ruleset.css"]}
        js = ["django_action_permissions/ruleset.js"]

    def __init__(self, attrs=None, validate_url="", verify_url=""):
        super().__init__(
            {"size": 80, "autocomplete": "off", "spellcheck": "false", "data-ruleset": "", **(attrs or {})}
        )
        self.validate_url, self.verify_url = validate_url, verify_url

    def get_context(self, name, value, attrs):
        context = super().get_context(name, value, attrs)
        predicates = list(ActionPermissionRule.objects.values("code", "description"))
        context["widget"]["attrs"].update(
            {
                "data-validate-url": self.validate_url,
                "data-verify-url": self.verify_url,
                "data-predicates": json.dumps(predicates),
            }
        )
        return context


def ruleset_widget(admin_site, request) -> RulesetWidget:
    """The ruleset widget of `admin_site`'s pages: Verify offered to the users who may use it."""
    opts = ActionPermission._meta
    entries_admin = admin_site._registry.get(ActionPermission)
    may_verify = entries_admin is not None and entries_admin.has_verify_permission(request)
    return RulesetWidget(
        validate_url=_url(admin_site, opts, "validate") or "",
        verify_url=(_url(admin_site, opts, "verify") or "") if may_verify else "",
    )


class ActionPermissionGroupFormSet(BaseInlineFormSet):
    def clean(self):
        """A ruleset is for a group holding the permission: one of the entry's form's `rbac` (check E006)."""
        super().clean()
        rbac = set(self.data.getlist("rbac")) if hasattr(self.data, "getlist") else set()
        for form in self.forms:
            data = getattr(form, "cleaned_data", None) or {}
            group = data.get("group")
            if group is not None and not data.get("DELETE") and str(group.pk) not in rbac:
                form.add_error(
                    "group",
                    f"{group.name} has a ruleset but isn't granted the permission: add it to rbac, or remove the "
                    "ruleset.",
                )


class ActionPermissionGroupInline(admin.TabularInline):
    model = ActionPermissionGroup
    formset = ActionPermissionGroupFormSet
    fields = ["group", "ruleset"]
    extra = 0

    def get_autocomplete_fields(self, request):
        return ["group"] if _searchable(self.admin_site, Group) else []

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == "ruleset":
            kwargs["widget"] = ruleset_widget(self.admin_site, request)
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def get_formset(self, request, obj=None, **kwargs):
        formset = super().get_formset(request, obj, **kwargs)
        if obj is not None:  # the permission Verify tries the ruleset on
            formset.form.base_fields["ruleset"].widget.attrs["data-perm"] = obj.perm_code
        return formset


# ── the predicates ───────────────────────────────────────────────────────────


@admin.register(ActionPermissionRule)
class ActionPermissionRuleAdmin(admin.ModelAdmin):
    list_display = ["code", "fqn", "description", "uses", "status"]
    search_fields = ["code", "fqn", "description"]
    readonly_fields = ["status", "used_by"]
    change_list_template = f"{RULE_TEMPLATES}/change_list.html"

    class Media:
        css = {"all": ["django_action_permissions/ruleset.css"]}

    def get_queryset(self, request):
        return super().get_queryset(request).annotate(uses_count=Count("usages"))

    @admin.display(ordering="uses_count")
    def uses(self, rule):
        return rule.uses_count

    @admin.display(description="status")
    def status(self, rule):
        """Where the predicate stands in the code: registered with `@predicate`, or only stored here."""
        if rule is None or not rule.pk:
            return "-"
        error = rule_error(rule.fqn)
        if error:
            return format_html('<span class="dap-bad" title="{}">doesn\'t import</span>', error)
        registered = discover().get(rule.code)
        if registered is None:
            return format_html('<span class="dap-warn">{}</span>', "stored only: no @predicate defines it")
        if registered.fqn != rule.fqn:
            return format_html('<span class="dap-warn">registered as {}</span>', registered.fqn)
        return format_html('<span class="dap-good">{}</span>', "registered")

    @admin.display(description="used by")
    def used_by(self, rule):
        rows = rule.usages.select_related("action_permission__permission__content_type", "group") if rule.pk else ()
        if not rows:
            return "-"
        opts = ActionPermissionGroup._meta
        return format_html_join(
            "",
            '<div><a href="{}">{} {}</a>: <code>{}</code></div>',
            (
                (
                    _url(self.admin_site, opts, "change", row.pk) or "#",
                    row.action_permission,
                    row.group.name,
                    row.ruleset,
                )
                for row in rows
            ),
        )

    def get_urls(self):
        info = self.opts.app_label, self.opts.model_name
        return [
            path("sync/", self.admin_site.admin_view(self.sync_view), name="{}_{}_sync".format(*info)),
        ] + super().get_urls()

    def has_sync_permission(self, request) -> bool:
        return self.has_add_permission(request) and self.has_change_permission(request)

    def changelist_view(self, request, extra_context=None):
        extra_context = {**(extra_context or {}), "may_sync": self.has_sync_permission(request)}
        return super().changelist_view(request, extra_context=extra_context)

    def sync_view(self, request):
        """Store the predicates registered in the code: on GET what it would write, on POST written."""
        if not self.has_sync_permission(request):
            raise PermissionDenied
        changelist = reverse(f"{self.admin_site.name}:{self.opts.app_label}_{self.opts.model_name}_changelist")
        if request.method == "POST":
            try:
                count = store_predicates()
            except ValueError as e:
                messages.error(request, str(e))
            else:
                messages.success(request, f"{count} registered predicates stored.")
            return redirect(changelist)
        stored = {rule.code: rule for rule in ActionPermissionRule.objects.all()}
        rows = []
        for code, registered in sorted(discover().items()):
            rule = stored.get(code)
            if rule is None:
                change = "new"
            elif (rule.fqn, rule.description) != (registered.fqn, registered.description):
                change = "changed"
            else:
                change = ""
            rows.append({"code": code, "fqn": registered.fqn, "description": registered.description, "change": change})
        context = {
            **self.admin_site.each_context(request),
            "opts": self.opts,
            "title": "Sync predicates",
            "rows": rows,
            "changes": sum(1 for row in rows if row["change"]),
        }
        return TemplateResponse(request, f"{RULE_TEMPLATES}/sync.html", context)


# ── the entries ──────────────────────────────────────────────────────────────


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


class VerifyForm(forms.Form):
    user = forms.CharField(label="User", help_text="The username of the user to check.")
    perm = forms.CharField(
        label="Permission",
        required=False,
        widget=forms.TextInput(attrs={"list": "dap-perms", "size": 40}),
        help_text="app_label.codename. Without it: every action permission the user holds.",
    )
    obj = forms.CharField(
        label="Object",
        required=False,
        help_text="The primary key of an object of the permission's model. Without it: on any object.",
    )
    draft_group = forms.CharField(
        label="Draft for group", required=False, help_text="What if this group's ruleset were the draft below?"
    )
    draft_ruleset = forms.CharField(
        label="Draft ruleset", required=False, help_text="Blank: the group holds the permission on any object."
    )

    def __init__(self, *args, ruleset_widget=None, **kwargs):
        super().__init__(*args, **kwargs)
        if ruleset_widget is not None:
            self.fields["draft_ruleset"].widget = ruleset_widget

    def clean_user(self):
        username = self.cleaned_data["user"]
        try:
            return get_user_model()._default_manager.get_by_natural_key(username)
        except get_user_model().DoesNotExist:
            raise ValidationError(f"No user {username!r}.") from None

    def clean(self):
        data = super().clean()
        perm, pk, group = data.get("perm", "").strip(), data.get("obj", "").strip(), data.get("draft_group", "").strip()
        data["perm"], data["obj"], data["draft"] = perm, None, None
        if (pk or group) and not perm:
            raise ValidationError("An object or a draft needs a permission.")
        if pk:
            app_label, _, codename = perm.partition(".")
            permission = Permission.objects.filter(content_type__app_label=app_label, codename=codename).first()
            model = permission.content_type.model_class() if permission else None
            if model is None:
                self.add_error("perm", f"No permission {perm!r} of an installed model.")
            else:
                try:
                    data["obj"] = model._default_manager.get(pk=pk)
                except (model.DoesNotExist, ValueError, ValidationError):
                    self.add_error("obj", f"No {model._meta.verbose_name} {pk!r}.")
        if group:
            if not Group.objects.filter(name=group).exists():
                self.add_error("draft_group", f"No group {group!r}.")
            else:
                try:
                    draft_info(perm, group, data.get("draft_ruleset", ""))
                except ValueError as e:
                    self.add_error("draft_ruleset" if isinstance(e, RulesetSyntaxError) else "perm", str(e))
                else:
                    data["draft"] = (group, data.get("draft_ruleset", ""))
        return data


@admin.register(ActionPermission)
class ActionPermissionAdmin(admin.ModelAdmin):
    form = ActionPermissionForm
    fieldsets = [(None, {"fields": ["permission", "rbac", "no_detail", "staff"], "description": SETUP_NOTE})]
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

    # ── the tools ────────────────────────────────────────────────────────────

    def get_urls(self):
        info = self.opts.app_label, self.opts.model_name
        tools = {
            "load": self.load_view,
            "export": self.export_view,
            "check": self.check_view,
            "overview": self.overview_view,
            "verify": self.verify_view,
            "validate": self.validate_view,
        }
        urls = [
            path(f"{name}/", self.admin_site.admin_view(view), name="{}_{}_{}".format(*info, name))
            for name, view in tools.items()
        ]
        return urls + super().get_urls()

    def changelist_view(self, request, extra_context=None):
        extra_context = {
            **(extra_context or {}),
            "yaml_available": yaml_available(),
            "may_verify": self.has_verify_permission(request),
        }
        return super().changelist_view(request, extra_context=extra_context)

    def has_verify_permission(self, request) -> bool:
        """Who may use Verify: superusers, as it runs the project's predicates on any object, for any user.
        Override it to open it to others."""
        return request.user.is_superuser

    def _changelist_url(self):
        return reverse(f"{self.admin_site.name}:{self.opts.app_label}_{self.opts.model_name}_changelist")

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
        """Set up the permission definitions of an uploaded YAML document. Superusers only: it rewrites the groups'
        permissions."""
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
        issues = [
            {"issue": issue, "url": self._object_url(issue.obj)}
            for issue in sorted(checks.run_all(), key=lambda issue: (-issue.level, issue.id))
        ]
        return TemplateResponse(
            request, f"{TEMPLATES}/check.html", self._context(request, "Check configuration", issues=issues)
        )

    def _object_url(self, obj) -> str | None:
        """The change page of a model instance in this admin site, or None."""
        if not isinstance(obj, models.Model) or not self.admin_site.is_registered(type(obj)):
            return None
        return _url(self.admin_site, obj._meta, "change", obj.pk)

    def overview_view(self, request):
        """The entries against the groups: who holds each permission, on which objects (a ruleset) or any."""
        if not self.has_view_permission(request):
            raise PermissionDenied
        filters = {name: request.GET.get(name, "").strip() for name in ("q", "app", "group", "predicate")}
        selected = [pk for pk in request.GET.getlist("entry") if pk.isdigit()]  # the rows checked in the list
        entries = self.get_queryset(request)
        if selected:
            entries = entries.filter(pk__in=selected)
        if filters["q"]:
            q = filters["q"]
            entries = entries.filter(
                Q(permission__codename__icontains=q)
                | Q(permission__name__icontains=q)
                | Q(permission__content_type__app_label__icontains=q)
            )
        if filters["app"]:
            entries = entries.filter(permission__content_type__app_label=filters["app"])
        if filters["predicate"]:
            entries = entries.filter(group_rules__rules__code=filters["predicate"]).distinct()
        if filters["group"]:
            entries = entries.filter(
                Q(permission__group__name=filters["group"]) | Q(group_rules__group__name=filters["group"])
            ).distinct()
        entries = list(entries)

        named = set()
        for entry in entries:
            named.update(group.name for group in entry.permission.group_set.all())
            named.update(row.group.name for row in entry.group_rules.all())
            named.update(group.name for group in [*entry.no_detail.all(), *entry.staff.all()])
        columns = sorted({filters["group"]} & named if filters["group"] else named)
        rows = [self._overview_row(request, entry, columns) for entry in entries]
        column_links = []  # each group's header: the same filters, only that group (Django 5.1's {% querystring %})
        for name in columns:
            query = request.GET.copy()
            query["group"] = name
            column_links.append((name, f"?{query.urlencode()}"))

        unlisted = []
        if filters["app"] and self.has_add_permission(request):
            add = _url(self.admin_site, self.opts, "add")
            unlisted = [
                {"permission": permission, "add_url": f"{add}?permission={permission.pk}"}
                for permission in Permission.objects.filter(
                    content_type__app_label=filters["app"], action_permission__isnull=True
                ).select_related("content_type")
            ]
        context = self._context(
            request,
            "Overview",
            filters=filters,
            selected=selected,
            columns=columns,
            column_links=column_links,
            rows=rows,
            unlisted=unlisted,
            apps=sorted(set(ContentType.objects.values_list("app_label", flat=True))),
            groups=Group.objects.order_by("name").values_list("name", flat=True),
            predicates=ActionPermissionRule.objects.values_list("code", flat=True),
            may_verify=self.has_verify_permission(request),
        )
        return TemplateResponse(request, f"{TEMPLATES}/overview.html", context)

    def _overview_row(self, request, entry, columns) -> dict:
        granted = {group.name: group for group in entry.permission.group_set.all()}
        rulesets = {row.group.name: row for row in entry.group_rules.all()}
        no_detail = {group.name for group in entry.no_detail.all()}
        staff = {group.name for group in entry.staff.all()}
        ruleset_opts = ActionPermissionGroup._meta
        may_add_ruleset = self.admin_site._registry.get(ActionPermissionGroup) is not None and request.user.has_perm(
            f"{ruleset_opts.app_label}.add_{ruleset_opts.model_name}"
        )
        add_ruleset = _url(self.admin_site, ruleset_opts, "add") if may_add_ruleset else None
        cells = []
        for name in columns:
            row = rulesets.get(name)
            cell = {"group": name, "granted": name in granted, "no_detail": name in no_detail, "staff": name in staff}
            if row is not None:
                cell.update(ruleset=row.ruleset, url=_url(self.admin_site, ruleset_opts, "change", row.pk))
            elif name in granted and add_ruleset:
                cell["add_url"] = f"{add_ruleset}?action_permission={entry.pk}&group={granted[name].pk}"
            cells.append(cell)
        return {
            "entry": entry,
            "model": f"{entry.permission.content_type.app_label}.{entry.permission.content_type.model}",
            "url": _url(self.admin_site, self.opts, "change", entry.pk),
            "cells": cells,
        }

    def verify_view(self, request):
        """Why a user may or may not use a permission (on an object; with a draft ruleset): `explain`. Or, given only
        a user, the action permissions they hold."""
        if not self.has_verify_permission(request):
            raise PermissionDenied
        widget = ruleset_widget(self.admin_site, request)
        widget.verify_url = ""  # already here
        query = request.GET.copy()
        entry = query.pop("entry", [""])[0]  # the row checked in the list: its permission
        if entry.isdigit() and not query.get("perm"):
            first = ActionPermission.objects.filter(pk=entry).select_related("permission__content_type").first()
            if first is not None:
                query["perm"] = first.perm_code
        bound = "user" in query
        form = VerifyForm(query if bound else None, initial=query.dict(), ruleset_widget=widget)
        context = {"form": form, "perm_codes": sorted(entry_codes(ActionPermission.objects.all()))}
        if bound and form.is_valid():
            data = form.cleaned_data
            user = data["user"]
            if not data["perm"]:
                context["held"] = sorted(held_permissions(user).items())
            else:
                try:
                    manager_user = conf.manager_user()
                except ImportError as e:
                    manager_user = None
                    messages.warning(request, f"MANAGER_USER can't be imported ({e}): staff groups allow nothing.")
                try:
                    context["explanation"] = explain(
                        user, data["perm"], data["obj"], manager_user=manager_user, draft=data["draft"]
                    )
                except ImproperlyConfigured as e:
                    form.add_error(None, str(e))
        return TemplateResponse(request, f"{TEMPLATES}/verify.html", self._context(request, "Verify", **context))

    def validate_view(self, request):
        """A ruleset checked against the stored predicates, as JSON (`check_ruleset`): the editor's live check."""
        if request.method != "GET":
            return HttpResponseNotAllowed(["GET"])
        opts = ActionPermissionGroup._meta
        if not request.user.has_perm(f"{opts.app_label}.view_{opts.model_name}") and not request.user.has_perm(
            f"{opts.app_label}.change_{opts.model_name}"
        ):
            raise PermissionDenied
        return JsonResponse(check_ruleset(request.GET.get("expression", "")))


class ActionPermissionGroupForm(forms.ModelForm):
    class Meta:
        model = ActionPermissionGroup
        fields = ["action_permission", "group", "ruleset"]

    def clean(self):
        """A ruleset is for a group holding the permission (check E006)."""
        data = super().clean()
        entry, group = data.get("action_permission"), data.get("group")
        if entry is not None and group is not None and not group.permissions.filter(pk=entry.permission_id).exists():
            self.add_error(
                "group",
                f"{group.name} isn't granted {entry.perm_code}: grant it on the entry's page (rbac) first.",
            )
        return data


@admin.register(ActionPermissionGroup)
class ActionPermissionGroupAdmin(admin.ModelAdmin):
    form = ActionPermissionGroupForm
    fieldsets = [(None, {"fields": ["action_permission", "group", "ruleset"], "description": SETUP_NOTE})]
    list_display = ["action_permission", "group", "ruleset", "predicates"]
    list_filter = ["group", "rules"]
    search_fields = ["ruleset", "group__name", "action_permission__permission__codename"]

    def get_queryset(self, request):
        return (
            super()
            .get_queryset(request)
            .select_related("action_permission__permission__content_type", "group")
            .prefetch_related("rules")
        )

    def get_autocomplete_fields(self, request):
        return ["group"] if _searchable(self.admin_site, Group) else []

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == "ruleset":
            kwargs["widget"] = ruleset_widget(self.admin_site, request)
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "action_permission":
            kwargs["queryset"] = ActionPermission.objects.select_related("permission__content_type")
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    @admin.display(description="predicates")
    def predicates(self, row):
        return ", ".join(sorted(rule.code for rule in row.rules.all()))
