"""DRF permission classes that check a viewset action against the matching
Django model permission, with the action permission's entry (`entries`), its
objects checked by `abac.allowed`. The one module that needs Django
REST framework (the `drf` extra); for an open default, DRF's own `AllowAny`."""

import logging

from django.http import Http404
from rest_framework import exceptions as rest_exceptions
from rest_framework import permissions as rest_permissions

from . import abac, entries

logger = logging.getLogger(__name__)

# DRF answers OPTIONS with the `metadata` action, which describes the endpoint: it
# takes the permission to view it. To describe the input of POST and PUT, DRF checks
# the permissions again on a copy of the request with that method, still under the
# `metadata` action: those checks are the ones of the create and update actions.
METADATA_METHOD_OPERATIONS = {"POST": "add", "PUT": "change"}


def parse_view_action(view):
    """The permission operation of a viewset action: Django's add/change/delete/view
    for the standard `ModelViewSet` actions, the action's own name for a custom one
    (e.g. `upload` -> `upload_document`)."""
    assert view, "parse_view_action invoked with null view argument"
    if not view.action:
        # view called with wrong request method, not in its action map
        raise rest_exceptions.PermissionDenied("invalid request, no action in view")
    if view.action == "metadata":
        return METADATA_METHOD_OPERATIONS.get(view.request.method, "view")
    if view.action == "create":
        return "add"
    if view.action in ("update", "partial_update"):
        return "change"
    if view.action == "destroy":
        return "delete"
    if view.action in ("retrieve", "list"):
        return "view"
    logger.debug(f"view with custom action: {view.action}")
    return view.action


class BaseActionModelPermission(rest_permissions.BasePermission):
    """Allows a viewset action if the user holds the matching model permission,
    `<app_label>.<operation>_<model_name>` (see `parse_view_action`), e.g.
    `shop.view_order` to list orders, and an object if the action permission's
    entry of that permission allows it (`get_perm_info`, `abac.allowed`)."""

    detail_access_actions = ["retrieve", "info"]  # view actions to check for detail access
    # An object refused is a 404 when the user can't read it either (as DRF's DjangoObjectPermissions), so that
    # its existence isn't revealed; False: 403 for every refusal.
    not_found_when_unreadable = True

    def has_permission(self, request, view):
        user = self.user(request)
        if not view.action:
            # A method the viewset doesn't route. Only an authenticated user is told
            # it isn't allowed (405); denying an anonymous one makes DRF ask for
            # credentials instead (NotAuthenticated).
            if not user.is_authenticated:
                return False
            raise rest_exceptions.MethodNotAllowed(request.method)
        perm_code = self.get_perm_code(request, view)
        logger.debug(f"checking user permission on {perm_code}")
        perm_info = self.get_perm_info(perm_code)
        if not perm_info:
            logger.warning(f"checking user permission '{perm_code}': permission info not found")
        else:
            if not self.has_detail_access_permission(request, view, user=user, perm_info=perm_info):
                return False
        return user.has_perm(perm_code)

    def has_object_permission(self, request, view, obj):
        user = self.user(request)
        perm_code = self.get_perm_code(request, view, instance=obj)
        logger.debug(f"checking user object permission on {perm_code}")
        perm_info = self.get_perm_info(perm_code)
        if not perm_info:
            logger.warning(f"checking object permission '{perm_code}' on instance {obj}: permission info not found")
            ok = user.has_perm(perm_code, obj=obj)
        else:
            # check detail access again, already checked by has_permission
            if not self.has_detail_access_permission(request, view, user=user, perm_info=perm_info):
                return False
            ok = abac.allowed(user, perm_code, obj, manager_user=self.manager_user, perm_info=perm_info)
        if not ok and self.not_found_when_unreadable:
            if abac.refusal(user, perm_code, obj, manager_user=self.manager_user) is Http404:
                raise Http404
        return ok

    def skip_detail_access(self, skip_actions=None):
        if skip_actions:
            detail_access_actions = set(set(self.detail_access_actions) - set(skip_actions))
        else:
            detail_access_actions = {}
        self.detail_access_actions = list(detail_access_actions)

    def get_operation(self, request, view, instance=None):
        return parse_view_action(view)

    def get_model_meta(self, request, view, instance=None, operation=None, **kwargs):
        """The `_meta` of the viewset's model."""
        return view.get_queryset().model._meta

    def get_perm_code(self, request, view, instance=None):
        operation = self.get_operation(request, view, instance=instance)
        model_meta = self.get_model_meta(request, view, instance=instance, operation=operation)
        assert model_meta, f"{type(self).__name__}.get_perm_code() requires model_meta"
        return f"{model_meta.app_label}.{operation}_{model_meta.model_name}"

    def get_perm_info(self, perm_code) -> dict | None:
        """The entry of `perm_code` (`entries.perm_info`): its 'abac', 'predicates',
        'no_detail' and 'staff', or None when it isn't an action permission."""
        return entries.perm_info(perm_code)

    def user(self, request):
        return request.user

    def manager_user(self, user):
        """The user whose rights a member of a 'staff' group acts with; needed only
        by the entries that list 'staff' groups."""
        raise NotImplementedError(f"{type(self).__name__} must implement manager_user()")

    def has_detail_access_permission(self, request, view, user=None, perm_info=None):
        """
        detail_access_actions in view are allowed unless user group name is in 'no_detail'
        """
        if not view:
            return True
        if not (view.detail and view.action in self.detail_access_actions):
            return True
        if not user:
            user = request.user
        if not perm_info:
            perm_code = self.get_perm_code(request, view)
            logger.debug(f"checking user detail access permission on {perm_code} for {user}")
            perm_info = self.get_perm_info(perm_code)
        assert perm_info, f"has_detail_access_permission: permission info null for {self}"
        block_detail_access = False
        for group in user.groups.all():
            logger.debug(f"checking object detail access permission for {group.name} on {perm_info}")
            if group.name in perm_info.get("no_detail", []):
                block_detail_access = True
                logger.debug("detail permission blocked")
                break
        return not block_detail_access


class DenyAll(rest_permissions.BasePermission):
    """Denies every request. Set it as `DEFAULT_PERMISSION_CLASSES` (`REST_FRAMEWORK`
    in settings) so a view that doesn't set its own `permission_classes` is closed."""

    def has_permission(self, request, view):
        return False
