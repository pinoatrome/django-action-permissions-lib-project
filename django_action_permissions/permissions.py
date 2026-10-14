"""DRF permission classes that check a viewset action against the matching
Django model permission, with an RBAC table entry for each permission."""
import logging

from rest_framework import exceptions as rest_exceptions
from rest_framework import permissions as rest_permissions

logger = logging.getLogger(__name__)

# DRF answers OPTIONS with the `metadata` action, which describes the endpoint: it
# takes the permission to view it. To describe the input of POST and PUT, DRF checks
# the permissions again on a copy of the request with that method, still under the
# `metadata` action: those checks are the ones of the create and update actions.
METADATA_METHOD_OPERATIONS = {'POST': 'add', 'PUT': 'change'}


def parse_view_action(view):
    """The permission operation of a viewset action: Django's add/change/delete/view
    for the standard `ModelViewSet` actions, the action's own name for a custom one
    (e.g. `upload` -> `upload_document`)."""
    assert view, 'parse_view_action invoked with null view argument'
    if not view.action:
        # view called with wrong request method, not in its action map
        raise rest_exceptions.PermissionDenied('invalid request, no action in view')
    if view.action == 'metadata':
        return METADATA_METHOD_OPERATIONS.get(view.request.method, 'view')
    if view.action == 'create':
        return 'add'
    if view.action in ('update', 'partial_update'):
        return 'change'
    if view.action == 'destroy':
        return 'delete'
    if view.action in ('retrieve', 'list'):
        return 'view'
    logger.debug(f'view with custom action: {view.action}')
    return view.action


class BaseActionModelPermission(rest_permissions.BasePermission):
    """Allows a viewset action if the user holds the matching model permission,
    `<app_label>.<operation>_<model_name>` (see `parse_view_action`), e.g.
    `shop.view_order` to list orders; subclasses add the RBAC table
    entry of that permission (`get_perm_info`)."""

    detail_access_actions = ['retrieve', 'info']  # view actions to check for detail access

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
        logger.debug(f'checking user permission on {perm_code}')
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
        logger.debug(f'checking user object permission on {perm_code}')
        perm_info = self.get_perm_info(perm_code)
        if not perm_info:
            logger.warning(f"checking object permission '{perm_code}' on instance {obj}: permission info not found")
            return user.has_perm(perm_code, obj=obj)

        if not perm_info.get('abac') and not perm_info.get('rules'):
            logger.warning(f'Info permission {perm_code} with no abac nor rules for {user}')
            return self.has_permission(request, view)

        # check detail access again, already checked by has_permission
        if not self.has_detail_access_permission(request, view, user=user, perm_info=perm_info):
            return False
        allow = None
        for group in user.groups.all():
            # For each of the group the user is part of, the following checks are made.
            # If one fails the next group is evaluated.
            # If none fails the user has permission allowed and no more groups are evaluated.
            # So, user just needs one group OK to obtain permission
            logger.debug(f'checking object permission {perm_code} for {group.name}')

            # A staff group acts with the rights of its manager
            if group.name in perm_info.get('staff', []):
                staff_manager_user = self.manager_user(user)
                assert staff_manager_user, f'user {user} does not belong to any staff: manager is missing'
                # User to check on business rules becomes the manager
                user_to_check = staff_manager_user
            else:
                user_to_check = user

            # Get business rules based on abac (or specific rules): they depend on the
            # role the user has on a specific object, so they're implemented by
            # subclasses, in `apply_rule`.
            try:
                allow = self.do_check_user_group_object_abac(user_to_check, group, perm_info.get('abac'), obj)
                if allow is None:
                    allow = self.do_check_user_group_object_rules(user_to_check, group, perm_info.get('rules'), obj)
                if allow:
                    logger.info(f'Permission {perm_code} allowed for {group.name}')
                    return True
                logger.debug(f'Permissions {perm_code} disallowed for {group.name}: checking next user group (if any)')
            except rest_exceptions.PermissionDenied as e:
                logger.info(f'PermissionDenied: {perm_code} for {group.name} blocked - {e}')
                return False
        if allow is None:
            logger.info(f'Permissions {perm_code} has no active abac rules for all groups of {user}')
            allow = self.has_permission(request, view)

        logger.debug(f'Permissions {perm_code} for all groups of {user}: {allow}')
        return allow

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
        assert model_meta, f'{type(self).__name__}.get_perm_code() requires model_meta'
        return f'{model_meta.app_label}.{operation}_{model_meta.model_name}'

    def get_perm_info(self, perm_code) -> dict | None:
        """The RBAC table entry of `perm_code`: a dict with the groups granted the
        permission ('rbac') and optionally 'abac', 'rules', 'staff' and 'no_detail'."""
        raise NotImplementedError(f'{type(self).__name__} must implement get_perm_info()')

    def user(self, request):
        return request.user

    def manager_user(self, user):
        """The user whose rights a member of a 'staff' group acts with; needed only
        by permission table entries that list 'staff' groups."""
        raise NotImplementedError(f'{type(self).__name__} must implement manager_user()')

    def apply_rule(self, br_code, user, obj):
        return False  # no ABAC business rules defined yet

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
            logger.debug(f'checking user detail access permission on {perm_code} for {user}')
            perm_info = self.get_perm_info(perm_code)
        assert perm_info, f'has_detail_access_permission: permission info null for {self}'
        block_detail_access = False
        for group in user.groups.all():
            logger.debug(f'checking object detail access permission for {group.name} on {perm_info}')
            if group.name in perm_info.get('no_detail', []):
                block_detail_access = True
                logger.debug('detail permission blocked')
                break
        return not block_detail_access

    def do_check_user_group_object_abac(self, user, group, abac, obj) -> bool | None:
        """
        Check ABAC: allow permission if at least one business rule allows the user or None if no rules for the group
        :param user: the user to check for permission
        :param group: one of the groups of the user
        :param abac: the 'abac' content of the permission info item
        :param obj: the model instance
        :return: True if at least one rule allows or None if no rules for the group
        """
        abac_rules = abac.get(group.name, []) if abac else []
        for br_code in abac_rules:
            logger.debug(f'evaluating abac rule {br_code} for object permission on {obj}')
            if self.apply_rule(br_code, user, obj):
                logger.debug(f'abac rule {br_code} succeeded')
                return True
        return False if abac_rules else None

    def do_check_user_group_object_rules(self, user, group, rules, obj) -> bool | None:
        """
        Check BR: allow permission if and only if all business rules allows the user
        :param user: user to check for permissions (request user, or its manager for a staff group)
        :param group: one of the user groups
        :param rules: the 'rules' content of the permission info item
        :param obj: the model instance
        :return: False if at least one rule disallows or None if no rules for the group
        """
        br_codes = [r['code'] for r in rules if group.name in r['for']] if rules else []
        for br_code in br_codes:
            allow = self.apply_rule(br_code, user, obj)
            if not allow:
                logger.debug(f'rule {br_code} disallowed in group {group.name} of {user}')
                return False
        return True if br_codes else None


class DenyAll(rest_permissions.BasePermission):
    """Denies every request. Set it as `DEFAULT_PERMISSION_CLASSES` (`REST_FRAMEWORK`
    in settings) so a view that doesn't set its own `permission_classes` is closed."""

    def has_permission(self, request, view):
        return False
