"""Plain Django views guarded by the action permissions (no Django REST framework needed): the counterparts of Django's
`permission_required` and `PermissionRequiredMixin`, built on `abac.unrestricted` and `abac.allowed`.

- `permission_required(perm, get_object=None)`: a view decorator. Without `get_object`, the user must hold the
  permission on any object (`unrestricted`), as a page acting on every object asks; with it, on the object it
  returns (`allowed`).
- `PermissionRequiredMixin`: a class-based view mixin. `dispatch` lets in a user holding the permission, maybe on
  their own objects only (`has_perm`; `permission_unrestricted = True` asks for any object), and `get_object()`
  checks the object (`allowed`).

As Django's: an anonymous visitor is sent to the login page; a signed-in user who may not is refused (403), not sent
to a login page they'd come back from, or answered 404 for an object they can't read either (as DRF's
`DjangoObjectPermissions`), so that its existence isn't revealed. Several permissions must all be held.
"""

from functools import wraps
from urllib.parse import urlsplit

from asgiref.sync import iscoroutinefunction, sync_to_async
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import AccessMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.shortcuts import resolve_url

from .abac import allowed, refusal, unrestricted


def _permissions(perm) -> tuple[str, ...]:
    return (perm,) if isinstance(perm, str) else tuple(perm)


def _login_redirect(request, login_url=None, redirect_field_name=REDIRECT_FIELD_NAME):
    """Django's `user_passes_test` redirect: the path only when the login page is on the same site."""
    path = request.build_absolute_uri()
    resolved_login_url = resolve_url(login_url or settings.LOGIN_URL)
    login_scheme, login_netloc = urlsplit(resolved_login_url)[:2]
    current_scheme, current_netloc = urlsplit(path)[:2]
    if (not login_scheme or login_scheme == current_scheme) and (not login_netloc or login_netloc == current_netloc):
        path = request.get_full_path()
    return redirect_to_login(path, resolved_login_url, redirect_field_name)


def permission_required(
    perm,
    *,
    get_object=None,
    manager_user=None,
    not_found_when_unreadable=True,
    login_url=None,
    redirect_field_name=REDIRECT_FIELD_NAME,
):
    """Guard a view with the action permissions.

    `perm` is a permission string ("app_label.codename") or several, all required. Without `get_object`, the user
    must hold them on any object (`unrestricted`); with `get_object(request, *args, **kwargs)`, on the object it
    returns (`allowed`; raise `Http404` there for a missing one), an object refused being a 404 when the user can't
    read it either (`abac.refusal`; `not_found_when_unreadable=False`: 403). `manager_user(user)` is the manager a
    `staff` group acts as. An anonymous visitor is redirected to `login_url` (`settings.LOGIN_URL`); a signed-in
    user who may not gets `PermissionDenied` (403). Sync and async views alike.
    """
    perms = _permissions(perm)

    def check(request, args, kwargs):
        """None when the request may go on, else the response (a login redirect), or `PermissionDenied`."""
        user = request.user
        if not user.is_authenticated:
            return _login_redirect(request, login_url, redirect_field_name)
        if get_object is None:
            if not all(unrestricted(user, p) for p in perms):
                raise PermissionDenied
            return None
        obj = get_object(request, *args, **kwargs)
        for p in perms:
            if not allowed(user, p, obj, manager_user=manager_user):
                if not_found_when_unreadable:
                    raise refusal(user, p, obj, manager_user=manager_user)
                raise PermissionDenied
        return None

    def decorator(view):
        if iscoroutinefunction(view):

            async def _view(request, *args, **kwargs):
                refused = await sync_to_async(check)(request, args, kwargs)
                return refused or await view(request, *args, **kwargs)

        else:

            def _view(request, *args, **kwargs):
                return check(request, args, kwargs) or view(request, *args, **kwargs)

        return wraps(view)(_view)

    return decorator


class PermissionRequiredMixin(AccessMixin):
    """A class-based view guarded by the action permissions, in place of Django's `PermissionRequiredMixin`.

    `dispatch` lets in a user holding `permission_required` (all of them, when several): through a group with or
    without a ruleset, so a user restricted to their own objects gets in; with `permission_unrestricted = True`,
    only one holding them on any object. `get_object()` (put it before `DetailView`, `UpdateView`, `DeleteView`...)
    refuses an object the rulesets don't allow the user: 404 when they can't read it either, else 403
    (`not_found_when_unreadable = False`: 403). Define `manager_user(user)` for `staff` groups.
    An anonymous visitor goes to the login page; a signed-in user who may not gets 403 (`AccessMixin`).
    """

    permission_required = None
    permission_unrestricted = False
    manager_user = None
    not_found_when_unreadable = True  # an object refused is a 404 when the user can't read it either

    def get_permission_required(self) -> tuple[str, ...]:
        if self.permission_required is None:
            name = type(self).__name__
            raise ImproperlyConfigured(
                f"{name} is missing the permission_required attribute. Define {name}.permission_required, "
                f"or override {name}.get_permission_required()."
            )
        return _permissions(self.permission_required)

    def has_permission(self) -> bool:
        user = self.request.user
        if self.permission_unrestricted:
            return all(unrestricted(user, perm) for perm in self.get_permission_required())
        return user.has_perms(self.get_permission_required())

    def has_object_permission(self, obj) -> bool:
        return self.refused_permission(obj) is None

    def refused_permission(self, obj) -> str | None:
        """The first permission the user may not use on `obj`, or None."""
        user = self.request.user
        for perm in self.get_permission_required():
            if not allowed(user, perm, obj, manager_user=self.manager_user):
                return perm
        return None

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated or not self.has_permission():
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        perm = self.refused_permission(obj)
        if perm is not None:
            if self.not_found_when_unreadable:
                raise refusal(self.request.user, perm, obj, manager_user=self.manager_user)
            raise PermissionDenied
        return obj
