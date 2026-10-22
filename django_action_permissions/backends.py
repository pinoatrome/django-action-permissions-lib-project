"""Rules backends: they evaluate a group's ruleset on an object, and decide when it doesn't.

A ruleset (see `predicates`) answers `True`, `False` or `None` (no predicate applies), or a predicate raises
`PermissionDenied` (Django's, or DRF's when DRF is installed), which blocks the whole check: backends let it
through. What `None` means is the backend's policy, which goes with the project's default permission
(`ACTION_PERMISSIONS["DEFAULT_PERMISSION"]`, compared by its dotted path, so the backends work without DRF):

- `DenyUnlessAllowedRulesBackend` (with `DenyAll`): a ruleset must allow; `None` denies;
- `AllowUnlessBlockedRulesBackend` (with DRF's `AllowAny`): a ruleset must block; `None` allows.
"""

import logging

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from . import conf
from .predicates import Ruleset, cached_ruleset

logger = logging.getLogger(__name__)


class BaseRulesBackend:
    default_permission: str = ""  # the dotted path of the DRF permission class the backend goes with
    default_allows: bool = False  # the answer when no group's ruleset decides (`None`)

    def ruleset(self, expression: str, predicates: dict[str, str]) -> Ruleset:
        """The ruleset of a stored expression, its predicates given by `{code: fqn}` (parsed once per process).
        `ValueError` when it doesn't parse."""
        return cached_ruleset(expression, tuple(sorted(predicates.items())))

    def evaluate(self, expression: str, predicates: dict[str, str], user, obj) -> bool | None:
        """A ruleset's answer on `obj` for `user`; one that doesn't parse (the checks report it) doesn't allow."""
        try:
            ruleset = self.ruleset(expression, predicates)
        except ValueError:
            logger.error(f"ruleset {expression!r} can't be used", exc_info=True)
            return False
        return ruleset(user, obj)


class DenyUnlessAllowedRulesBackend(BaseRulesBackend):
    """A ruleset must allow: when none decides (`None`), the answer is no."""

    default_permission = "django_action_permissions.permissions.DenyAll"
    default_allows = False


class AllowUnlessBlockedRulesBackend(BaseRulesBackend):
    """A ruleset must block: when none decides (`None`), the answer is yes."""

    default_permission = "rest_framework.permissions.AllowAny"
    default_allows = True


def backend_error() -> str | None:
    """What's wrong with `RULES_BACKEND` and `DEFAULT_PERMISSION` together, or None."""
    path = conf.get("RULES_BACKEND")
    try:
        backend_class = import_string(path)
    except ImportError as e:
        return f"RULES_BACKEND {path!r} can't be imported: {e}"
    if not (isinstance(backend_class, type) and issubclass(backend_class, BaseRulesBackend)):
        return f"RULES_BACKEND {path!r} isn't a BaseRulesBackend"
    default_permission = conf.get("DEFAULT_PERMISSION")
    if backend_class.default_permission != default_permission:
        return (
            f"RULES_BACKEND {path!r} goes with {backend_class.default_permission!r}, "
            f"not with DEFAULT_PERMISSION {default_permission!r}"
        )
    return None


def get_rules_backend() -> BaseRulesBackend:
    """The configured backend. `ImproperlyConfigured` when it can't be used with `DEFAULT_PERMISSION`."""
    error = backend_error()
    if error:
        raise ImproperlyConfigured(error)
    return import_string(conf.get("RULES_BACKEND"))()
