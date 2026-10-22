from importlib.util import find_spec

from django.utils.module_loading import import_string


def drf_installed() -> bool:
    """Whether Django REST framework is installed (the `drf` extra)."""
    return find_spec("rest_framework") is not None


def import_rule(fqn: str):
    """The rule function at the dotted path `fqn`. `ImportError` when it doesn't import, `TypeError` when what it
    names isn't callable."""
    function = import_string(fqn)
    if not callable(function):
        raise TypeError(f"'{fqn}' isn't callable")
    return function


def rule_error(fqn: str) -> str | None:
    """Why `fqn` isn't a usable rule function, or None when it is."""
    try:
        import_rule(fqn)
    except (ImportError, TypeError) as e:
        return str(e)
    return None
