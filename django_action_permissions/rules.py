"""The predicates the library defines, ready to compose into rulesets (`is_self | is_staff`). Their codes are
reserved: a project's predicate can't take one of them."""

from .predicates import predicate


@predicate
def always(user, obj):
    """Always allows."""
    return True


@predicate
def never(user, obj):
    """Never allows."""
    return False


@predicate
def is_authenticated(user, obj):
    """The user is authenticated."""
    return bool(user.is_authenticated)


@predicate
def is_active(user, obj):
    """The user's account is active."""
    return bool(user.is_active)


@predicate
def is_staff(user, obj):
    """The user may sign in to the admin site (Django's is_staff)."""
    return bool(user.is_staff)


@predicate
def is_superuser(user, obj):
    """The user is a superuser."""
    return bool(user.is_superuser)


@predicate
def is_self(user, obj):
    """The object is the user themselves."""
    return obj == user
