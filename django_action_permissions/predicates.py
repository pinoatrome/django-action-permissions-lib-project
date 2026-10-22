"""Predicates and rulesets: the rules of the permissions table on an object.

A predicate is a function `(user, obj) -> bool | None` (the `Predicate` protocol): `True` or `False`, `None` when it
doesn't apply, or it raises `PermissionDenied` (Django's, or DRF's), which blocks. `@predicate` makes a function
one: it gets a code (its name, unless given), a description (its docstring's first paragraph) and its dotted path,
and is registered, so that setup stores its definition in the database. Predicates compose into rulesets:

| | evaluates | answers |
|---|---|---|
| `a & b & ...` | left to right, up to the first `False` | `False` if one is; else `True` if one is; else `None` |
| `a | b | ...` | left to right, up to the first `True` | `True` if one is; else `False` if one is; else `None` |
| `~a` | `a` | `True` and `False` swapped; `None` stays `None` |

`~` binds tighter than `&`, and `&` tighter than `|`. A ruleset is written as the expression (`str()`),
`own_order & ~archived | is_staff`, and read back with `parse`.

The registry holds what the code defines, the same in every process: it isn't shared state.
"""

import inspect
import logging
import re
from functools import lru_cache
from typing import Protocol, runtime_checkable

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import autodiscover_modules

from .utils import import_rule

logger = logging.getLogger(__name__)


@runtime_checkable
class Predicate(Protocol):
    def __call__(self, user, obj, /) -> bool | None: ...


def _answer(value) -> bool | None:
    return None if value is None else bool(value)


def _ruleset(value) -> "Ruleset":
    if isinstance(value, Ruleset):
        return value
    raise TypeError(f"{value!r} isn't a predicate: decorate it with @predicate")


class Ruleset:
    """A predicate or a composition of predicates (`&`, `|`, `~`)."""

    precedence = 3  # a leaf, or ~: binds tightest

    def __and__(self, other):
        return AllOf(self, _ruleset(other))

    def __or__(self, other):
        return AnyOf(self, _ruleset(other))

    def __invert__(self):
        return Not(self)

    def __call__(self, user, obj, /) -> bool | None:
        raise NotImplementedError

    def codes(self) -> set[str]:
        """The codes of the predicates it uses."""
        raise NotImplementedError

    def _operand(self, operand: "Ruleset") -> str:
        return f"({operand})" if operand.precedence < self.precedence else str(operand)

    def __eq__(self, other):
        return isinstance(other, Ruleset) and str(self) == str(other)

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return f"<{type(self).__name__} {self}>"


class NamedPredicate(Ruleset):
    """A predicate with its code: a decorated function, or a reference to one by its dotted path (`fqn`), imported
    when first called; one that can't be imported answers `False`."""

    def __init__(self, code: str, fqn: str, function=None, description: str = ""):
        self.code, self.fqn, self.function, self.description = code, fqn, function, description

    def __call__(self, user, obj, /):
        function = self.function
        if function is None:
            try:
                function = self.function = import_rule(self.fqn)
            except (ImportError, TypeError):
                logger.error(f"predicate {self.code!r}: {self.fqn!r} can't be used", exc_info=True)
                return False
        answer = _answer(function(user, obj))
        logger.debug(f"predicate {self.code!r} on {obj!r} for {user}: {answer}")
        return answer

    def codes(self):
        return {self.code}

    def __str__(self):
        return self.code


class _Operator(Ruleset):
    symbol = ""

    def __init__(self, *operands: Ruleset):
        flat = []
        for operand in operands:
            flat.extend(operand.operands if type(operand) is type(self) else [operand])
        self.operands = tuple(flat)

    def codes(self):
        return set().union(*(operand.codes() for operand in self.operands))

    def __str__(self):
        return self.symbol.join(self._operand(operand) for operand in self.operands)


class AllOf(_Operator):
    symbol, precedence = " & ", 2

    def __call__(self, user, obj, /):
        answer = None
        for operand in self.operands:
            result = operand(user, obj)
            if result is False:
                return False
            if result:
                answer = True
        return answer


class AnyOf(_Operator):
    symbol, precedence = " | ", 1

    def __call__(self, user, obj, /):
        answer = None
        for operand in self.operands:
            result = operand(user, obj)
            if result:
                return True
            if result is False:
                answer = False
        return answer


class Not(Ruleset):
    def __init__(self, operand: Ruleset):
        self.operand = operand

    def __call__(self, user, obj, /):
        result = self.operand(user, obj)
        return None if result is None else not result

    def codes(self):
        return self.operand.codes()

    def __str__(self):
        return f"~{self._operand(self.operand)}"


# ── the registry ─────────────────────────────────────────────────────────────

REGISTRY: dict[str, NamedPredicate] = {}


def predicate(function=None, *, code=None, description=None):
    """Make `function(user, obj)` a predicate, registered under `code` (its name by default). A code taken by
    another function is `ImproperlyConfigured`; the same function again (a module reloaded) replaces itself."""

    def register(function):
        name = code or function.__name__
        fqn = f"{function.__module__}.{function.__qualname__}"
        text = description if description is not None else (inspect.getdoc(function) or "").split("\n\n")[0]
        existing = REGISTRY.get(name)
        if existing is not None and existing.fqn != fqn:
            raise ImproperlyConfigured(f"predicate {name!r} is already {existing.fqn}, it can't be {fqn} too")
        REGISTRY[name] = registered = NamedPredicate(name, fqn, function, " ".join(text.split()))
        registered.__doc__, registered.__module__, registered.__qualname__ = (
            function.__doc__,
            function.__module__,
            function.__qualname__,
        )
        return registered

    return register(function) if function is not None else register


def discover() -> dict[str, NamedPredicate]:
    """Import each installed app's `rules` module (this library's included) and return the registered
    predicates."""
    autodiscover_modules("rules")
    return dict(REGISTRY)


# ── the expressions ──────────────────────────────────────────────────────────

_TOKEN = re.compile(r"(?P<space>\s+)|(?P<name>[A-Za-z_]\w*)|(?P<op>[&|~()])|(?P<bad>.)")


def _tokens(expression: str) -> list[tuple[str, int]]:
    """The expression's tokens with their positions: predicate codes, `&`, `|`, `~` and parentheses."""
    tokens = []
    for match in _TOKEN.finditer(expression):
        if match.lastgroup == "bad":
            raise ValueError(f"{expression!r}: unexpected {match.group()!r} at {match.start()}")
        if match.lastgroup != "space":
            tokens.append((match.group(), match.start()))
    return tokens


def codes_of(expression: str) -> set[str]:
    """The predicate codes an expression names, parsed or not."""
    try:
        return {token for token, _ in _tokens(expression) if token not in "&|~()"}
    except ValueError:
        return set()


def parse(expression: str, resolve) -> Ruleset:
    """The ruleset an expression writes, its codes given by `resolve(code) -> NamedPredicate` (`KeyError` for an
    unknown one). A malformed expression or an unknown code is a `ValueError` saying where."""
    tokens = _tokens(expression)
    if not tokens:
        raise ValueError("an empty ruleset")
    index = 0

    def peek():
        return tokens[index][0] if index < len(tokens) else None

    def fail(what):
        at = tokens[index][1] if index < len(tokens) else len(expression)
        token = repr(tokens[index][0]) if index < len(tokens) else "the end"
        raise ValueError(f"{expression!r}: {what} {token} at {at}")

    def any_of():
        nonlocal index
        operands = [all_of()]
        while peek() == "|":
            index += 1
            operands.append(all_of())
        return operands[0] if len(operands) == 1 else AnyOf(*operands)

    def all_of():
        nonlocal index
        operands = [factor()]
        while peek() == "&":
            index += 1
            operands.append(factor())
        return operands[0] if len(operands) == 1 else AllOf(*operands)

    def factor():
        nonlocal index
        token = peek()
        if token == "~":
            index += 1
            return Not(factor())
        if token == "(":
            index += 1
            inner = any_of()
            if peek() != ")":
                fail("expected ')', not")
            index += 1
            return inner
        if token is None or token in "&|)":
            fail("unexpected")
        try:
            leaf = resolve(token)
        except KeyError:
            fail("unknown predicate")
        index += 1
        return leaf

    ruleset = any_of()
    if index < len(tokens):
        fail("unexpected")
    return ruleset


def canonical(ruleset, resolve) -> Ruleset:
    """A ruleset given as a `Ruleset` or as an expression, parsed (and so checked) with `resolve`."""
    if isinstance(ruleset, str):
        return parse(ruleset, resolve)
    return parse(str(_ruleset(ruleset)), resolve)


@lru_cache(maxsize=1024)
def cached_ruleset(expression: str, predicates: tuple[tuple[str, str], ...]) -> Ruleset:
    """The ruleset of a stored expression, its predicates referenced by `(code, fqn)`. Parsed once per process:
    the same input always gives the same ruleset."""
    references = {code: NamedPredicate(code, fqn) for code, fqn in predicates}
    return parse(expression, references.__getitem__)
