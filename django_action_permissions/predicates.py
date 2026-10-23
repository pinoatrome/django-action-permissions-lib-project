"""Predicates and rulesets: the rules of the action permissions on an object.

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
from dataclasses import dataclass, field
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


@dataclass
class TraceNode:
    """A node of a ruleset's evaluation (`Ruleset.trace`): a predicate (`label` its code) or an operator (`label` its
    symbol, `children` its operands). `evaluated` is False for an operand the evaluation skipped (`&` stops at the
    first `False`, `|` at the first `True`); `blocked` holds what a blocking exception said, `error` why a predicate
    can't be imported (it answers `False`)."""

    kind: str  # "predicate", "all", "any" or "not"
    label: str
    answer: bool | None = None
    evaluated: bool = True
    blocked: str | None = None
    error: str | None = None
    description: str = ""
    children: list["TraceNode"] = field(default_factory=list)


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

    def trace(self, user, obj, /, blocks=()) -> TraceNode:
        """The evaluation `__call__` makes, as a tree of `TraceNode`: the same answers, the predicates called in the
        same order, the operands it skips marked not evaluated. An exception of `blocks` is recorded where it's
        raised and stops the evaluation, as `__call__` lets it through; any other goes through."""
        raise NotImplementedError

    def skipped(self) -> TraceNode:
        """The tree of the ruleset, not evaluated."""
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

    def trace(self, user, obj, /, blocks=()):
        node = self.skipped()
        node.evaluated = True
        function = self.function
        if function is None:
            try:
                function = self.function = import_rule(self.fqn)
            except (ImportError, TypeError) as e:
                node.answer, node.error = False, str(e)
                return node
        try:
            node.answer = _answer(function(user, obj))
        except blocks as e:
            node.blocked = str(e) or type(e).__name__
        return node

    def skipped(self):
        return TraceNode("predicate", self.code, evaluated=False, description=self.description)

    def codes(self):
        return {self.code}

    def __str__(self):
        return self.code


class _Operator(Ruleset):
    symbol, kind = "", ""
    decisive: bool  # the answer of an operand that decides: the evaluation stops there

    def __init__(self, *operands: Ruleset):
        flat = []
        for operand in operands:
            flat.extend(operand.operands if type(operand) is type(self) else [operand])
        self.operands = tuple(flat)

    def codes(self):
        return set().union(*(operand.codes() for operand in self.operands))

    def trace(self, user, obj, /, blocks=()):
        node = TraceNode(self.kind, self.symbol.strip())
        stopped = False
        for operand in self.operands:
            if stopped:
                node.children.append(operand.skipped())
                continue
            child = operand.trace(user, obj, blocks)
            node.children.append(child)
            if child.blocked is not None:
                node.answer, node.blocked, stopped = None, child.blocked, True
            elif child.answer is self.decisive:
                node.answer, stopped = self.decisive, True
            elif child.answer is not None:
                node.answer = not self.decisive
        return node

    def skipped(self):
        return TraceNode(
            self.kind, self.symbol.strip(), evaluated=False, children=[operand.skipped() for operand in self.operands]
        )

    def __str__(self):
        return self.symbol.join(self._operand(operand) for operand in self.operands)


class AllOf(_Operator):
    symbol, kind, precedence, decisive = " & ", "all", 2, False

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
    symbol, kind, precedence, decisive = " | ", "any", 1, True

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

    def trace(self, user, obj, /, blocks=()):
        child = self.operand.trace(user, obj, blocks)
        node = TraceNode("not", "~", children=[child], blocked=child.blocked)
        node.answer = None if child.answer is None or child.blocked is not None else not child.answer
        return node

    def skipped(self):
        return TraceNode("not", "~", evaluated=False, children=[self.operand.skipped()])

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


class RulesetSyntaxError(ValueError):
    """An expression that doesn't parse: `position` is where (an index into it), `token` what was found there
    (None at the end)."""

    def __init__(self, message: str, position: int, token: str | None = None):
        super().__init__(message)
        self.position, self.token = position, token


_TOKEN = re.compile(r"(?P<space>\s+)|(?P<name>[A-Za-z_]\w*)|(?P<op>[&|~()])|(?P<bad>.)")


def _tokens(expression: str) -> list[tuple[str, int]]:
    """The expression's tokens with their positions: predicate codes, `&`, `|`, `~` and parentheses."""
    tokens = []
    for match in _TOKEN.finditer(expression):
        if match.lastgroup == "bad":
            raise RulesetSyntaxError(
                f"{expression!r}: unexpected {match.group()!r} at {match.start()}", match.start(), match.group()
            )
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
    unknown one). A malformed expression or an unknown code is a `RulesetSyntaxError` (a `ValueError`) saying
    where."""
    tokens = _tokens(expression)
    if not tokens:
        raise RulesetSyntaxError("an empty ruleset", 0)
    index = 0

    def peek():
        return tokens[index][0] if index < len(tokens) else None

    def fail(what):
        at = tokens[index][1] if index < len(tokens) else len(expression)
        token = tokens[index][0] if index < len(tokens) else None
        found = "the end" if token is None else repr(token)
        raise RulesetSyntaxError(f"{expression!r}: {what} {found} at {at}", at, token)

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
