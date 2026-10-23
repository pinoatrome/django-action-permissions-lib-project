"""Why a user may, or may not, use an action permission: `abac.allowed`'s answer step by step, each group's ruleset
evaluated as a tree (`Ruleset.trace`). What the admin's Verify page shows; usable in a shell or a test too.

`explain` goes through the steps of `unrestricted` and `allowed`, with their helpers, so its `allowed` is their
answer. Unlike them, it doesn't let an exception through: a block, or a predicate that raises, is reported. With a
`draft` (a group and a ruleset), it answers as if that group's ruleset were the draft (`draft_info`): who holds the
permission is still read from the database.
"""

from dataclasses import dataclass, field

from django.http import Http404

from . import entries
from .abac import BLOCKS, _restricted, granting_groups, refusal
from .backends import BaseRulesBackend, get_rules_backend
from .predicates import TraceNode, parse


@dataclass
class Step:
    """A check of the way to the answer, before the rulesets: passed or not."""

    label: str
    passed: bool
    detail: str = ""


@dataclass
class GroupAnswer:
    """A group of the user holding the permission, and what its ruleset answered."""

    group: str
    expression: str = ""  # empty: held without a ruleset, on any object
    draft: bool = False  # the expression is the draft's
    checked_user: str = ""  # whose rights the ruleset ran with: the user, or a staff group's manager
    skipped: str = ""  # why the ruleset didn't run
    error: str = ""  # it doesn't parse, or a predicate raised
    trace: TraceNode | None = None
    answer: bool | None = None
    blocked: str | None = None


@dataclass
class Explanation:
    perm_code: str
    user: object
    obj: object = None
    entry: dict | None = None
    steps: list[Step] = field(default_factory=list)
    groups: list[GroupAnswer] = field(default_factory=list)
    backend: str = ""
    default_allows: bool = False
    allowed: bool = False
    reason: str = ""
    refusal: int | None = None  # with an object refused: the status a view answers, 403 or 404
    raises: str = ""  # a predicate raised what no check catches: a view answers 500
    no_detail: list[str] = field(default_factory=list)  # the user's groups that may not retrieve a single object
    draft: tuple[str, str] | None = None
    notes: list[str] = field(default_factory=list)

    def finish(self, allowed: bool, reason: str) -> "Explanation":
        self.allowed, self.reason = allowed, reason
        return self


def draft_info(perm_code: str, group: str, expression: str) -> dict:
    """The entry of `perm_code` from the database, with `group`'s ruleset replaced by `expression` (canonical), or
    removed when it's blank (the group holds the permission on any object). `ValueError` when it isn't an action
    permission, or the expression doesn't parse against the stored predicates (`RulesetSyntaxError`)."""
    from .models import ActionPermissionRule, stored_resolver

    entry = entries.read_entry(perm_code)
    if entry is None:
        raise ValueError(f"{perm_code} isn't an action permission")
    abac = dict(entry["abac"])
    if expression.strip():
        abac[group] = str(parse(expression, stored_resolver()))
    else:
        abac.pop(group, None)
    codes = set().union(*(parse(ruleset, stored_resolver()).codes() for ruleset in abac.values()))
    predicates = dict(ActionPermissionRule.objects.filter(code__in=codes).values_list("code", "fqn"))
    return {**entry, "abac": abac, "predicates": predicates}


def _describe(node: TraceNode, descriptions: dict[str, str]) -> None:
    if node.kind == "predicate":
        node.description = node.description or descriptions.get(node.label, "")
    for child in node.children:
        _describe(child, descriptions)


def explain(user, perm_code: str, obj=None, *, manager_user=None, draft: tuple[str, str] | None = None) -> Explanation:
    """How `abac.allowed(user, perm_code, obj, manager_user=manager_user)` answers, step by step, and with an object
    refused, what a view answers (`abac.refusal`). With `draft`, `(group, expression)`, as if the group's ruleset were
    `expression` (see `draft_info`)."""
    info = draft_info(perm_code, *draft) if draft else entries.perm_info(perm_code)
    explanation = _explain(Explanation(perm_code, user, obj, entry=info, draft=draft), manager_user)
    if obj is not None and user.is_authenticated and not explanation.allowed and not explanation.raises:
        explanation.refusal = 404 if refusal(user, perm_code, obj, manager_user=manager_user) is Http404 else 403
    return explanation


def _explain(explanation: Explanation, manager_user) -> Explanation:
    from .models import ActionPermissionRule

    user, perm_code, obj, info, draft = (
        explanation.user,
        explanation.perm_code,
        explanation.obj,
        explanation.entry,
        explanation.draft,
    )
    steps = explanation.steps

    # unrestricted()
    steps.append(Step("authenticated", user.is_authenticated))
    if not user.is_authenticated:
        return explanation.finish(False, "The user isn't authenticated: a view asks for credentials.")
    holding = granting_groups(user, perm_code)
    holds = user.has_perm(perm_code)
    detail = f"through {', '.join(holding)}" if holding else ""
    steps.append(Step(f"holds {perm_code} (has_perm)", holds, detail if holds else "inactive, or not granted"))
    if not holds:
        return explanation.finish(False, f"The user doesn't hold {perm_code}: no group of theirs is granted it.")
    steps.append(Step("superuser", user.is_superuser))
    if user.is_superuser:
        return explanation.finish(True, "A superuser holds every permission on any object.")
    app_label, _, codename = perm_code.partition(".")
    direct = user.user_permissions.filter(content_type__app_label=app_label, codename=codename).exists()
    steps.append(Step("given to the user directly", direct))
    if direct:
        return explanation.finish(True, "The permission is given to the user directly: on any object.")
    steps.append(Step("an action permission", info is not None))
    if info is None:
        if obj is None:
            return explanation.finish(False, "Not an action permission: no group holds it on any object.")
        return explanation.finish(
            user.has_perm(perm_code, obj=obj),
            "Not an action permission: user.has_perm(perm, obj) answers (the object permission backends).",
        )

    user_groups = set(user.groups.values_list("name", flat=True))
    explanation.no_detail = sorted(user_groups & set(info["no_detail"]))
    if draft and draft[0] not in holding:
        explanation.notes.append(
            f"{draft[0]} doesn't hold {perm_code}: its draft ruleset isn't evaluated (the grants aren't simulated)."
        )
    free = [group for group in holding if not _restricted(info, group)]
    if free:
        explanation.groups = [
            GroupAnswer(group, draft=bool(draft and draft[0] == group), checked_user=str(user), answer=True)
            for group in free
        ]
        return explanation.finish(True, f"{', '.join(free)} holds it without a ruleset: on any object.")

    # allowed()
    if obj is None:
        explanation.groups = [GroupAnswer(group, info["abac"][group], skipped="no object") for group in holding]
        return explanation.finish(
            False,
            "On any object, no: every group of the user holding it has a ruleset. A list is allowed (has_perm); "
            "give an object to check it.",
        )
    backend = get_rules_backend()
    explanation.backend = f"{type(backend).__module__}.{type(backend).__qualname__}"
    explanation.default_allows = backend.default_allows
    if type(backend).evaluate is not BaseRulesBackend.evaluate:
        explanation.notes.append("The rules backend overrides evaluate(): the trace shows the default evaluation.")
    descriptions = dict(
        ActionPermissionRule.objects.filter(code__in=info["predicates"]).values_list("code", "description")
    )
    answers, stopped = [], ""
    for group in holding:
        row = GroupAnswer(group, info["abac"][group], draft=bool(draft and draft[0] == group))
        explanation.groups.append(row)
        if stopped:
            row.skipped = stopped
            continue
        checked = user
        if group in info["staff"]:
            if manager_user is None:
                row.skipped = "a staff group, and no manager_user is given: it allows nothing"
                continue
            checked = manager_user(user)
        row.checked_user = str(checked)
        try:
            ruleset = backend.ruleset(row.expression, info["predicates"])
        except ValueError as e:
            row.error, row.answer = f"it doesn't parse: {e}", False
            answers.append(False)
            continue
        try:
            row.trace = ruleset.trace(checked, obj, blocks=BLOCKS)
        except Exception as e:
            row.error = f"a predicate raises {type(e).__name__}: {e}"
            explanation.raises = row.error
            stopped = "not evaluated: the check stopped at an exception"
            continue
        _describe(row.trace, descriptions)
        row.answer, row.blocked = row.trace.answer, row.trace.blocked
        if row.blocked is not None:
            stopped = "not evaluated: a block stopped the check"
            continue
        answers.append(row.answer)

    if explanation.raises:
        explanation.finish(False, f"{explanation.raises}: the check raises it, a view answers 500.")
    elif stopped:
        blocker = next(row for row in explanation.groups if row.blocked is not None)
        explanation.finish(False, f"Blocked by {blocker.group}'s ruleset: {blocker.blocked}.")
    elif any(answers):
        deciding = [row.group for row in explanation.groups if row.answer]
        explanation.finish(True, f"Allowed by {', '.join(deciding)}'s ruleset.")
    elif None in answers and backend.default_allows:
        explanation.finish(True, "No group's ruleset decided (None): the rules backend allows then.")
    elif None in answers:
        explanation.finish(False, "No group's ruleset decided (None): the rules backend denies then.")
    else:
        explanation.finish(False, "No group's ruleset allows it.")
    return explanation
