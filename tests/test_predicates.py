"""Predicates and rulesets (`predicates`), and the built-in predicates (`rules`)."""

from types import SimpleNamespace

import pytest
from django.core.exceptions import ImproperlyConfigured, PermissionDenied

from django_action_permissions import rules as builtin
from django_action_permissions.predicates import (
    AllOf,
    AnyOf,
    NamedPredicate,
    Not,
    Predicate,
    cached_ruleset,
    canonical,
    codes_of,
    discover,
    parse,
    predicate,
)
from django_action_permissions.utils import drf_installed
from tests import rules

USER = SimpleNamespace(username="ann", is_authenticated=True, is_active=True, is_staff=False, is_superuser=False)


def answering(value):
    """A predicate answering `value` (not registered: the operators don't need it)."""
    return NamedPredicate(f"answers_{value}", "tests.nowhere", function=lambda user, obj: value)


def resolve(code):
    return discover()[code]


# ── the decorator ────────────────────────────────────────────────────────────


def test_a_predicate_has_a_code_a_path_and_a_description():
    assert (rules.owner.code, rules.owner.fqn, rules.owner.description) == (
        "owner",
        "tests.rules.owner",
        "The object's owner is the user.",
    )
    assert rules.yes.description == ""
    assert discover()["owner"] is rules.owner


def test_the_code_and_the_description_may_be_given(registry):
    @predicate(code="custom", description="Given here")
    def anything(user, obj):
        """Not this."""
        return True

    assert (anything.code, anything.description) == ("custom", "Given here")
    assert registry["custom"] is anything and anything(USER, None) is True


def test_the_description_is_the_docstrings_first_paragraph(registry):
    @predicate
    def documented(user, obj):
        """The first
        paragraph.

        Not the rest."""

    assert documented.description == "The first paragraph."


def test_a_code_belongs_to_one_function(registry):
    with pytest.raises(ImproperlyConfigured, match="'owner' is already tests.rules.owner"):

        @predicate(code="owner")
        def another(user, obj):
            return True


def test_registering_the_same_function_again_replaces_it(registry):
    again = predicate(rules.owner.function)

    assert registry["owner"] is again and again.fqn == "tests.rules.owner"


def test_a_plain_function_follows_the_protocol():
    def plain(user, obj):
        return True

    assert isinstance(plain, Predicate) and isinstance(rules.owner, Predicate)


def test_discovery_finds_the_librarys_and_the_apps_predicates():
    found = discover()

    assert {"always", "never", "is_authenticated", "is_active", "is_staff", "is_superuser", "is_self"} <= set(found)
    assert {"owner", "yes", "no", "abstain", "block"} <= set(found)


# ── the operators ────────────────────────────────────────────────────────────

T, F, N = True, False, None


@pytest.mark.parametrize(
    "left, right, expected",
    [(T, T, T), (T, F, F), (F, T, F), (T, N, T), (N, T, T), (F, N, F), (N, F, F), (N, N, N), (F, F, F)],
)
def test_and_skips_what_doesnt_apply(left, right, expected):
    assert (answering(left) & answering(right))(USER, None) is expected


@pytest.mark.parametrize(
    "left, right, expected",
    [(T, T, T), (T, F, T), (F, T, T), (T, N, T), (N, T, T), (F, N, F), (N, F, F), (N, N, N), (F, F, F)],
)
def test_or_skips_what_doesnt_apply(left, right, expected):
    assert (answering(left) | answering(right))(USER, None) is expected


@pytest.mark.parametrize("value, expected", [(T, F), (F, T), (N, N)])
def test_not_swaps_true_and_false(value, expected):
    assert (~answering(value))(USER, None) is expected


def test_and_stops_at_the_first_false_and_or_at_the_first_true(calls):
    assert (rules.no & rules.yes)(USER, None) is False
    assert (rules.yes | rules.no)(USER, None) is True
    assert calls == ["no", "yes"]


def test_a_block_goes_through_the_operators(calls):
    with pytest.raises(PermissionDenied):
        (rules.abstain | rules.block | rules.yes)(USER, None)
    assert calls == ["abstain", "block"]


@pytest.mark.skipif(not drf_installed(), reason="Django REST framework isn't installed")
def test_drfs_block_goes_through_too():
    from rest_framework.exceptions import PermissionDenied as DRFPermissionDenied

    with pytest.raises(DRFPermissionDenied):
        (~rules.block_drf)(USER, None)


def test_another_answer_is_read_as_a_bool():
    assert answering("yes")(USER, None) is True and answering(0)(USER, None) is False


def test_compositions_are_flattened():
    ruleset = rules.yes & rules.no & rules.abstain

    assert isinstance(ruleset, AllOf) and len(ruleset.operands) == 3
    assert isinstance(rules.yes | rules.no | rules.owner, AnyOf)
    assert isinstance(~rules.yes, Not)
    assert ruleset.codes() == {"yes", "no", "abstain"}


def test_only_predicates_compose():
    with pytest.raises(TypeError, match="decorate it with @predicate"):
        rules.yes & (lambda user, obj: True)
    with pytest.raises(TypeError):
        canonical(42, resolve)


# ── expressions ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "ruleset, expression",
    [
        (rules.owner, "owner"),
        (rules.owner & ~rules.no | builtin.is_staff, "owner & ~no | is_staff"),
        ((rules.owner | rules.no) & rules.yes, "(owner | no) & yes"),
        (~(rules.owner & rules.yes), "~(owner & yes)"),
        (~~rules.owner, "~~owner"),
        (rules.owner & (rules.yes & rules.no), "owner & yes & no"),
    ],
)
def test_a_ruleset_is_written_with_the_fewest_parentheses(ruleset, expression):
    assert str(ruleset) == expression
    assert parse(expression, resolve) == ruleset
    assert repr(ruleset).endswith(f"{expression}>")


def test_precedence_is_not_then_and_then_or():
    assert str(parse("~owner | yes & no", resolve)) == "~owner | yes & no"
    assert isinstance(parse("~owner | yes & no", resolve), AnyOf)
    assert str(parse(" ( owner|yes ) &no ", resolve)) == "(owner | yes) & no"
    assert {parse("owner", resolve), parse("owner", resolve)} == {rules.owner}


@pytest.mark.parametrize(
    "expression, message",
    [
        ("", "an empty ruleset"),
        ("   ", "an empty ruleset"),
        ("owner &", "unexpected the end at 7"),
        ("& owner", "unexpected '&' at 0"),
        ("owner yes", "unexpected 'yes' at 6"),
        ("(owner | yes", "expected '\\)', not the end at 12"),
        ("owner)", "unexpected '\\)' at 5"),
        ("owner && yes", "unexpected '&' at 7"),
        ("owner + yes", "unexpected '\\+' at 6"),
        ("owner & nobody", "unknown predicate 'nobody' at 8"),
    ],
)
def test_a_bad_expression_says_where(expression, message):
    with pytest.raises(ValueError, match=message):
        parse(expression, resolve)


def test_the_codes_of_an_expression():
    assert codes_of("owner & ~(yes | is_staff)") == {"owner", "yes", "is_staff"}
    assert codes_of("owner + 1") == set()


def test_a_stored_ruleset_is_parsed_once_per_process():
    predicates = (("owner", "tests.rules.owner"),)

    assert cached_ruleset("owner", predicates) is cached_ruleset("owner", predicates)


def test_a_referenced_predicate_is_imported_when_called_and_answers_false_when_it_cant_be(caplog):
    assert NamedPredicate("owner", "tests.rules.owner")(USER, SimpleNamespace(owner="ann")) is True
    assert NamedPredicate("gone", "tests.rules.gone")(USER, None) is False
    assert NamedPredicate("bad", "tests.rules.NOT_CALLABLE")(USER, None) is False
    assert "predicate 'gone'" in caplog.text


def test_the_base_ruleset_is_abstract():
    from django_action_permissions.predicates import Ruleset

    with pytest.raises(NotImplementedError):
        Ruleset()(USER, None)
    with pytest.raises(NotImplementedError):
        Ruleset().codes()


# ── the built-in predicates ──────────────────────────────────────────────────


def test_the_built_in_predicates(django_user_model):
    staff = SimpleNamespace(is_authenticated=True, is_active=False, is_staff=True, is_superuser=True)

    assert builtin.always(USER, None) is True and builtin.never(USER, None) is False
    assert builtin.is_authenticated(USER, None) is True
    assert builtin.is_active(USER, None) is True and builtin.is_active(staff, None) is False
    assert builtin.is_staff(staff, None) is True and builtin.is_staff(USER, None) is False
    assert builtin.is_superuser(staff, None) is True and builtin.is_superuser(USER, None) is False
    assert builtin.is_self(USER, USER) is True and builtin.is_self(USER, staff) is False
