"""The shared bounded readers (Task 10).

Every value the three abuse.ch adapters keep passes through this module, so it
is where "provider text is untrusted input" is actually implemented: bounded,
control-character-free, shape-checked, and returning ``None`` rather than
guessing.
"""

from __future__ import annotations

from typing import Any

import pytest

from ti_recon.providers.abusech.values import (
    MAX_LABEL,
    MAX_TEXT,
    count,
    flag,
    hex_digest,
    mapping,
    number,
    scalar,
    string_list,
    text,
)

# --------------------------------------------------------------------------- #
# text
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Dridex", "Dridex"),
        ("  padded  ", "padded"),
        ("", None),
        ("   ", None),
        (None, None),
        (42, None),
        (True, None),
        ([], None),
    ],
)
def test_only_a_usable_string_survives(value: Any, expected: str | None) -> None:
    assert text(value) == expected


def test_control_characters_are_stripped_rather_than_escaped() -> None:
    """A stored newline is how provider text starts looking like structure."""
    assert text("Evil\x00Corp\r\nX: y") == "EvilCorpX: y"
    assert text("\x7f") is None


def test_text_is_bounded() -> None:
    assert len(text("x" * 10_000, MAX_LABEL) or "") == MAX_LABEL
    assert len(text("x" * 10_000, MAX_TEXT) or "") == MAX_TEXT


# --------------------------------------------------------------------------- #
# scalar, flag, number, count
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (7, 7), (1.5, 1.5), ("text", "text"), (None, None), ([1], None), ({}, None)],
)
def test_scalar_keeps_only_storable_json_scalars(value: Any, expected: Any) -> None:
    assert scalar(value) == expected


def test_a_scalar_string_is_still_cleaned() -> None:
    assert scalar("a\x00b") == "ab"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, True),
        (False, False),
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("0", False),
        (" True ", True),
    ],
)
def test_both_boolean_spellings_abusech_uses_are_read(value: Any, expected: bool) -> None:
    assert flag(value) is expected


@pytest.mark.parametrize("value", [None, 1, 0, "maybe", "", "y", [], {}])
def test_an_unrecognized_boolean_stays_unknown(value: Any) -> None:
    """Guessing is how ``is_compromised`` silently becomes the wrong answer."""
    assert flag(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(7, 7.0), (1.5, 1.5), ("42", 42.0), (" 42 ", 42.0), ("-1", -1.0)],
)
def test_number_accepts_numerics_and_numeric_strings(value: Any, expected: float) -> None:
    assert number(value) == expected


@pytest.mark.parametrize("value", [None, True, False, "abc", "", [], {}])
def test_number_refuses_anything_else(value: Any) -> None:
    """A bool is not a number here: ``True`` becoming ``1.0`` hides a type error."""
    assert number(value) is None


@pytest.mark.parametrize(
    ("value", "expected"), [(7, 7), (7.9, 7), ("12", 12), (0, 0), (-1, None), ("abc", None)]
)
def test_count_is_a_non_negative_whole_number(value: Any, expected: int | None) -> None:
    assert count(value) == expected


# --------------------------------------------------------------------------- #
# hex_digest
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "lengths", "expected"),
    [
        ("a" * 64, {64}, "a" * 64),
        ("A" * 64, {64}, "a" * 64),
        (" " + "a" * 32 + " ", {32}, "a" * 32),
        ("a" * 40, {32, 64}, None),
        ("z" * 64, {64}, None),
        ("a" * 63, {64}, None),
        (None, {64}, None),
        (12345, {64}, None),
    ],
)
def test_a_digest_is_shape_checked_not_passed_through(
    value: Any, lengths: set[int], expected: str | None
) -> None:
    """A digest becomes an identity, a pivot key and part of a request."""
    assert hex_digest(value, lengths=lengths) == expected


# --------------------------------------------------------------------------- #
# string_list, mapping
# --------------------------------------------------------------------------- #


def test_a_list_is_bounded_deduplicated_and_forgiving() -> None:
    assert string_list(["a", "b", "a", None, 3, "c"], 10) == ["a", "b", "c"]
    assert string_list([f"tag-{index}" for index in range(500)], 5) == [
        f"tag-{index}" for index in range(5)
    ]


def test_a_bare_string_where_a_list_belongs_reads_as_one_item() -> None:
    """abuse.ch does this; raising over it would lose the value."""
    assert string_list("dridex", 10) == ["dridex"]
    assert string_list("", 10) == []


@pytest.mark.parametrize("value", [None, 7, {}, b"bytes"])
def test_a_non_list_reads_as_empty(value: Any) -> None:
    assert string_list(value, 10) == []


def test_list_items_are_length_bounded() -> None:
    assert string_list(["x" * 5_000], 10, 50) == ["x" * 50]


def test_mapping_never_raises_on_a_shape_change() -> None:
    assert mapping({"a": 1}) == {"a": 1}
    for value in (None, [], "text", 7):
        assert mapping(value) == {}
