"""Normalization errors."""

from __future__ import annotations

__all__ = ["NormalizationError"]


class NormalizationError(ValueError):
    """Raised when an input cannot be normalized into a supported observable.

    The message intentionally describes *why* the input was rejected but does
    not echo unbounded analyst input back into logs.
    """

    def __init__(self, reason: str, *, input_length: int | None = None) -> None:
        self.reason = reason
        self.input_length = input_length
        super().__init__(reason)
