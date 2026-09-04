"""Version markers recorded on investigations and assessments.

Recording these makes a past result explainable later: the same evidence can
produce a different verdict once the engine or the scoring policy changes, and
without a version stamp there is no way to tell which one produced a result.
"""

from __future__ import annotations

from typing import Final

from ti_recon import __version__

__all__ = ["ENGINE_VERSION", "POLICY_VERSION"]

#: Version of the TI Recon engine that produced a record.
ENGINE_VERSION: Final[str] = __version__

#: Version of the assessment policy in force.
#:
#: No scoring policy is implemented yet (that is a later task), so this is an
#: explicit placeholder rather than a plausible-looking version number.
POLICY_VERSION: Final[str] = "0-unimplemented"
