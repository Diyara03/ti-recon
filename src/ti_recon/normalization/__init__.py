"""Observable normalization (Task 3).

Pure, syntactic normalization only: no DNS resolution and no network I/O.
"""

from ti_recon.normalization.errors import NormalizationError
from ti_recon.normalization.observables import (
    NormalizationResult,
    normalize_domain,
    normalize_file_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
)

__all__ = [
    "NormalizationError",
    "NormalizationResult",
    "normalize_domain",
    "normalize_file_hash",
    "normalize_ip",
    "normalize_observable",
    "normalize_url",
]
