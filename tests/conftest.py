"""Shared pytest configuration.

Adds ``tests/`` to ``sys.path`` so fixture packages are importable as
``fixtures.*`` without installing the test tree.
"""

from __future__ import annotations

import sys
from pathlib import Path

_TESTS_ROOT = Path(__file__).resolve().parent
if str(_TESTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_TESTS_ROOT))
