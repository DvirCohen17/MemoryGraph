"""Linux: helpers the rules share (SKELETON): path classes, command lines, interpreters. Compare ``app/engines/windows/indicators/helpers.py``."""
from __future__ import annotations

from app.engines.linux.indicators import baseline


def is_risky_dir(path: str) -> bool:
    """A directory code should not normally run from (``/tmp``, ``/dev/shm``, ``/var/tmp`` ...). Uses ``baseline.HIGH_RISK_DIR_FRAGMENTS``; False while that table is empty."""
    text = str(path or "")
    return any(fragment in text for fragment in baseline.HIGH_RISK_DIR_FRAGMENTS)


def is_trusted_dir(path: str) -> bool:
    """A directory system programs normally live in. Uses ``baseline.TRUSTED_DIR_FRAGMENTS``; False while that table is empty."""
    text = str(path or "")
    return any(fragment in text for fragment in baseline.TRUSTED_DIR_FRAGMENTS)
