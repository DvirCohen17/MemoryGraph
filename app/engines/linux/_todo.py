"""How the Linux skeleton says "not written yet": one helper, one exception, so every placeholder fails the same readable way."""
from __future__ import annotations

from app.engines.base import EngineNotImplemented


def todo(function: str):
    """Raise :class:`EngineNotImplemented` naming the Linux function that is still to be written. Call it as the body of a placeholder: ``return todo("normalize")``."""
    raise EngineNotImplemented("Linux", function)
