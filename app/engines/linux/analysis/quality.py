"""Linux: things about the image that limit what the rules can say (SKELETON): swapped-out pages, a kernel whose ISF is only approximate, an acquisition that was still running."""
from __future__ import annotations

from typing import List

from app.engines.linux._todo import todo
from app.models import AnalysisResult


def data_quality_warnings(result: AnalysisResult) -> List[str]:
    return todo("data_quality_warnings")
