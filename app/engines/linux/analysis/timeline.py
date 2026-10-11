"""Linux: the timeline (SKELETON). Sources to read: process start times (pslist), socket creation, ``linux.bash`` history timestamps, ``linux.kmsg`` lines, file times."""
from __future__ import annotations

from typing import List

from app.engines.linux._todo import todo
from app.models import AnalysisResult, TimelineEvent


def build_timeline(result: AnalysisResult) -> List[TimelineEvent]:
    return todo("build_timeline")


def apply_severity(result: AnalysisResult) -> None:
    """Give every timeline event the highest severity among the findings of its process."""
    return todo("apply_severity")
