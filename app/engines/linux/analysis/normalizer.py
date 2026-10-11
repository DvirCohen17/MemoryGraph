"""Linux: plugin rows -> :class:`AnalysisResult` (SKELETON).

Must build, from the raw ``PluginResult`` rows (kept untouched in ``result.plugins``): ``processes`` (pid, ppid, name, path, command line, user, start time, ``dlls`` = the
libraries, ``network``, ``memory_regions``, ``handles`` = the open files), ``connections`` (sockstat), ``memory_regions`` (malfind), ``system_info`` (the banner as rows with
``Variable`` / ``Value``), ``capture_time``, ``users``, ``accounts`` and ``warnings``. Every field that comes from a plugin keeps its provenance (plugin name + row index), as in
``app/engines/windows/analysis/normalizer.py``. ``app.analysis.rows.flatten_rows`` flattens Volatility's ``__children`` trees.
"""
from __future__ import annotations

from typing import Sequence

from app.engines.linux._todo import todo
from app.models import AnalysisResult, PluginResult


def normalize(dump_path: str, plugins: Sequence[PluginResult]) -> AnalysisResult:
    return todo("normalize")
