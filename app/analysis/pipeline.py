"""Normalize -> timeline -> rules. Shared by live analysis and re-analysis of saved investigations.

The steps are the same for every operating system; what each step does is the engine's (``app/engines/<os>``): ``engine.normalize``, ``engine.build_timeline``,
``engine.indicator_engine``. The engine is the one the result belongs to (``result.target_os``), or the one passed in, or Windows.
"""
from __future__ import annotations

from typing import Callable, Optional, Sequence

from app.analysis.case_state import apply_case
from app.engines import DEFAULT_OS, engine_for, get_engine
from app.logging_setup import get_logger
from app.models import AnalysisResult, PluginResult

log = get_logger("pipeline")
Progress = Optional[Callable[[str, int], None]]


def analyze_plugins(dump_path: str, plugins: Sequence[PluginResult], progress: Progress = None,
                    case: Optional[dict] = None, iocs=None, engine=None) -> AnalysisResult:
    """``case``: the investigator's work (triage, notes, baselines) to carry into the rebuilt result.
    ``iocs``: an :class:`app.analysis.ioc.IocSet` of user-supplied indicators (separate rule family), or None.
    ``engine``: the operating-system engine (an :class:`app.engines.base.Engine` or its id); Windows when not given."""
    engine = get_engine(engine) if isinstance(engine, str) or engine is None else engine
    engine = engine or get_engine(DEFAULT_OS)

    def tick(text: str, value: int) -> None:
        if progress:
            progress(text, value)

    tick("Normalizing plugin output", 78)
    result = engine.normalize(dump_path, plugins)
    result.target_os = engine.id
    if case:
        result.case = case
    tick("Building timeline", 86)
    try:
        result.timeline = engine.build_timeline(result)
    except Exception as exc:  # noqa: BLE001
        log.exception("Timeline build failed")
        result.warnings.append(f"Timeline could not be built: {exc}")
    tick("Evaluating investigation rules", 92)
    rules = engine.indicator_engine(iocs)
    try:
        result.indications = rules.evaluate(result)
    except Exception as exc:  # noqa: BLE001
        log.exception("Rule evaluation failed")
        result.warnings.append(f"Rule evaluation failed: {exc}")
        result.indications = []
    result.warnings.extend(getattr(rules, "errors", []))
    try:
        apply_case(result)           # triage decisions / baselines -> Indication.triage
    except Exception as exc:  # noqa: BLE001 - never lose the analysis because of the case data
        log.exception("Applying the case state failed")
        result.warnings.append(f"The saved triage decisions could not be applied: {exc}")
    try:
        engine.apply_timeline_severity(result)
    except Exception:  # noqa: BLE001
        log.exception("Applying severity to the timeline failed")
    try:
        result.warnings.extend(engine.data_quality_warnings(result))
    except Exception:  # noqa: BLE001
        log.exception("Data quality check failed")
    tick("Analysis complete", 100)
    return result


def data_quality_warnings(result: AnalysisResult) -> list:
    """Things about the image itself that limit what the rules can say (the engine of the result decides)."""
    return engine_for(result).data_quality_warnings(result)


def reanalyze(result: AnalysisResult, progress: Progress = None, iocs=None) -> AnalysisResult:
    """Rebuild processes, timeline and indications from the plugin rows stored in ``result`` (the case state is kept)."""
    if not any(p.rows for p in result.plugins):
        raise ValueError("This investigation has no stored plugin output, so it cannot be re-analysed.")
    rebuilt = analyze_plugins(result.dump_path, result.plugins, progress, case=result.case, iocs=iocs, engine=engine_for(result))
    rebuilt.tool_info = dict(getattr(result, "tool_info", {}) or {})
    return rebuilt


def refresh_image_hash_findings(result: AnalysisResult, iocs=None) -> int:
    """Re-evaluate only rule IOC-007 (hashes of dumped process images vs. the IOC list) after "Hash all process images…". Returns the number of IOC-007 findings."""
    return engine_for(result).refresh_image_hash_findings(result, iocs)
