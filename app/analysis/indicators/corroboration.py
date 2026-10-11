"""A High finding must be seen by two independent plugins.

Some rules report High from the rows of ONE Volatility plugin (hollowed image, PEB differences, ghosted image, patched ETW, IRP handlers outside a
driver). On a real Windows 10 image such a single note (``hollowprocesses`` for svchost.exe: "no VAD at the image base") could not be confirmed, and a stale driver
object was reported High on its own. A plugin can be wrong where the memory it reads is paged out or half overwritten, so these rules are rated Medium unless a second
plugin independently points at the same process (or, for kernel findings, at the same part of the kernel). The reason is added to the finding so the investigator
sees why it is not High. Nothing is removed.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from app.analysis.indicators.scoring import finding_score, severity_rank
from app.models import Indication

# rules whose High rests on the rows of one plugin
SINGLE_SOURCE_RULES = {"MAL-001", "MAL-003", "MAL-004", "MAL-007", "MAL-006"}
# findings that never count as a second source: the investigator's own reference data, correlations (built from the others) and weak leads
NOT_A_SOURCE_CATEGORIES = {"ioc", "baseline", "correlation"}
NOT_A_SOURCE_RULES = {"BEH-001"}


def _sources(finding: Indication) -> set:
    return {s for s in finding.source_plugins if s}


def second_source(finding: Indication, others: Iterable[Indication]) -> List[Indication]:
    """Other findings about the same process (or, for a kernel finding, the same kernel area) that come from different plugins."""
    mine = _sources(finding)
    found = []
    for other in others:
        if other is finding or other.rule_id == finding.rule_id or other.category in NOT_A_SOURCE_CATEGORIES or other.rule_id in NOT_A_SOURCE_RULES:
            continue
        if severity_rank(other.severity) < 1 or _sources(other) <= mine:
            continue                                          # nothing new: the same plugin(s) again
        if finding.process_pid:
            same = other.process_pid == finding.process_pid
        else:
            same = other.category == finding.category and not other.process_pid
        if same:
            found.append(other)
    return found


def require_second_source(findings: List[Indication]) -> List[Indication]:
    """Lower the single-plugin High findings that no second plugin supports to Medium (in place; returns the lowered ones)."""
    by_pid: Dict[int, List[Indication]] = {}
    for f in findings:
        by_pid.setdefault(f.process_pid, []).append(f)
    lowered = []
    for f in findings:
        if f.rule_id not in SINGLE_SOURCE_RULES or f.severity != "High":
            continue
        support = second_source(f, by_pid.get(f.process_pid, []))
        if support:
            f.reasons.append("Corroborated by another plugin: " + "; ".join(f"{s.rule_id} ({', '.join(sorted(_sources(s)))})" for s in support[:3]))
            continue
        f.severity = "Medium"
        f.confidence = "Low"
        f.score = finding_score(f.severity, f.confidence)
        f.reasons.append("Rated Medium, not High: this rests on one plugin and no second plugin points at the same "
                         + ("process" if f.process_pid else "part of the kernel") + " (High needs two independent sources)")
        lowered.append(f)
    return lowered
