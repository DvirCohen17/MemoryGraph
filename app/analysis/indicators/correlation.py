from __future__ import annotations

from collections import defaultdict
from typing import List

from app.analysis.indicators.base import display, parent_of, process_map
from app.analysis.indicators.scoring import finding_score, max_severity, severity_rank
from app.models import AnalysisResult, Indication

MIN_SEVERITY_FOR_CORRELATION = 2   # Medium


def correlate(result: AnalysisResult, findings: List[Indication]) -> List[Indication]:
    """Combine independent findings; never replaces them.

    * CORR-001: one process with strong findings from at least two *different* categories
      (e.g. path + command line, memory + network).
    * CORR-002: a process and one of its ancestors both carry strong findings.
    Low-priority findings never trigger correlation, so noise cannot snowball.
    """
    procs = process_map(result)
    strong_by_pid = defaultdict(list)
    for f in findings:
        if f.process_pid and severity_rank(f.severity) >= MIN_SEVERITY_FOR_CORRELATION:
            strong_by_pid[f.process_pid].append(f)

    output: List[Indication] = []
    for pid, items in strong_by_pid.items():
        categories = {f.category or f.rule_id.split("-")[0] for f in items}
        process = procs.get(pid)
        if len(categories) < 2 or process is None:
            continue
        top = max_severity(f.severity for f in items)
        severity = "High" if (len(categories) >= 3 or top == "High") else "Medium"
        sources = sorted({s for f in items for s in f.source_plugins})
        output.append(Indication(
            title=f"{len(categories)} independent kinds of evidence point at {process.name}",
            severity=severity, confidence="High" if len(categories) >= 3 else "Medium",
            process_pid=pid, process_name=process.name,
            summary="Different artifact types (for example path, command line, memory and network) all produced leads for the same process. The grouped finding is a prioritisation aid, not a malware verdict.",
            description="Correlation finding. Review the linked rules and their evidence.",
            reasons=[f"{f.rule_id}: {f.title}" for f in items],
            evidence=list(dict.fromkeys(e for f in items for e in f.evidence[:2])),
            source_plugins=sources, rule_id="CORR-001", category="correlation",
            related_processes=[display(process)], score=finding_score(severity, "High"),
        ))

    for pid, items in strong_by_pid.items():
        child = procs.get(pid)
        if not child:
            continue
        ancestor, seen = parent_of(procs, child), {pid}
        depth = 0
        while ancestor is not None and ancestor.pid not in seen and depth < 4:
            seen.add(ancestor.pid)
            parent_items = strong_by_pid.get(ancestor.pid)
            if parent_items:
                severity = "High" if max_severity(f.severity for f in items + parent_items) == "High" else "Medium"
                output.append(Indication(
                    title=f"Suspicious parent {ancestor.name} and child {child.name}",
                    severity=severity, confidence="Medium", process_pid=pid, process_name=child.name,
                    summary="Both this process and one of its ancestors have strong investigation leads, so their relationship is worth reviewing as one execution chain.",
                    description="Process lineage correlation.",
                    reasons=[f"Ancestor finding: {f.rule_id} — {f.title}" for f in parent_items[:3]] + [f"Child finding: {f.rule_id} — {f.title}" for f in items[:3]],
                    evidence=[f"{display(ancestor)} → … → {display(child)}"],
                    source_plugins=sorted({s for f in items + parent_items for s in f.source_plugins}), rule_id="CORR-002",
                    category="correlation", related_processes=[display(ancestor), display(child)],
                    score=finding_score(severity, "Medium"),
                ))
                break
            ancestor = parent_of(procs, ancestor)
            depth += 1
    return output
