"""Severity/confidence scoring shared by the rule engine, correlation and the GUI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

SEVERITY_RANK = {"": 0, "Info": 0, "Low": 1, "Medium": 2, "High": 3}
SEVERITY_POINTS = {"Info": 0.0, "Low": 1.0, "Medium": 3.0, "High": 6.0}
CONFIDENCE_FACTOR = {"Low": 0.5, "Medium": 0.8, "High": 1.0}


# Triage states that take a finding out of scores, counts and default lists (it stays in the investigation).
HIDDEN_TRIAGE = ("false_positive", "baseline")


def is_active(indication) -> bool:
    """False for findings the investigator marked as false positive or a known-good baseline suppressed."""
    return getattr(indication, "triage", "") not in HIDDEN_TRIAGE


def active_findings(indications) -> List:
    return [i for i in indications if is_active(i)]


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity or "", 0)


def finding_score(severity: str, confidence: str) -> float:
    return round(SEVERITY_POINTS.get(severity, 0.0) * CONFIDENCE_FACTOR.get(confidence, 0.8), 2)


def max_severity(severities: Iterable[str]) -> str:
    best = ""
    for sev in severities:
        if severity_rank(sev) > severity_rank(best):
            best = sev
    return best


@dataclass
class ProcessRisk:
    pid: int
    score: float = 0.0
    severity: str = ""
    count: int = 0
    rule_ids: List[str] = field(default_factory=list)


def risk_by_pid(indications) -> Dict[int, ProcessRisk]:
    """Aggregate findings per process: one score, one severity, the contributing rule ids.

    Only the strongest finding of every rule counts towards the score, so a rule that fires
    many times for one process (e.g. several memory regions) cannot inflate it.
    """
    indications = active_findings(indications)
    best_per_rule: Dict[tuple, object] = {}
    for ind in indications:
        if not ind.process_pid:
            continue
        key = (ind.process_pid, ind.rule_id or ind.title)
        current = best_per_rule.get(key)
        if current is None or ind.score > current.score:
            best_per_rule[key] = ind
    risks: Dict[int, ProcessRisk] = {}
    for (pid, _rule), ind in best_per_rule.items():
        risk = risks.setdefault(pid, ProcessRisk(pid))
        risk.score += ind.score
        risk.count += 1
        risk.rule_ids.append(ind.rule_id)
    for ind in indications:
        if ind.process_pid:
            risk = risks.setdefault(ind.process_pid, ProcessRisk(ind.process_pid))
            if severity_rank(ind.severity) > severity_rank(risk.severity) and not (
                    ind.severity == "High" and ind.confidence == "Low"):
                risk.severity = ind.severity
    for risk in risks.values():
        risk.score = round(risk.score, 2)
        if risk.score >= 10 and severity_rank(risk.severity) < 3:
            risk.severity = "High"
        elif risk.score >= 4 and severity_rank(risk.severity) < 2:
            risk.severity = "Medium"
        risk.rule_ids = sorted(set(risk.rule_ids))
    return risks
