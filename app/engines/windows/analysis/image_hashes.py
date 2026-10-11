"""Windows: rule IOC-007 (hashes of dumped process images against the IOC list) re-evaluated on its own after "Hash all process images…"."""
from __future__ import annotations

from app.analysis.case_state import apply_case
from app.analysis.indicators.scoring import severity_rank
from app.engines.windows.analysis.timeline_builder import apply_severity
from app.engines.windows.indicators.rules.ioc import ImageHashIocRule
from app.models import AnalysisResult


def refresh_image_hash_findings(result: AnalysisResult, iocs=None) -> int:
    """Re-evaluate only rule IOC-007; returns the number of IOC-007 findings now in ``result`` (the rest of the analysis is left as it is)."""
    result.indications = [i for i in result.indications if i.rule_id != "IOC-007"]
    found = ImageHashIocRule(iocs).evaluate(result) if iocs else []
    result.indications.extend(found)
    result.indications.sort(key=lambda f: (-severity_rank(f.severity), -f.score, f.process_pid, f.rule_id))
    apply_case(result)
    apply_severity(result)
    return len(found)
