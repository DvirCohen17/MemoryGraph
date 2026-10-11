"""Linux: the rule engine (SKELETON). ``DEFAULT_RULES`` is the list to fill; ``IndicatorEngine.evaluate`` must run them defensively (a failing rule is logged and reported
in ``errors``, never fatal), apply ``app.analysis.indicators.corroboration.require_second_source``, add ``app.analysis.indicators.correlation.correlate``, remove duplicates and sort
by severity, exactly as ``app/engines/windows/indicators/engine.py`` does."""
from __future__ import annotations

from typing import Dict, List

from app.engines.linux._todo import todo
from app.models import AnalysisResult, Indication

DEFAULT_RULES: List = []              # instances of IndicatorRule subclasses (app/analysis/indicators/base.py), written in ./rules/
RULE_CATALOG: Dict[str, object] = {}  # rule id -> rule object (name and description are shown in the Indications view)


def rule_name(rule_id: str) -> str:
    """The display name of a rule; the demo's name (``demo.RULE_NAMES``) or the id itself until the rule exists. A real rule in ``RULE_CATALOG`` always wins."""
    rule = RULE_CATALOG.get(rule_id)
    if rule is not None:
        return rule.name
    from app.engines.linux import demo
    return demo.RULE_NAMES.get(rule_id, rule_id)


def rule_catalog() -> Dict[str, object]:
    """``{rule id: object with name and description}``: the rules that exist, and (until there are real ones) the demo's."""
    from types import SimpleNamespace
    from app.engines.linux import demo
    catalog = {rid: SimpleNamespace(rule_id=rid, name=name, description=demo.RULE_DESCRIPTIONS.get(rid, "")) for rid, name in demo.RULE_NAMES.items()}
    catalog.update(RULE_CATALOG)
    return catalog


class IndicatorEngine:
    def __init__(self, rules=None, iocs=None):
        self.rules = list(rules or DEFAULT_RULES)
        self.errors: List[str] = []

    def evaluate(self, result: AnalysisResult) -> List[Indication]:
        return todo("IndicatorEngine.evaluate")
