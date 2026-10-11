"""Backward-compatible facade for the refactored indicator engine."""
from app.engines.windows.indicators.engine import IndicatorEngine, DEFAULT_RULES, RULE_CATALOG, rule_name
from app.analysis.indicators.base import IndicatorRule

__all__ = ["IndicatorEngine", "DEFAULT_RULES", "IndicatorRule", "RULE_CATALOG", "rule_name"]
