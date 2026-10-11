from __future__ import annotations

from typing import List

from app.analysis.indicators.correlation import correlate
from app.analysis.indicators.corroboration import require_second_source
from app.engines.windows.indicators.rules.commandline import InterpreterRunsFromRiskyPathRule, LolbinAbuseRule, ObfuscatedInterpreterRule, PowerShellAbuseRule
from app.engines.windows.indicators.rules.dll import SystemDllImpostorRule, UntrustedModuleLocationRule
from app.engines.windows.indicators.rules.handles import LsassHandleRule
from app.engines.windows.indicators.rules.ioc import DomainIocRule, FileIocRule, ImageHashIocRule, IpIocRule, MutexIocRule, ioc_rules
from app.engines.windows.indicators.rules.behaviour import UserFolderProgramRule
from app.engines.windows.indicators.rules.autostart import AutostartKeyRule
from app.engines.windows.indicators.rules.crossview import CrossViewRule, NewProcessRule
from app.engines.windows.indicators.rules.environment import EnvironmentVariableRule
from app.engines.windows.indicators.rules.files import FileObjectRule
from app.engines.windows.indicators.rules.kernel import HiddenDriverRule
from app.engines.windows.indicators.rules.kernel_objects import DriverObjectRule, SsdtHookRule, UnbackedCallbackRule
from app.engines.windows.indicators.rules.malware import EtwPatchRule, HiddenServiceRule, HollowedProcessRule, IrpHookRule, PebMasqueradeRule, ProcessGhostingRule, SuspiciousThreadRule
from app.engines.windows.indicators.rules.memory import InjectedMemoryRule
from app.engines.windows.indicators.rules.persistence import ScheduledTaskRule, ServiceKeyRule
from app.engines.windows.indicators.rules.network import NetworkWithOtherSuspicionRule, UnexpectedNetworkProcessRule
from app.engines.windows.indicators.rules.path import CoreProcessPathRule, LookalikeNameRule, NameMismatchRule, RiskyPathExecutionRule
from app.engines.windows.indicators.rules.process import CoreProcessParentRule, HiddenProcessRule, InterpreterParentRule, MissingOnThisWindowsRule, SingletonProcessRule
from app.engines.windows.indicators.rules.registry import RunKeyRule, UserAssistRule
from app.engines.windows.indicators.rules.services import RiskyServiceBinaryRule
from app.engines.windows.indicators.rules.vad import UnlinkedModuleRule, UnlistedImageRule
from app.analysis.indicators.scoring import severity_rank
from app.logging_setup import get_logger
from app.models import AnalysisResult, Indication

log = get_logger("indicators")

DEFAULT_RULES = [
    CoreProcessParentRule(), SingletonProcessRule(), MissingOnThisWindowsRule(), HiddenProcessRule(), InterpreterParentRule(),
    LookalikeNameRule(), CoreProcessPathRule(), RiskyPathExecutionRule(), NameMismatchRule(),
    PowerShellAbuseRule(), LolbinAbuseRule(), InterpreterRunsFromRiskyPathRule(), ObfuscatedInterpreterRule(),
    InjectedMemoryRule(), UntrustedModuleLocationRule(), SystemDllImpostorRule(),
    NetworkWithOtherSuspicionRule(), UnexpectedNetworkProcessRule(), LsassHandleRule(),
    # rules for the extended / opt-in plugins: each stays silent when its plugin did not run
    HiddenDriverRule(), DriverObjectRule(), SsdtHookRule(), UnbackedCallbackRule(), RiskyServiceBinaryRule(), RunKeyRule(),
    UserAssistRule(), FileObjectRule(), EnvironmentVariableRule(), UnlistedImageRule(), UnlinkedModuleRule(),
    AutostartKeyRule(), ServiceKeyRule(), ScheduledTaskRule(), CrossViewRule(),
    HollowedProcessRule(), SuspiciousThreadRule(), PebMasqueradeRule(), ProcessGhostingRule(), HiddenServiceRule(), IrpHookRule(), EtwPatchRule(),
    UserFolderProgramRule(),
    NewProcessRule(),                                  # only active when a baseline with a process list was imported (Case Notes)
]

RULE_CATALOG = {r.rule_id: r for r in DEFAULT_RULES}
RULE_CATALOG.update({r.rule_id: r for r in ioc_rules(None)})          # names/descriptions for the IOC family (separate from DEFAULT_RULES)
RULE_CATALOG.update({r.rule_id: r for r in (IpIocRule(), DomainIocRule(), MutexIocRule(), FileIocRule(), ImageHashIocRule())})
RULE_CATALOG["CORR-001"] = None
RULE_CATALOG["CORR-002"] = None
CORRELATION_NAMES = {
    "CORR-001": "Several kinds of evidence on one process",
    "CORR-002": "Suspicious parent and child",
}


def rule_name(rule_id: str) -> str:
    rule = RULE_CATALOG.get(rule_id)
    if rule is not None:
        return rule.name
    return CORRELATION_NAMES.get(rule_id, rule_id)


class IndicatorEngine:
    """Runs every rule defensively: a failing rule is logged and reported, never fatal."""

    def __init__(self, rules=None, iocs=None):
        """``iocs``: user-supplied indicators; they add the separate IOC rule family and never touch the behavioural rules."""
        self.rules = list(rules or DEFAULT_RULES) + ioc_rules(iocs)
        self.errors: List[str] = []

    def evaluate(self, result: AnalysisResult) -> List[Indication]:
        self.errors = []
        findings: List[Indication] = []
        for rule in self.rules:
            try:
                findings.extend(rule.evaluate(result))
            except Exception as exc:  # noqa: BLE001 - one bad rule must not stop the analysis
                log.exception("Rule %s failed", getattr(rule, "rule_id", rule))
                self.errors.append(f"Rule {getattr(rule, 'rule_id', '?')} failed: {exc}")
        try:
            require_second_source(findings)                # a single-plugin High is Medium unless a second plugin agrees
        except Exception as exc:  # noqa: BLE001
            log.exception("Second-source check failed")
            self.errors.append(f"Second-source check failed: {exc}")
        # IOC matches and baseline differences come from the investigator's own reference data: they must not snowball into correlation
        behavioural = [f for f in findings if f.category not in ("ioc", "baseline")]
        try:
            findings.extend(correlate(result, behavioural))
        except Exception as exc:  # noqa: BLE001
            log.exception("Correlation failed")
            self.errors.append(f"Correlation failed: {exc}")
        # Remove exact duplicates (same rule, process, title and first evidence line).
        unique, seen = [], set()
        for f in findings:
            key = (f.rule_id, f.process_pid, f.title, f.evidence[0] if f.evidence else "")
            if key not in seen:
                seen.add(key)
                unique.append(f)
        unique.sort(key=lambda f: (-severity_rank(f.severity), -f.score, f.process_pid, f.rule_id))
        return unique
