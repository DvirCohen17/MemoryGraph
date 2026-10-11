from __future__ import annotations

import ipaddress
import re
from typing import Iterable, List, Optional, Sequence

from app.analysis.indicators.scoring import finding_score
from app.models import AnalysisResult, EvidenceItem, Indication, Process
from app.util import norm_path, path_dir, path_file


class IndicatorRule:
    """Base class. A rule inspects *normalized* evidence and returns investigation leads."""

    rule_id = "base"
    category = "general"
    name = "Unnamed rule"
    description = ""

    def evaluate(self, result: AnalysisResult) -> List[Indication]:
        raise NotImplementedError

    def make(
        self, *, title: str, severity: str, summary: str, reasons: Sequence[str],
        evidence: Sequence[str] = (), source_plugins: Sequence[str] = (),
        process: Optional[Process] = None, related_processes: Sequence[str] = (),
        confidence: str = "Medium", evidence_items: Sequence[EvidenceItem] = (),
    ) -> Indication:
        return Indication(
            title=title, severity=severity,
            process_pid=process.pid if process else 0,
            process_name=process.name if process else "",
            summary=summary, description=summary,
            reasons=list(reasons), evidence=list(evidence)[:40],
            source_plugins=list(dict.fromkeys(source_plugins)), rule_id=self.rule_id,
            related_processes=list(related_processes), confidence=confidence,
            evidence_items=list(evidence_items), score=finding_score(severity, confidence),
            category=self.category,
        )


def name(value: str) -> str:
    return str(value or "").strip()


def lower(value: str) -> str:
    return name(value).lower()


def proc_name(p: Process) -> str:
    return lower(p.name)


def display(p: Process) -> str:
    return f"{p.name} (PID {p.pid})"


def endpoint_host(value: str) -> str:
    v = str(value or "").strip().strip("[]")
    if not v:
        return ""
    if v.count(":") == 1:
        return v.rsplit(":", 1)[0]
    return v


def is_private_or_local(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    except ValueError:
        return True  # wildcard ('*'), empty or hostnames are never treated as external


def is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def process_map(result: AnalysisResult):
    return {p.pid: p for p in result.processes}


def children_of(result: AnalysisResult, pid: int):
    return [p for p in result.processes if p.ppid == pid]


def active(result: AnalysisResult) -> List[Process]:
    """Processes that were still running at capture time (not exited)."""
    return [p for p in result.processes if not p.exited]


def plugin_rows(result: AnalysisResult, plugin_name: str):
    for plugin in result.plugins:
        if plugin.name == plugin_name and plugin.status == "Completed":
            for row in plugin.rows:
                if isinstance(row, dict):
                    yield row


def plugin_rows_indexed(result: AnalysisResult, plugin_name: str):
    """Like :func:`plugin_rows` but yields ``(row_index, row)``; the index is the row's position in the plugin
    output, which is what evidence provenance (``EvidenceItem.row_index``) points at."""
    for plugin in result.plugins:
        if plugin.name == plugin_name and plugin.status == "Completed":
            for index, row in enumerate(plugin.rows):
                if isinstance(row, dict):
                    yield index, row


def plugin_completed(result: AnalysisResult, plugin_name: str) -> bool:
    """True when the plugin ran successfully and produced rows (an empty or failed plugin gives a rule nothing to compare)."""
    return any(p.name == plugin_name and p.status == "Completed" and p.rows for p in result.plugins)


def row_value(row, *keys, default=""):
    normalized = {str(k).strip().lower().replace(" ", "").replace("_", ""): v for k, v in row.items()}
    for key in keys:
        k = str(key).strip().lower().replace(" ", "").replace("_", "")
        if k in normalized:
            return normalized[k]
    return default


def pid_from_row(row):
    value = row_value(row, "PID", "Pid", "ProcessId", default=None)
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def process_for_pid(result, pid):
    return process_map(result).get(pid)


def parent_of(result_map, proc: Process) -> Optional[Process]:
    """Parent process, ignoring PID reuse (a 'parent' created after its child is not its parent)."""
    from app.util import parse_time
    parent = result_map.get(proc.ppid)
    if not parent or parent.pid == proc.pid:
        return None
    pt, ct = parse_time(parent.create_time), parse_time(proc.create_time)
    if pt and ct and pt > ct:
        return None
    return parent
