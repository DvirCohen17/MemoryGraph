"""Process-injection chains: the evidence about one process from several plugins, put into one story (no Qt, unit-tested without a GUI).

A single sign (an executable private region, a DLL missing from the loader lists) is often benign. The same process having several of them, plus
another process holding a handle that can write into it, plus a thread that starts in unbacked memory, is a story. For every process that has at least
one memory-level sign this module collects:

* **signs in the process**: executable private memory (malfind: MZ header / shellcode / other), images in no loader list (LDR-001 / VAD-001), threads that start
  outside any module (MAL-002), hollowing (MAL-001), ghosting (MAL-004), a rewritten PEB (MAL-003), patched ETW (MAL-007);
* **who could have done it**: processes holding a handle to it with access that allows writing memory or creating a thread (``windows.handles`` raw rows),
  except the operating system's own processes, which hold such handles all the time;
* **what it did afterwards**: processes it started, connections it holds, injection-capable handles it holds into other processes.

Nothing here decides anything: the chain orders what the plugins reported. Rule findings that the investigator marked as false positive are left out.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.analysis.indicators.base import is_public_ip, lower, plugin_rows_indexed, row_value
from app.engines.windows.indicators.rules.memory import classify_region
from app.analysis.indicators.scoring import severity_rank
from app.util import format_time, to_hex, to_int

# access rights of a process handle (PROCESS_*)
PROCESS_RIGHTS = {0x0001: "TERMINATE", 0x0002: "CREATE_THREAD", 0x0008: "VM_OPERATION", 0x0010: "VM_READ", 0x0020: "VM_WRITE", 0x0040: "DUP_HANDLE",
                  0x0080: "CREATE_PROCESS", 0x0200: "SET_INFORMATION", 0x0400: "QUERY_INFORMATION", 0x0800: "SUSPEND_RESUME"}
THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME = 0x0010, 0x0002
FULL_ACCESS = (0x1F0FFF, 0x1FFFFF, 0x1F0FFF)
# operating-system processes hold handles into other processes all the time: not evidence of injection on their own
SYSTEM_HANDLE_HOLDERS = {"system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe", "svchost.exe", "msmpeng.exe"}
EVIDENCE_RULES = {"MEM-001": "memory", "LDR-001": "module", "VAD-001": "module", "MAL-001": "hollowing", "MAL-002": "thread", "MAL-003": "peb",
                  "MAL-004": "ghosting", "MAL-007": "etw"}
KIND_LABEL = {"memory": "executable private memory", "module": "image in no loader list", "hollowing": "hollowed image", "thread": "thread outside any module",
              "peb": "rewritten PEB", "ghosting": "deleted image file", "etw": "patched ETW", "handle": "write-capable handle from another process",
              "network": "external connection"}
_PID = re.compile(r"Pid\s+(\d+)", re.IGNORECASE)


@dataclass
class Step:
    phase: str                 # "In the process" / "Who could have done it" / "What it did afterwards"
    kind: str
    text: str
    severity: str = "Low"
    source: str = ""           # rule id or plugin
    pid: int = 0               # another process this step is about (for "open process")


@dataclass
class Chain:
    pid: int
    process: str
    steps: List[Step] = field(default_factory=list)

    @property
    def kinds(self) -> Set[str]:
        return {s.kind for s in self.steps}

    @property
    def score(self) -> int:
        """Distinct kinds of evidence, weighted by the worst severity of each (High counts 3, Medium 2, Low 1)."""
        best: Dict[str, int] = {}
        for step in self.steps:
            best[step.kind] = max(best.get(step.kind, 0), severity_rank(step.severity))
        return sum(best.values()) + len(best)


def access_names(mask: int) -> List[str]:
    return [name for bit, name in PROCESS_RIGHTS.items() if mask & bit]


def process_access_can_inject(mask: int) -> bool:
    """Write into the process's memory (VM_OPERATION + VM_WRITE), start a thread in it, or everything."""
    return bool(mask & 0x0002) or bool(mask & 0x0008 and mask & 0x0020) or (mask & 0x1F0FFF) == 0x1F0FFF


def _handles_into(result) -> Dict[int, List[Tuple[int, str, str, int, int]]]:
    """``{target pid: [(holder pid, holder name, kind, mask, row index)]}`` from the raw windows.handles rows."""
    found: Dict[int, List[Tuple[int, str, str, int, int]]] = {}
    for index, row in plugin_rows_indexed(result, "windows.handles"):
        kind = lower(row_value(row, "Type"))
        if kind not in ("process", "thread"):
            continue
        holder = to_int(row_value(row, "PID", default=None))
        match = _PID.search(str(row_value(row, "Details", "Name") or ""))
        mask = to_int(row_value(row, "GrantedAccess", default=0), 0) or 0
        if holder is None or not match or int(match.group(1)) == holder:
            continue
        if kind == "process" and not process_access_can_inject(mask):
            continue
        if kind == "thread" and not (mask & THREAD_SET_CONTEXT and mask & THREAD_SUSPEND_RESUME) and (mask & 0x1F03FF) != 0x1F03FF:
            continue
        found.setdefault(int(match.group(1)), []).append((holder, str(row_value(row, "Process") or ""), kind, mask, index))
    return found


def build_chains(result) -> List[Chain]:
    """Chains of every process that has at least one memory-level sign, most evidence first."""
    by_pid = {p.pid: p for p in result.processes}
    steps: Dict[int, List[Step]] = {}

    def add(pid: int, step: Step) -> None:
        steps.setdefault(pid, []).append(step)

    # --- signs in the process: malfind regions, scored like rule MEM-001
    for region in result.memory_regions:
        proc = by_pid.get(region.pid)
        modules = {lower(d.name) for d in proc.dlls} if proc else set()
        severity, why = classify_region(region, modules)
        if severity == "Low" and not any("MZ" in w or "shellcode" in w for w in why):
            continue                                   # empty / JIT regions are not a sign
        add(region.pid, Step("In the process", "memory", f"{region.range} {region.protection}: {why[0]}", severity, "windows.malfind"))
    # --- signs from the other rules
    for finding in result.indications:
        kind = EVIDENCE_RULES.get(finding.rule_id)
        if kind and finding.process_pid and finding.triage != "false_positive" and finding.category != "ioc":
            if kind == "memory":
                continue                               # already listed region by region
            add(finding.process_pid, Step("In the process", kind, finding.title, finding.severity, finding.rule_id))
    if not steps:
        return []

    # --- who could have done it, and what the process holds into others
    into = _handles_into(result)
    for target, holders in into.items():
        for holder, name, kind, mask, _index in holders:
            if lower(name) in SYSTEM_HANDLE_HOLDERS or target not in steps:
                continue
            rights = ", ".join(access_names(mask)[:5]) if kind == "process" else "SET_CONTEXT, SUSPEND_RESUME"
            add(target, Step("Who could have done it", "handle", f"{name} (PID {holder}) holds a {kind} handle to it with {rights} (0x{mask:x})",
                             "Medium", "windows.handles", holder))
    for target, holders in into.items():
        for holder, name, kind, mask, _index in holders:
            if holder in steps and lower(name) not in SYSTEM_HANDLE_HOLDERS and target in by_pid:
                add(holder, Step("What it did afterwards", "handle", f"holds a {kind} handle into {by_pid[target].name} (PID {target}) with {', '.join(access_names(mask)[:4]) or hex(mask)}",
                                 "Low", "windows.handles", target))
    for pid in list(steps):
        proc = by_pid.get(pid)
        if proc is None:
            continue
        for child in result.processes:
            if child.ppid == pid and child.pid != pid:
                add(pid, Step("What it did afterwards", "child", f"started {child.name} (PID {child.pid}) at {format_time(child.create_time) if child.create_time else 'an unknown time'}",
                              "Low", "windows.pslist", child.pid))
        for conn in proc.network:
            if is_public_ip(conn.remote_address):
                add(pid, Step("What it did afterwards", "network", f"{conn.protocol} {conn.local} → {conn.remote} {conn.state}".strip(), "Medium", ", ".join(conn.source_plugins)))

    chains = []
    for pid, items in steps.items():
        proc = by_pid.get(pid)
        name = proc.name if proc else next((r.process for r in result.memory_regions if r.pid == pid), f"PID {pid}")
        order = {"In the process": 0, "Who could have done it": 1, "What it did afterwards": 2}
        items.sort(key=lambda s: (order[s.phase], -severity_rank(s.severity)))
        chains.append(Chain(pid, name, items))
    # a chain needs a sign inside the process; handles and children alone are not evidence
    chains = [c for c in chains if any(s.phase == "In the process" for s in c.steps)]
    chains.sort(key=lambda c: (-c.score, c.pid))
    return chains


def parent_line(result, pid: int) -> str:
    proc = next((p for p in result.processes if p.pid == pid), None)
    if proc is None:
        return ""
    parent = next((p for p in result.processes if p.pid == proc.ppid), None)
    started = format_time(proc.create_time) if proc.create_time else "unknown time"
    return (f"{proc.name} (PID {proc.pid}) was started {started} by {parent.name + ' (PID ' + str(parent.pid) + ')' if parent else 'PID ' + str(proc.ppid) + ' (no longer in the list)'}"
            f"{'; image ' + proc.path if proc.path else ''}")
