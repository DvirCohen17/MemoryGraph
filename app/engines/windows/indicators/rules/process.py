"""Process tree / hierarchy rules, driven by the baseline tables."""
from datetime import timedelta

from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, active, display, lower, parent_of, plugin_rows_indexed, process_map, row_value
from app.engines.windows.indicators.helpers import full_name, is_interpreter, nt_major, nt_version
from app.models import EvidenceItem
from app.util import parse_time, to_int

# DumpIt and similar tools record the time the acquisition STARTED; writing a large image takes minutes, and the process lists keep changing meanwhile.
ACQUISITION_GRACE = timedelta(seconds=5)


class CoreProcessParentRule(IndicatorRule):
    rule_id = "PT-001"
    category = "process"
    name = "Core Windows process with unexpected parent"
    description = "A well-known Windows process (lsass, services, svchost, ...) was started by a process that is not its normal parent."

    def evaluate(self, result):
        by_pid = process_map(result)
        findings = []
        legacy = 0 < nt_major(result) < 6            # Windows XP / 2003: other parents for services.exe and lsass.exe
        for p in result.processes:
            spec = baseline.CORE_PROCESSES.get(full_name(p))
            if not spec:
                continue
            if legacy and full_name(p) in baseline.LEGACY_PARENTS:
                spec = dict(spec, parents=baseline.LEGACY_PARENTS[full_name(p)])
            parent = parent_of(by_pid, p)
            if parent is None:
                if not spec["parent_may_be_gone"] and not p.exited and p.ppid not in (0, 4):
                    findings.append(self.make(
                        title=f"{p.name} has no running parent process", severity="Medium", confidence="Low", process=p,
                        summary=f"{p.name} normally has a living parent ({', '.join(sorted(spec['parents']))}) but PPID {p.ppid} was not found in the process list.",
                        reasons=[f"Parent PID {p.ppid} not present", f"Expected parent: {', '.join(sorted(spec['parents']))}"],
                        evidence=[f"{display(p)} created {p.create_time or 'unknown'}"], source_plugins=["windows.pslist", "windows.psscan"]))
                continue
            pname = full_name(parent)
            if pname in spec["parents"] or (pname == "system" and "system" in spec["parents"]):
                continue
            findings.append(self.make(
                title=f"{p.name} started by unexpected parent {parent.name}", severity="High", confidence="High", process=p,
                summary=f"{p.name} is a core Windows component whose parent is normally {', '.join(sorted(spec['parents']))}, but it was started by {parent.name}.",
                reasons=[f"Observed parent: {display(parent)}", f"Expected parent: {', '.join(sorted(spec['parents']))}"],
                evidence=[f"{display(parent)} → {display(p)}"], source_plugins=["windows.pslist", "windows.pstree"],
                related_processes=[display(parent)]))
        return findings


class MissingOnThisWindowsRule(IndicatorRule):
    rule_id = "PT-005"
    category = "process"
    name = "System process that does not exist on this Windows version"
    description = ("wininit.exe, lsm.exe, dwm.exe, conhost.exe, sihost.exe and similar system processes were introduced with later Windows versions. One "
                   "running on an older Windows (for example wininit.exe on Windows XP) is not a system process: it borrows the name. Needs the Windows "
                   "version from windows.info.")

    def evaluate(self, result):
        version = nt_version(result)
        if version == (0, 0):
            return []
        findings = []
        for p in active(result):
            needs = baseline.MIN_WINDOWS_FOR_PROCESS.get(full_name(p))
            if needs and version < needs:
                findings.append(self.make(
                    title=f"{p.name} cannot exist on this Windows version", severity="Medium", confidence="High", process=p,
                    summary=f"{p.name} was introduced with Windows NT {needs[0]}.{needs[1]}; this image runs NT {version[0]}.{version[1]}, so the process only borrows the name.",
                    reasons=[f"Image Windows: NT {version[0]}.{version[1]}", f"{p.name} appears from NT {needs[0]}.{needs[1]}"],
                    evidence=[f"{display(p)} path: {p.path or 'unknown'}"], source_plugins=["windows.pslist", "windows.info"]))
        return findings


class SingletonProcessRule(IndicatorRule):
    rule_id = "PT-002"
    category = "process"
    name = "Duplicate of a single-instance Windows process"
    description = "lsass.exe, services.exe, wininit.exe, ... only run once; a second running copy is a strong masquerading sign."

    def evaluate(self, result):
        groups = {}
        for p in active(result):
            spec = baseline.CORE_PROCESSES.get(full_name(p))
            if spec and spec["single"]:
                groups.setdefault(full_name(p), []).append(p)
        findings = []
        for pname, procs in groups.items():
            if len(procs) < 2:
                continue
            for p in procs:
                findings.append(self.make(
                    title=f"More than one running {pname}", severity="High", confidence="High", process=p,
                    summary=f"{pname} should exist exactly once but {len(procs)} running instances were found.",
                    reasons=[f"Instances: {', '.join(display(x) for x in procs)}"],
                    evidence=[f"{display(x)} path: {x.path or 'unknown'}" for x in procs],
                    source_plugins=["windows.pslist"], related_processes=[display(x) for x in procs if x is not p]))
        return findings


class HiddenProcessRule(IndicatorRule):
    rule_id = "PT-003"
    category = "process"
    name = "Process found by scanning but missing from the process list"
    description = ("psscan found a non-exited process that pslist (the active process list) does not contain: unlinked or hidden. A process that was created at or after the "
                   "moment the acquisition started (the capture time of windows.info) is more likely caught while the lists were changing than hidden, and is Low; "
                   "one that is older, and that csrss and the thread scan still know, is unlinked while alive (Medium, high confidence).")

    def evaluate(self, result):
        captured = parse_time(result.capture_time)
        views = {}
        for _i, row in plugin_rows_indexed(result, "windows.psxview"):
            pid = to_int(row_value(row, "PID", default=None))
            if pid is not None:
                views[pid] = {k: row_value(row, k, default=None) in (True, 1, "True", "true", "1") for k in ("pslist", "psscan", "thrdscan", "csrss")}
        findings = []
        for p in result.processes:
            if not p.hidden:
                continue
            created = parse_time(p.create_time)
            late = captured is not None and created is not None and created >= captured - ACQUISITION_GRACE
            seen = views.get(p.pid, {})
            alive = bool(seen.get("csrss") and seen.get("thrdscan"))
            reasons = ["Found by windows.psscan only", "No exit time recorded"]
            if seen:
                reasons.append("windows.psxview: " + ", ".join(f"{k}={'True' if v else 'False'}" for k, v in seen.items()))
            if late:
                severity, confidence = "Low", "Low"
                reasons.append(f"Created {p.create_time}, at or after the capture start recorded by windows.info ({result.capture_time}): the lists were still changing while "
                               "the image was written, so this is more likely a process caught mid-creation than a hidden one")
            else:
                severity, confidence = "Medium", ("High" if alive else "Medium")
                if alive:
                    reasons.append("csrss and the thread scan still know this process although it is not in the active list: unlinked while alive")
            findings.append(self.make(
                title="Process present in psscan but not in pslist", severity=severity, confidence=confidence, process=p,
                summary="The process structure was found by pool scanning and has no exit time, but it is not linked into the active process list. This can indicate unlinking (hiding), "
                        "or a process that was being created or ended while the image was captured.",
                reasons=reasons,
                evidence=[f"{display(p)} created {p.create_time or 'unknown'}", f"Offset {p.offset or 'unknown'}"],
                source_plugins=["windows.psscan", "windows.pslist"] + (["windows.psxview"] if seen else []),
                evidence_items=[EvidenceItem("process", "PID", str(p.pid), p.name, "windows.psscan", -1)]))
        return findings


class InterpreterParentRule(IndicatorRule):
    rule_id = "PT-004"
    category = "process"
    name = "Interpreter started by an unusual parent"
    description = "cmd/PowerShell/script hosts spawned by something that is not a shell, terminal or installer. Low priority; matters in combination."

    def evaluate(self, result):
        by_pid = process_map(result)
        findings = []
        for child in result.processes:
            if not is_interpreter(child.name):
                continue
            parent = parent_of(by_pid, child)
            if not parent:
                continue
            pname = full_name(parent)
            if pname in baseline.NORMAL_INTERPRETER_PARENTS:
                continue
            findings.append(self.make(
                title=f"{child.name} started by {parent.name}", severity="Low", confidence="Medium", process=child,
                summary="A command/script interpreter was started by a process that does not normally launch one. Review the command line and what the parent was doing.",
                reasons=[f"Parent: {display(parent)}", f"Child: {display(child)}"],
                evidence=[f"Command line: {child.command_line or 'not available'}"],
                source_plugins=["windows.pslist", "windows.pstree", "windows.cmdline"], related_processes=[display(parent)]))
        return findings
