"""Rules that compare several views of the same objects (process cross-view, baseline of the process list)."""
from app.analysis.indicators.base import IndicatorRule, plugin_rows_indexed, process_for_pid, row_value
from app.engines.windows.indicators.helpers import is_high_risk_dir
from app.models import EvidenceItem
from app.util import norm_path, to_int

_TRUE = (True, 1, "True", "true", "1")
_MAX_LISTED = 25


def process_key(proc) -> str:
    """How a baseline recognises 'the same program': image name + image path, no PID, no times."""
    return f"{proc.name.lower()}|{norm_path(proc.path)}"


class CrossViewRule(IndicatorRule):
    rule_id = "PX-001"
    category = "process"
    name = "Process hidden from the process list and from the pool scan"
    description = ("windows.psxview shows each process in several independent views: the active list (pslist), a pool scan (psscan), a thread "
                   "scan (thrdscan) and the csrss handle table. A running process that is missing from pslist AND psscan but still seen through "
                   "its threads or by csrss has been hidden more thoroughly than PT-003's simple unlinking. Needs windows.psxview.")

    def evaluate(self, result):
        findings = []
        for index, row in plugin_rows_indexed(result, "windows.psxview"):
            flags = {key: row_value(row, key, default=None) in _TRUE for key in ("pslist", "psscan", "thrdscan", "csrss")}
            exited = row_value(row, "Exit Time", default=None)
            if exited not in (None, "", "N/A"):
                continue                                                # a process that already exited is expected to be gone from pslist
            if flags["pslist"] or flags["psscan"] or not (flags["thrdscan"] or flags["csrss"]):
                continue                                                # psscan-only unlinking is PT-003; this rule is the stricter case
            pid = to_int(row_value(row, "PID", default=None))
            name = str(row_value(row, "Name") or "")
            seen = [k for k in ("thrdscan", "csrss") if flags[k]]
            findings.append(self.make(
                title=f"{name or 'Process'} (PID {pid}) is only visible through {' and '.join(seen)}", severity="Medium", confidence="Medium",
                process=process_for_pid(result, pid),
                summary="The process is not in pslist and not found by the pool scan, yet its threads or csrss still know about it. Hiding from both pslist and psscan takes more than unlinking one list.",
                reasons=[f"windows.psxview: pslist=False, psscan=False, {', '.join(k + '=True' for k in seen)}", "No exit time recorded"],
                evidence=[f"{name} PID {pid}"], source_plugins=["windows.psxview"],
                evidence_items=[EvidenceItem("process", "PID", str(pid), name, "windows.psxview", index)]))
        return findings


class NewProcessRule(IndicatorRule):
    rule_id = "BASE-001"
    category = "baseline"
    name = "Process that is not in the known-good baseline"
    description = ("When a baseline made from a clean dump of this system is imported (Case Notes), processes whose image name and path do not "
                   "occur in it are listed. New is not bad: software gets installed. It narrows hundreds of processes down to what changed. "
                   "Baselines exported before this feature carry no process list and are ignored here.")

    def evaluate(self, result):
        baselines = [b for b in (result.case or {}).get("baselines", []) if isinstance(b, dict) and b.get("processes")]
        if not baselines:
            return []
        known = {str(p) for b in baselines for p in b["processes"]}
        new = [p for p in result.processes if process_key(p) not in known]
        if not new:
            return []
        names = ", ".join(sorted({str(b.get("name", "baseline")) for b in baselines}))
        risky = [p for p in new if is_high_risk_dir(p.path)]
        shown = new[:_MAX_LISTED]
        return [self.make(
            title=f"{len(new)} process(es) are not in baseline '{names}'", severity="Medium" if risky else "Low", confidence="Medium",
            summary="These processes (by image name and path) did not exist in the clean dump the baseline was made from."
                    + (f" {len(risky)} of them run from a temporary or user-writable folder." if risky else ""),
            reasons=[f"Baseline(s): {names}", f"{len(new)} of {len(result.processes)} processes are new"],
            evidence=[f"{p.name} (PID {p.pid}) {p.path}".strip() for p in shown] + ([f"... and {len(new) - _MAX_LISTED} more"] if len(new) > _MAX_LISTED else []),
            source_plugins=["windows.pslist", "windows.pstree"],
            evidence_items=[EvidenceItem("process", "image", p.path or p.name, f"PID {p.pid}", "windows.pslist", -1) for p in shown])]
