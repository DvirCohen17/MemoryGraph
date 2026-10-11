"""Handle rules."""
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, lower, process_map
from app.engines.windows.indicators.helpers import full_name


class LsassHandleRule(IndicatorRule):
    rule_id = "HND-001"
    category = "handle"
    name = "Handle to lsass.exe with memory-read access"
    description = "A process other than the normal system components holds a handle to lsass with PROCESS_VM_READ (credential dumping technique)."

    def evaluate(self, result):
        lsass_pids = {p.pid for p in result.processes if full_name(p) == "lsass.exe" and not p.exited}
        if not lsass_pids:
            return []
        findings = []
        for p in result.processes:
            if p.pid in lsass_pids or lower(p.name) in baseline.LSASS_HANDLE_ALLOWED or full_name(p) in baseline.LSASS_HANDLE_ALLOWED:
                continue
            hits = []
            for h in p.handles:
                if not isinstance(h, dict) or lower(h.get("type")) != "process":
                    continue
                target = lower(h.get("name"))
                if not target.startswith("lsass.exe"):
                    continue
                access = int(h.get("access") or 0)
                if access & baseline.PROCESS_VM_READ:
                    hits.append((h, access))
            if not hits:
                continue
            findings.append(self.make(
                title="Process holds a memory-read handle to lsass.exe", severity="High", confidence="Medium", process=p,
                summary="This process can read the memory of lsass.exe, which stores credentials. Legitimate security tools do this too, so review the process identity.",
                reasons=[f"{len(hits)} handle(s) to lsass with PROCESS_VM_READ"],
                evidence=[f"{h['name']} access=0x{access:x}" for h, access in hits[:10]], source_plugins=["windows.handles"]))
        return findings
