"""Service (persistence) rules. Need the opt-in plugin windows.svcscan."""
import re

from app.analysis.indicators.base import IndicatorRule, lower, plugin_rows_indexed, process_for_pid, row_value
from app.engines.windows.indicators.helpers import is_appdata, is_high_risk_dir, is_vendor_appdata
from app.models import EvidenceItem
from app.util import norm_path, to_int

_PATH = re.compile(r'[A-Za-z]:\\[^"|<>*?\r\n]*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js)\b|\\\\[^"\s]+', re.IGNORECASE)


class RiskyServiceBinaryRule(IndicatorRule):
    rule_id = "SVC-001"
    category = "persistence"
    name = "Service whose binary is in a temporary or user-writable folder"
    description = ("Services normally run from Windows or Program Files. A service binary (or service DLL) in Temp, Downloads, Public "
                   "or per-user AppData is a common persistence location. Needs windows.svcscan (Settings → opt-in plugins).")

    def evaluate(self, result):
        findings = []
        for index, row in plugin_rows_indexed(result, "windows.svcscan"):
            kind = str(row_value(row, "Type"))
            if "WIN32" not in kind.upper():          # kernel/filesystem "services" are driver names, not file paths
                continue
            name = str(row_value(row, "Name"))
            hits = []
            for column in ("Binary", "Binary (Registry)", "Dll"):
                text = str(row_value(row, column) or "")
                for match in _PATH.findall(text):
                    path = norm_path(match)
                    if is_high_risk_dir(path):
                        hits.append((column, match, "Medium"))
                    elif is_appdata(path) and not is_vendor_appdata(path):
                        hits.append((column, match, "Low"))
            if not hits:
                continue
            severity = "Medium" if any(h[2] == "Medium" for h in hits) else "Low"
            pid = to_int(row_value(row, "PID", default=None))
            proc = process_for_pid(result, pid) if pid else None
            state = f"{row_value(row, 'State')} / start {row_value(row, 'Start')}"
            findings.append(self.make(
                title=f"Service {name} runs from {'a temporary/user-writable folder' if severity == 'Medium' else 'a per-user AppData folder'}",
                severity=severity, confidence="Medium", process=proc,
                summary="The service's binary or DLL is in a location where untrusted or per-user files live, which is unusual for a Windows service.",
                reasons=[f"{column}: {path}" for column, path, _s in hits[:4]] + [f"State: {state}"],
                evidence=[f"{name} ({row_value(row, 'Display')}) {column}={path}" for column, path, _s in hits[:4]],
                source_plugins=["windows.svcscan"],
                evidence_items=[EvidenceItem("service", column, path, name, "windows.svcscan", index) for column, path, _s in hits[:4]]))
        return findings
