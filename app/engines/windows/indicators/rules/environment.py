"""Environment-variable rules (need the opt-in windows.envars)."""
from collections import OrderedDict

from app.analysis.indicators.base import IndicatorRule, lower, plugin_rows_indexed, process_for_pid, row_value
from app.models import EvidenceItem
from app.util import norm_path, to_int

# variable -> (suffixes a normal value ends with, why it matters)
_EXPECTED = {
    "comspec": (("\\system32\\cmd.exe",), "COMSPEC decides which program 'cmd' and many installers launch"),
    "systemroot": (("\\windows", "\\winnt"), "SystemRoot is where the system looks for its DLLs and programs"),
    "windir": (("\\windows", "\\winnt"), "windir is where the system looks for its DLLs and programs"),
}
_MAX_PROCESSES = 12


class EnvironmentVariableRule(IndicatorRule):
    rule_id = "ENV-001"
    category = "environment"
    name = "System environment variable pointing somewhere unusual"
    description = ("COMSPEC, SystemRoot and windir have fixed, well-known values. A process whose value differs (another folder or program) "
                   "may have been redirected by malware or a shim. One finding per distinct odd value, listing the processes. "
                   "Needs windows.envars.")

    def evaluate(self, result):
        groups = OrderedDict()
        for index, row in plugin_rows_indexed(result, "windows.envars"):
            variable = lower(row_value(row, "Variable"))
            if variable not in _EXPECTED:
                continue
            value = str(row_value(row, "Value") or "")
            normal = norm_path(value)
            if not normal or normal.endswith(_EXPECTED[variable][0]):
                continue
            groups.setdefault((variable, value), []).append((index, to_int(row_value(row, "PID", default=None)), str(row_value(row, "Process"))))
        findings = []
        for (variable, value), rows in groups.items():
            listed = rows[:_MAX_PROCESSES]
            first_pid = next((pid for _i, pid, _n in rows if pid), None)
            findings.append(self.make(
                title=f"{variable.upper() if variable == 'comspec' else variable} is set to '{value}' in {len(rows)} process(es)",
                severity="Medium", confidence="Medium", process=process_for_pid(result, first_pid) if first_pid else None,
                summary=f"{_EXPECTED[variable][1]}. The normal value ends with {' or '.join(_EXPECTED[variable][0])}.",
                reasons=[f"{variable} = {value}"],
                evidence=[f"{name} (PID {pid})" for _i, pid, name in listed] + ([f"... and {len(rows) - _MAX_PROCESSES} more"] if len(rows) > _MAX_PROCESSES else []),
                source_plugins=["windows.envars"],
                evidence_items=[EvidenceItem("environment", "Value", value, f"{name} (PID {pid})", "windows.envars", i) for i, pid, name in listed]))
        return findings
