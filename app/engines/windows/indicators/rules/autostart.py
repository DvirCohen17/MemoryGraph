"""Autostart registry rules beyond the Run keys: Winlogon, AppInit_DLLs, Image File Execution Options."""
from app.engines.windows.analysis import plugin_registry
from app.analysis.indicators.base import IndicatorRule, row_value
from app.models import EvidenceItem

# Sysinternals Process Explorer replacing Task Manager through an IFEO debugger is a known legitimate use
_KNOWN_DEBUGGER_REPLACEMENTS = ("procexp.exe", "procexp64.exe")


def autostart_issue(key: str, name: str, data: str):
    """``(reason, severity)`` when this Winlogon / AppInit_DLLs / IFEO value is unusual, else ``("", "")``. Pure: also used by the timeline."""
    low_key, low_name, low_data = key.lower(), name.lower(), data.lower().replace('"', "").strip()
    if low_key.endswith("\\winlogon") and low_name == "shell" and low_data and low_data.rstrip(",") != "explorer.exe":
        return f"Winlogon Shell is '{data}' instead of explorer.exe", "Medium"
    if low_key.endswith("\\winlogon") and low_name == "userinit" and low_data:
        parts = [p.strip() for p in low_data.split(",") if p.strip()]
        if not parts or not parts[0].endswith("\\system32\\userinit.exe") or len(parts) > 1:
            return f"Winlogon Userinit is '{data}' (normally only C:\\Windows\\system32\\userinit.exe,)", "Medium"
    elif low_key.endswith("\\windows") and low_name == "appinit_dlls" and low_data not in ("", "0"):
        return f"AppInit_DLLs loads '{data}' into every program that uses user32.dll", "Medium"
    elif "image file execution options\\" in low_key and low_name == "debugger" and low_data:
        if low_key.endswith("\\your image file name here without a path"):
            return "", ""                      # the inert placeholder entry Windows XP / 2003 ship (Debugger = ntsd -d)
        severity = "Low" if any(known in low_data for known in _KNOWN_DEBUGGER_REPLACEMENTS) else "Medium"
        return f"Starting {key.rsplit(chr(92), 1)[-1]} runs '{data}' instead", severity
    return "", ""


class AutostartKeyRule(IndicatorRule):
    rule_id = "PER-002"
    category = "persistence"
    name = "Winlogon, AppInit_DLLs or Image File Execution Options changed"
    description = ("Three registry places that run code for every logon or every start of a program: Winlogon's Shell and Userinit values "
                   "(normally explorer.exe and userinit.exe), AppInit_DLLs (DLLs injected into every program that loads user32), and an "
                   "Image File Execution Options 'Debugger' (runs another program instead of the one the user started). Needs the opt-in "
                   "'registry autostart keys' plugins.")

    def evaluate(self, result):
        findings = []
        mine = set(plugin_registry.plugin_names_used_by(self.rule_id))
        for plugin in result.plugins:
            if plugin.name not in mine or plugin.status != "Completed":
                continue
            for index, row in enumerate(plugin.rows):
                if not isinstance(row, dict) or str(row_value(row, "Type")).upper() == "KEY":
                    continue
                key = str(row_value(row, "Key") or "")
                name = str(row_value(row, "Name") or "")
                data = str(row_value(row, "Data") or "").strip()
                reason, severity = autostart_issue(key, name, data)
                if not reason:
                    continue
                findings.append(self.make(
                    title=reason, severity=severity, confidence="Medium",
                    summary="These registry values decide what Windows runs automatically. Software that legitimately changes them exists "
                            "(some security tools, Process Explorer as the Task Manager replacement), so check who installed it.",
                    reasons=[reason, f"Key: {key}", f"Last written: {row_value(row, 'Last Write Time')}"],
                    evidence=[f"{key}\\{name} = {data[:400]}"], source_plugins=[plugin.name],
                    evidence_items=[EvidenceItem("registry", "Data", data[:400], f"{key}\\{name}", plugin.name, index)]))
        return findings
