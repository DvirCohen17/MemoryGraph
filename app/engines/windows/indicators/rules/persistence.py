"""Persistence rules that read the registry's own view of services and the scheduled-task store.

* PER-003  services as registered in the SYSTEM hive (``ImagePath``, ``ServiceDll``, ``FailureCommand``), from the opt-in
           ``printkey [Services]`` run. svcscan only sees services Windows has loaded into its structures; this sees the registry.
* PER-004  scheduled tasks (``windows.registry.scheduled_tasks``): what a task runs, flagged like an autorun entry.
"""
import re

from app.engines.windows.analysis import plugin_registry
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, plugin_rows_indexed, row_value
from app.engines.windows.indicators.helpers import expand_env_path, has_encoded_powershell, is_appdata, is_high_risk_dir, is_vendor_appdata, looks_obfuscated, split_command
from app.engines.windows.indicators.rules.registry import _PATHS
from app.models import EvidenceItem
from app.util import norm_path, path_file, to_int

_SERVICE_KEY = re.compile(r"\\services\\([^\\]+)(?:\\(.*))?$", re.IGNORECASE)
_SERVICE_VALUES = ("imagepath", "servicedll", "failurecommand", "start", "type")
_TASK_ARGS = re.compile(
    r"(?i)(-w(?:indowstyle)?\s+hidden|-nop\b|-noprofile|-ep\s+bypass|-executionpolicy\s+bypass|downloadstring|downloadfile|"
    r"invoke-expression|\biex\b|https?://|frombase64string|scrobj\.dll)")


def _program_name(command: str) -> str:
    name = path_file(norm_path(split_command(command)[0]))
    return name + ".exe" if name and "." not in name else name


def command_reasons(command: str):
    """``[(reason, severity)]`` for a command line that starts at boot/logon/schedule: risky folder, encoded text. Shared by PER-003/4."""
    found = []
    risky = [p for p in _PATHS.findall(expand_env_path(command)) if is_high_risk_dir(p)]
    program = split_command(command)[0]
    if not risky and program and is_high_risk_dir(program):
        risky = [program]
    if risky:
        found.append((f"Runs {risky[0]} (temporary/user-writable folder)", "Medium"))
    elif program and is_appdata(program) and not is_vendor_appdata(program):
        found.append((f"Runs {program} (per-user AppData folder)", "Low"))
    if has_encoded_powershell(command) or looks_obfuscated(command):
        found.append(("The command looks encoded or obfuscated", "Medium"))
    return found


def _worst(severities):
    return "Medium" if "Medium" in severities else "Low"


class ServiceKeyRule(IndicatorRule):
    rule_id = "PER-003"
    category = "persistence"
    name = "Service registered in the registry with a binary in a risky place or an encoded command"
    description = ("Reads every service key of the SYSTEM hive (windows.registry.printkey on ControlSet001\\Services): ImagePath, ServiceDll "
                   "(the DLL a svchost service loads, which svcscan does not show as a path), and FailureCommand. Flagged: a target in "
                   "Temp/Public/Downloads/Recycle Bin, an encoded command, or a script host as the service image. Disabled services "
                   "(Start = 4) are reported one level lower. Needs the opt-in 'registry services' plugin.")

    def evaluate(self, result):
        services = {}
        mine = set(plugin_registry.plugin_names_used_by(self.rule_id))
        for plugin in result.plugins:
            if plugin.name not in mine or plugin.status != "Completed":
                continue
            for index, row in enumerate(plugin.rows):
                if not isinstance(row, dict) or str(row_value(row, "Type")).upper() == "KEY":
                    continue
                match = _SERVICE_KEY.search(str(row_value(row, "Key") or ""))
                value_name = str(row_value(row, "Name") or "").lower()
                if not match or value_name not in _SERVICE_VALUES:
                    continue
                data = str(row_value(row, "Data") or "").strip()
                if data:
                    services.setdefault(match.group(1), {})[(value_name, (match.group(2) or "").lower())] = (data, index, plugin.name,
                                                                                                         str(row_value(row, "Key") or ""))
        findings = []
        for service, values in services.items():
            reasons, severities, items, evidence = [], [], [], []
            source = ""
            for (value_name, _sub), (data, index, plugin_name, key) in values.items():
                if value_name not in ("imagepath", "servicedll", "failurecommand"):
                    continue
                field = {"imagepath": "ImagePath", "servicedll": "ServiceDll", "failurecommand": "FailureCommand"}[value_name]
                hits = command_reasons(data)
                if value_name == "imagepath" and _program_name(data) in baseline.INTERPRETERS:
                    hits.append((f"The service image is {_program_name(data)}", "Low"))
                for reason, severity in hits:
                    reasons.append(f"{field}: {reason}")
                    severities.append(severity)
                if hits:
                    evidence.append(f"{field} = {data[:400]}")
                    items.append(EvidenceItem("registry", field, data[:400], f"{key}\\{field}", plugin_name, index))
                    source = source or plugin_name
            if not reasons:
                continue
            severity = _worst(severities)
            start = to_int(values.get(("start", ""), ("",))[0])
            if start == 4 and severity == "Medium":
                severity = "Low"
                reasons.append("The service is disabled (Start = 4), so it does not start by itself")
            findings.append(self.make(
                title=f"Service '{service}': {reasons[0].split(': ', 1)[-1]}", severity=severity, confidence="Medium",
                summary="A service is registered with a program or command that Windows services do not normally use. Compare the "
                        "image with svcscan, the process list and the file on disk.",
                reasons=reasons + [f"Start type: {start if start is not None else 'unknown'}"],
                evidence=evidence, source_plugins=[source], evidence_items=items))
        return findings


class ScheduledTaskRule(IndicatorRule):
    rule_id = "PER-004"
    category = "persistence"
    name = "Scheduled task that runs code from a risky place or through an interpreter with hiding/downloading options"
    description = ("Reads the scheduled-task store (windows.registry.scheduled_tasks). Flagged: an action in Temp/Public/Downloads/Recycle Bin "
                   "(also written as %TEMP%), an encoded command, or any program started with hidden-window / bypass / download "
                   "arguments or a URL. A script host or LOLBin alone is not flagged (system tasks use them). Disabled tasks are "
                   "reported one level lower. Needs the opt-in 'scheduled tasks' plugin.")

    def evaluate(self, result):
        findings = []
        seen = set()
        for plugin_name in plugin_registry.plugin_names_used_by(self.rule_id):
            for index, row in plugin_rows_indexed(result, plugin_name):
                kind = str(row_value(row, "Action Type") or "").lower()
                if kind and kind not in ("exe", "exec", "execute"):          # COM handler / e-mail / message box: no command line
                    continue
                action = str(row_value(row, "Action") or "").strip()
                args = str(row_value(row, "Action Arguments") or "").strip()
                task = str(row_value(row, "Task Name") or row_value(row, "Key Name") or "").strip()
                if not action or (task, action, args) in seen:
                    continue
                seen.add((task, action, args))
                command = f"{action} {args}".strip()
                hits = command_reasons(command)
                if _TASK_ARGS.search(command):
                    hits.append((f"Started with hiding/bypass/download options: {_TASK_ARGS.search(command).group(0)}", "Medium"))
                if not hits:
                    continue
                severity = _worst([s for _r, s in hits])
                reasons = [r for r, _s in hits]
                if str(row_value(row, "Enabled")).lower() in ("false", "0") and severity == "Medium":
                    severity = "Low"
                    reasons.append("The task is disabled")
                findings.append(self.make(
                    title=f"Scheduled task '{task or '(unnamed)'}': {reasons[0].split(' (')[0]}", severity=severity, confidence="Medium",
                    summary="A scheduled task runs a program that is unusual for a task. Check who created it and whether the file exists on disk.",
                    reasons=reasons + [f"Created: {row_value(row, 'Creation Time') or 'unknown'}",
                                       f"Last run: {row_value(row, 'Last Run Time') or 'unknown'}",
                                       f"Trigger: {row_value(row, 'Trigger Type') or 'unknown'} {row_value(row, 'Trigger Description') or ''}".strip()],
                    evidence=[f"{task} → {command[:400]}"], source_plugins=[plugin_name],
                    evidence_items=[EvidenceItem("scheduled_task", "Action", command[:400], task, plugin_name, index)]))
        return findings
