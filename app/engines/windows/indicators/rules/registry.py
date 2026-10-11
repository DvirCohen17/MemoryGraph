"""Registry-based rules: persistence (Run keys) and program-execution history (UserAssist)."""
import re

from app.engines.windows.analysis import plugin_registry
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, lower, plugin_rows_indexed, row_value
from app.engines.windows.indicators.helpers import expand_env_path, has_encoded_powershell, is_high_risk_dir, looks_obfuscated, split_command
from app.models import EvidenceItem
from app.util import norm_path, path_file

_PATHS = re.compile(r'[A-Za-z]:\\[^"|<>*?\r\n]*?\.(?:exe|dll|sys|bat|cmd|ps1|vbs|js|hta|scr|lnk)\b|\\\\[^"\s]+', re.IGNORECASE)
_MAX_LISTED = 25
# Windows folders that nothing legitimate runs programs from (stronger than a user's Temp folder, where installers unpack)
_SHORTCUT_FOLDERS = ("\\users\\public\\desktop\\",)
_STRICT = ("\\users\\public\\", "$recycle.bin\\", "\\recycler\\", "\\windows\\temp\\", "\\windows\\tasks\\", "\\windows\\debug\\")


class RunKeyRule(IndicatorRule):
    rule_id = "PER-001"
    category = "persistence"
    name = "Autorun registry entry that starts code from a risky place or through an interpreter"
    description = ("Values under the Run / RunOnce keys (machine, user and 32-bit hives), Policies\\Explorer\\Run and the StubPath of Active Setup "
                   "components (from windows.registry.printkey) start at logon. Flagged: a target in Temp/Public/Downloads/Recycle Bin "
                   "(also written as %TEMP% or %PUBLIC%), an encoded or obfuscated command, or a script host / LOLBin launched from "
                   "the key (Active Setup: script hosts only, because rundll32/regsvr32 are normal there). Needs the opt-in "
                   "'registry Run keys' / 'more registry autostart keys' plugins.")

    def evaluate(self, result):
        findings = []
        seen = set()
        mine = set(plugin_registry.plugin_names_used_by(self.rule_id))      # the Run/RunOnce runs only (not Winlogon, IFEO, ...)
        for plugin in result.plugins:
            if plugin.name not in mine or plugin.status != "Completed":
                continue
            for index, row in enumerate(plugin.rows):
                if not isinstance(row, dict) or str(row_value(row, "Type")).upper() == "KEY":
                    continue
                data = str(row_value(row, "Data") or "")
                name = str(row_value(row, "Name") or "")
                key = str(row_value(row, "Key") or "")
                if not data or (key, name, data) in seen:
                    continue
                seen.add((key, name, data))
                active_setup = "active setup\\installed components" in key.lower()
                if active_setup and name.lower() != "stubpath":           # the other values of a component are versions, GUIDs, names
                    continue
                reasons, severity = [], ""
                risky = [p for p in _PATHS.findall(expand_env_path(data)) if is_high_risk_dir(p)]
                if risky:
                    reasons.append(f"Starts a program from a temporary/user-writable folder: {risky[0]}")
                    severity = "Medium"
                if has_encoded_powershell(data) or looks_obfuscated(data):
                    reasons.append("The command looks encoded or obfuscated")
                    severity = "Medium"
                first = path_file(norm_path(split_command(data)[0]))
                if first and "." not in first:
                    first += ".exe"
                if first in baseline.INTERPRETERS or (first in baseline.LOLBINS and not active_setup):
                    reasons.append(f"Runs {first} at logon")
                    severity = severity or "Low"
                if not reasons:
                    continue
                findings.append(self.make(
                    title=f"Autorun entry '{name or '(default)'}': " + reasons[0].split(":")[0], severity=severity, confidence="Medium",
                    summary="A program or command is configured to start automatically. Review whether this entry belongs to installed software.",
                    reasons=reasons + [f"Key: {key}", f"Last written: {row_value(row, 'Last Write Time')}"],
                    evidence=[f"{name} = {data[:500]}"], source_plugins=[plugin.name],
                    evidence_items=[EvidenceItem("registry", "Data", data[:500], f"{key}\\{name}", plugin.name, index)]))
        return findings


class UserAssistRule(IndicatorRule):
    rule_id = "UA-001"
    category = "execution"
    name = "Program started by the user from a temporary or user-writable folder"
    description = ("UserAssist records programs a user launched (shell, double-click). Entries pointing into Temp, Downloads, Public or the "
                   "Recycle Bin are evidence of execution from there, even when the process is long gone. Needs windows.registry.userassist.")

    def evaluate(self, result):
        strict, other = {}, {}
        for index, row in plugin_rows_indexed(result, "windows.registry.userassist"):
            raw = str(row_value(row, "Name") or "")
            path = re.sub(r"^\{[0-9A-Fa-f-]{36}\}\\", "", raw)          # known-folder GUID prefix: not a literal path, ignore the prefix
            if ":\\" not in path and not path.startswith("\\\\"):
                continue
            full = norm_path(path) + ("" if norm_path(path).endswith("\\") else "")
            if full.endswith(".lnk") and any(f in full for f in _SHORTCUT_FOLDERS):
                continue                    # an installer's shortcut on the Public Desktop is not a program started from Public
            if not is_high_risk_dir(path):
                continue
            target = strict if any(s in full + "\\" for s in _STRICT) else other
            entry = target.setdefault(full, [])
            entry.append((index, row, path))
        findings = []
        for bucket, severity, where in ((strict, "Medium", "Public, Recycle Bin or Windows\\Temp"), (other, "Low", "Temp or Downloads")):
            if not bucket:
                continue
            shown = list(bucket.items())[:_MAX_LISTED]
            lines = []
            for _full, entries in shown:
                index, row, path = entries[0]
                lines.append(f"{path}  (run count {row_value(row, 'Count')}, last {row_value(row, 'Last Updated') or 'unknown'})")
            findings.append(self.make(
                title=f"{len(bucket)} program(s) started from {where} (UserAssist)", severity=severity, confidence="Medium",
                summary="UserAssist shows these programs were launched interactively from a folder where untrusted files are dropped.",
                reasons=["Execution history from the user's registry hive (windows.registry.userassist)"],
                evidence=lines + ([f"... and {len(bucket) - _MAX_LISTED} more"] if len(bucket) > _MAX_LISTED else []),
                source_plugins=["windows.registry.userassist"],
                evidence_items=[EvidenceItem("userassist", "Name", path, "", "windows.registry.userassist", entries[0][0])
                                for _f, entries in shown for (_i, _r, path) in entries[:1]]))
        return findings
