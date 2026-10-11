"""Command-line rules. Command lines are only judged for the programs that can act on them."""
import re

from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, lower
from app.engines.windows.indicators.helpers import full_name, has_encoded_powershell, is_high_risk_dir, is_interpreter, looks_obfuscated
from app.util import norm_path

_POWERSHELL = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}
_PS_OPTIONS = [
    (r"(?:^|\s)[-/]w(?:indowstyle)?\s+h(?:idden)?\b", "hidden window"),
    (r"(?:^|\s)[-/]ep\s+bypass|executionpolicy\s+(?:bypass|unrestricted)", "execution policy bypass"),
    (r"(?:^|\s)[-/]nop(?:rofile)?\b", "no profile"),
    (r"(?:^|\s)[-/]nonin(?:teractive)?\b", "non-interactive"),
    (r"\b(?:iex|invoke-expression)\b", "Invoke-Expression"),
    (r"downloadstring|downloadfile|invoke-webrequest|iwr\s|net\.webclient|start-bitstransfer", "download cradle"),
    (r"frombase64string", "base64 decoding"),
]

_LOLBIN_PATTERNS = [
    ("certutil.exe", r"-urlcache|-decode\b|-verifyctl|-f\s+http", "certutil used to download or decode a file"),
    ("bitsadmin.exe", r"/transfer|/addfile|/setnotifycmdline", "bitsadmin transfer job"),
    ("regsvr32.exe", r"/i:https?://|scrobj\.dll|/s\s+/n\s+/u", "regsvr32 loading a remote/script payload"),
    ("rundll32.exe", r"javascript:|vbscript:|mshtml,runhtmlapplication|url\.dll,fileprotocolhandler\s+https?://", "rundll32 running script content"),
    ("mshta.exe", r"https?://|javascript:|vbscript:", "mshta executing remote or inline script"),
    ("wmic.exe", r"process\s+call\s+create|/format:https?://|/node:", "wmic remote execution or XSL fetch"),
    ("msiexec.exe", r"/i\s+https?://|(?:/q|/quiet).*https?://", "msiexec installing a remote package"),
    ("cmstp.exe", r"/s\s+.*\.inf|/ni\s+/s", "cmstp executing an INF file"),
    ("installutil.exe", r"/u\b.*\.(?:exe|dll)", "installutil executing an assembly"),
    ("wscript.exe", r"https?://|\.js[e]?\b|\.vbs\b|\.wsf\b", "script host running a script file"),
    ("cscript.exe", r"https?://|\.js[e]?\b|\.vbs\b|\.wsf\b", "script host running a script file"),
]


class PowerShellAbuseRule(IndicatorRule):
    rule_id = "CL-001"
    category = "commandline"
    name = "Suspicious PowerShell command line"
    description = "Encoded commands, hidden windows, execution-policy bypass and download cradles."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            if full_name(p) not in _POWERSHELL or not p.command_line:
                continue
            cmd = p.command_line
            low = lower(cmd)
            hits = [label for pattern, label in _PS_OPTIONS if re.search(pattern, low)]
            encoded = has_encoded_powershell(cmd)
            if encoded:
                hits.insert(0, "encoded command")
            if not hits:
                continue
            strong = encoded or "download cradle" in hits or "Invoke-Expression" in hits
            severity = "High" if (encoded and len(hits) >= 2) or (strong and len(hits) >= 3) else "Medium" if strong or len(hits) >= 2 else "Low"
            findings.append(self.make(
                title="Suspicious PowerShell options: " + ", ".join(hits[:3]), severity=severity,
                confidence="High", process=p,
                summary="The PowerShell command line contains options commonly used to hide or obfuscate execution. Decode and review the command before drawing conclusions.",
                reasons=[f"Indicators: {', '.join(hits)}"], evidence=[f"Command line: {cmd[:600]}"], source_plugins=["windows.cmdline"]))
        return findings


class LolbinAbuseRule(IndicatorRule):
    rule_id = "CL-002"
    category = "commandline"
    name = "Signed Windows binary used to fetch or run code"
    description = "certutil/bitsadmin/regsvr32/mshta/... with arguments that download, decode or execute remote content."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            if not p.command_line:
                continue
            exe = full_name(p)
            low = lower(p.command_line)
            for binary, pattern, label in _LOLBIN_PATTERNS:
                if exe == binary and re.search(pattern, low):
                    findings.append(self.make(
                        title=label[0].upper() + label[1:], severity="Medium", confidence="High", process=p,
                        summary=f"{p.name} was started with arguments associated with living-off-the-land abuse.",
                        reasons=[f"Binary: {binary}", f"Pattern: {label}"], evidence=[f"Command line: {p.command_line[:600]}"],
                        source_plugins=["windows.cmdline"]))
                    break
        return findings


class InterpreterRunsFromRiskyPathRule(IndicatorRule):
    rule_id = "CL-003"
    category = "commandline"
    name = "Interpreter or LOLBin launches content from a risky folder"
    description = "cmd/PowerShell/LOLBin whose command line references Temp, Downloads, Public or Recycle Bin."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            exe = full_name(p)
            if exe not in baseline.INTERPRETERS and exe not in baseline.LOLBINS:
                continue
            cmd = p.command_line or ""
            if not cmd:
                continue
            tokens = re.findall(r'[A-Za-z]:\\[^"\s]+|\\\\[^"\s]+', cmd)
            risky = [t for t in tokens if is_high_risk_dir(t)]
            if not risky:
                continue
            findings.append(self.make(
                title="Command line references a temporary/user-writable location", severity="Medium", confidence="High", process=p,
                summary="An interpreter or system utility was told to run or open something from a folder where untrusted files are commonly dropped.",
                reasons=[f"Referenced: {', '.join(dict.fromkeys(risky))[:300]}"], evidence=[f"Command line: {cmd[:600]}"],
                source_plugins=["windows.cmdline"]))
        return findings


class ObfuscatedInterpreterRule(IndicatorRule):
    rule_id = "CL-004"
    category = "commandline"
    name = "Obfuscated interpreter command line"
    description = "Very long base64-like strings, character-code joins or caret/backtick obfuscation in interpreter arguments."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            if not is_interpreter(full_name(p)) or not p.command_line:
                continue
            if full_name(p) in _POWERSHELL and has_encoded_powershell(p.command_line):
                continue  # already reported by CL-001
            if not looks_obfuscated(p.command_line):
                continue
            findings.append(self.make(
                title="Interpreter command line looks obfuscated", severity="Medium", confidence="Medium", process=p,
                summary="The command line contains patterns typical of encoding or obfuscation (long base64-like data, character code joins, escape characters).",
                reasons=["Obfuscation-like syntax in an interpreter command line"], evidence=[f"Command line: {p.command_line[:600]}"],
                source_plugins=["windows.cmdline"]))
        return findings
