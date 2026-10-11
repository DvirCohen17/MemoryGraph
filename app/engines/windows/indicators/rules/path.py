"""Process identity rules: name look-alikes, wrong install paths, execution from risky folders."""
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, lower
from app.engines.windows.indicators.helpers import full_name, in_dir, is_appdata, is_high_risk_dir, is_trusted_dir, is_vendor_appdata
from app.util import norm_path, path_file

_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "!": "i"})


def _distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    prev2, prev = None, list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[lb]


def lookalike_of(name: str):
    """Return the core name ``name`` imitates, or None."""
    n = lower(name)
    if not n.endswith(".exe") or n in baseline.KNOWN_LEGIT_NAMES or len(n) >= 15:
        return None
    stem = n[:-4]
    if len(stem) < 4:
        return None
    for target in baseline.LOOKALIKE_TARGETS:
        t_stem = target[:-4]
        if stem.translate(_HOMOGLYPHS).replace("rn", "m") == t_stem and stem != t_stem:
            return target
        if _distance(stem, t_stem) == 1 and len(t_stem) >= 5:
            return target
    return None


class LookalikeNameRule(IndicatorRule):
    rule_id = "PR-001"
    category = "path"
    name = "Process name imitates a Windows component"
    description = "Names like svch0st.exe, scvhost.exe or lsasss.exe that are one typo/homoglyph away from a core process."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            target = lookalike_of(full_name(p))
            if not target:
                continue
            findings.append(self.make(
                title=f"{p.name} imitates {target}", severity="High", confidence="High", process=p,
                summary=f"The process name is almost identical to the Windows component {target}, a common masquerading technique.",
                reasons=[f"Process name: {p.name}", f"Resembles: {target}"],
                evidence=[f"Image path: {p.path or 'unknown'}"], source_plugins=["windows.pslist", "windows.pstree"]))
        return findings


class CoreProcessPathRule(IndicatorRule):
    rule_id = "PR-002"
    category = "path"
    name = "Core Windows process running from an unexpected path"
    description = "svchost/lsass/services/... must run from their Windows directory."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            spec = baseline.CORE_PROCESSES.get(full_name(p))
            path = norm_path(p.path)
            if not spec or not path or "\\" not in path:
                continue
            if any(in_dir(path, d) for d in spec["dirs"]):
                continue
            if path_file(path) != full_name(p) and not path.endswith(".exe"):
                continue
            findings.append(self.make(
                title=f"{p.name} runs from an unexpected location", severity="High", confidence="High", process=p,
                summary=f"{p.name} is a Windows component that normally runs from {spec['dirs'][0]} but its image path is different.",
                reasons=[f"Observed path: {p.path}", f"Expected directory: {spec['dirs'][0]}"],
                evidence=[f"Image path: {p.path}"], source_plugins=["windows.pstree", "windows.dlllist"]))
        return findings


class RiskyPathExecutionRule(IndicatorRule):
    rule_id = "PR-003"
    category = "path"
    name = "Executable running from a temporary or user-writable folder"
    description = "Temp, Downloads, Public and Recycle Bin folders are medium priority; other AppData folders are low priority; mainstream per-user installers are ignored."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            if not p.path or p.exited:
                continue
            if is_high_risk_dir(p.path):
                severity, why = "Medium", "temporary / download / public folder"
            elif is_appdata(p.path) and not is_vendor_appdata(p.path) and not is_trusted_dir(p.path):
                severity, why = "Low", "AppData folder"
            else:
                continue
            findings.append(self.make(
                title=f"Executable running from {why}", severity=severity, confidence="High", process=p,
                summary="The process image is located in a folder that regular users can write to. Legitimate software is normally installed elsewhere, so review how this file got there.",
                reasons=[f"Image path: {p.path}"], evidence=[f"{display(p)}: {p.path}"],
                source_plugins=["windows.pstree", "windows.dlllist"]))
        return findings


class NameMismatchRule(IndicatorRule):
    rule_id = "PR-004"
    category = "path"
    name = "Process name does not match its image file"
    description = "The name Windows reports (ImageFileName) differs from the executable file on disk."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            path = norm_path(p.path)
            if not path or "\\" not in path or p.source == "pstree":
                continue
            file_name = path_file(path)
            n = lower(p.name)
            if not file_name or not n or n == "system":
                continue
            # ImageFileName is truncated to 14/15 characters by the kernel.
            if file_name == n or file_name.startswith(n) or n.startswith(file_name):
                continue
            if file_name.endswith("..") or not file_name.endswith((".exe", ".com", ".scr")):
                continue
            findings.append(self.make(
                title="Process name differs from image filename", severity="Medium", confidence="High", process=p,
                summary="The process name and the executable file name do not match, which can happen with renamed or hollowed processes.",
                reasons=[f"Process name: {p.name}", f"Image file: {path_file(p.path.replace('/', chr(92)))}"],
                evidence=[f"Image path: {p.path}"], source_plugins=["windows.pslist", "windows.pstree"]))
        return findings
