"""Behavioural leads that do not depend on a name, a hash or a plugin that detects one technique."""
import re

from app.analysis.indicators.base import IndicatorRule, display, is_public_ip, lower
from app.engines.windows.indicators.helpers import is_appdata, is_high_risk_dir, is_trusted_dir, nt_major
from app.engines.windows.indicators.rules.memory import classify_region
from app.models import EvidenceItem
from app.util import norm_path

# a program started from the user's own content folders (not installed, not a temp / download folder: PR-003 reports those)
_USER_CONTENT = re.compile(r"^[a-z]:\\(?:users|documents and settings)\\[^\\]+\\(desktop|documents|my documents|pictures|my pictures|music|my music|videos|my videos|onedrive[^\\]*)\\")
_USER_PROFILE = re.compile(r"^[a-z]:\\(?:users|documents and settings)\\[^\\]+\\[^\\]+$")      # a program directly in the profile folder
# programs that start things on the user's behalf: a child of these that runs from a user folder says little
_SHELLS = {"explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe"}
# the parents a document or a mail attachment starts a program through
_DOCUMENT_HOSTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe", "foxitreader.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


def user_folder_of(path: str) -> str:
    """``'Desktop'`` / ``'Documents'`` / ... when ``path`` is a program in one of the user's own content folders, else ''."""
    low = norm_path(path)
    if not low or is_high_risk_dir(low) or is_appdata(low):
        return ""
    match = _USER_CONTENT.match(low)
    if match:
        return match.group(1).title()
    return "profile folder" if _USER_PROFILE.match(low) else ""


class UserFolderProgramRule(IndicatorRule):
    rule_id = "BEH-001"
    category = "behaviour"
    name = "Program running from the user's own folders"
    description = ("A program that was not installed (it runs from the Desktop, Documents, Pictures, OneDrive or the profile folder) is a lead: it is how dropped and "
                   "downloaded samples are usually run by hand, and no plugin reports it. Low on its own (people run portable tools too); Medium when something else "
                   "is wrong with the same process: it talks to a public address, was started by a document viewer / script host, hides from the process list, or has executable "
                   "memory with an MZ header or shellcode. Temp, Downloads, Public and AppData folders are rule PR-003.")

    def evaluate(self, result):
        findings = []
        regions = {}
        for region in result.memory_regions:
            regions.setdefault(region.pid, []).append(region)
        by_pid = {p.pid: p for p in result.processes}
        legacy = 0 < nt_major(result) < 6
        for p in result.processes:
            if p.exited or not p.path:
                continue
            folder = user_folder_of(p.path)
            if not folder or is_trusted_dir(p.path):
                continue
            signs = []
            external = [c for c in p.network if is_public_ip(c.remote_address)]
            if external:
                signs.append(f"talks to a public address ({external[0].remote})")
            parent = by_pid.get(p.ppid)
            if parent is not None and lower(parent.name) in _DOCUMENT_HOSTS:
                signs.append(f"was started by {parent.name}")
            if p.hidden:
                signs.append("is not in the active process list")
            modules = {lower(d.name) for d in p.dlls}
            for region in regions.get(p.pid, []):
                severity, why = classify_region(region, modules, legacy)
                if severity == "High":
                    signs.append("has executable memory that starts with an MZ header or shellcode")
                    break
            findings.append(self.make(
                title=f"{p.name} runs from the user's {folder} folder", severity="Medium" if signs else "Low", confidence="Medium" if signs else "Low", process=p,
                summary="The program was not installed: it runs from a folder the user keeps their own files in. That is how a dropped or downloaded sample is typically started. "
                        "Review where the file came from; on its own it is not evidence of anything.",
                reasons=[f"Image path: {p.path}"] + ([f"Also: {sign}" for sign in signs] or ["Nothing else is wrong with this process in the plugins that ran"]),
                evidence=[f"{display(p)}: {p.path}", f"started {p.create_time or 'at an unknown time'} by "
                          f"{(display(parent) if parent is not None else 'PID ' + str(p.ppid))}"],
                source_plugins=["windows.pstree", "windows.pslist"] + (["windows.netscan", "windows.netstat"] if external else []),
                evidence_items=[EvidenceItem("process", "image", p.path, display(p), "windows.pstree", -1)]))
        return findings
