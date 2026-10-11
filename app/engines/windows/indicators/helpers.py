"""Windows helpers of the indicator rules: path classes (temp / user-writable / trusted folders), command lines and encoded PowerShell, interpreters,
environment-variable paths and the NT version of the image. The generic rule helpers (IndicatorRule, plugin rows, process maps, endpoints) are in
``app.analysis.indicators.base`` and are shared by every engine."""
from __future__ import annotations

import re

from app.analysis.indicators.base import lower, name
from app.engines.windows.indicators import baseline
from app.models import AnalysisResult, Process
from app.util import norm_path, path_dir, path_file


def is_interpreter(value: str) -> bool:
    return lower(value) in baseline.INTERPRETERS


def interpreter_category(value: str) -> str:
    v = lower(value)
    if v in {"cmd.exe", "powershell.exe", "pwsh.exe"}:
        return "command_interpreter"
    if v in {"wscript.exe", "cscript.exe", "mshta.exe"}:
        return "script_engine"
    return "other"


def full_name(p: Process) -> str:
    """Image name without Volatility's 14-character truncation when the path gives the full name."""
    from_path = path_file(norm_path(p.path))
    n = lower(p.name)
    if from_path and from_path.startswith(n[:14]) and len(from_path) >= len(n):
        return from_path
    return n


def _canon(path: str) -> str:
    return norm_path(path)


def looks_temp(path: str) -> bool:
    p = _canon(path) + ("\\" if not _canon(path).endswith("\\") else "")
    return "\\appdata\\local\\temp\\" in p or "\\windows\\temp\\" in p or "\\temp\\" in p


def is_high_risk_dir(path: str) -> bool:
    p = _canon(path)
    if not p:
        return False
    p = p + ("" if p.endswith("\\") else "\\")
    return any(fragment in p for fragment in baseline.HIGH_RISK_DIR_FRAGMENTS)


def is_appdata(path: str) -> bool:
    return "\\appdata\\" in _canon(path)


def is_vendor_appdata(path: str) -> bool:
    p = _canon(path)
    return any(fragment in p for fragment in baseline.APPDATA_VENDOR_FRAGMENTS)


def looks_user_writable(path: str) -> bool:
    """Broad check (kept for compatibility): high-risk directories or any AppData."""
    return is_high_risk_dir(path) or is_appdata(path)


def is_trusted_dir(path: str) -> bool:
    p = _canon(path)
    return any(fragment in p for fragment in baseline.TRUSTED_DIR_FRAGMENTS)


def is_system_path(path: str) -> bool:
    p = _canon(path)
    return "\\windows\\system32\\" in p or "\\windows\\syswow64\\" in p


def in_dir(path: str, directory: str) -> bool:
    return path_dir(_canon(path)).rstrip("\\") == directory.rstrip("\\")


_ENV_PATHS = {
    "systemroot": "C:\\Windows", "windir": "C:\\Windows", "systemdrive": "C:", "programfiles": "C:\\Program Files",
    "programfiles(x86)": "C:\\Program Files (x86)", "programw6432": "C:\\Program Files", "programdata": "C:\\ProgramData",
    "allusersprofile": "C:\\ProgramData", "public": "C:\\Users\\Public", "userprofile": "C:\\Users\\user",
    "temp": "C:\\Users\\user\\AppData\\Local\\Temp", "tmp": "C:\\Users\\user\\AppData\\Local\\Temp",
    "localappdata": "C:\\Users\\user\\AppData\\Local", "appdata": "C:\\Users\\user\\AppData\\Roaming",
    "homedrive": "C:", "commonprogramfiles": "C:\\Program Files\\Common Files",
}


_ENV_REF = re.compile(r"%([A-Za-z0-9_()]+)%")


_COMMAND_EXE = re.compile(r"""^\s*(?:"([^"]+)"|(.+?\.(?:exe|com|scr|bat|cmd|ps1|vbs|js|jse|vbe|wsf|hta|dll|sys|cpl|msi))(?=$|[\s"',;]))""", re.IGNORECASE)


def expand_env_path(text: str) -> str:
    """Replace the usual ``%SystemRoot%`` / ``%TEMP%`` style variables and NT prefixes (``\\??\\``, ``\\SystemRoot``) by plain paths."""
    value = str(text or "")
    value = _ENV_REF.sub(lambda m: _ENV_PATHS.get(m.group(1).lower(), m.group(0)), value)
    if value.startswith("\\??\\"):
        value = value[4:]
    if value.lower().startswith("\\systemroot"):
        value = "C:\\Windows" + value[len("\\systemroot"):]
    return value


def split_command(text: str):
    """``(program path, arguments)`` of a command line or service ImagePath, environment variables expanded.

    Unquoted paths with spaces are handled by looking for the first executable extension; a path without drive
    (``System32\\drivers\\x.sys``, as drivers are registered) is taken relative to the Windows folder."""
    value = expand_env_path(str(text or "").strip())
    match = _COMMAND_EXE.match(value)
    if match:
        program = (match.group(1) or match.group(2) or "").strip()
        rest = value[match.end():].strip()
    else:
        program, _, rest = value.partition(" ") if not value.startswith('"') else (value.strip('"'), "", "")
        program = program.strip('"')
    if program and ":" not in program and not program.startswith("\\\\") and "\\" in program and not program.startswith("\\"):
        program = "C:\\Windows\\" + program
    return program, rest


_B64 = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")


def has_encoded_powershell(cmd: str) -> bool:
    return bool(re.search(r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[A-Za-z0-9+/=]{12,}", lower(cmd)))


def looks_obfuscated(cmd: str) -> bool:
    """Strong obfuscation signals only (a long path or a stray quote is not obfuscation)."""
    if not cmd:
        return False
    low = lower(cmd)
    if has_encoded_powershell(cmd) or "frombase64string" in low:
        return True
    if _B64.search(cmd):
        return True
    if cmd.count("^") >= 4 and "\\" not in cmd.replace("^", ""):
        return True
    if cmd.count("`") >= 3:
        return True
    if re.search(r"(?i)(\[char\]\s*\d+\s*\+?\s*){3,}", cmd) or low.count("-join") >= 2:
        return True
    return False


def nt_version(result: AnalysisResult):
    """``(major, minor)`` NT version of the image (``(5, 1)`` = XP, ``(6, 1)`` = Windows 7, ``(10, 0)``), ``(0, 0)`` when unknown."""
    from app.engines.windows.analysis import os_profile
    return os_profile.from_result(result).version


def nt_major(result: AnalysisResult) -> int:
    """Major NT version of the image from windows.info (5 = XP / 2003, 6 = Vista - 8.1, 10 = Windows 10 / 11); 0 when unknown."""
    for row in getattr(result, "system_info", None) or []:
        if isinstance(row, dict) and str(row.get("Variable", "")).lower() == "ntmajorversion":
            try:
                return int(str(row.get("Value", "")).strip(), 0)
            except ValueError:
                return 0
    return 0
