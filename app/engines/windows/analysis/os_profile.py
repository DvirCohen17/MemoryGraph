"""Which Windows an image is, and what that means for plugins and rules (no Qt, unit-tested without a GUI).

The facts come from ``windows.info`` (NtMajorVersion, NtMinorVersion, Is64Bit, NTBuildLab, Major/Minor), so nothing here needs the internet
or a scan of the image. They decide three things:

* which plugins make sense (``windows.netscan`` does not exist for Windows XP: such a plugin is *skipped with a reason* instead of failing),
* which expectations the rules use (on XP / 2003 ``winlogon.exe`` starts ``services.exe`` and ``lsass.exe``; there is no ``wininit.exe``),
* the profile name Volatility 2 needs (``WinXPSP3x86``, ``Win7SP1x64``, ...), chosen automatically.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class OsProfile:
    nt_major: int = 0
    nt_minor: int = 0
    build: int = 0
    is64: bool = False
    service_pack: int = 0
    build_lab: str = ""

    @property
    def known(self) -> bool:
        return self.nt_major > 0

    @property
    def version(self) -> Tuple[int, int]:
        return (self.nt_major, self.nt_minor)

    @property
    def legacy(self) -> bool:
        """NT 5.x: Windows 2000, XP, Server 2003. Volatility 3's network plugins do not support these."""
        return 0 < self.nt_major < 6

    @property
    def family(self) -> str:
        return {(5, 0): "2000", (5, 1): "xp", (5, 2): "2003", (6, 0): "vista", (6, 1): "7", (6, 2): "8", (6, 3): "8.1"}.get(
            self.version, "11" if self.nt_major == 10 and self.build >= 22000 else "10" if self.nt_major == 10 else "unknown")

    @property
    def name(self) -> str:
        if not self.known:
            return "unknown Windows"
        base = {"2000": "Windows 2000", "xp": "Windows XP", "2003": "Windows XP x64 / Server 2003" if self.is64 else "Windows Server 2003",
                "vista": "Windows Vista / Server 2008", "7": "Windows 7 / Server 2008 R2", "8": "Windows 8 / Server 2012",
                "8.1": "Windows 8.1 / Server 2012 R2", "10": "Windows 10 / Server 2016-2019", "11": "Windows 11 / Server 2022+"}.get(self.family, "Windows")
        sp = f" SP{self.service_pack}" if self.service_pack and self.nt_major < 10 else ""
        return f"{base}{sp} ({'x64' if self.is64 else 'x86'}, NT {self.nt_major}.{self.nt_minor}" + (f", build {self.build}" if self.build else "") + ")"

    @property
    def short_name(self) -> str:
        return self.name.split(" (")[0] if self.known else "unknown Windows"

    @property
    def vol2_profile(self) -> str:
        """The Volatility 2 profile for this image, '' when there is no Volatility 2 profile (Windows 10+ is handled by Volatility 3)."""
        bits = "x64" if self.is64 else "x86"
        sp = self.service_pack
        if self.family == "xp":
            return "WinXPSP3x86" if sp >= 3 else "WinXPSP2x86" if not self.is64 else "WinXPSP2x64"
        if self.family == "2003":
            return f"Win2003SP{min(max(sp, 0), 2)}{bits}"
        if self.family == "vista":
            return f"VistaSP{min(max(sp, 0), 2)}{bits}"
        if self.family == "7":
            return f"Win7SP{min(max(sp, 0), 1)}{bits}"
        if self.family == "8":
            return f"Win8SP0{bits}"
        if self.family == "8.1":
            return f"Win81U1{bits}"
        return ""


def _service_pack(major: int, minor: int, build: int, lab: str) -> int:
    lab = lab.lower()
    explicit = re.search(r"sp(\d)", lab)
    if (major, minor) == (5, 1):                        # XP: the lab string names the service pack, SP3 is "xpsp.080413"
        if "xpsp." in lab or "sp3" in lab:
            return 3
        return int(explicit.group(1)) if explicit else (1 if "xpsp1" in lab else 0)
    if (major, minor) == (5, 2):
        return int(explicit.group(1)) if explicit else 0
    if (major, minor) == (6, 0):
        return {6000: 0, 6001: 1, 6002: 2}.get(build, int(explicit.group(1)) if explicit else 0)
    if (major, minor) == (6, 1):
        return 1 if build >= 7601 else 0
    return 0


def _value(rows: Dict[str, str], *names: str) -> str:
    for name in names:
        if name.lower() in rows:
            return rows[name.lower()]
    return ""


def from_rows(rows: Iterable[Any]) -> OsProfile:
    """Profile from ``windows.info`` rows (``{"Variable": ..., "Value": ...}``); unknown values give ``OsProfile()`` with ``known`` False."""
    values: Dict[str, str] = {}
    for row in rows or []:
        if isinstance(row, dict) and row.get("Variable") is not None:
            values[str(row["Variable"]).strip().lower()] = str(row.get("Value", "")).strip()
    try:
        major, minor = int(_value(values, "NtMajorVersion"), 0), int(_value(values, "NtMinorVersion"), 0)
    except ValueError:
        return OsProfile()
    lab = _value(values, "NTBuildLab")
    build = 0
    for text in (_value(values, "Major/Minor").split(".")[-1], lab.split(".")[0]):
        if text.isdigit():
            build = int(text)
            break
    is64 = _value(values, "Is64Bit").lower() == "true"
    return OsProfile(major, minor, build, is64, _service_pack(major, minor, build, lab), lab)


def from_result(result) -> OsProfile:
    """Profile of an :class:`AnalysisResult` (its ``system_info`` rows are the ``windows.info`` output)."""
    return from_rows(getattr(result, "system_info", None) or [])


def parse_imageinfo(text: str) -> List[str]:
    """Profile names from Volatility 2's ``imageinfo`` text ("Suggested Profile(s) : Win7SP1x64, Win7SP0x64 (Instantiated with ...)")."""
    match = re.search(r"Suggested Profile\(s\)\s*:\s*(.+)", text or "")
    if not match:
        return []
    line = re.sub(r"\(.*?\)", "", match.group(1))
    return [p.strip() for p in line.split(",") if p.strip() and p.strip().lower() != "no suggestion"]


def debug_addresses(rows: Iterable[Any]) -> Dict[str, str]:
    """``{"dtb": "0x...", "kdbg": "0x..."}`` from windows.info when present: Volatility 2 starts much faster when it is told where they are."""
    values = {str(r.get("Variable", "")).strip().lower(): str(r.get("Value", "")).strip() for r in rows or [] if isinstance(r, dict)}
    found = {}
    if values.get("dtb", "").lower().startswith("0x"):
        found["dtb"] = values["dtb"]
    for key in ("kddebuggerdatablock", "kdbg"):
        if values.get(key, "").lower().startswith("0x"):
            found["kdbg"] = values[key]
            break
    return found
