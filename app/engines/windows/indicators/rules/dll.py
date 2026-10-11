"""Loaded-module rules. Modules are judged relative to the process that loaded them."""
from app.engines.windows.indicators import baseline
from app.analysis.indicators.base import IndicatorRule, display, lower
from app.engines.windows.indicators.helpers import is_high_risk_dir, is_trusted_dir, is_vendor_appdata, is_appdata
from app.util import norm_path, path_dir, path_file

_ODD_EXTENSIONS = (".tmp", ".dat", ".bin", ".log", ".txt", ".jpg", ".png", ".db")


def _same_app_dir(process_path: str, dll_path: str) -> bool:
    """True when the DLL ships next to (or below) the executable's own folder."""
    exe_dir = path_dir(norm_path(process_path))
    dll_dir = path_dir(norm_path(dll_path))
    if not exe_dir or not dll_dir:
        return False
    parent = path_dir(exe_dir)
    return dll_dir.startswith(exe_dir) or (parent and dll_dir.startswith(parent) and "\\appdata\\" in dll_dir and "\\appdata\\" in exe_dir)


class UntrustedModuleLocationRule(IndicatorRule):
    rule_id = "DLL-001"
    category = "dll"
    name = "Module loaded from a temporary or untrusted location"
    description = "DLLs from Temp/Downloads/Public, or from AppData into a process that does not live there, or with an unusual file extension."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            suspicious = []
            for d in p.dlls:
                path = d.path or ""
                if not path:
                    continue
                low = norm_path(path)
                if low == norm_path(p.path):
                    continue  # the executable itself
                if is_high_risk_dir(path):
                    suspicious.append((d, "temporary/download/public folder"))
                elif low.endswith(_ODD_EXTENSIONS):
                    suspicious.append((d, f"unusual module extension ({path_file(low).rsplit('.', 1)[-1]})"))
                elif is_appdata(path) and not is_vendor_appdata(path) and not _same_app_dir(p.path, path):
                    suspicious.append((d, "AppData folder outside the process's own directory"))
            if not suspicious:
                continue
            severity = "Medium" if any("temporary" in why or "extension" in why for _d, why in suspicious) else "Low"
            findings.append(self.make(
                title=f"{len(suspicious)} module(s) loaded from an untrusted location", severity=severity, confidence="High", process=p,
                summary="One or more loaded modules come from folders that are writable by regular users or have an unexpected file type.",
                reasons=sorted({why for _d, why in suspicious}), evidence=[f"{d.name}: {d.path}" for d, _why in suspicious[:15]],
                source_plugins=["windows.dlllist"]))
        return findings


class SystemDllImpostorRule(IndicatorRule):
    rule_id = "DLL-002"
    category = "dll"
    name = "System DLL name loaded from a non-system folder"
    description = "ntdll/kernel32/ws2_32/... loaded from anywhere except the Windows system directories (DLL hijacking / side-loading)."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            odd = []
            for d in p.dlls:
                if lower(d.name) not in baseline.SYSTEM_DLLS or not d.path:
                    continue
                path = norm_path(d.path)
                if "\\windows\\system32\\" in path or "\\windows\\syswow64\\" in path or "\\windows\\winsxs\\" in path:
                    continue
                odd.append(d)
            if not odd:
                continue
            findings.append(self.make(
                title="System DLL name loaded from a non-system folder", severity="High", confidence="High", process=p,
                summary="A DLL named like a core Windows library was loaded from outside the Windows directories, a typical DLL hijacking pattern.",
                reasons=[f"{d.name} → {d.path}" for d in odd[:5]], evidence=[f"{d.name}: {d.path}" for d in odd[:10]],
                source_plugins=["windows.dlllist"]))
        return findings
