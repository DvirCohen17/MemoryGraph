"""Memory-map rules (need the opt-in, very large windows.vadinfo and windows.dlllist)."""
from app.engines.windows.analysis import known_good
from app.analysis.indicators.base import IndicatorRule, lower, plugin_completed, plugin_rows_indexed, process_for_pid, row_value
from app.engines.windows.indicators.helpers import is_high_risk_dir, is_trusted_dir
from app.models import EvidenceItem
from app.util import norm_path, to_hex, to_int

_IMAGE_EXT = (".dll", ".exe", ".sys", ".ocx", ".cpl")
# What can be a program image. Everything else (fonts, .nls tables, .mui, .dat ...) is mapped as data and is never in a loader list.
_LDR_IMAGE_EXT = _IMAGE_EXT + (".drv", ".scr", ".ax", ".acm", ".tsp", ".efi", ".mun")
# 64-bit system DLLs that a 32-bit (WOW64) process maps but never lists in its own loader data
_WOW64_ONLY = {"ntdll.dll", "wow64.dll", "wow64cpu.dll", "wow64win.dll", "wow64base.dll"}
# Every process that has loader lists lists these. When one of them is mapped but "unlisted", the lists themselves were only partly readable (paged out):
# real Windows 10 image, svchost.exe PID 844: no KernelBase.dll in dlllist, and ldrmodules shows it in no list. Then "not in the list" says nothing.
_CORE_DLLS = {"ntdll.dll", "kernel32.dll", "kernelbase.dll"}
_MAX_LISTED = 12
_MAX_PROCESSES_LISTED = 25


def lists_incomplete(names) -> bool:
    return any(lower(n) in _CORE_DLLS for n in names)


def _base(path: str) -> str:
    return norm_path(path).rsplit("\\", 1)[-1]


def quiet_finding(rule, title: str, summary: str, reasons, quiet, source_plugins, kind: str):
    """ONE Low finding for all the processes whose unlisted images are all in trusted Windows folders (``quiet``: ``[(process, pid, [(row, path)])]``).
    On a real Windows 10 image these were 43 separate Low findings (one per process) that nobody can act on one by one."""
    shown = quiet[:_MAX_PROCESSES_LISTED]
    evidence = [f"{name} (PID {pid}): {len(items)} image(s), e.g. {', '.join(_base(p) for _i, p in items[:3])}" for name, pid, items in shown]
    if len(quiet) > len(shown):
        evidence.append(f"... and {len(quiet) - len(shown)} more process(es)")
    return rule.make(title=title, severity="Low", confidence="Low", summary=summary, reasons=reasons, evidence=evidence, source_plugins=source_plugins,
                     evidence_items=[EvidenceItem(kind, "File", items[0][1], f"{name} (PID {pid})", source_plugins[0], items[0][0]) for name, pid, items in shown])


class UnlistedImageRule(IndicatorRule):
    rule_id = "VAD-001"
    category = "memory"
    name = "Executable image mapped in a process but missing from its module list"
    description = ("windows.vadinfo shows file-backed executable mappings. A DLL/EXE image mapped (and executable) in a process that does not appear "
                   "in that process's windows.dlllist may have been unlinked from the loader lists or mapped manually. WOW64 system DLLs are "
                   "excluded, and so are modules in an installed known-good list for this Windows. Images outside the trusted Windows folders are one finding per "
                   "process; trusted system images are one single Low finding for all processes. Low confidence: dlllist and the memory map are read at different "
                   "levels. Needs windows.vadinfo + windows.dlllist.")

    def evaluate(self, result):
        if not plugin_completed(result, "windows.dlllist"):
            return []                                  # without module lists every mapping would look 'unlisted'
        per_pid = {}
        for index, row in plugin_rows_indexed(result, "windows.vadinfo"):
            pid = to_int(row_value(row, "PID", default=None))
            path = str(row_value(row, "File") or "")
            protection = str(row_value(row, "Protection") or "").upper()
            if not pid or not path or "EXECUTE" not in protection or not lower(path).endswith(_IMAGE_EXT):
                continue
            if to_int(row_value(row, "PrivateMemory", default=0), 0):
                continue
            per_pid.setdefault(pid, []).append((index, path))
        good = known_good.for_result(result)
        findings, quiet = [], []
        for pid, mappings in per_pid.items():
            proc = process_for_pid(result, pid)
            if proc is None or not proc.dlls:
                continue
            listed = {lower(d.name) for d in proc.dlls} | {_base(d.path) for d in proc.dlls if d.path}
            listed.add(lower(proc.name))
            unlisted = []
            for index, path in mappings:
                base = _base(path)
                if base in listed or (proc.wow64 and base in _WOW64_ONLY) or good.knows(proc.name, base):
                    continue
                unlisted.append((index, path))
            if not unlisted or lists_incomplete(_base(p) for _i, p in unlisted):
                continue                                    # nothing unlisted, or the module list itself is incomplete
            if not any(is_high_risk_dir(p) or not is_trusted_dir(p) for _i, p in unlisted):
                quiet.append((proc.name, pid, unlisted))
                continue
            shown = unlisted[:_MAX_LISTED]
            findings.append(self.make(
                title=f"{len(unlisted)} executable image(s) mapped but not in the module list of {proc.name}",
                severity="Medium", confidence="Low", process=proc,
                summary="These images are mapped executable in the process but the loader's module list does not name them. Review whether they belong to the process.",
                reasons=["In windows.vadinfo (file-backed, executable), absent from windows.dlllist"],
                evidence=[p for _i, p in shown] + ([f"... and {len(unlisted) - _MAX_LISTED} more"] if len(unlisted) > _MAX_LISTED else []),
                source_plugins=["windows.vadinfo", "windows.dlllist"],
                evidence_items=[EvidenceItem("vad", "File", p, proc.name, "windows.vadinfo", i) for i, p in shown]))
        if quiet:
            findings.append(quiet_finding(
                self, f"Trusted system images mapped but not in the module list: {len(quiet)} process(es)",
                "Windows DLLs from the system folders are mapped in these processes but their dlllist does not name them. For system DLLs this is usually a module list "
                "that was only partly readable in the dump; it matters only when it is accompanied by other signs. Install a known-good list for this Windows to silence "
                "what is normal (Case Notes).",
                ["In windows.vadinfo (file-backed, executable), absent from windows.dlllist", "Every image is in a trusted Windows folder"],
                quiet, ["windows.vadinfo", "windows.dlllist"], "vad"))
        return findings


class UnlinkedModuleRule(IndicatorRule):
    rule_id = "LDR-001"
    category = "memory"
    name = "Module mapped in a process but absent from all three loader lists"
    description = ("windows.ldrmodules compares each mapped image with the process's three loader lists (load order, initialisation order, "
                   "memory order). An image that is in none of them was unlinked from the PEB or mapped by hand, which injected DLLs and "
                   "reflective loaders do. Ignored: apisetschema.dll, the WOW64 system DLLs, the System process (it has no loader lists), files "
                   "that are not program images (fonts, resources), modules in an installed known-good list for this Windows, and, when windows.vadinfo is available, "
                   "mappings that are not executable (a DLL opened only as data, for its resources, is mapped read-only and is never in a loader list), and processes "
                   "whose own lists are incomplete (ntdll / kernel32 / KernelBase mapped but in no list: the lists could not be read, so nothing can be said). "
                   "Images outside the trusted Windows folders are one finding per process; trusted system images are one single Low finding. Needs windows.ldrmodules.")

    def evaluate(self, result):
        protection = {}                                      # (pid, start address) -> protection, from windows.vadinfo when it was run
        for _i, row in plugin_rows_indexed(result, "windows.vadinfo"):
            pid, start = to_int(row_value(row, "PID", default=None)), to_int(row_value(row, "Start VPN", "Start", default=None))
            if pid is not None and start is not None:
                protection[(pid, start)] = str(row_value(row, "Protection") or "").upper()
        per_pid = {}
        for index, row in plugin_rows_indexed(result, "windows.ldrmodules"):
            path = str(row_value(row, "MappedPath") or "")
            flags = [row_value(row, key, default=None) for key in ("InLoad", "InInit", "InMem")]
            if not path or any(f not in (False, 0, "False", "false") for f in flags):
                continue
            pid = to_int(row_value(row, "Pid", default=None))
            if not pid or pid == 4 or lower(row_value(row, "Process")) == "system" or not lower(path).endswith(_LDR_IMAGE_EXT):
                continue
            mode = protection.get((pid, to_int(row_value(row, "Base", default=None))), "")
            if mode and "EXECUTE" not in mode:
                continue                                    # mapped read-only: opened as data, not run
            per_pid.setdefault(pid, []).append((index, path, row_value(row, "Base")))
        good = known_good.for_result(result)
        findings, quiet = [], []
        for pid, hits in per_pid.items():
            proc = process_for_pid(result, pid)
            kept = []
            for index, path, base in hits:
                name = _base(path)
                if name == "apisetschema.dll" or (proc is not None and proc.wow64 and name in _WOW64_ONLY):
                    continue
                if proc is not None and good.knows(proc.name, name):
                    continue
                kept.append((index, path, base))
            if not kept or lists_incomplete(_base(p) for _i, p, _b in kept):
                continue                                    # nothing left, or the loader lists of this process were only partly readable
            if not any(is_high_risk_dir(p) or not is_trusted_dir(p) for _i, p, _b in kept):
                quiet.append((proc.name if proc else f"PID {pid}", pid, [(i, p) for i, p, _b in kept]))
                continue
            shown = kept[:_MAX_LISTED]
            findings.append(self.make(
                title=f"{len(kept)} image(s) mapped in {proc.name if proc else 'PID ' + str(pid)} but missing from every loader list",
                severity="Medium", confidence="Medium", process=proc,
                summary="Normal DLLs appear in the loader lists. These images are mapped but listed nowhere, which is typical for injected or manually mapped code.",
                reasons=["windows.ldrmodules: InLoad, InInit and InMem are all False"],
                evidence=[f"{p} (base {to_hex(b)})" for _i, p, b in shown] + ([f"... and {len(kept) - _MAX_LISTED} more"] if len(kept) > _MAX_LISTED else []),
                source_plugins=["windows.ldrmodules"],
                evidence_items=[EvidenceItem("module", "MappedPath", p, proc.name if proc else "", "windows.ldrmodules", i) for i, p, _b in shown]))
        if quiet:
            findings.append(quiet_finding(
                self, f"Trusted system images in no loader list: {len(quiet)} process(es)",
                "Windows DLLs from the system folders are mapped in these processes but are in none of the three loader lists. On a real Windows 10 image this "
                "was the normal state of many system processes whose lists were only partly readable; it matters only when it is accompanied by other signs. "
                "Install a known-good list for this Windows to silence what is normal (Case Notes).",
                ["windows.ldrmodules: InLoad, InInit and InMem are all False", "Every image is in a trusted Windows folder"],
                quiet, ["windows.ldrmodules"], "module"))
        return findings
