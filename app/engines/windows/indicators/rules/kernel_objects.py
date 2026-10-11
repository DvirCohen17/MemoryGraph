"""Kernel object rules for the extended / opt-in plugins: driver objects, the system call table and callbacks."""
from app.analysis.indicators.base import IndicatorRule, lower, plugin_completed, plugin_rows_indexed, row_value
from app.models import EvidenceItem
from app.util import to_hex, to_int

_MAX_LISTED = 25
_KERNEL_IMAGES = {"ntoskrnl", "ntkrnlpa", "ntkrnlmp", "ntkrpamp", "ntoskrnl.exe", "ntkrnlpa.exe", "ntkrnlmp.exe", "ntkrpamp.exe"}


class DriverObjectRule(IndicatorRule):
    rule_id = "DRV-002"
    category = "kernel"
    name = "Driver object whose code is not in any loaded module"
    description = ("windows.driverscan finds DRIVER_OBJECTs by pool tag. A driver whose start address lies outside every module of the "
                   "loaded-module list (windows.modules) AND whose name matches no loaded module may be running unlinked code. Unloaded "
                   "drivers leave stale objects too, so this is one low-confidence finding. Needs windows.driverscan + windows.modules.")

    def evaluate(self, result):
        if not (plugin_completed(result, "windows.modules") and plugin_completed(result, "windows.driverscan")):
            return []
        ranges, stems = [], set()
        for _i, row in plugin_rows_indexed(result, "windows.modules"):
            base, size = to_int(row_value(row, "Base", default=None)), to_int(row_value(row, "Size", default=None))
            if base is not None and size:
                ranges.append((base, base + size))
            stems.add(lower(row_value(row, "Name")).rsplit(".", 1)[0])
        # an image that modscan still finds is a known module that is simply not loaded any more (DRV-001 reports those): its driver object is not an orphan.
        # (Real Windows 10 image: the object of USBSTOR had an unreadable name, but modscan listed USBSTOR.SYS at its start address.)
        scanned = []
        for _i, row in plugin_rows_indexed(result, "windows.modscan"):
            base, size = to_int(row_value(row, "Base", default=None)), to_int(row_value(row, "Size", default=None))
            if base is not None and size:
                scanned.append((base, base + size))
        orphans = []
        for index, row in plugin_rows_indexed(result, "windows.driverscan"):
            start = to_int(row_value(row, "Start", default=None))
            name = str(row_value(row, "Driver Name") or row_value(row, "Name") or "")
            stem = lower(name).replace("\\driver\\", "").replace("\\filesystem\\", "").rsplit(".", 1)[0]
            if not start or any(low <= start < high for low, high in ranges) or stem in stems or any(low <= start < high for low, high in scanned):
                continue
            orphans.append((index, to_hex(start), name))
        if not orphans:
            return []
        shown = orphans[:_MAX_LISTED]
        return [self.make(
            title=f"{len(orphans)} driver object(s) are not backed by a loaded module", severity="Medium", confidence="Low",
            summary="These driver objects point at code that is not in the loaded-module list and have no module of the same name. Often stale objects of unloaded drivers; review the names.",
            reasons=["In windows.driverscan; start address outside all windows.modules ranges and no module with that name"],
            evidence=[f"{n} start={s}" for _i, s, n in shown] + ([f"... and {len(orphans) - _MAX_LISTED} more"] if len(orphans) > _MAX_LISTED else []),
            source_plugins=["windows.driverscan", "windows.modules"],
            evidence_items=[EvidenceItem("driver", "Start", s, n, "windows.driverscan", i) for i, s, n in shown])]


class SsdtHookRule(IndicatorRule):
    rule_id = "SSDT-001"
    category = "kernel"
    name = "System call table entries outside the Windows kernel"
    description = ("windows.ssdt lists where each system call of the kernel's service table points. Entries that point into another module "
                   "(a driver) are classic hooks; indexes missing from the list point into memory that belongs to no loaded module "
                   "(Volatility omits them). Some security products hook legitimately. Needs windows.ssdt.")

    def evaluate(self, result):
        rows = list(plugin_rows_indexed(result, "windows.ssdt"))
        if not rows:
            return []
        foreign, indexes = [], set()
        for index, row in rows:
            number = to_int(row_value(row, "Index", default=None))
            if number is not None:
                indexes.add(number)
            module = lower(row_value(row, "Module"))
            if module and module not in _KERNEL_IMAGES:
                foreign.append((index, number, module, str(row_value(row, "Symbol") or ""), to_hex(row_value(row, "Address", default=None))))
        missing = sorted(set(range(max(indexes) + 1)) - indexes) if indexes else []
        if not foreign and not missing:
            return []
        reasons = []
        if foreign:
            reasons.append(f"{len(foreign)} entr{'y' if len(foreign) == 1 else 'ies'} point into: {', '.join(sorted({f[2] for f in foreign}))}")
        if missing:
            reasons.append(f"{len(missing)} index(es) up to {max(indexes)} have an address in no loaded module: "
                           + ", ".join(map(str, missing[:12])) + (" ..." if len(missing) > 12 else ""))
        return [self.make(
            title="System call table has entries outside the Windows kernel", severity="Medium", confidence="Medium",
            summary="Hooking the system call table lets a driver see or change every system call. Compare the module with installed security software.",
            reasons=reasons, evidence=[f"#{n} {sym} → {mod} @ {addr}" for _x, n, mod, sym, addr in foreign[:_MAX_LISTED]] or reasons,
            source_plugins=["windows.ssdt"],
            evidence_items=[EvidenceItem("ssdt", "Module", mod, f"index {n} {sym}", "windows.ssdt", x) for x, n, mod, sym, _a in foreign[:_MAX_LISTED]])]


def _executable_ranges(result):
    """``[(start, end)]`` of the executable regions of every process, from malfind and (when it ran) vadinfo."""
    ranges = []
    for region in result.memory_regions:
        lo, hi = to_int(region.start), to_int(region.end)
        if lo is not None and hi is not None:
            ranges.append((lo, hi))
    for _i, row in plugin_rows_indexed(result, "windows.vadinfo"):
        if "EXECUTE" in str(row_value(row, "Protection") or "").upper():
            lo, hi = to_int(row_value(row, "Start VPN", "Start", default=None)), to_int(row_value(row, "End VPN", "End", default=None))
            if lo is not None and hi is not None:
                ranges.append((lo, hi))
    return ranges


def _looks_like_code(address) -> bool:
    """True when the little-endian bytes of the value contain two x86-64 mov opcodes with a REX prefix (48 89 / 48 8b / 4c 89 / 4c 8b)."""
    if address is None or address <= 0:
        return False
    raw = address.to_bytes(8, "little").rstrip(bytes(1))
    return sum(raw.count(bytes(op)) for op in ((0x48, 0x89), (0x48, 0x8B), (0x4C, 0x89), (0x4C, 0x8B))) >= 2


class UnbackedCallbackRule(IndicatorRule):
    rule_id = "CBK-001"
    category = "kernel"
    name = "Kernel callback whose address is in no loaded module"
    description = ("windows.callbacks lists routines the kernel calls on process/thread/image/registry events. A callback with no owning module "
                   "points at memory outside every loaded driver, which is how some rootkits hide code; one whose address lies in user-mode "
                   "memory (below 0x80000000 on 32-bit, below 0x800000000000 on 64-bit) is stronger evidence because a driver would never register it. "
                   "Needs windows.callbacks.")

    def evaluate(self, result):
        user_limit = 0x80000000 if str(next((r.get("Value") for r in result.system_info if isinstance(r, dict)
                                              and str(r.get("Variable", "")).lower() == "is64bit"), "")).lower() == "false" else 0x800000000000
        unbacked, seen = [], set()
        for index, row in plugin_rows_indexed(result, "windows.callbacks"):
            module = str(row_value(row, "Module") or "").strip()
            if module.lower() not in ("", "n/a", "none", "unknown", "-"):
                continue
            kind, detail = str(row_value(row, "Type") or ""), str(row_value(row, "Detail") or "")
            address = to_int(row_value(row, "Callback", default=None))
            if (kind, address, detail) in seen:               # the same registration is listed once per list it is on
                continue
            seen.add((kind, address, detail))
            unbacked.append((index, kind, to_hex(address) if address is not None else "", detail, address))
        # A value whose bytes are x86-64 instructions is not a pointer to a routine: windows.callbacks read something that is not a callback (seen on a real
        # Windows 10 image). It cannot be called evidence of a hook.
        unreliable = [u for u in unbacked if _looks_like_code(u[4])]
        reliable = [u for u in unbacked if u not in unreliable]
        # A user-mode value is cross-checked against the memory of the processes: malware that hooks a kernel callback from user mode points into memory it
        # owns (an executable region that malfind or vadinfo shows). A value that is in no executable user memory of any process (real Windows XP and Windows 10
        # images) is not the address of any code.
        user = [u for u in reliable if u[4] is not None and u[4] < user_limit]
        executable = _executable_ranges(result)
        checked = plugin_completed(result, "windows.vadinfo")
        backed = [u for u in user if executable and any(lo <= u[4] <= hi for lo, hi in executable)]
        unbacked_user = [u for u in user if u not in backed and checked]
        unchecked = [u for u in user if u not in backed and u not in unbacked_user]
        kernel_side = [u for u in reliable if u not in user]
        findings = []
        for items, severity, confidence, title, why in (
            (backed, "High", "High", "{n} kernel callback(s) point into executable memory of a process",
             "The callback address is in user-mode memory, and that memory is an executable region of a process (malfind / vadinfo). A driver registers kernel routines, "
             "so this is code placed outside the kernel and called by it."),
            (unchecked, "Medium", "Low", "{n} kernel callback(s) point into user-mode memory",
             "The callback address is below the kernel's address range: a driver registers kernel routines, so this is code placed outside the kernel (or a hooked/damaged list entry). "
             "It could not be cross-checked against the processes' memory (run windows.vadinfo, Deep check), so it is Medium."),
            (kernel_side, "Medium", "Medium", "{n} kernel callback(s) point outside every loaded module",
             "The callback routine is not inside any driver in the loaded-module list: unlinked or injected kernel code can look like this."),
            (unbacked_user, "Low", "Low", "{n} kernel callback value(s) in user-mode memory that holds no executable code",
             "The value is below the kernel's address range, but it is in no executable region of any process (windows.vadinfo), so it is not the address of any code; "
             "windows.callbacks most likely read a list entry it could not interpret. Not evidence of a hook on its own."),
            (unreliable, "Low", "Low", "{n} kernel callback value(s) that look like code bytes, not a routine address",
             "The value's bytes are x86-64 instructions, so it is not a pointer to a routine; windows.callbacks most likely read memory that is not a callback entry. "
             "Not evidence of a hook on its own."),
        ):
            if not items:
                continue
            shown = items[:_MAX_LISTED]
            findings.append(self.make(
                title=title.format(n=len(items)), severity=severity, confidence=confidence, summary=why,
                reasons=["Module column empty in windows.callbacks"] + (["Address is inside an executable region of a process"] if severity == "High" else []),
                evidence=[f"{t} @ {a} {d}".strip() for _i, t, a, d, _x in shown] + ([f"... and {len(items) - _MAX_LISTED} more"] if len(items) > _MAX_LISTED else []),
                source_plugins=["windows.callbacks"],
                evidence_items=[EvidenceItem("callback", "Callback", a, t, "windows.callbacks", i) for i, t, a, _d, _x in shown]))
        return findings
