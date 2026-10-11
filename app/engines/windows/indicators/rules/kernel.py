"""Kernel driver rules (need the opt-in "extended" plugins windows.modules + windows.modscan)."""
from app.analysis.indicators.base import IndicatorRule, lower, plugin_completed, plugin_rows_indexed, row_value
from app.engines.windows.indicators.helpers import is_high_risk_dir
from app.models import EvidenceItem
from app.util import to_hex, to_int

_MAX_LISTED = 25


def _readable(value) -> str:
    """Text from pool memory is sometimes garbage (a driver object whose name was overwritten): show it only when it looks like text."""
    text = str(value or "")
    if len(text) < 3 or text.upper() in ("N/A", "NONE"):          # empty, "N/A" or a stray character
        return ""
    return text if all(32 <= ord(ch) < 127 for ch in text) else "(unreadable name)"


class HiddenDriverRule(IndicatorRule):
    rule_id = "DRV-001"
    category = "kernel"
    name = "Driver found by scanning but missing from the loaded-module list"
    description = ("windows.modscan finds driver objects in memory by pool tag; windows.modules walks the kernel's loaded-module list. "
                   "A driver in the first but not the second may have unlinked itself (rootkit technique) or may simply have been "
                   "unloaded (stale object). Needs windows.modules and windows.modscan (Settings → extended plugins).")

    def evaluate(self, result):
        if not (plugin_completed(result, "windows.modules") and plugin_completed(result, "windows.modscan")):
            return []                      # nothing to compare: not an error, not a finding
        loaded_bases, loaded_names = set(), set()
        for _i, row in plugin_rows_indexed(result, "windows.modules"):
            base = to_int(row_value(row, "Base", default=None))
            if base is not None:
                loaded_bases.add(base)
            loaded_names.add(lower(row_value(row, "Name")))
        missing, risky = [], []
        for index, row in plugin_rows_indexed(result, "windows.modscan"):
            base = to_int(row_value(row, "Base", default=None))
            name = row_value(row, "Name")
            # same name loaded elsewhere = the usual "driver was reloaded" case, not hiding
            if base is None or base in loaded_bases or lower(name) in loaded_names:
                continue
            path = _readable(row_value(row, "Path"))
            name = _readable(name) or name
            entry = (index, to_hex(base), name or "(no name)", path)
            (risky if is_high_risk_dir(path) else missing).append(entry)

        findings = []
        for index, base, name, path in risky:
            findings.append(self.make(
                title=f"Driver {name} is not in the loaded-module list and sits in a temporary/user-writable folder",
                severity="Medium", confidence="Medium",
                summary="A driver object was found by scanning memory but is not in the kernel's loaded-module list, and its path is a place where untrusted files are dropped.",
                reasons=["In windows.modscan, absent from windows.modules (by base address and by name)", f"Path: {path}"],
                evidence=[f"{name} base={base} path={path}"], source_plugins=["windows.modscan", "windows.modules"],
                evidence_items=[EvidenceItem("driver", "Base", base, f"{name} {path}", "windows.modscan", index)]))
        if missing:
            shown = missing[:_MAX_LISTED]
            more = [f"... and {len(missing) - _MAX_LISTED} more"] if len(missing) > _MAX_LISTED else []
            findings.append(self.make(
                title=f"{len(missing)} driver object(s) found by scan are not in the loaded-module list",
                severity="Low", confidence="Low",
                summary="Unloaded drivers leave stale objects in memory, so this is common on healthy systems. Review names and paths for anything that should not be there.",
                reasons=["In windows.modscan, absent from windows.modules (by base address and by name)"],
                evidence=[f"{n} base={b}" + (f" path={p}" if p else "") for _i, b, n, p in shown] + more,
                source_plugins=["windows.modscan", "windows.modules"],
                evidence_items=[EvidenceItem("driver", "Base", b, f"{n} {p}".strip(), "windows.modscan", i) for i, b, n, p in shown]))
        return findings
