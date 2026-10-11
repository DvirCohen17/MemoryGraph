"""Compare two investigations (two memory images, or the same system at two moments): what is new, what is gone, what changed.

*Current* is the investigation that is open; *reference* is the one it is compared with (normally the older image, or a clean one).
"new" means present in the current investigation only, "gone" present in the reference only. Nothing is judged here: a difference is
a lead, not a verdict (a new process may be the user opening a program).

Matching modes
  same boot   the two images come from the same running system. A process is the same process when its image name and start time
              match, so PIDs may differ; memory regions can be compared by address.
  different   other boot, other system, or a clean baseline machine. Processes are matched by image name + path only (counts per
              pair), modules by name + path, connections by process + remote endpoint; addresses and times are not compared.

No Qt in here: unit-tested without a GUI.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from app.analysis import case_state
from app.engines.windows.analysis.fileindex import split_name
from app.engines.windows.indicators.helpers import is_trusted_dir
from app.models import AnalysisResult
from app.util import format_time, norm_path, parse_time

SAME_BOOT, DIFFERENT = "same_boot", "different"
MODES = (SAME_BOOT, DIFFERENT)
MAX_ROWS_PER_SECTION = 5000
_HIDDEN_TRIAGE = ("false_positive", "baseline")
_NO_REMOTE = {"", "*", "0.0.0.0", "::", "[::]"}

# Plugins whose rows are compared, and the columns that identify a row. A plugin missing here is not compared (handles, getsids, ...
# are large and change all the time). Names are the result names of plugin_registry (printkey runs are matched by their full label).
ROW_IDENTITY: Dict[str, Tuple[str, ...]] = {
    "windows.modules": ("Name", "Path"),
    "windows.modscan": ("Name", "Path"),
    "windows.driverscan": ("Driver Name", "Name"),
    "windows.callbacks": ("Type", "Symbol", "Module"),
    "windows.svcscan": ("Name", "Binary"),
    "windows.registry.userassist": ("Name",),
    "windows.registry.scheduled_tasks": ("Task Name", "Action", "Action Arguments"),
    "windows.scheduled_tasks": ("Task Name", "Action", "Action Arguments"),
    "windows.registry.amcache": ("Path", "SHA1"),
    "windows.shimcachemem": ("File Path",),
    "windows.mutantscan": ("Name",),
    "windows.filescan": ("Name",),
    "windows.envars": ("Process", "Variable", "Value"),
}
PRINTKEY_IDENTITY = ("Key", "Name", "Data")
SECTIONS = ("Processes", "Modules", "Network", "Findings", "Memory", "Plugin rows")


@dataclass
class DiffRow:
    section: str
    change: str                  # "new" | "gone" | "changed"
    item: str
    detail: str = ""
    pid: int = 0                 # PID in the *current* investigation when the item exists there (for "show process")
    trusted: bool = False        # modules / paths inside Windows or Program Files (the view can hide them)


@dataclass
class Comparison:
    mode: str
    current_label: str
    reference_label: str
    rows: Dict[str, List[DiffRow]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    truncated: Dict[str, int] = field(default_factory=dict)         # section -> rows left out
    match_fraction: float = 0.0

    def counts(self) -> Dict[str, Dict[str, int]]:
        return {section: {change: sum(1 for r in rows if r.change == change) for change in ("new", "gone", "changed")}
                for section, rows in self.rows.items()}

    def all_rows(self) -> List[DiffRow]:
        return [row for section in SECTIONS for row in self.rows.get(section, [])]


# ----------------------------------------------------------------------------- helpers
def _clip(rows: List[DiffRow], section: str, comparison: Comparison) -> List[DiffRow]:
    if len(rows) > MAX_ROWS_PER_SECTION:
        comparison.truncated[section] = len(rows) - MAX_ROWS_PER_SECTION
        return rows[:MAX_ROWS_PER_SECTION]
    return rows


def _process_start_key(p) -> Tuple[str, str]:
    return (p.name.lower(), p.create_time or f"pid:{p.pid}")


def _process_image_key(p) -> Tuple[str, str]:
    return (p.name.lower(), norm_path(p.path))


def same_boot_fraction(current: AnalysisResult, reference: AnalysisResult) -> float:
    """Share of the reference's processes that also exist, with the same start time, in the current investigation (0..1)."""
    reference_keys = [_process_start_key(p) for p in reference.processes if p.create_time]
    if not reference_keys:
        return 0.0
    current_keys = {_process_start_key(p) for p in current.processes if p.create_time}
    return sum(1 for key in reference_keys if key in current_keys) / len(reference_keys)


def suggest_mode(current: AnalysisResult, reference: AnalysisResult) -> str:
    """``same_boot`` when many processes keep their start time between the two images, else ``different``."""
    return SAME_BOOT if same_boot_fraction(current, reference) >= 0.3 else DIFFERENT


def _describe(p) -> str:
    started = format_time(p.create_time) if p.create_time else "start unknown"
    return f"started {started} · {p.path or 'path unknown'}" + (f" · {p.command_line[:140]}" if p.command_line else "")


def _label(result: AnalysisResult) -> str:
    name = os.path.basename(result.dump_path or "") or "investigation"
    return f"{name} (captured {format_time(result.capture_time) if result.capture_time else 'time unknown'})"


# ----------------------------------------------------------------------------- sections
def _processes(current, reference, mode, out: Comparison) -> Tuple[List[DiffRow], Dict[int, int]]:
    """Process rows, and ``{current pid: reference pid}`` for the processes that exist in both (for the module / memory sections)."""
    rows: List[DiffRow] = []
    paired: Dict[int, int] = {}
    if mode == SAME_BOOT:
        ref_index: Dict[Tuple[str, str], List] = {}
        for p in reference.processes:
            ref_index.setdefault(_process_start_key(p), []).append(p)
        matched_ref = set()
        for p in current.processes:
            candidates = [r for r in ref_index.get(_process_start_key(p), []) if id(r) not in matched_ref]
            if not candidates:
                rows.append(DiffRow("Processes", "new", f"{p.name} (PID {p.pid})", _describe(p), p.pid))
                continue
            other = candidates[0]
            matched_ref.add(id(other))
            paired[p.pid] = other.pid
            if p.exit_time and not other.exit_time:
                rows.append(DiffRow("Processes", "changed", f"{p.name} (PID {p.pid})", f"exited at {format_time(p.exit_time)} (was still running in the reference)", p.pid))
            if p.command_line != other.command_line and p.command_line and other.command_line:
                rows.append(DiffRow("Processes", "changed", f"{p.name} (PID {p.pid})", f"command line changed: {p.command_line[:120]}", p.pid))
            if norm_path(p.path) != norm_path(other.path) and p.path and other.path:
                rows.append(DiffRow("Processes", "changed", f"{p.name} (PID {p.pid})", f"image path changed: {other.path} → {p.path}", p.pid))
        for r in reference.processes:
            if id(r) not in matched_ref:
                rows.append(DiffRow("Processes", "gone", f"{r.name} (PID {r.pid})", _describe(r) + (" · had exited" if r.exit_time else ""), 0))
        return rows, paired
    groups_cur: Dict[Tuple[str, str], List] = {}
    groups_ref: Dict[Tuple[str, str], List] = {}
    for p in current.processes:
        groups_cur.setdefault(_process_image_key(p), []).append(p)
    for p in reference.processes:
        groups_ref.setdefault(_process_image_key(p), []).append(p)
    for key in sorted(set(groups_cur) | set(groups_ref)):
        a, b = groups_cur.get(key, []), groups_ref.get(key, [])
        sample = (a or b)[0]
        title = f"{sample.name}  {sample.path or ''}".strip()
        if a and not b:
            rows.append(DiffRow("Processes", "new", title, f"{len(a)} instance(s), e.g. PID {a[0].pid} · {_describe(a[0])}", a[0].pid))
        elif b and not a:
            rows.append(DiffRow("Processes", "gone", title, f"{len(b)} instance(s) in the reference", 0))
        else:
            for p, other in zip(a, b):
                paired[p.pid] = other.pid
            if len(a) != len(b):
                rows.append(DiffRow("Processes", "changed", title, f"{len(b)} instance(s) → {len(a)}", a[0].pid))
    return rows, paired


def _modules(current, reference, mode, paired: Dict[int, int], out: Comparison) -> List[DiffRow]:
    rows: List[DiffRow] = []
    cur_by_pid = {p.pid: p for p in current.processes}
    ref_by_pid = {p.pid: p for p in reference.processes}

    def keys(proc) -> Dict[Tuple[str, str], object]:
        return {(d.name.lower(), norm_path(d.path)): d for d in proc.dlls}

    if mode == SAME_BOOT:
        pairs = [(cur_by_pid[c], ref_by_pid[r]) for c, r in paired.items() if c in cur_by_pid and r in ref_by_pid]
        groups = [([cur], [ref]) for cur, ref in pairs]
    else:
        merged: Dict[Tuple[str, str], Tuple[List, List]] = {}
        for p in current.processes:
            merged.setdefault(_process_image_key(p), ([], []))[0].append(p)
        for p in reference.processes:
            merged.setdefault(_process_image_key(p), ([], []))[1].append(p)
        groups = [(a, b) for a, b in merged.values() if a and b]
    for cur_list, ref_list in groups:
        cur_mods: Dict[Tuple[str, str], object] = {}
        ref_mods: Dict[Tuple[str, str], object] = {}
        for p in cur_list:
            cur_mods.update(keys(p))
        for p in ref_list:
            ref_mods.update(keys(p))
        proc = cur_list[0]
        for key in sorted(set(cur_mods) - set(ref_mods)):
            dll = cur_mods[key]
            rows.append(DiffRow("Modules", "new", dll.name, f"{dll.path or 'path unknown'} — in {proc.name} (PID {proc.pid})", proc.pid, is_trusted_dir(dll.path)))
        for key in sorted(set(ref_mods) - set(cur_mods)):
            dll = ref_mods[key]
            rows.append(DiffRow("Modules", "gone", dll.name, f"{dll.path or 'path unknown'} — was in {proc.name}", proc.pid, is_trusted_dir(dll.path)))
    return rows


def _connections(result: AnalysisResult) -> List:
    return list(result.connections) or [c for p in result.processes for c in p.network]


def _connection_key(conn) -> Tuple:
    if conn.remote_address in _NO_REMOTE:
        return ("listen", (conn.process or "").lower(), (conn.protocol or "").lower(), conn.local_port)
    return ("remote", (conn.process or "").lower(), (conn.protocol or "").lower(), conn.remote_address, conn.remote_port)


def _network(current, reference) -> List[DiffRow]:
    cur = {_connection_key(c): c for c in _connections(current)}
    ref = {_connection_key(c): c for c in _connections(reference)}
    rows = []

    def describe(c) -> str:
        return f"{c.process or 'PID ' + str(c.pid)} {c.protocol} {c.local} → {c.remote or '*'} {c.state}".strip()

    for key in sorted(set(cur) - set(ref), key=str):
        rows.append(DiffRow("Network", "new", describe(cur[key]), "listening" if key[0] == "listen" else "connection", max(cur[key].pid, 0)))
    for key in sorted(set(ref) - set(cur), key=str):
        rows.append(DiffRow("Network", "gone", describe(ref[key]), "listening" if key[0] == "listen" else "connection"))
    return rows


def _findings(current, reference) -> List[DiffRow]:
    def table(result: AnalysisResult) -> Dict[str, object]:
        procs = {p.pid: p for p in result.processes}
        found: Dict[str, object] = {}
        for ind in result.indications:
            if ind.triage in _HIDDEN_TRIAGE or ind.category in ("ioc", "baseline"):
                continue
            found.setdefault(case_state.finding_signature(ind, procs.get(ind.process_pid)), ind)
        return found

    cur, ref = table(current), table(reference)
    rows = []
    for signature in sorted(set(cur) | set(ref), key=lambda s: (cur.get(s) or ref.get(s)).title):
        a, b = cur.get(signature), ref.get(signature)
        if a and not b:
            rows.append(DiffRow("Findings", "new", f"{a.rule_id} {a.title}", f"{a.severity} · {a.process_name or 'system-wide'}", a.process_pid))
        elif b and not a:
            rows.append(DiffRow("Findings", "gone", f"{b.rule_id} {b.title}", f"{b.severity} · {b.process_name or 'system-wide'}"))
        elif a.severity != b.severity:
            rows.append(DiffRow("Findings", "changed", f"{a.rule_id} {a.title}", f"severity {b.severity} → {a.severity}", a.process_pid))
    return rows


def _memory(current, reference, paired: Dict[int, int]) -> List[DiffRow]:
    """malfind regions by address in processes that exist in both images (only meaningful for the same boot)."""
    cur_by_pid = {p.pid: p for p in current.processes}
    ref_by_pid = {p.pid: p for p in reference.processes}
    rows = []
    for cur_pid, ref_pid in paired.items():
        cur, ref = cur_by_pid.get(cur_pid), ref_by_pid.get(ref_pid)
        if cur is None or ref is None:
            continue
        before = {(r.start, r.end): r for r in ref.memory_regions}
        after = {(r.start, r.end): r for r in cur.memory_regions}
        for key in sorted(set(after) - set(before)):
            r = after[key]
            rows.append(DiffRow("Memory", "new", f"{cur.name} (PID {cur.pid}) {r.range}", f"{r.protection} · {r.size} · tag {r.tag or '?'}", cur.pid))
        for key in sorted(set(before) - set(after)):
            r = before[key]
            rows.append(DiffRow("Memory", "gone", f"{cur.name} (PID {cur.pid}) {r.range}", f"{r.protection} · {r.size}", cur.pid))
    return rows


def _row_identity(plugin_name: str) -> Optional[Tuple[str, ...]]:
    if plugin_name in ROW_IDENTITY:
        return ROW_IDENTITY[plugin_name]
    if plugin_name.startswith("windows.registry.printkey ["):
        return PRINTKEY_IDENTITY
    return None


def _identity_text(plugin_name: str, row: dict, columns: Sequence[str]) -> str:
    values = []
    for column in columns:
        value = next((v for k, v in row.items() if str(k).lower() == column.lower()), "")
        text = "" if value is None else str(value)
        if plugin_name == "windows.filescan" and column == "Name":
            device, path = split_name(text)
            text = path                                  # the volume number can differ between boots
        values.append(text.strip())
    return " | ".join(values)


def _plugin_rows(current, reference) -> Tuple[List[DiffRow], List[str]]:
    cur = {p.name: p for p in current.plugins if p.status == "Completed"}
    ref = {p.name: p for p in reference.plugins if p.status == "Completed"}
    rows, notes = [], []
    for name in sorted(set(cur) | set(ref)):
        columns = _row_identity(name)
        if columns is None:
            continue
        if name not in cur or name not in ref:
            notes.append(f"{name} was run in the {'current' if name in cur else 'reference'} investigation only, so it is not compared.")
            continue
        a = {_identity_text(name, r, columns): r for r in cur[name].rows if isinstance(r, dict)}
        b = {_identity_text(name, r, columns): r for r in ref[name].rows if isinstance(r, dict)}
        a.pop("", None)
        b.pop("", None)
        short = name.replace("windows.", "")
        for key in sorted(set(a) - set(b)):
            rows.append(DiffRow("Plugin rows", "new", key[:300], short))
        for key in sorted(set(b) - set(a)):
            rows.append(DiffRow("Plugin rows", "gone", key[:300], short))
    return rows, notes


# ----------------------------------------------------------------------------- entry point
def compare(current: AnalysisResult, reference: AnalysisResult, mode: str = "") -> Comparison:
    """Differences between the open investigation and a reference. ``mode`` defaults to :func:`suggest_mode`."""
    fraction = same_boot_fraction(current, reference)
    mode = mode if mode in MODES else suggest_mode(current, reference)
    out = Comparison(mode, _label(current), _label(reference), match_fraction=fraction)
    if not current.processes or not reference.processes:
        out.notes.append("One of the investigations has no process list, so processes and modules cannot be compared.")
    cur_time, ref_time = parse_time(current.capture_time), parse_time(reference.capture_time)
    if cur_time and ref_time:
        delta = cur_time - ref_time
        out.notes.append(f"The current image was captured {abs(delta.total_seconds()) / 3600:.1f} hours "
                         f"{'after' if delta.total_seconds() >= 0 else 'before'} the reference.")
    out.notes.append(f"{fraction:.0%} of the reference's processes exist in the current image with the same start time → "
                     + ("treated as the same boot." if mode == SAME_BOOT else "treated as different boots / systems (matched by image name and path)."))
    processes, paired = _processes(current, reference, mode, out)
    out.rows["Processes"] = processes
    out.rows["Modules"] = _modules(current, reference, mode, paired, out)
    out.rows["Network"] = _network(current, reference)
    out.rows["Findings"] = _findings(current, reference)
    out.rows["Memory"] = _memory(current, reference, paired) if mode == SAME_BOOT else []
    plugin_rows, notes = _plugin_rows(current, reference)
    out.rows["Plugin rows"] = plugin_rows
    out.notes.extend(notes)
    for section in SECTIONS:
        out.rows[section] = _clip(out.rows.get(section, []), section, out)
    return out


def export_csv(comparison: Comparison, path: str) -> int:
    """Write every difference to a CSV file (Section, Change, Item, Detail, PID); returns the number of rows."""
    tmp = path + ".tmp"
    rows = comparison.all_rows()
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Section", "Change", "Item", "Detail", "PID"])
        for row in rows:
            writer.writerow([row.section, row.change, row.item, row.detail, row.pid or ""])
    os.replace(tmp, path)
    return len(rows)
