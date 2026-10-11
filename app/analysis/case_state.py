"""The investigator's work on top of the automatic analysis: triage decisions, notes, bookmarks and known-good baselines.

Why this is separate from the findings: findings are rebuilt from the stored plugin rows every time an investigation is
loaded (``reanalyze_on_load``) and whenever the rules change. Anything stored *on* a finding would be lost, so the decisions live in
``AnalysisResult.case`` (saved with the investigation, carried across re-analysis) and are matched to findings by key:

* **finding key** (instance): rule + process name + PID + process start time + title. Identifies "this finding in this dump";
  PID alone is not enough because PIDs are reused.
* **finding signature** (dump-independent): rule + process name + process path + title. Used by baselines to recognise "the same
  thing" in another dump of the same system.

``apply_case`` stamps ``Indication.triage`` / ``triage_note`` from the case. Findings marked ``false_positive`` or suppressed by a
baseline are hidden and leave all scores and counts, but are never deleted.

No Qt in here: it is plain data and is unit-tested without a GUI.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple

from app.logging_setup import get_logger
from app.util import norm_path

log = get_logger("case")

REVIEWED, FALSE_POSITIVE, BASELINE, OPEN = "reviewed", "false_positive", "baseline", "open"
USER_STATUSES = (REVIEWED, FALSE_POSITIVE, OPEN)       # OPEN = explicitly re-opened (also overrides a baseline)
BASELINE_FORMAT = "memorygraph-baseline"
STATUS_LABEL = {REVIEWED: "Reviewed", FALSE_POSITIVE: "False positive", BASELINE: "Suppressed by baseline", OPEN: "Open", "": "Open"}


# ----------------------------------------------------------------------------- structure
def empty_case() -> Dict[str, Any]:
    return {"version": 1, "findings": {}, "notes": [], "bookmarks": {}, "baselines": [], "image_hashes": {}}


def ensure_case(result) -> Dict[str, Any]:
    """The case dict of ``result`` with every section present (tolerates missing/garbled data from old or edited files)."""
    case = result.case if isinstance(result.case, dict) else {}
    fresh = empty_case()
    for key, default in fresh.items():
        if not isinstance(case.get(key), type(default)):
            case[key] = default
    case["notes"] = [n for n in case["notes"] if isinstance(n, dict) and n.get("text")]
    case["baselines"] = [b for b in case["baselines"] if isinstance(b, dict) and isinstance(b.get("signatures"), list)]
    result.case = case
    return case


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _digest(*parts: Any, length: int = 16) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode("utf-8", "replace")).hexdigest()[:length]


# ----------------------------------------------------------------------------- keys
def _process_of(result, ind):
    if not ind.process_pid:
        return None
    return next((p for p in result.processes if p.pid == ind.process_pid), None)


def finding_signature(ind, proc=None) -> str:
    name = (proc.name if proc else ind.process_name or "").lower()
    path = norm_path(proc.path) if proc else ""
    return _digest(ind.rule_id, name, path, ind.title, length=20)


def finding_key(ind, proc=None) -> str:
    name = (proc.name if proc else ind.process_name or "").lower()
    return _digest(finding_signature(ind, proc), ind.process_pid, proc.create_time if proc else "")


def process_target(proc) -> str:
    return f"process|{proc.name.lower()}|{proc.pid}|{proc.create_time}"


def network_target(conn) -> str:
    return f"network|{conn.pid}|{conn.protocol}|{conn.local}|{conn.remote}|{conn.state}"


def event_target(event) -> str:
    return f"event|{event.timestamp}|{event.event_type}|{event.pid}|{_digest(event.description, length=8)}"


def dll_target(proc, dll) -> str:
    """A module loaded in one process (same process identity as :func:`process_target`, plus the module name and base address)."""
    return f"dll|{proc.name.lower()}|{proc.pid}|{proc.create_time}|{dll.name.lower()}|{dll.base}"


def plugin_row_target(plugin_name: str, row) -> str:
    """One row of a plugin's output, identified by its content (row order can change when a plugin is run again)."""
    return f"row|{plugin_name}|{_digest(json.dumps(row, sort_keys=True, default=str, ensure_ascii=False), length=12)}"


def region_target(proc, region) -> str:
    return f"memory|{proc.name.lower() if proc else region.process.lower()}|{region.pid}|{region.start}|{region.end}"


# ----------------------------------------------------------------------------- applying the case to the findings
def baseline_signatures(case: Dict[str, Any]) -> Dict[str, str]:
    """{signature: baseline name} over all imported baselines."""
    found: Dict[str, str] = {}
    for baseline in case.get("baselines", []):
        for signature in baseline.get("signatures", []):
            found.setdefault(str(signature), str(baseline.get("name", "baseline")))
    return found


def apply_case(result) -> None:
    """Stamp ``triage`` / ``triage_note`` on every finding from the case (idempotent; safe to call after any re-analysis)."""
    case = ensure_case(result)
    baselines = baseline_signatures(case)
    procs = {p.pid: p for p in result.processes}
    for ind in result.indications:
        proc = procs.get(ind.process_pid)
        entry = case["findings"].get(finding_key(ind, proc))
        if entry and entry.get("status") in USER_STATUSES:
            status = entry["status"]
            ind.triage = "" if status == OPEN else status
            ind.triage_note = str(entry.get("note", ""))
        elif finding_signature(ind, proc) in baselines:
            ind.triage = BASELINE
            ind.triage_note = f"Suppressed by baseline '{baselines[finding_signature(ind, proc)]}'"
        else:
            ind.triage, ind.triage_note = "", ""


# ----------------------------------------------------------------------------- triage decisions
def set_finding_status(result, ind, status: str, note: str = "", reapply: bool = True) -> str:
    """Record the investigator's decision for ``ind`` and re-apply the case. Returns the finding key.

    ``reapply=False`` is for bulk updates: call :func:`apply_case` once afterwards."""
    if status not in USER_STATUSES:
        raise ValueError(f"Unknown triage status: {status}")
    case = ensure_case(result)
    proc = _process_of(result, ind)
    key = finding_key(ind, proc)
    case["findings"][key] = {
        "status": status, "note": note.strip(), "time": _now(), "signature": finding_signature(ind, proc), "rule_id": ind.rule_id,
        "title": ind.title, "severity": ind.severity, "process": ind.process_name or (proc.name if proc else ""), "pid": ind.process_pid,
    }
    if reapply:
        apply_case(result)
    return key


def finding_entry(result, ind) -> Optional[dict]:
    return ensure_case(result)["findings"].get(finding_key(ind, _process_of(result, ind)))


# ----------------------------------------------------------------------------- notes and bookmarks
def add_note(result, kind: str, target: str, label: str, text: str, pid: int = 0) -> dict:
    text = (text or "").strip()
    if not text:
        raise ValueError("A note cannot be empty.")
    note = {"id": uuid.uuid4().hex[:8], "kind": kind, "target": target, "label": label, "pid": int(pid or 0), "text": text, "time": _now()}
    ensure_case(result)["notes"].append(note)
    return note


def delete_note(result, note_id: str) -> bool:
    case = ensure_case(result)
    before = len(case["notes"])
    case["notes"] = [n for n in case["notes"] if n.get("id") != note_id]
    return len(case["notes"]) != before


def notes_for(result, target: str) -> List[dict]:
    return [n for n in ensure_case(result)["notes"] if n.get("target") == target]


def toggle_bookmark(result, kind: str, target: str, label: str, pid: int = 0) -> bool:
    """Add or remove a bookmark; returns True when the target is bookmarked afterwards."""
    marks = ensure_case(result)["bookmarks"]
    if target in marks:
        del marks[target]
        return False
    marks[target] = {"kind": kind, "label": label, "pid": int(pid or 0), "time": _now()}
    return True


def is_bookmarked(result, target: str) -> bool:
    return target in ensure_case(result)["bookmarks"]


def has_marks(result, target: str) -> Tuple[bool, bool]:
    """(bookmarked, has notes) for a target."""
    case = ensure_case(result)
    return target in case["bookmarks"], any(n.get("target") == target for n in case["notes"])


# ----------------------------------------------------------------------------- baselines
def export_baseline(result, path: str, name: str = "", only_false_positives: bool = False) -> int:
    """Write a baseline file; returns how many findings it contains.

    ``only_false_positives=False``: every finding of this investigation (use on a dump of a known-clean system).
    ``only_false_positives=True``: only the findings the investigator marked as false positive here.
    """
    case = ensure_case(result)
    procs = {p.pid: p for p in result.processes}
    entries: Dict[str, dict] = {}
    if only_false_positives:
        for entry in case["findings"].values():
            if entry.get("status") == FALSE_POSITIVE and entry.get("signature"):
                entries[entry["signature"]] = {"signature": entry["signature"], "rule_id": entry.get("rule_id", ""),
                                               "process": entry.get("process", ""), "title": entry.get("title", "")}
    else:
        for ind in result.indications:
            signature = finding_signature(ind, procs.get(ind.process_pid))
            entries.setdefault(signature, {"signature": signature, "rule_id": ind.rule_id, "process": ind.process_name, "title": ind.title})
    data = {
        "format": BASELINE_FORMAT, "version": 2, "created": _now(), "source_dump": result.dump_path,
        "name": name or os.path.splitext(os.path.basename(path))[0], "entries": sorted(entries.values(), key=lambda e: (e["rule_id"], e["process"])),
        # "image name|image path" of every process, so a later dump can be asked "what is new here?" (rule BASE-001)
        "processes": sorted({f"{p.name.lower()}|{norm_path(p.path)}" for p in result.processes}) if not only_false_positives else [],
    }
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)
    os.replace(tmp, path)
    return len(entries)


def import_baseline(result, path: str) -> Tuple[str, int]:
    """Add a baseline file to the case and re-apply it. Returns (baseline name, entries)."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError(f"The baseline file could not be read: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT or not isinstance(data.get("entries"), list):
        raise ValueError("The file is not a MemoryGraph baseline (format marker missing).")
    signatures = [str(e["signature"]) for e in data["entries"] if isinstance(e, dict) and e.get("signature")]
    name = str(data.get("name") or os.path.splitext(os.path.basename(path))[0])
    case = ensure_case(result)
    case["baselines"] = [b for b in case["baselines"] if b.get("name") != name]       # re-importing replaces
    processes = [str(p) for p in data.get("processes", []) if isinstance(p, str)] if isinstance(data.get("processes"), list) else []
    case["baselines"].append({"name": name, "source_dump": str(data.get("source_dump", "")), "imported": _now(),
                              "signatures": signatures, "processes": processes})
    apply_case(result)
    return name, len(signatures)


def remove_baseline(result, name: str) -> bool:
    case = ensure_case(result)
    before = len(case["baselines"])
    case["baselines"] = [b for b in case["baselines"] if b.get("name") != name]
    apply_case(result)
    return len(case["baselines"]) != before


# ----------------------------------------------------------------------------- report
def export_markdown(result, path: str) -> None:
    """Case notes as a Markdown report: bookmarks, notes and triage decisions, each with where it came from."""
    case = ensure_case(result)
    lines = ["# MemoryGraph case notes", "", f"* Memory image: `{result.dump_path}`", f"* Captured: {result.capture_time or 'unknown'}",
             f"* Exported: {_now()}", ""]
    marks = case["bookmarks"]
    lines += ["## Bookmarks", ""] + ([f"* **{m.get('label', t)}** ({m.get('kind', '')}{', PID ' + str(m['pid']) if m.get('pid') else ''}) — {m.get('time', '')}"
                                      for t, m in marks.items()] or ["_none_"]) + [""]
    lines += ["## Notes", ""]
    for note in sorted(case["notes"], key=lambda n: n.get("time", "")):
        lines.append(f"### {note.get('label', '')} ({note.get('kind', '')}{', PID ' + str(note['pid']) if note.get('pid') else ''}) — {note.get('time', '')}")
        lines += ["", note.get("text", ""), ""]
    if not case["notes"]:
        lines += ["_none_", ""]
    lines += ["## Triage decisions", ""]
    decided = [e for e in case["findings"].values() if e.get("status") in (REVIEWED, FALSE_POSITIVE)]
    for entry in sorted(decided, key=lambda e: e.get("time", "")):
        lines.append(f"* **{STATUS_LABEL[entry['status']]}** — {entry.get('rule_id', '')} {entry.get('title', '')} "
                     f"({entry.get('process', '') or 'system-wide'}{', PID ' + str(entry['pid']) if entry.get('pid') else ''}); "
                     f"{entry.get('time', '')}" + (f"; reason: {entry['note']}" if entry.get("note") else ""))
    if not decided:
        lines.append("_none_")
    if case["baselines"]:
        lines += ["", "## Baselines applied", ""] + [f"* {b.get('name')}: {len(b.get('signatures', []))} known-good finding(s)" for b in case["baselines"]]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
