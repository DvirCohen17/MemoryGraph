"""Hashes of the process images dumped from a memory image (``windows.pslist --dump`` for every process).

Why: an IOC list (or a threat-intelligence export) usually holds file hashes, but a memory image holds no file hashes until the files are
carved out of it. "Hash all process images…" dumps every running process's executable once, hashes each (SHA-256 + MD5), and stores the
list in the investigation's case data (so it survives re-analysis and save/load). Rule IOC-007 matches that list against your IOC hashes.

The hash is of the *reconstructed* image from memory: headers and the pages that were in memory, relocated data and unpaged zero pages
included. It equals the file's hash only when nothing was changed or paged out, so a match is strong evidence and a non-match proves nothing.
No Qt in here: unit-tested without a GUI.
"""
from __future__ import annotations

import csv
import datetime
import os
import re
from typing import Any, Dict, Iterable, List, Optional

from app.analysis import case_state

# windows.pslist --dump names its files "<pid>.<ImageFileName>.<image base>.dmp"
_DUMP_NAME = re.compile(r"^(?:pid\.)?(\d+)\.(.+)\.(0x[0-9a-fA-F]+)\.dmp$")


def parse_dump_name(name: str) -> Optional[Dict[str, Any]]:
    match = _DUMP_NAME.match(os.path.basename(name))
    if not match:
        return None
    return {"pid": int(match.group(1)), "image_name": match.group(2), "image_base": match.group(3)}


def entries_from_artifacts(artifacts: Iterable, processes: Iterable) -> List[Dict[str, Any]]:
    """One entry per dumped file that belongs to a known process (``artifacts`` are ``dumper.DumpedFile`` objects)."""
    by_pid = {p.pid: p for p in processes}
    entries = []
    for artifact in artifacts:
        parsed = parse_dump_name(artifact.name)
        if parsed is None or not getattr(artifact, "sha256", ""):
            continue
        proc = by_pid.get(parsed["pid"])
        entries.append({
            "pid": parsed["pid"], "process": proc.name if proc else parsed["image_name"], "create_time": proc.create_time if proc else "",
            "path": proc.path if proc else "", "image_base": parsed["image_base"], "file": artifact.name, "size": int(artifact.size),
            "sha256": artifact.sha256.lower(), "md5": artifact.md5.lower(),
        })
    return sorted(entries, key=lambda e: e["pid"])


def unreadable(artifacts: Iterable) -> List[str]:
    """Names of dumped process images that could not be hashed (``DumpedFile.error`` set), for the message shown to the investigator."""
    return [a.name for a in artifacts if getattr(a, "error", "") and parse_dump_name(a.name)]


def store(result, entries: List[Dict[str, Any]], source_dir: str = "") -> int:
    """Keep the hashes in the investigation (replacing an earlier list). Returns how many entries were stored."""
    case = case_state.ensure_case(result)
    case["image_hashes"] = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                            "source_dir": source_dir, "entries": list(entries)}
    return len(entries)


def stored(result) -> List[Dict[str, Any]]:
    section = case_state.ensure_case(result).get("image_hashes") or {}
    return [e for e in section.get("entries", []) if isinstance(e, dict) and e.get("sha256")]


def export_csv(result, path: str) -> int:
    """Write the stored list as CSV (PID, process, path, size, SHA-256, MD5): a list that can be checked against feeds offline."""
    entries = stored(result)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["pid", "process", "path", "size_bytes", "sha256", "md5", "image_base"])
        for e in entries:
            writer.writerow([e["pid"], e.get("process", ""), e.get("path", ""), e.get("size", ""), e["sha256"], e.get("md5", ""), e.get("image_base", "")])
    os.replace(tmp, path)
    return len(entries)
