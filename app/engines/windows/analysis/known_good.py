"""Known-good module lists: which DLLs a program normally has on a given Windows (no Qt; plain JSON files).

Analyse a clean system once, export its module list (Case Notes → *Export known-good modules*) and install it on the computer you investigate with (Case Notes →
*Install known-good list*, or copy the file to ``<MemoryGraph home>/known_good``). Every later analysis of the same Windows (NT version and 32/64-bit) then treats a module
that appears in the list for that program name as expected: VAD-001, LDR-001 and MEM-001 leave it alone. A list is the investigator's own data: nothing is shipped with
MemoryGraph, because a list is only as good as the system it was made from.

File format: ``{"format": "memorygraph-known-good", "name": ..., "nt": [10, 0], "is64": true, "build": 15063, "modules": {"svchost.exe": ["wldp.dll", ...]}}``.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.engines.windows.analysis import os_profile
from app.analysis.indicators.base import plugin_rows_indexed, row_value
from app.paths import app_dir
from app.util import norm_path, to_int

FORMAT = "memorygraph-known-good"


def folder() -> str:
    path = os.path.join(str(app_dir()), "known_good")
    os.makedirs(path, exist_ok=True)
    return path


def _base(path: str) -> str:
    return norm_path(path).rsplit("\\", 1)[-1]


def mapped_images(result) -> Dict[int, Set[str]]:
    """``{pid: lower-case image names}`` of everything the process has mapped according to dlllist, ldrmodules and vadinfo (file-backed images only)."""
    found: Dict[int, Set[str]] = {}
    for proc in result.processes:
        names = found.setdefault(proc.pid, set())
        names.update(d.name.lower() for d in proc.dlls if d.name)
        names.update(_base(d.path) for d in proc.dlls if d.path)
    for _i, row in plugin_rows_indexed(result, "windows.ldrmodules"):
        pid, path = to_int(row_value(row, "Pid", default=None)), str(row_value(row, "MappedPath") or "")
        if pid and path:
            found.setdefault(pid, set()).add(_base(path))
    for _i, row in plugin_rows_indexed(result, "windows.vadinfo"):
        pid, path = to_int(row_value(row, "PID", default=None)), str(row_value(row, "File") or "")
        if pid and path and not to_int(row_value(row, "PrivateMemory", default=0), 0):
            found.setdefault(pid, set()).add(_base(path))
    return found


def build(result, name: str = "") -> dict:
    """The known-good list of ``result`` (every module every program of this system had), ready to be saved."""
    profile = os_profile.from_result(result)
    by_pid = mapped_images(result)
    modules: Dict[str, Set[str]] = {}
    for proc in result.processes:
        modules.setdefault(proc.name.lower(), set()).update(n for n in by_pid.get(proc.pid, ()) if n)
    return {"format": FORMAT, "name": name or os.path.basename(result.dump_path or "") or "known-good", "nt": [profile.nt_major, profile.nt_minor],
            "is64": bool(profile.is64), "build": profile.build, "source": result.dump_path or "",
            "modules": {k: sorted(v) for k, v in sorted(modules.items()) if v}}


def save(data: dict, path: str) -> int:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=1, ensure_ascii=False)
    return sum(len(v) for v in data.get("modules", {}).values())


def install(path: str) -> Tuple[str, int]:
    """Copy a known-good file into the library; returns ``(name, modules)``. Raises ValueError for a file that is not one."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError(f"The file could not be read: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("modules"), dict):
        raise ValueError("This is not a MemoryGraph known-good list.")
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", str(data.get("name") or "known-good"))[:60] or "known-good"
    count = save(data, os.path.join(folder(), f"{slug}.json"))
    _CACHE.clear()
    return str(data.get("name") or slug), count


class KnownGood:
    """The merged lists that apply to one Windows version."""

    def __init__(self, lists: Iterable[dict] = ()):
        self.names: List[str] = []
        self._modules: Dict[str, Set[str]] = {}
        for data in lists:
            self.names.append(str(data.get("name", "")))
            for program, mods in (data.get("modules") or {}).items():
                self._modules.setdefault(str(program).lower(), set()).update(str(m).lower() for m in mods)

    def __bool__(self) -> bool:
        return bool(self._modules)

    def knows(self, program: str, module: str) -> bool:
        return str(module).lower() in self._modules.get(str(program).lower(), ())


_CACHE: Dict[tuple, Tuple[float, List[dict]]] = {}


def _lists() -> List[dict]:
    path = folder()
    stamp = max([os.path.getmtime(os.path.join(path, f)) for f in os.listdir(path) if f.endswith(".json")] or [0.0])
    cached = _CACHE.get((path,))
    if cached and cached[0] == stamp:
        return cached[1]
    lists = []
    for name in sorted(os.listdir(path)):
        if name.endswith(".json"):
            try:
                with open(os.path.join(path, name), encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict) and data.get("format") == FORMAT:
                    lists.append(data)
            except (OSError, ValueError):
                continue
    _CACHE[(path,)] = (stamp, lists)
    return lists


def for_result(result) -> KnownGood:
    """The installed lists made on the same Windows as ``result`` (same NT version and 32/64-bit; an unknown version matches nothing)."""
    profile = os_profile.from_result(result)
    if not profile.known:
        return KnownGood()
    return KnownGood(d for d in _lists() if list(d.get("nt") or []) == [profile.nt_major, profile.nt_minor] and bool(d.get("is64")) == bool(profile.is64))
