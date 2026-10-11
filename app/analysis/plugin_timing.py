"""How long plugins take (seconds per GB of memory image), learned from earlier runs on this computer.

Used to start the slowest plugins first (so the last plugin to finish is not a 10-minute one that could have run alongside the others), and to show an estimate before
a run. The starting values were measured on a real 5 GB Windows 10 image (2 plugins at a time); every completed run replaces them with what this computer does.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Dict, Iterable, List

from app.paths import app_dir

# seconds per GB of image, from the first real run (4,992 MiB Windows 10, 2026-10-08); plugins not listed use DEFAULT
MEASURED_SECONDS_PER_GB: Dict[str, float] = {
    "windows.handles": 174.0, "windows.malfind": 135.0, "windows.vadinfo": 121.0, "windows.malware.suspicious_threads": 79.0, "windows.malware.hollowprocesses": 74.0,
    "windows.filescan": 77.0, "windows.psscan": 30.0, "windows.psxview": 24.0, "windows.ldrmodules": 19.0, "windows.registry.amcache": 36.0, "windows.registry.printkey [Services]": 56.0,
    "windows.netscan": 14.0, "windows.callbacks": 15.0, "windows.malware.processghosting": 13.0, "windows.etwpatch": 20.0, "windows.malware.svcdiff": 12.0,
    "windows.dlllist": 13.0, "windows.svcscan": 13.0, "windows.getsids": 10.0, "windows.mutantscan": 8.0, "windows.modscan": 9.0, "windows.driverscan": 10.0,
    "windows.driverirp": 10.0, "windows.registry.scheduled_tasks": 10.0, "windows.registry.userassist": 3.0,
}
DEFAULT_SECONDS_PER_GB = 3.0
_LOCK = threading.Lock()          # plugins finish in parallel threads: one read-modify-write of the file at a time
GB = 1024 ** 3


def _path() -> str:
    return os.path.join(str(app_dir()), "timings.json")


def _learned() -> Dict[str, float]:
    try:
        with open(_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        return {str(k): float(v) for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def seconds_per_gb(name: str, learned: Dict[str, float] = None) -> float:
    learned = _learned() if learned is None else learned
    if name in learned:
        return learned[name]
    if name.startswith("windows.registry.printkey ["):
        return MEASURED_SECONDS_PER_GB.get(name, 3.5)
    return MEASURED_SECONDS_PER_GB.get(name, DEFAULT_SECONDS_PER_GB)


def record(name: str, seconds: float, image_bytes: int) -> None:
    """Remember how long ``name`` took (blended with what was known: a single odd run does not rule)."""
    if seconds <= 0 or image_bytes <= 0:
        return
    rate = seconds / max(0.05, image_bytes / GB)
    with _LOCK:
        learned = _learned()
        old = learned.get(name)
        learned[name] = round(rate if old is None else 0.5 * old + 0.5 * rate, 2)
        target = _path()
        try:
            with open(target + ".tmp", "w", encoding="utf-8") as handle:
                json.dump(learned, handle, indent=1, sort_keys=True)
            os.replace(target + ".tmp", target)              # a reader never sees a half-written file
        except OSError:
            pass


def expected(name: str, image_bytes: int, learned: Dict[str, float] = None) -> float:
    return seconds_per_gb(name, learned) * max(0.05, image_bytes / GB)


def order(names: Iterable[str], image_bytes: int) -> List[str]:
    """Slowest first (stable for equal estimates)."""
    learned = _learned()
    items = list(names)
    return sorted(items, key=lambda n: -expected(n, image_bytes, learned))


def estimate_total(names: Iterable[str], image_bytes: int, workers: int) -> float:
    """Wall-clock seconds when ``workers`` plugins run at a time and the slowest are started first (greedy list scheduling)."""
    learned = _learned()
    lanes = [0.0] * max(1, workers)
    for name in sorted(names, key=lambda n: -expected(n, image_bytes, learned)):
        lanes[lanes.index(min(lanes))] += expected(name, image_bytes, learned)
    return max(lanes)


def describe(seconds: float) -> str:
    minutes = seconds / 60
    return "under a minute" if minutes < 1 else f"about {round(minutes)} min" if minutes < 90 else f"about {minutes / 60:.1f} h"
