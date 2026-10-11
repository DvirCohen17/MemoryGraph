"""On-disk cache of successful plugin output, keyed by dump identity + plugin + Volatility version.

A re-run after a crash (or of a dump you analysed before) reuses finished plugins instead of
scanning the image again. Only *Completed* plugins are cached and the key contains the dump's
size and modification time, so a changed dump never reuses stale output.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
from typing import Optional

from app.logging_setup import get_logger
from app.models import PluginResult
from app.paths import cache_dir

log = get_logger("cache")


def _dump_identity(dump_path: str) -> str:
    stat = os.stat(dump_path)
    return f"{os.path.abspath(dump_path).lower()}|{stat.st_size}|{int(stat.st_mtime)}"


def cache_key(dump_path: str, plugin: str, vol_version: str) -> str:
    raw = f"{_dump_identity(dump_path)}|{plugin}|{vol_version}"
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()


def _path(key: str) -> str:
    return os.path.join(str(cache_dir()), f"{key}.json.gz")


def load(dump_path: str, plugin: str, vol_version: str) -> Optional[PluginResult]:
    try:
        path = _path(cache_key(dump_path, plugin, vol_version))
        if not os.path.isfile(path):
            return None
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            data = json.load(handle)
        if data.get("plugin") != plugin or not isinstance(data.get("rows"), list):
            return None
        return PluginResult(plugin, "Completed", data["rows"], "", "", list(data.get("command", [])),
                            float(data.get("duration", 0.0)), True)
    except Exception as exc:  # noqa: BLE001 - a damaged cache file must never break an analysis
        log.warning("Ignoring unreadable cache entry for %s: %s", plugin, exc)
        return None


def store(dump_path: str, plugin: str, vol_version: str, result: PluginResult) -> None:
    if result.status != "Completed":
        return
    try:
        path = _path(cache_key(dump_path, plugin, vol_version))
        tmp = path + ".tmp"
        with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=3) as handle:
            json.dump({"plugin": plugin, "rows": result.rows, "command": result.command,
                       "duration": result.duration}, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not cache %s: %s", plugin, exc)


def size_bytes() -> int:
    total = 0
    try:
        for name in os.listdir(str(cache_dir())):
            full = os.path.join(str(cache_dir()), name)
            if os.path.isfile(full):
                total += os.path.getsize(full)
    except OSError:
        pass
    return total


def clear() -> int:
    removed = 0
    try:
        for name in os.listdir(str(cache_dir())):
            full = os.path.join(str(cache_dir()), name)
            if os.path.isfile(full):
                try:
                    os.remove(full)
                    removed += 1
                except OSError:
                    pass
    except OSError:
        pass
    return removed
