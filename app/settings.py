"""Persistent application settings (stored as JSON in the user's profile)."""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Dict

from app.logging_setup import get_logger
from app.paths import settings_path

log = get_logger("settings")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "target_os": "windows",         # the engine picked on the start window: "windows" | "linux" (app/engines)
    "os_profiles": {},              # the settings that belong to ONE operating system, kept for the one that is not selected: {"linux": {...}}
    "theme": "Dark",                # the only theme (older files may hold another name: it is read as Dark)
    "font_size": 10,                # base font size in points (the stylesheet scales from this)
    "remember_layout": True,        # restore window size and splitter positions
    "layout": {},                   # saved window geometry / splitter sizes
    "run_extended_plugins": False,
    "preserve_plugin_output": True,
    "show_evidence_provenance": True,
    # Volatility execution
    "volatility_path": "",          # empty = auto-detect
    "symbol_dirs": [],              # folders with Volatility symbol (ISF .json/.json.xz) files, passed as -s (MemoryGraph itself never goes online)
    "vol2_path": "",                # Volatility 2: the standalone .exe or vol.py (needs Python 2.7); empty = tools/volatility2 in the project, else none
    "python2_path": "",             # Python 2.7 interpreter for vol.py; empty = find py -2 / python2
    "vol2_deep_scan": False,        # also run connscan / sockscan (whole-image scans: minutes) on Windows XP / 2003 images
    "vol2_timeout_seconds": 1200,   # stop a Volatility 2 plugin after this long
    "parallel_plugins": 3,          # how many Volatility processes run at once
    "idle_timeout_seconds": 900,    # kill a plugin only if it prints nothing for this long
    "max_plugin_seconds": 7200,     # absolute safety limit per plugin
    "use_cache": True,              # reuse plugin output from a previous run of the same dump
    "enabled_plugins": [],          # empty = all core plugins
    "optional_plugins": [],         # opt-in checkbox ids from plugin_registry (a plugin name, or e.g. "run_keys")
    "yara_rules_file": "",          # rule file for windows.vadyarascan (--yara-file)
    "ioc_files": [],                # IOC list files (separate IOC-* rule family, see app/analysis/ioc.py)
    "reanalyze_on_load": True,      # rebuild processes/timeline/indications from stored plugin rows when loading
    # UI
    "min_severity": "Medium",
    "group_process_duplicates": True,
    "last_dump_dir": "",
    "last_analysis_dir": "",
    "recent_dumps": [],
    "recent_analyses": [],
}

_INT_LIMITS = {
    "parallel_plugins": (1, 8),
    "idle_timeout_seconds": (30, 86400),
    "max_plugin_seconds": (60, 172800),
    "font_size": (8, 18),
}


def sanitize(values: Dict[str, Any]) -> Dict[str, Any]:
    """Merge with defaults and coerce values into safe ranges."""
    merged = copy.deepcopy(DEFAULT_SETTINGS)          # a copy of the nested values too: a settings object must never change the defaults of the next one
    for key, value in (values or {}).items():
        merged[key] = value
    for key, (low, high) in _INT_LIMITS.items():
        try:
            merged[key] = max(low, min(high, int(merged[key])))
        except (TypeError, ValueError):
            merged[key] = DEFAULT_SETTINGS[key]
    for key in ("recent_dumps", "recent_analyses"):
        if not isinstance(merged.get(key), list):
            merged[key] = []
        merged[key] = [str(x) for x in merged[key]][:10]
    if not isinstance(merged.get("enabled_plugins"), list):
        merged["enabled_plugins"] = []
    merged["enabled_plugins"] = [str(x) for x in merged["enabled_plugins"]]
    if not isinstance(merged.get("optional_plugins"), list):
        merged["optional_plugins"] = []
    merged["optional_plugins"] = [str(x) for x in merged["optional_plugins"]]
    if not isinstance(merged.get("symbol_dirs"), list):
        merged["symbol_dirs"] = []
    merged["symbol_dirs"] = [str(x).strip() for x in merged["symbol_dirs"] if str(x).strip()]
    if not isinstance(merged.get("ioc_files"), list):
        merged["ioc_files"] = []
    merged["ioc_files"] = [str(x) for x in merged["ioc_files"] if str(x).strip()]
    from app.engines import OS_IDS
    if merged.get("target_os") not in OS_IDS:
        merged["target_os"] = "windows"
    if not isinstance(merged.get("os_profiles"), dict):
        merged["os_profiles"] = {}
    merged["theme"] = "Dark"
    if not isinstance(merged.get("layout"), dict):
        merged["layout"] = {}
    merged["yara_rules_file"] = str(merged.get("yara_rules_file") or "").strip()
    for key in ("run_extended_plugins", "preserve_plugin_output", "show_evidence_provenance",
                "use_cache", "group_process_duplicates", "reanalyze_on_load", "remember_layout", "vol2_deep_scan"):
        merged[key] = bool(merged.get(key))
    return merged


def load_settings() -> Dict[str, Any]:
    try:
        path = settings_path()
        if path.is_file():
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                return sanitize(data)
    except (OSError, ValueError) as exc:
        log.warning("Could not read settings, using defaults: %s", exc)
    return sanitize({})


def save_settings(values: Dict[str, Any]) -> bool:
    try:
        path = settings_path()
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(sanitize(values), handle, indent=2)
        os.replace(tmp, path)
        return True
    except (OSError, TypeError, ValueError) as exc:
        log.warning("Could not save settings: %s", exc)
        return False


def remember_recent(values: Dict[str, Any], key: str, item: str) -> None:
    items = [x for x in values.get(key, []) if x != item]
    items.insert(0, item)
    values[key] = items[:10]


def switch_target_os(settings: Dict[str, Any], new_os: str) -> Dict[str, Any]:
    """Make ``new_os`` the operating system MemoryGraph works on and swap the settings that belong to one operating system (which plugin groups run, symbol folders, the YARA
    file): the ones in use are stored under ``settings["os_profiles"][old]``, and the ones last used for ``new_os`` (or that engine's defaults the first time) are loaded.
    Everything else (theme, Volatility path, timeouts, IOC lists ...) is shared. ``settings`` is changed in place and returned."""
    from app.engines import DEFAULT_OS, OS_IDS, get_engine
    new_os = new_os if new_os in OS_IDS else DEFAULT_OS
    old_os = settings.get("target_os") if settings.get("target_os") in OS_IDS else DEFAULT_OS
    if new_os == old_os:
        settings["target_os"] = new_os
        return settings
    profiles = settings.get("os_profiles")
    if not isinstance(profiles, dict):
        profiles = settings["os_profiles"] = {}
    keys = tuple(get_engine(old_os).os_settings_keys)
    profiles[old_os] = {k: settings.get(k) for k in keys}
    incoming = profiles.get(new_os)
    if not isinstance(incoming, dict):
        incoming = get_engine(new_os).default_settings()
    for key in get_engine(new_os).os_settings_keys:
        if key in incoming:
            settings[key] = incoming[key]
    settings["target_os"] = new_os
    return settings
