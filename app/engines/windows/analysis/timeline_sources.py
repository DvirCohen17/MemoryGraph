"""Timeline events from the opt-in registry / execution-history plugins.

Each source turns the rows of one plugin into events with the plugin name and row index as provenance. Noise control is the same
idea as for module loads: things that live in Windows / Program Files (system services, system tasks, routine Active Setup entries)
are left out, so the timeline shows what a person would have to explain. Every event keeps the full row in its details.

    printkey [Run keys, Active Setup, Services, Winlogon / AppInit / IFEO]  -> "Registry key written"
    windows.registry.scheduled_tasks                                         -> "Scheduled task created" / "last ran"
    windows.registry.userassist                                              -> "Program run (UserAssist)"
    windows.registry.amcache (windows.amcache)                               -> "Program installed / Amcache entry modified"
    windows.shimcachemem                                                     -> "File last modified / Shimcache entry updated"

``add`` is the timeline builder's own function (it validates the time, drops duplicates and garbage dates).
"""
from __future__ import annotations

from typing import Callable, Dict, List

from app.engines.windows.analysis import plugin_registry
from app.engines.windows.indicators.helpers import expand_env_path, is_high_risk_dir, is_trusted_dir, split_command
from app.analysis.indicators.base import row_value
from app.engines.windows.indicators.rules.autostart import autostart_issue
from app.engines.windows.indicators.rules.registry import _PATHS
from app.util import norm_path

MAX_EVENTS_PER_PLUGIN = 2000
FILE_TIME = "File time"          # modification times of files: not activity, often years old; the timeline shows them only on request
PRINTKEY_PREFIX = "windows.registry.printkey ["
_TASK_PLUGINS = ("windows.registry.scheduled_tasks", "windows.scheduled_tasks")
_AMCACHE_PLUGINS = ("windows.registry.amcache", "windows.amcache")
_USERASSIST, _SHIMCACHE = "windows.registry.userassist", "windows.shimcachemem"

Add = Callable[..., None]


def covers(plugin_name: str) -> bool:
    """True when this module builds the events of ``plugin_name`` (the generic 'any row with a time' fallback must skip it)."""
    return (plugin_name.startswith(PRINTKEY_PREFIX) or plugin_name in _TASK_PLUGINS + _AMCACHE_PLUGINS + (_USERASSIST, _SHIMCACHE))


def _text(row, *keys) -> str:
    value = row_value(row, *keys)
    return "" if value is None else str(value).strip()


def routine(path: str) -> bool:
    """A bare file name, or a file in Windows / Program Files that is not in a temporary folder."""
    canonical = norm_path(path)
    if ":\\" not in canonical and not canonical.startswith("\\\\"):
        return True                                           # no folder to judge (rundll32.exe, a CLSID, ...)
    if is_high_risk_dir(canonical):
        return False
    return is_trusted_dir(canonical) or canonical.startswith("c:\\windows\\")


def third_party(command: str) -> bool:
    """True when the program, or a path in its arguments, is outside the routine system folders."""
    command = str(command or "")
    program, _args = split_command(command)
    candidates = [program] + _PATHS.findall(expand_env_path(command))
    return any(candidate and not routine(candidate) for candidate in candidates)


# ----------------------------------------------------------------------------- registry keys
def _interesting_key(plugin_name: str, key: str, values: List[tuple]) -> bool:
    spec = plugin_registry.find(plugin_name)
    used_by = spec.used_by if spec else ()
    if "PER-003" in used_by:                                  # services: only those whose program is not a routine system one
        return any(name.lower() in ("imagepath", "servicedll", "failurecommand") and third_party(data) for name, data in values)
    if "PER-002" in used_by:                                  # Winlogon / AppInit_DLLs / IFEO: only values the PER-002 rule objects to
        return any(autostart_issue(key, name, data)[0] for name, data in values)
    if "Active Setup" in plugin_name:
        return any(name.lower() == "stubpath" and third_party(data) for name, data in values)
    return bool(values)                                       # Run / RunOnce style keys: every value is a program that starts by itself


def _registry_events(plugin, add: Add) -> int:
    keys: Dict[str, dict] = {}
    for index, row in enumerate(plugin.rows):
        if not isinstance(row, dict) or _text(row, "Type").upper() == "KEY":
            continue
        entry = keys.setdefault(_text(row, "Key"), {"time": row_value(row, "Last Write Time"), "index": index, "values": []})
        entry["values"].append((_text(row, "Name"), _text(row, "Data")))
    count = 0
    for key, entry in keys.items():
        if not entry["time"] or not _interesting_key(plugin.name, key, entry["values"]):
            continue
        shown = "; ".join(f"{name or '(default)'} = {data[:90]}" for name, data in entry["values"][:3])
        details = {"Key": key, **{(name or "(default)"): data[:300] for name, data in entry["values"][:12]}}
        short = "\\".join(key.split("\\")[-2:])
        add(entry["time"], "Registry", "Registry key written", f"{short}: {shown}", 0, plugin.name, details,
            {"timestamp": {"plugin": plugin.name, "row_index": entry["index"]}})
        count += 1
    return count


# ----------------------------------------------------------------------------- other sources
def _task_events(plugin, add: Add) -> int:
    count = 0
    for index, row in enumerate(plugin.rows):
        if not isinstance(row, dict):
            continue
        command = f"{_text(row, 'Action')} {_text(row, 'Action Arguments')}".strip()
        task = _text(row, "Task Name", "Key Name") or "(unnamed task)"
        if not _text(row, "Action") or not third_party(command):
            continue
        for column, etype in (("Creation Time", "Scheduled task created"), ("Last Run Time", "Scheduled task last ran")):
            stamp = row_value(row, column)
            if stamp:
                add(stamp, "Scheduled task", etype, f"{task}: {command[:140]}", 0, plugin.name, dict(row),
                    {"timestamp": {"plugin": plugin.name, "row_index": index, "field": column}})
                count += 1
    return count


def _userassist_events(plugin, add: Add) -> int:
    count = 0
    for index, row in enumerate(plugin.rows):
        if not isinstance(row, dict):
            continue
        name, stamp = _text(row, "Name"), row_value(row, "Last Updated")
        if not stamp or not name or name.startswith("UEME_"):
            continue
        add(stamp, "Execution", "Program run (UserAssist)", f"UserAssist: {name} (run count {_text(row, 'Count') or '?'})", 0, plugin.name,
            dict(row), {"timestamp": {"plugin": plugin.name, "row_index": index}})
        count += 1
    return count


def _amcache_events(plugin, add: Add) -> int:
    count = 0
    for index, row in enumerate(plugin.rows):
        if not isinstance(row, dict):
            continue
        path = _text(row, "Path")
        if not path or not third_party(path):
            continue
        for column, etype in (("InstallTime", "Program installed (Amcache)"), ("LastModifyTime", "Amcache entry modified")):
            stamp = row_value(row, column)
            if stamp:
                add(stamp, "Execution", etype, f"Amcache: {path}", 0, plugin.name, dict(row),
                    {"timestamp": {"plugin": plugin.name, "row_index": index, "field": column}})
                count += 1
    return count


def _shimcache_events(plugin, add: Add) -> int:
    count = 0
    for index, row in enumerate(plugin.rows):
        if not isinstance(row, dict):
            continue
        path = _text(row, "File Path")
        if not path or not third_party(path):
            continue
        for column, etype, category in (("Last Modified", "File last modified (shimcache)", FILE_TIME), ("Last Update", "Shimcache entry updated", "Execution")):
            stamp = row_value(row, column)
            if stamp:
                add(stamp, category, etype, f"Shimcache: {path}", 0, plugin.name, dict(row),
                    {"timestamp": {"plugin": plugin.name, "row_index": index, "field": column}})
                count += 1
    return count


def add_events(plugin, add: Add) -> int:
    """Add the events of one (completed) plugin; returns how many were offered to ``add``."""
    if plugin.name.startswith(PRINTKEY_PREFIX):
        return _registry_events(plugin, add)
    if plugin.name in _TASK_PLUGINS:
        return _task_events(plugin, add)
    if plugin.name == _USERASSIST:
        return _userassist_events(plugin, add)
    if plugin.name in _AMCACHE_PLUGINS:
        return _amcache_events(plugin, add)
    if plugin.name == _SHIMCACHE:
        return _shimcache_events(plugin, add)
    return 0
