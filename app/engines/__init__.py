"""The operating-system engines and how to find one.

    get_engine("windows") / get_engine("linux")      an engine by id (Windows when the id is unknown or empty)
    engine_for(result)                               the engine a result was made by (``result.target_os``)
    engine_for_settings(settings)                    the engine the user picked on the start window (``settings["target_os"]``)

See :mod:`app.engines.base` for what an engine is and how the front end uses it.
"""
from __future__ import annotations

import importlib
from typing import Dict, List

DEFAULT_OS = "windows"
OS_IDS = ("windows", "linux")
_CLASSES = {"windows": ("app.engines.windows", "WindowsEngine"), "linux": ("app.engines.linux", "LinuxEngine")}
_INSTANCES: Dict[str, object] = {}


def get_engine(os_id=None):
    """The engine with this id (an unknown or empty id gives the Windows engine, which is what every older saved investigation was made by)."""
    key = str(os_id or DEFAULT_OS).lower()
    if key not in _CLASSES:
        key = DEFAULT_OS
    if key not in _INSTANCES:
        module, name = _CLASSES[key]
        _INSTANCES[key] = getattr(importlib.import_module(module), name)()
    return _INSTANCES[key]


def all_engines() -> List[object]:
    return [get_engine(i) for i in OS_IDS]


def engine_for(result):
    return get_engine(getattr(result, "target_os", DEFAULT_OS))


def engine_for_settings(settings):
    return get_engine((settings or {}).get("target_os", DEFAULT_OS))
