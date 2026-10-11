"""Locations used by MemoryGraph for settings, logs and the plugin-output cache."""
from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """The folder that holds ``app/`` and ``tools/`` (the source tree; where drop-in tools such as tools/volatility2 live)."""
    return Path(__file__).resolve().parent.parent


def app_dir() -> Path:
    """Per-user application data directory (created on demand)."""
    override = os.environ.get("MEMORYGRAPH_HOME")
    base = Path(override) if override else Path.home() / ".memorygraph"
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fall back to a temp-like location so the app still starts on read-only profiles.
        import tempfile
        base = Path(tempfile.gettempdir()) / "memorygraph"
        base.mkdir(parents=True, exist_ok=True)
    return base


def log_dir() -> Path:
    path = app_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def cache_dir() -> Path:
    path = app_dir() / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


def settings_path() -> Path:
    return app_dir() / "settings.json"
