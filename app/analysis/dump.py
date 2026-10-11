"""Checks on the memory image file itself (the same for every operating system)."""
from __future__ import annotations

import os

from app.errors import DumpFileError


def validate_dump(path: str) -> str:
    """Return a cleaned path or raise :class:`DumpFileError` with a message a person can act on."""
    cleaned = (path or "").strip().strip('"')
    if not cleaned:
        raise DumpFileError("No memory dump was selected.")
    if os.path.isdir(cleaned):
        raise DumpFileError("The selected path is a folder. Choose the memory image file itself (.raw, .mem, .dmp, .vmem, .lime ...).")
    if not os.path.isfile(cleaned):
        raise DumpFileError(f"Memory dump not found:\n{cleaned}")
    try:
        size = os.path.getsize(cleaned)
        with open(cleaned, "rb") as handle:
            handle.read(16)
    except PermissionError as exc:
        raise DumpFileError(f"Permission denied while opening the memory dump:\n{cleaned}\n\nClose programs that lock the file or run MemoryGraph with access to it.") from exc
    except OSError as exc:
        raise DumpFileError(f"The memory dump cannot be read: {exc}") from exc
    if size == 0:
        raise DumpFileError("The memory dump file is empty (0 bytes).")
    if size < 1024 * 1024:
        raise DumpFileError(f"The file is only {size} bytes: too small to be a memory image.")
    return cleaned
