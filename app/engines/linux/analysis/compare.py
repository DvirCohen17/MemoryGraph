"""Linux: comparing two investigations (SKELETON). Windows compares processes, modules, connections, findings, memory regions and plugin rows section by section
(``app/engines/windows/analysis/compare.py``); Linux needs the same with its own plugin sections (kernel modules, sockets, ...)."""
from __future__ import annotations

from app.engines.linux._todo import todo


def compare(current, reference):
    return todo("compare")
