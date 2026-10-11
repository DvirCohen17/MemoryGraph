"""Remember window geometry and splitter positions between sessions (stored in the settings under ``layout``).

Only sizes are remembered, never data, and everything is optional: a missing or stale entry (different number of panels after an
update, a monitor that is gone) is ignored and the default layout is used. Switched off by Settings → "Remember window size and panel positions".
"""
from __future__ import annotations

from typing import Dict, List

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtWidgets import QHeaderView, QSplitter, QWidget


def _enabled(settings: dict) -> bool:
    return bool(settings.get("remember_layout", True))


def _section(settings: dict, name: str) -> Dict:
    layout = settings.get("layout")
    if not isinstance(layout, dict):
        layout = settings["layout"] = {}
    section = layout.get(name)
    if not isinstance(section, dict):
        section = layout[name] = {}
    return section


def save_geometry(settings: dict, key: str, widget: QWidget) -> None:
    if _enabled(settings):
        _section(settings, "windows")[key] = bytes(widget.saveGeometry().toBase64()).decode("ascii")


def restore_geometry(settings: dict, key: str, widget: QWidget) -> bool:
    """True when a saved geometry existed and was applied."""
    if not _enabled(settings):
        return False
    text = _section(settings, "windows").get(key)
    if not isinstance(text, str) or not text:
        return False
    return bool(widget.restoreGeometry(QByteArray.fromBase64(text.encode("ascii"))))


def _headers(view: QWidget) -> List[QHeaderView]:
    return [h for h in view.findChildren(QHeaderView) if h.orientation() == Qt.Orientation.Horizontal and h.count() > 0]


def capture_columns(settings: dict, view_key: str, view: QWidget) -> None:
    """Remember the column widths of every table/tree in a view (only the widths, never sort order or hidden columns)."""
    if not _enabled(settings):
        return
    headers = _headers(view)
    if headers:
        _section(settings, "columns")[view_key] = [[h.sectionSize(i) for i in range(h.count())] for h in headers]


def apply_columns(settings: dict, view_key: str, view: QWidget) -> None:
    if not _enabled(settings):
        return
    saved = _section(settings, "columns").get(view_key)
    headers = _headers(view)
    if not isinstance(saved, list) or len(saved) != len(headers):
        return
    for header, widths in zip(headers, saved):
        if isinstance(widths, list) and len(widths) == header.count():
            for index, width in enumerate(widths):
                if isinstance(width, int) and 20 <= width <= 3000:
                    header.resizeSection(index, width)


def capture_splitters(settings: dict, view_key: str, view: QWidget) -> None:
    if not _enabled(settings):
        return
    splitters = view.findChildren(QSplitter)
    if splitters:
        _section(settings, "splitters")[view_key] = [splitter.sizes() for splitter in splitters]


def apply_splitters(settings: dict, view_key: str, view: QWidget) -> None:
    if not _enabled(settings):
        return
    saved = _section(settings, "splitters").get(view_key)
    splitters = view.findChildren(QSplitter)
    if not isinstance(saved, list) or len(saved) != len(splitters):
        return
    for splitter, sizes in zip(splitters, saved):
        if isinstance(sizes, list) and len(sizes) == splitter.count() and all(isinstance(s, int) for s in sizes) and sum(sizes) > 0:
            splitter.setSizes(sizes)
