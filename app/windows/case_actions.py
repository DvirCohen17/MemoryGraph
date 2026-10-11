"""Small GUI helpers shared by the views that let the investigator bookmark, annotate and triage."""
from __future__ import annotations

from typing import Optional

from PySide6.QtWidgets import QInputDialog, QWidget

from app.analysis import case_state


def find_dashboard(widget: Optional[QWidget]):
    """The DashboardWindow above ``widget`` (anything offering ``case_changed``), or None when used standalone."""
    while widget is not None:
        if hasattr(widget, "case_changed") and hasattr(widget, "triage_changed"):
            return widget
        widget = widget.parent() if hasattr(widget, "parent") else None
    return None


def notify_case_changed(widget: Optional[QWidget]) -> None:
    dashboard = find_dashboard(widget)
    if dashboard is not None:
        dashboard.case_changed()


def notify_triage_changed(widget: Optional[QWidget]) -> None:
    dashboard = find_dashboard(widget)
    if dashboard is not None:
        dashboard.triage_changed()


def toggle_bookmark(widget: QWidget, result, kind: str, target: str, label: str, pid: int = 0) -> bool:
    now = case_state.toggle_bookmark(result, kind, target, label, pid)
    notify_case_changed(widget)
    return now


def ask_and_add_note(widget: QWidget, result, kind: str, target: str, label: str, pid: int = 0) -> Optional[dict]:
    text, ok = QInputDialog.getMultiLineText(widget, "Add note", f"Note for {label}:")
    if not ok or not text.strip():
        return None
    note = case_state.add_note(result, kind, target, label, text, pid)
    notify_case_changed(widget)
    return note
