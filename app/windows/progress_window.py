"""Analysis / loading progress page with a per-plugin status table, cancel, and a recoverable failure state."""
from __future__ import annotations

import time
from typing import Dict

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit, QProgressBar, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QAbstractItemView,
)

from app.errors import safe_slot
from app.windows import motion

STATE_STYLE = {
    "queued": ("·", "#76859a", "queued"), "running": ("▶", "#4b91ff", "running"), "progress": ("▶", "#4b91ff", "running"),
    "done": ("✔", "#2ec4a6", "done"), "cached": ("⚡", "#cf9a00", "cached"), "failed": ("✖", "#ff5c6c", "failed"), "skipped": ("—", "#76859a", "not for this Windows"),
}


class ProgressWindow(QWidget):
    cancel_requested = Signal()
    back_requested = Signal()
    retry_requested = Signal()

    def __init__(self, dump_path: str = ""):
        super().__init__()
        self.setWindowTitle("MemoryGraph — Analysis")
        self.dump_path = dump_path
        self.home = None
        self._rows: Dict[str, int] = {}
        self._started: Dict[str, float] = {}
        self._failed = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(60, 40, 60, 30)
        layout.setSpacing(8)
        self.title = QLabel("Analyzing Memory Dump")
        self.title.setObjectName("Title")
        layout.addWidget(self.title)
        self.dump = QLabel(dump_path)
        self.dump.setObjectName("Muted")
        self.dump.setWordWrap(True)
        layout.addWidget(self.dump)
        self.status = QLabel("Initializing…")
        self.status.setObjectName("SectionTitle")
        layout.addWidget(self.status)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setMinimumHeight(18)
        layout.addWidget(self.bar)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Plugin", "Status", "Details"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 220)
        self.table.setColumnWidth(1, 110)
        layout.addWidget(self.table, 1)

        self.message = QLabel("")
        self.message.setObjectName("Error")
        self.message.setWordWrap(True)
        self.message.setVisible(False)
        layout.addWidget(self.message)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(140)
        self.details.setVisible(False)
        layout.addWidget(self.details)

        buttons = QHBoxLayout()
        self.cancel = QPushButton("Cancel analysis")
        self.cancel.setObjectName("Danger")
        self.retry = QPushButton("Try again")
        self.back = QPushButton("← Back")
        self.log_button = QPushButton("Show technical details")
        for button in (self.log_button, self.retry, self.back):
            button.setVisible(False)
        buttons.addWidget(self.cancel)
        buttons.addWidget(self.log_button)
        buttons.addStretch()
        buttons.addWidget(self.retry)
        buttons.addWidget(self.back)
        layout.addLayout(buttons)

        self.cancel.clicked.connect(self._on_cancel)
        self.retry.clicked.connect(self.retry_requested)
        self.back.clicked.connect(self.back_requested)
        self.log_button.clicked.connect(self._toggle_details)

        self._clock = QTimer(self)
        self._clock.setInterval(1000)
        self._clock.timeout.connect(self._tick)

    # ------------------------------------------------------------------ lifecycle
    def begin(self, title: str, dump_path: str, show_plugins: bool = True) -> None:
        self.title.setText(title)
        self.dump_path = dump_path
        self.dump.setText(dump_path)
        self.status.setText("Initializing…")
        self.bar.setValue(0)
        self.table.setRowCount(0)
        self.table.setVisible(show_plugins)
        self._rows.clear()
        self._started.clear()
        self._failed = False
        self.message.setVisible(False)
        self.details.setVisible(False)
        self.details.clear()
        self.cancel.setVisible(True)
        self.cancel.setEnabled(True)
        for button in (self.retry, self.back, self.log_button):
            button.setVisible(False)
        self._clock.start()

    def set_dump_path(self, dump_path: str) -> None:
        self.dump_path = dump_path
        self.dump.setText(dump_path)

    def set_home(self, home) -> None:
        self.home = home

    @safe_slot
    def update_progress(self, text, value):
        self.status.setText(text)
        motion.animate_value(self.bar, max(0, min(100, int(value))))

    @safe_slot
    def plugin_event(self, name, state, detail):
        row = self._rows.get(name)
        if row is None:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self._rows[name] = row
            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(""))
            self.table.setItem(row, 2, QTableWidgetItem(""))
        icon, color, label = STATE_STYLE.get(state, ("·", "#76859a", state))
        if state == "running":
            self._started[name] = time.monotonic()
        if state in ("done", "cached", "failed", "skipped"):
            self._started.pop(name, None)
        status_item = self.table.item(row, 1)
        status_item.setText(f"{icon} {label}")
        status_item.setForeground(QColor(color))
        if detail or state != "progress":
            self.table.item(row, 2).setText(detail)
        self.table.item(row, 2).setToolTip(detail)

    @safe_slot
    def _tick(self, *_):
        now = time.monotonic()
        for name, started in self._started.items():
            row = self._rows.get(name)
            if row is None:
                continue
            item = self.table.item(row, 1)
            item.setText(f"▶ running {int(now - started)}s")

    @safe_slot
    def _on_cancel(self, *_):
        self.cancel.setEnabled(False)
        self.status.setText("Cancelling… (stopping Volatility)")
        self.cancel_requested.emit()

    @safe_slot
    def _toggle_details(self, *_):
        self.details.setVisible(not self.details.isVisible())

    def finish_ok(self) -> None:
        self._clock.stop()
        self.status.setText("Analysis complete")
        self.bar.setValue(100)

    def show_failure(self, message: str, details: str = "") -> None:
        self._clock.stop()
        self._failed = True
        self.status.setText("Analysis failed")
        self.message.setText(message)
        self.message.setVisible(True)
        self.details.setPlainText(details or "No further technical details.")
        self.cancel.setVisible(False)
        for button in (self.retry, self.back, self.log_button):
            button.setVisible(True)

    def show_cancelled(self) -> None:
        self._clock.stop()
        self.status.setText("Analysis cancelled")
        self.message.setText("The analysis was cancelled. Finished plugins were cached, so a new run continues faster.")
        self.message.setVisible(True)
        self.cancel.setVisible(False)
        for button in (self.retry, self.back):
            button.setVisible(True)
        self.log_button.setVisible(False)
