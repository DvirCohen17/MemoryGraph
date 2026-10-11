"""Raw plugin output: sortable table view for big plugins, terminal-style text view on demand."""
from __future__ import annotations

from typing import List

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextDocument
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton,
    QSplitter, QStackedWidget, QVBoxLayout, QWidget,
)

from app.analysis import case_state
from app.analysis.rows import flatten_rows
from app.errors import safe_slot
from app.theme import SEVERITY_COLORS
from app.util import to_int
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import TableModel, escape, make_table, muted

TEXT_CHUNK = 1500   # rows rendered per click in the text view (keeps the UI responsive)


class PluginOutputView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self._rows_cache = {}
        self._text_offset = 0
        self._current = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        title = QLabel("Plugin Output")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("The original Volatility output for every plugin. Use the table for sorting and filtering, or the text view for terminal-style reading."))

        splitter = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.plugins = QListWidget()
        self.plugins.setMinimumWidth(240)
        for plugin in result.plugins:
            suffix = {"Completed": "", "Failed": "  ✖ failed", "Skipped": "  — not for this Windows"}.get(plugin.status, f"  [{plugin.status}]")
            item = QListWidgetItem(f"{plugin.name}{suffix}")
            if plugin.failed:
                item.setForeground(QColor(SEVERITY_COLORS["High"]))
            elif plugin.skipped:
                item.setForeground(QColor("#8290a3"))
            self.plugins.addItem(item)
        left_layout.addWidget(self.plugins, 1)
        self.rerun_button = QPushButton("Re-run failed plugins")
        failed = [p for p in result.plugins if p.failed]
        self.rerun_button.setVisible(bool(failed))
        left_layout.addWidget(self.rerun_button)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.header = muted("", wrap=True)
        right_layout.addWidget(self.header)
        bar = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter rows…")
        self.filter.setClearButtonEnabled(True)
        bar.addWidget(self.filter, 1)
        self.text_mode = QCheckBox("Text view")
        bar.addWidget(self.text_mode)
        self.more = QPushButton("Load more rows")
        self.more.setVisible(False)
        bar.addWidget(self.more)
        right_layout.addLayout(bar)

        self.stack = QStackedWidget()
        self.table_holder = QWidget()
        self.table_layout = QVBoxLayout(self.table_holder)
        self.table_layout.setContentsMargins(0, 0, 0, 0)
        self.stack.addWidget(self.table_holder)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setStyleSheet("QPlainTextEdit { background:#080b0f; color:#d7e1ea; font-family: Consolas, 'Courier New', monospace; font-size: 10pt; border: 1px solid #253342; }")
        self.stack.addWidget(self.text)
        right_layout.addWidget(self.stack, 1)
        self.marks_bar = QWidget()
        marks = QHBoxLayout(self.marks_bar)
        marks.setContentsMargins(0, 0, 0, 0)
        self.bookmark_button = QPushButton("☆ Bookmark row")
        self.note_button = QPushButton("✎ Add note…")
        for button in (self.bookmark_button, self.note_button):
            button.setEnabled(False)
            marks.addWidget(button)
        self.note_info = muted("Select a row to bookmark it or add a note (listed in Case Notes).")
        marks.addWidget(self.note_info, 1)
        right_layout.addWidget(self.marks_bar)
        self.error_box = QPlainTextEdit()
        self.error_box.setReadOnly(True)
        self.error_box.setMaximumHeight(110)
        self.error_box.setVisible(False)
        right_layout.addWidget(self.error_box)
        splitter.addWidget(right)
        splitter.setSizes([300, 1000])
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter, 1)

        self.table_view = None
        self.table_proxy = None
        self.table_model = None
        self.bookmark_button.clicked.connect(self.toggle_bookmark_current)
        self.note_button.clicked.connect(self.add_note_current)
        self.plugins.currentRowChanged.connect(self.show_plugin)
        self.filter.textChanged.connect(self.apply_filter)
        self.text_mode.toggled.connect(self.toggle_mode)
        self.more.clicked.connect(self.load_more_text)
        self.rerun_button.clicked.connect(self.rerun_failed)
        if result.plugins:
            self.plugins.setCurrentRow(0)

    def _rows(self, index: int) -> list:
        if index not in self._rows_cache:
            self._rows_cache[index] = [r for r in flatten_rows(self.result.plugins[index].rows) if r is not None]
        return self._rows_cache[index]

    @safe_slot
    def show_plugin(self, index):
        if index < 0 or index >= len(self.result.plugins):
            return
        plugin = self.result.plugins[index]
        self._current = index
        rows = self._rows(index)
        info = f"{plugin.name} — {plugin.status}"
        if plugin.cached:
            info += " (from cache)"
        if plugin.duration:
            info += f" — {plugin.duration:.0f}s"
        info += f" — {len(rows)} rows"
        if plugin.command:
            info += f"\n{' '.join(plugin.command)}"
        self.header.setText(info)
        message = plugin.error.strip() if plugin.error else ""
        self.error_box.setVisible(bool(message))
        self.error_box.setPlainText(message)
        self._build_table(rows, plugin)
        self._text_offset = 0
        self.text.clear()
        self.load_more_text()
        self.apply_filter()

    def _build_table(self, rows: list, plugin) -> None:
        if self.table_view is not None:
            self.table_layout.removeWidget(self.table_view)
            self.table_view.deleteLater()
            self.table_view = None
        columns: List[str] = []
        for row in rows[:300]:
            if isinstance(row, dict):
                for key in row:
                    if key not in columns and key != "__children":
                        columns.append(key)
        pseudo = False
        if not columns:
            columns = ["Output"]
            pseudo = bool(plugin.raw_output or not rows)
            rows = [{"Output": plugin.raw_output.strip() or "<No output returned>"}] if pseudo else rows
        table_rows = []
        for row in rows:
            if isinstance(row, dict):
                table_rows.append([""] + [_cell(row.get(c)) for c in columns])
            else:
                table_rows.append([""] + [str(row)] + [""] * (len(columns) - 1))
        payloads = [None if (pseudo or not isinstance(row, dict)) else (plugin.name, row) for row in rows]
        self.table_model = TableModel(["Marks"] + columns, table_rows, payloads=payloads)
        self._fill_marks(plugin.name)
        self.table_view, self.table_proxy = make_table(self.table_model, [50] + [140] * len(columns))
        self.table_layout.addWidget(self.table_view)
        self.table_view.selectionModel().currentRowChanged.connect(self.on_row_selected)
        self.on_row_selected()

    # -- bookmarks and notes on rows
    def _marked_targets(self, plugin_name: str) -> set:
        case = case_state.ensure_case(self.result)
        prefix = f"row|{plugin_name}|"
        return {t for t in list(case["bookmarks"]) + [n.get("target", "") for n in case["notes"]] if str(t).startswith(prefix)}

    def _fill_marks(self, plugin_name: str) -> None:
        """Put ★/✎ in the first column. Rows are only hashed when this plugin has marks at all (big plugins have tens of thousands of rows)."""
        marked = self._marked_targets(plugin_name)
        for number, payload in enumerate(self.table_model.payloads):
            text = ""
            if marked and payload is not None:
                starred, noted = case_state.has_marks(self.result, case_state.plugin_row_target(*payload))
                text = ("★" if starred else "") + ("✎" if noted else "")
            self.table_model.rows[number][0] = text

    def _refresh_marks(self) -> None:
        if self._current is None or self.table_model is None or not self.table_model.rows:
            return
        self._fill_marks(self.result.plugins[self._current].name)
        self.table_model.dataChanged.emit(self.table_model.index(0, 0), self.table_model.index(len(self.table_model.rows) - 1, 0))
        self.on_row_selected()

    def _current_row(self):
        return self.table_proxy.payload_at(self.table_view.currentIndex()) if self.table_proxy is not None else None

    @staticmethod
    def _row_label(plugin_name: str, row: dict) -> str:
        summary = " ".join(str(v)[:40] for v in list(row.values())[:3] if v not in (None, "", []) and not isinstance(v, (list, dict)))
        return f"{plugin_name}: {summary}"[:140]

    @safe_slot
    def on_row_selected(self, *_):
        payload = self._current_row()
        self.bookmark_button.setEnabled(payload is not None)
        self.note_button.setEnabled(payload is not None)
        if payload is None:
            self.bookmark_button.setText("☆ Bookmark row")
            self.note_info.setText("Select a row to bookmark it or add a note (listed in Case Notes).")
            return
        target = case_state.plugin_row_target(*payload)
        self.bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, target) else "☆ Bookmark row")
        notes = case_state.notes_for(self.result, target)
        self.note_info.setText("Your notes: " + " · ".join(escape(n.get("text", "")) for n in notes) if notes else "No notes on this row.")

    @safe_slot
    def toggle_bookmark_current(self, *_):
        payload = self._current_row()
        if payload is not None:
            name, row = payload
            toggle_bookmark(self, self.result, "row", case_state.plugin_row_target(name, row), self._row_label(name, row), to_int(row.get("PID"), 0) or 0)
            self._refresh_marks()

    @safe_slot
    def add_note_current(self, *_):
        payload = self._current_row()
        if payload is not None:
            name, row = payload
            if ask_and_add_note(self, self.result, "row", case_state.plugin_row_target(name, row), self._row_label(name, row), to_int(row.get("PID"), 0) or 0):
                self._refresh_marks()

    # -- navigation from Case Notes
    def show_plugin_by_name(self, name: str) -> bool:
        for index, plugin in enumerate(self.result.plugins):
            if plugin.name == name:
                self.plugins.setCurrentRow(index)
                return True
        return False

    def select_row_target(self, target: str) -> bool:
        """Select (and scroll to) the row a bookmark or note refers to, in the plugin that is currently shown."""
        if self.table_model is None or self.table_proxy is None:
            return False
        self.filter.clear()
        for number, payload in enumerate(self.table_model.payloads):
            if payload is not None and case_state.plugin_row_target(*payload) == target:
                index = self.table_proxy.mapFromSource(self.table_model.index(number, 0))
                if index.isValid():
                    self.table_view.setCurrentIndex(index)
                    self.table_view.scrollTo(index)
                    return True
        return False

    @safe_slot
    def apply_filter(self, *_):
        if self.table_proxy is not None:
            self.table_proxy.set_text(self.filter.text())
        query = self.filter.text().strip()
        if self.text_mode.isChecked() and query:
            self.text.find(query)

    @safe_slot
    def toggle_mode(self, checked=False):
        self.stack.setCurrentIndex(1 if checked else 0)
        self.marks_bar.setVisible(not checked)
        self.more.setVisible(checked and self._current is not None and self._text_offset < len(self._rows(self._current)))

    @safe_slot
    def load_more_text(self, *_):
        if self._current is None:
            return
        rows = self._rows(self._current)
        chunk = rows[self._text_offset:self._text_offset + TEXT_CHUNK]
        lines = []
        for offset, row in enumerate(chunk, start=self._text_offset):
            lines.append(f"--- ROW {offset} {'-' * 72}")
            if isinstance(row, dict):
                for key, value in row.items():
                    lines.append(f"{str(key):<24} : {_cell(value)}")
            else:
                lines.append(str(row))
        if not rows and self.result.plugins[self._current].raw_output:
            lines.append(self.result.plugins[self._current].raw_output.strip())
        if lines:
            self.text.appendPlainText("\n".join(lines))
        self._text_offset += len(chunk)
        remaining = len(rows) - self._text_offset
        self.more.setVisible(self.text_mode.isChecked() and remaining > 0)
        self.more.setText(f"Load more rows ({remaining} left)")
        if not rows and not self.result.plugins[self._current].raw_output:
            self.text.setPlainText("<No output returned>")

    @safe_slot
    def rerun_failed(self, *_):
        if self.dashboard is not None and hasattr(self.dashboard, "rerun_failed"):
            self.dashboard.rerun_failed()


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, dict)):
        text = str(value)
    else:
        text = str(value)
    return text if len(text) <= 4000 else text[:4000] + " …"
