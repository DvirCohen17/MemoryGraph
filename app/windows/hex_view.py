"""Hex view of one memory region: offsets and addresses, search, inspector and a disassembly of as many bytes as are loaded.

malfind keeps only the first 64 bytes of each region. "Load bytes from file…" opens the file ``windows.malfind --dump`` wrote for the
region (Process window → Dump malfind pages) and shows up to 2 MiB of it. Everything shown is computed from those bytes by
``app.analysis.hexview``; nothing is read from the memory image itself.
"""
from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QTextCursor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSpinBox, QSplitter,
    QTextEdit, QVBoxLayout, QWidget,
)

from app.analysis import case_state, hexview
from app.errors import safe_slot
from app.util import to_int
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import FlowLayout, TableModel, escape, make_table, muted, show_error

MATCH_COLOR = QColor(255, 196, 0, 70)
CURRENT_COLOR = QColor(255, 140, 0, 150)
INSTRUCTION_COLOR = QColor(80, 160, 255, 90)
MAX_HIGHLIGHTED_MATCHES = 2000


class HexViewDialog(QDialog):
    def __init__(self, region, process=None, parent=None, result=None, dump_dir: str = "", subject=None):
        """``subject`` (``{"title", "label", "target", "path"}``) turns the view into a plain file viewer (a file dumped by the Files
        view): addresses start at 0, the file is loaded at once and bookmarks / notes use ``target`` and ``label``."""
        super().__init__(parent)
        self.subject = subject
        self.region = region
        self.process = process
        self.result = result
        self.dump_dir = dump_dir
        self.base = 0 if subject else (to_int(region.start, 0) or 0)
        self.data = b""
        self.source = ""
        self._matches: List[tuple] = []
        self._current: Optional[tuple] = None
        self._instruction: Optional[tuple] = None
        self._cursor_offset = 0
        self.grid = hexview.Layout(self.base, 0)
        name = process.name if process else region.process
        self.setWindowTitle(f"Hex view — {subject['title']}" if subject else f"Hex view — {name} ({region.pid}) {region.range}")
        self.resize(1180, 740)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 14, 18, 12)
        title = QLabel(subject["title"] if subject else f"{name} (PID {region.pid}) — {region.range}")
        title.setObjectName("Title")
        root.addWidget(title)
        self.info = muted("")
        root.addWidget(self.info)

        bar = FlowLayout()
        self.load_button = QPushButton("Load bytes from file…")
        self.reset_button = QPushButton("Use malfind's bytes")
        self.arch = QComboBox()
        self.arch.addItem("64-bit code", 64)
        self.arch.addItem("32-bit code", 32)
        self.arch.setCurrentIndex(1 if process is not None and process.wow64 else 0)
        self.bookmark_button = QPushButton("☆ Bookmark region")
        self.note_button = QPushButton("✎ Add note…")
        for widget in (self.load_button, self.reset_button, self.arch, self.bookmark_button, self.note_button):
            bar.addWidget(widget)
        for button in (self.bookmark_button, self.note_button):
            button.setEnabled(result is not None)
        root.addLayout(bar)

        search = FlowLayout()
        self.search_mode = QComboBox()
        self.search_mode.addItem("Hex bytes (?? = any)", "hex")
        self.search_mode.addItem("Text (ASCII)", "ascii")
        self.search_mode.addItem("Text (UTF-16)", "utf16")
        self.search_text = QLineEdit()
        self.search_text.setPlaceholderText("e.g. 4d 5a ?? 00   or   kernel32")
        self.search_text.setClearButtonEnabled(True)
        self.search_text.setMinimumWidth(220)
        self.ignore_case = QCheckBox("Ignore case")
        self.ignore_case.setEnabled(False)
        self.find_next_button = QPushButton("Find next")
        self.find_previous_button = QPushButton("Find previous")
        self.goto_text = QLineEdit()
        self.goto_text.setPlaceholderText("Go to address or offset")
        self.goto_text.setMinimumWidth(170)
        self.goto_button = QPushButton("Go")
        for widget in (self.search_mode, self.search_text, self.ignore_case, self.find_next_button, self.find_previous_button,
                       self.goto_text, self.goto_button):
            search.addWidget(widget)
        root.addLayout(search)
        self.search_status = muted("", wrap=False)
        root.addWidget(self.search_status)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.hex_text = QPlainTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.hex_text.setStyleSheet("QPlainTextEdit{font-family:Consolas,'Courier New',monospace;}")
        splitter.addWidget(self.hex_text)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        dis_bar = FlowLayout()
        self.count = QSpinBox()
        self.count.setRange(10, 5000)
        self.count.setValue(200)
        self.count.setSuffix(" instructions")
        self.from_cursor_button = QPushButton("Disassemble from cursor")
        self.from_start_button = QPushButton("From start")
        for widget in (self.count, self.from_cursor_button, self.from_start_button):
            dis_bar.addWidget(widget)
        right_layout.addLayout(dis_bar)
        self.dis_status = muted("", wrap=False)
        right_layout.addWidget(self.dis_status)
        self.dis_model = TableModel(["Address", "Bytes", "Instruction"], [])
        self.dis_view, self.dis_proxy = make_table(self.dis_model, [130, 120, 210])
        self.dis_view.setSortingEnabled(False)                  # instructions stay in address order
        self.dis_view.horizontalHeader().setSortIndicatorShown(False)
        self.dis_proxy.sort(-1)
        right_layout.addWidget(self.dis_view, 1)
        splitter.addWidget(right)
        splitter.setSizes([700, 480])
        root.addWidget(splitter, 1)

        self.inspector = muted("", wrap=False)
        self.inspector.setStyleSheet("font-family:Consolas,'Courier New',monospace;")
        root.addWidget(self.inspector)
        self.note_info = muted("")
        root.addWidget(self.note_info)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        root.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)

        self.load_button.clicked.connect(self.load_file)
        self.reset_button.clicked.connect(self.use_malfind_bytes)
        self.arch.currentIndexChanged.connect(self.disassemble_from_start)
        self.search_mode.currentIndexChanged.connect(self._mode_changed)
        self.search_text.returnPressed.connect(self.find_next)
        self.find_next_button.clicked.connect(self.find_next)
        self.find_previous_button.clicked.connect(self.find_previous)
        self.goto_text.returnPressed.connect(self.go_to)
        self.goto_button.clicked.connect(self.go_to)
        self.from_cursor_button.clicked.connect(self.disassemble_from_cursor)
        self.from_start_button.clicked.connect(self.disassemble_from_start)
        self.hex_text.cursorPositionChanged.connect(self._cursor_moved)
        self.dis_view.selectionModel().currentRowChanged.connect(self._instruction_selected)
        self.bookmark_button.clicked.connect(self.toggle_region_bookmark)
        self.note_button.clicked.connect(self.add_region_note)

        if subject:
            self.reset_button.setVisible(False)
            if not self.load_path(subject["path"]):
                self._set_data(b"", subject["path"], 0)
        else:
            self.use_malfind_bytes()

    # ------------------------------------------------------------------ data
    def _set_data(self, data: bytes, source: str, total: int) -> None:
        self.data = data
        self.source = source
        self.grid = hexview.Layout(self.base, len(data))
        self.hex_text.setPlainText(hexview.format_dump(data, self.base) or "(malfind stored no bytes for this region)")
        self._matches, self._current, self._instruction, self._cursor_offset = [], None, None, 0
        self._apply_highlights()
        size = f"{len(data):,} byte(s)"
        if total > len(data):
            size += f" of {total:,} (only the first {len(data):,} are loaded)"
        self.info.setText((f"{self.region.protection} · {self.region.tag or 'no tag'} · " if not self.subject else "") + f"{size} from {escape(source)}. "
                          + ("malfind keeps only the first 64 bytes of a region: use “Dump malfind pages” in the Process window, then "
                             "“Load bytes from file…”, to see more." if source == "malfind" else ""))
        self.search_status.setText("")
        self.disassemble_from_start()
        self._refresh_marks()
        self._cursor_moved()

    @safe_slot
    def use_malfind_bytes(self, *_):
        data = hexview.region_bytes(self.region)
        self._set_data(data, "malfind", len(data))

    @safe_slot
    def load_file(self, *_):
        start = to_int(self.region.start)
        end = to_int(self.region.end)
        found = hexview.find_dump_file(self.dump_dir, self.region.pid, start, end) if start is not None and end is not None else None
        path, _ = QFileDialog.getOpenFileName(self, "Load the bytes of this region", found or self.dump_dir,
                                              "Region dumps (*.dmp *.bin);;All files (*)")
        if not path:
            return
        self.load_path(path)

    def load_path(self, path: str) -> bool:
        try:
            data, size = hexview.read_file(path)
        except OSError as exc:
            show_error(self, "Load bytes", f"The file could not be read.\n\n{exc}")
            return False
        self._set_data(data, path, size)
        return True

    # ------------------------------------------------------------------ highlighting
    def _range_selections(self, offset: int, length: int, color: QColor) -> list:
        selections = []
        document = self.hex_text.document()
        last = min(offset + max(length, 1), len(self.data)) - 1
        for line in range(self.grid.line_of(offset), self.grid.line_of(last) + 1):
            block = document.findBlockByNumber(line)
            if not block.isValid():
                break
            first = max(offset, line * self.grid.width)
            final = min(last, line * self.grid.width + self.grid.width - 1)
            for start_col, end_col in ((self.grid.hex_column(first), self.grid.hex_column(final) + 2),
                                       (self.grid.ascii_column(first), self.grid.ascii_column(final) + 1)):
                cursor = QTextCursor(block)
                cursor.setPosition(block.position() + start_col)
                cursor.setPosition(block.position() + end_col, QTextCursor.MoveMode.KeepAnchor)
                selection = QTextEdit.ExtraSelection()
                selection.cursor = cursor
                selection.format.setBackground(color)
                selections.append(selection)
        return selections

    def _apply_highlights(self) -> None:
        selections = []
        if self.data:
            for offset, length in self._matches[:MAX_HIGHLIGHTED_MATCHES]:
                selections += self._range_selections(offset, length, MATCH_COLOR)
            if self._instruction is not None:
                selections += self._range_selections(*self._instruction, INSTRUCTION_COLOR)
            if self._current is not None:
                selections += self._range_selections(*self._current, CURRENT_COLOR)
        self.hex_text.setExtraSelections(selections)

    def _goto(self, offset: int) -> None:
        if not 0 <= offset < len(self.data):
            return
        block = self.hex_text.document().findBlockByNumber(self.grid.line_of(offset))
        if not block.isValid():
            return
        cursor = QTextCursor(block)
        cursor.setPosition(block.position() + self.grid.hex_column(offset))
        self.hex_text.setTextCursor(cursor)
        self.hex_text.ensureCursorVisible()

    @safe_slot
    def _cursor_moved(self, *_):
        cursor = self.hex_text.textCursor()
        offset = self.grid.offset_at(cursor.blockNumber(), cursor.positionInBlock())
        if offset is not None:
            self._cursor_offset = offset
            self.inspector.setText(f"{self.base + offset:#x}   " + hexview.inspect_at(self.data, offset))

    # ------------------------------------------------------------------ search / go to
    @safe_slot
    def _mode_changed(self, *_):
        self.ignore_case.setEnabled(self.search_mode.currentData() != "hex")

    def _pattern(self):
        try:
            return hexview.compile_pattern(self.search_text.text().strip(), self.search_mode.currentData(), self.ignore_case.isChecked())
        except ValueError as exc:
            self.search_status.setText(str(exc))
            return None

    def _show_hit(self, hit, pattern) -> None:
        if hit is None:
            self._matches, self._current = [], None
            self.search_status.setText("No match in the loaded bytes.")
        else:
            self._matches = [(m.start(), m.end() - m.start()) for _i, m in zip(range(MAX_HIGHLIGHTED_MATCHES), pattern.finditer(self.data))]
            self._current = hit
            total = hexview.count_matches(self.data, pattern)
            self.search_status.setText(f"Match at {self.base + hit[0]:#x} (offset {hit[0]:#x}, {hit[1]} byte(s)) · "
                                       f"{total}{'+' if total >= 10000 else ''} match(es) in the loaded bytes")
            self._goto(hit[0])
        self._apply_highlights()

    @safe_slot
    def find_next(self, *_):
        pattern = self._pattern()
        if pattern is not None and self.data:
            start = self._current[0] + 1 if self._current else self._cursor_offset
            self._show_hit(hexview.find_next(self.data, pattern, start), pattern)

    @safe_slot
    def find_previous(self, *_):
        pattern = self._pattern()
        if pattern is not None and self.data:
            before = self._current[0] if self._current else self._cursor_offset
            self._show_hit(hexview.find_previous(self.data, pattern, before), pattern)

    @safe_slot
    def go_to(self, *_):
        value = to_int(self.goto_text.text().strip())
        if value is None:
            self.search_status.setText("Enter an address (0x7ff…) or an offset inside the loaded bytes.")
            return
        offset = value - self.base if value >= self.base else value
        if not 0 <= offset < len(self.data):
            self.search_status.setText(f"{value:#x} is outside the loaded bytes ({self.base:#x} – {self.base + len(self.data) - 1:#x}).")
            return
        self.search_status.setText(f"Address {self.base + offset:#x} (offset {offset:#x})")
        self._goto(offset)

    # ------------------------------------------------------------------ disassembly
    def _disassemble(self, start: int) -> None:
        instructions, error = hexview.disassemble(self.data, self.base, self.arch.currentData(), start, self.count.value())
        rows = [[f"{i.address:#x}", i.raw.hex(" "), i.text] for i in instructions]
        self.dis_model = TableModel(["Address", "Bytes", "Instruction"], rows, payloads=list(instructions),
                                    colors={n: "#8a97a8" for n, i in enumerate(instructions) if not i.valid})
        self.dis_proxy.setSourceModel(self.dis_model)
        invalid = sum(1 for i in instructions if not i.valid)
        if error:
            self.dis_status.setText(error)
        elif not self.data:
            self.dis_status.setText("No bytes to disassemble.")
        else:
            self.dis_status.setText(f"{len(instructions)} instruction(s) from {self.base + start:#x}"
                                    + (f"; {invalid} undecodable byte(s) shown as db" if invalid else "")
                                    + ". Select a line to see its bytes in the dump.")

    @safe_slot
    def disassemble_from_start(self, *_):
        self._disassemble(0)

    @safe_slot
    def disassemble_from_cursor(self, *_):
        self._disassemble(self._cursor_offset)

    @safe_slot
    def _instruction_selected(self, *_):
        instruction = self.dis_proxy.payload_at(self.dis_view.currentIndex())
        if instruction is None:
            return
        self._instruction = (instruction.offset, len(instruction.raw))
        self._apply_highlights()
        self._goto(instruction.offset)

    # ------------------------------------------------------------------ bookmarks and notes
    def _target(self) -> str:
        if self.subject:
            return self.subject["target"]
        return case_state.region_target(self.process, self.region)

    def _label(self) -> str:
        if self.subject:
            return self.subject["label"][:140]
        name = self.process.name if self.process else self.region.process
        return f"Memory region {self.region.range} in {name} (PID {self.region.pid})"[:140]

    def _refresh_marks(self) -> None:
        if self.result is None:
            self.note_info.setText("Bookmarks and notes are available when the process is opened from an investigation.")
            return
        self.bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, self._target()) else "☆ Bookmark region")
        notes = case_state.notes_for(self.result, self._target())
        self.note_info.setText("Your notes: " + " · ".join(escape(n.get("text", "")) for n in notes) if notes else "No notes on this region.")

    @safe_slot
    def toggle_region_bookmark(self, *_):
        if self.result is not None:
            toggle_bookmark(self, self.result, "file" if self.subject else "memory", self._target(), self._label(), self.region.pid)
            self._refresh_marks()

    @safe_slot
    def add_region_note(self, *_):
        if self.result is not None and ask_and_add_note(self, self.result, "file" if self.subject else "memory", self._target(), self._label(), self.region.pid):
            self._refresh_marks()
