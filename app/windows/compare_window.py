"""Compare: this investigation against another saved investigation (another memory image, the same system earlier, or a clean machine).

"New" is in this investigation only, "gone" in the reference only. Differences are leads, not verdicts: the view says what changed,
not whether it is malicious. To compare with another memory image, analyse it first and use Save Investigation on it.
"""
from __future__ import annotations

from typing import Dict, Optional

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from app.engines.windows.analysis import compare as compare_module
from app.engines.windows.analysis.compare import SECTIONS, Comparison
from app.errors import safe_slot
from app.models import AnalysisResult, load_analysis_result
from app.tasks import BackgroundTask
from app.windows.widgets import FlowLayout, TableModel, compact_combo, make_table, muted, show_error, show_info

_CHANGE_COLORS = {"new": "#e0a030", "gone": "#8a97a8", "changed": "#4f9dff"}
_CHANGE_LABELS = {"new": "NEW", "gone": "gone", "changed": "changed"}


class CompareView(QWidget):
    def __init__(self, result: AnalysisResult, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self.reference: Optional[AnalysisResult] = None
        self.reference_path = ""
        self.comparison: Optional[Comparison] = None
        self._task: Optional[BackgroundTask] = None
        self._views: Dict[str, tuple] = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Compare")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Compare this investigation with another saved investigation: a later or earlier image of the same system, or a clean "
                               "machine. “New” is only in this one, “gone” only in the other. Differences are leads, not verdicts. To compare with "
                               "another memory image, analyse it first and use Save Investigation."))
        bar = FlowLayout()
        self.choose_button = QPushButton("Choose reference investigation…")
        self.choose_button.setObjectName("Primary")
        self.mode = QComboBox()
        self.mode.addItem("Match: automatic", "")
        self.mode.addItem("Same boot (image name + start time)", compare_module.SAME_BOOT)
        self.mode.addItem("Different boot or system (image name + path)", compare_module.DIFFERENT)
        compact_combo(self.mode, 34)
        self.hide_system = QCheckBox("Hide modules in Windows / Program Files")
        self.hide_system.setChecked(True)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(180)
        self.export_button = QPushButton("Export differences (CSV)…")
        self.export_button.setEnabled(False)
        for widget in (self.choose_button, self.mode, self.hide_system, self.search, self.export_button):
            bar.addWidget(widget)
        layout.addLayout(bar)
        self.summary = muted("No reference chosen yet.")
        layout.addWidget(self.summary)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)
        self._build_tabs()

        self.choose_button.clicked.connect(self.choose_reference)
        self.mode.currentIndexChanged.connect(self.recompare)
        self.hide_system.toggled.connect(self.apply_filters)
        self.search.textChanged.connect(self.apply_filters)
        self.export_button.clicked.connect(self.export_csv)

    # ------------------------------------------------------------------ tabs
    def _build_tabs(self) -> None:
        self.tabs.clear()
        self._views = {}
        for section in SECTIONS:
            page = QWidget()
            box = QVBoxLayout(page)
            note = muted("")
            box.addWidget(note)
            model = TableModel(["Change", "Item", "Detail", "PID"], [])
            view, proxy = make_table(model, [90, 380, 640, 70])
            view.doubleClicked.connect(lambda index, p=proxy: self._open(p.payload_at(index)))
            box.addWidget(view, 1)
            self.tabs.addTab(page, section)
            self._views[section] = (model, view, proxy, note)

    # ------------------------------------------------------------------ loading
    @safe_slot
    def choose_reference(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Reference investigation", "", "MemoryGraph investigation (*.json *.json.gz *.gz);;All files (*)")
        if path:
            self.load_reference(path)

    def load_reference(self, path: str) -> None:
        if self._task is not None and self._task.running:
            return
        self.status.setText("Reading the reference investigation…")
        task = BackgroundTask(lambda ctx: load_analysis_result(path), self)
        task.finished.connect(lambda reference, p=path: self._loaded(p, reference))
        task.failed.connect(self._load_failed)
        self._task = task
        task.start()

    @safe_slot
    def _loaded(self, path: str, reference: AnalysisResult) -> None:
        self.reference, self.reference_path = reference, path
        self.status.setText("")
        self.recompare()

    @safe_slot
    def _load_failed(self, message, details) -> None:
        self.status.setText("")
        show_error(self, "Reference investigation", f"The file could not be opened as an investigation.\n\n{message}", details)

    def set_reference(self, reference: AnalysisResult, path: str = "") -> None:
        """Use an investigation that is already in memory (used by tests and callers that have one)."""
        self.reference, self.reference_path = reference, path
        self.recompare()

    # ------------------------------------------------------------------ comparison
    @safe_slot
    def recompare(self, *_):
        if self.reference is None:
            return
        self.comparison = compare_module.compare(self.result, self.reference, self.mode.currentData() or "")
        self.export_button.setEnabled(True)
        counts = self.comparison.counts()
        parts = [f"{section}: {c['new']} new, {c['gone']} gone" + (f", {c['changed']} changed" if c["changed"] else "") for section, c in counts.items()
                 if section != "Memory" or self.comparison.mode == compare_module.SAME_BOOT]
        self.summary.setText(f"This investigation: {self.comparison.current_label}\nReference: {self.comparison.reference_label}\n"
                             + " · ".join(parts) + "\n" + " ".join(self.comparison.notes))
        for section in SECTIONS:
            model, _view, _proxy, note = self._views[section]
            tab = SECTIONS.index(section)
            c = counts.get(section, {"new": 0, "gone": 0, "changed": 0})
            self.tabs.setTabText(tab, f"{section} ({c['new'] + c['gone'] + c['changed']})")
            extra = self.comparison.truncated.get(section)
            note.setText((f"Only the first {compare_module.MAX_ROWS_PER_SECTION:,} rows are shown ({extra:,} more): export the CSV for all of them." if extra else "")
                         + (" Memory regions are compared only when both images are from the same boot." if section == "Memory" and self.comparison.mode != compare_module.SAME_BOOT else ""))
        self.apply_filters()

    @safe_slot
    def apply_filters(self, *_):
        if self.comparison is None:
            return
        hide = self.hide_system.isChecked()
        words = self.search.text().lower().split()
        shown = 0
        for section in SECTIONS:
            model, view, proxy, _note = self._views[section]
            rows = [r for r in self.comparison.rows.get(section, [])
                    if not (hide and r.trusted) and all(w in f"{r.item} {r.detail}".lower() for w in words)]
            new_model = TableModel(["Change", "Item", "Detail", "PID"],
                                   [[_CHANGE_LABELS[r.change], r.item, r.detail, r.pid or ""] for r in rows], payloads=rows,
                                   colors={n: _CHANGE_COLORS[r.change] for n, r in enumerate(rows) if r.change != "gone"})
            proxy.setSourceModel(new_model)
            self._views[section] = (new_model, view, proxy, self._views[section][3])
            shown += len(rows)
        self.status.setText(f"{shown:,} difference(s) shown. Double-click a process, module, connection or finding of this investigation to open its process.")

    @safe_slot
    def _open(self, row) -> None:
        if row is not None and row.pid and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(int(row.pid))

    @safe_slot
    def export_csv(self, *_):
        if self.comparison is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export differences", "comparison.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            count = compare_module.export_csv(self.comparison, path)
        except OSError as exc:
            show_error(self, "Export differences", f"The file could not be written.\n\n{exc}")
            return
        show_info(self, "Export differences", f"{count:,} difference(s) written to:\n{path}")
