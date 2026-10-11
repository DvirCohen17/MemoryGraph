"""Main window: home page -> progress page -> dashboard.

Fixes compared with the earlier version:
  * the dashboard is rebuilt for every result (the old code only swapped an attribute, so after
    loading a saved investigation a NEW analysis kept showing the OLD data),
  * one controller is created once and wired once (no stacked signal connections),
  * a failed or cancelled run leaves the progress page with Retry/Back instead of a dead end,
  * there is a way back from the dashboard to start another analysis,
  * saving and loading run in the background and every error is reported in a dialog.
"""
from __future__ import annotations

import os

from PySide6.QtCore import QEasingCurve, QPropertyAnimation, Qt
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QScrollArea, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

from app.analysis.controller import AnalysisController
from app.analysis.dump import validate_dump
from app.errors import MemoryGraphError, safe_slot, short_message
from app.logging_setup import get_logger
from app.models import NotAnInvestigationFile, save_analysis_result, sniff_investigation_file
from app.engines import OS_IDS, engine_for_settings, get_engine
from app.settings import load_settings, remember_recent, save_settings, switch_target_os
from app.tasks import BackgroundTask
from app.theme import get_theme_style
from app.windows import layout_state, motion, os_switch
from app.windows.os_switch import OsSwitch
from app.windows.progress_window import ProgressWindow
from app.windows.widgets import muted, show_error, show_info

log = get_logger("home")


class HomeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MemoryGraph")
        self.resize(1100, 760)
        self.setMinimumSize(760, 520)
        self.settings = load_settings()
        layout_state.restore_geometry(self.settings, "home", self)
        self.current_result = None
        self.dashboard_window = None
        self._settings_page = None
        self._settings_from = None
        self._save_task = None
        self._mode = "idle"            # idle | analysis | loading | rerun
        self._last_request = None

        self.controller = AnalysisController(self)
        self.progress_window = ProgressWindow()
        self.progress_window.set_home(self)

        self.stack = QStackedWidget(self)
        self.setCentralWidget(self.stack)
        self.home_page = self._build_home_page()
        self.stack.addWidget(self.home_page)
        self.stack.addWidget(self.progress_window)
        self.stack.setCurrentWidget(self.home_page)

        # wire the controller exactly once
        c, p = self.controller, self.progress_window
        c.progress.connect(p.update_progress)
        c.plugin_event.connect(p.plugin_event)
        c.finished.connect(self.on_finished)
        c.failed.connect(self.on_failed)
        c.cancelled.connect(self.on_cancelled)
        p.cancel_requested.connect(c.cancel)
        p.back_requested.connect(self.show_home)
        p.retry_requested.connect(self.retry_last)

    @property
    def engine(self):
        """The engine of the operating system picked with the switch (``settings["target_os"]``)."""
        return engine_for_settings(self.settings)

    # ------------------------------------------------------------------ home page
    def _build_home_page(self) -> QWidget:
        """The start page: a centred column in a scroll area. On a short window the page scrolls; no control is ever squeezed on top of another (each has a minimum height)."""
        scroll = QScrollArea()
        scroll.setObjectName("PageScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        content = QWidget()
        scroll.setWidget(content)
        outer = QHBoxLayout(content)
        outer.setContentsMargins(36, 22, 36, 30)
        outer.addStretch(1)
        column = QWidget()
        column.setMaximumWidth(980)
        column.setMinimumWidth(520)
        outer.addWidget(column, 12)
        outer.addStretch(1)
        root = QVBoxLayout(column)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(14)

        top = QHBoxLayout()
        brand = QLabel("MEMORYGRAPH")
        brand.setObjectName("Brand")
        top.addWidget(brand)
        top.addStretch()
        settings = QPushButton("⚙  Settings")
        settings.setObjectName("Small")
        settings.clicked.connect(self.show_settings)
        top.addWidget(settings)
        root.addLayout(top)
        root.addSpacing(10)

        self.os_switch = OsSwitch({i: get_engine(i).label for i in OS_IDS}, current=self.settings.get("target_os", "windows"))
        self.os_switch.changed.connect(self.on_os_changed)
        switch_row = QHBoxLayout()
        switch_row.addStretch()
        switch_row.addWidget(self.os_switch)
        switch_row.addStretch()
        root.addLayout(switch_row)
        self.title_label = QLabel()
        self.title_label.setObjectName("Title")
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title_label.setWordWrap(True)
        root.addWidget(self.title_label)
        self.subtitle_label = QLabel()
        self.subtitle_label.setObjectName("Subtitle")
        self.subtitle_label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.subtitle_label.setWordWrap(True)
        root.addWidget(self.subtitle_label)
        self.os_note = QLabel()
        self.os_note.setObjectName("Warning")
        self.os_note.setWordWrap(True)
        root.addWidget(self.os_note)

        card = QFrame()
        card.setObjectName("Card")
        self.dump_card = card
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(26, 22, 26, 24)
        card_layout.setSpacing(14)
        label = QLabel("MEMORY DUMP")
        label.setObjectName("Eyebrow")
        card_layout.addWidget(label)
        row = QHBoxLayout()
        row.setSpacing(10)
        self.path = QLineEdit()
        self.path.setMinimumHeight(40)
        self.path.setPlaceholderText(self.engine.terms.image_placeholder)
        self.path.returnPressed.connect(self.run_analysis)
        row.addWidget(self.path, 1)
        browse = QPushButton("📁  Browse")
        browse.setMinimumSize(124, 44)
        browse.clicked.connect(self.browse)
        row.addWidget(browse)
        card_layout.addLayout(row)
        self.run_button = QPushButton("RUN ANALYSIS")
        self.run_button.setObjectName("Primary")
        self.run_button.setMinimumHeight(50)
        self.run_button.clicked.connect(self.run_analysis)
        card_layout.addWidget(self.run_button)

        actions = QHBoxLayout()
        actions.setSpacing(10)
        self.save_button = QPushButton("💾  Save current")
        self.save_button.clicked.connect(self.save_current_analysis)
        load_button = QPushButton("📂  Load existing")
        load_button.clicked.connect(self.load_previous_analysis)
        self.resume_button = QPushButton("↩  Back to current investigation")
        self.resume_button.setVisible(False)
        self.resume_button.clicked.connect(self.resume_dashboard)
        for button in (self.save_button, load_button, self.resume_button):
            button.setMinimumHeight(42)
            actions.addWidget(button, 1)
        card_layout.addLayout(actions)
        self.demo_button = QPushButton("▶  Show a demo investigation (made-up data, to see how a result looks)")
        self.demo_button.setMinimumHeight(42)
        self.demo_button.clicked.connect(self.open_demo)
        card_layout.addWidget(self.demo_button)
        root.addWidget(card)

        recent_card = QFrame()
        recent_card.setObjectName("Card")
        self.recent_card = recent_card
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(26, 18, 26, 20)
        recent_layout.setSpacing(10)
        self.recent_label = QLabel("RECENT  ·  double-click to open")
        self.recent_label.setObjectName("Eyebrow")
        recent_layout.addWidget(self.recent_label)
        self.recent = QListWidget()
        self.recent.setMinimumHeight(96)
        self.recent.setMaximumHeight(210)
        self.recent.itemDoubleClicked.connect(self.open_recent)
        recent_layout.addWidget(self.recent)
        root.addWidget(recent_card)
        self._refresh_recent()
        self.apply_os_terms(animate=False)

        footer = muted("Select a dump to run the Volatility collection, normalize the evidence, evaluate the investigation rules and review the results.")
        footer.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        root.addWidget(footer)
        root.addStretch(1)
        self._entrance_targets = [self.os_switch, self.title_label, self.subtitle_label, card, recent_card]
        return scroll

    def showEvent(self, event) -> None:
        super().showEvent(event)
        if not getattr(self, "_entered", False):
            self._entered = True
            motion.stagger_in([w for w in self._entrance_targets if w.isVisible()], ms=360, step=90)

    @safe_slot
    def open_demo(self, *_):
        """Open the engine's demo investigation (made-up data in the shape of a real result), to see how a run looks without an image."""
        try:
            result = self.engine.demo_result()
        except MemoryGraphError as exc:
            show_error(self, "Demo investigation", exc.message)
            return
        self._mode = "demo"
        self.show_dashboard(result)

    @safe_slot
    def on_os_changed(self, os_id: str, *_):
        """The operating system was switched: swap the settings that belong to it, save, and change the words on this page."""
        switch_target_os(self.settings, os_id)
        save_settings(self.settings)
        self.apply_os_terms(animate=True)

    def apply_os_terms(self, animate: bool = True) -> None:
        """Title, hint, file filter and the "not written yet" note of the chosen operating system (the title and hint cross-fade)."""
        terms = self.engine.terms
        self.path.setPlaceholderText(terms.image_placeholder)
        self.os_note.setText(self.engine.status_note if not self.engine.implemented else "")
        self.os_note.setVisible(not self.engine.implemented)
        self.demo_button.setVisible(self.engine.capabilities.demo)
        for label, text in ((self.title_label, terms.title), (self.subtitle_label, terms.subtitle)):
            if label.text() == text:
                continue
            if animate and os_switch.ANIMATED and label.text():
                self._cross_fade(label, text)
            else:
                label.setText(text)

    def _cross_fade(self, label: QLabel, text: str) -> None:
        effect = QGraphicsOpacityEffect(label)
        label.setGraphicsEffect(effect)
        out = QPropertyAnimation(effect, b"opacity", label)
        out.setDuration(110)
        out.setStartValue(1.0)
        out.setEndValue(0.0)
        back = QPropertyAnimation(effect, b"opacity", label)
        back.setDuration(220)
        back.setStartValue(0.0)
        back.setEndValue(1.0)
        back.setEasingCurve(QEasingCurve.Type.OutCubic)
        out.finished.connect(lambda: (label.setText(text), back.start()))
        back.finished.connect(lambda: label.setGraphicsEffect(None))
        out.start()

    def _refresh_recent(self) -> None:
        self.recent.clear()
        for path in self.settings.get("recent_analyses", []):
            item = QListWidgetItem(f"📂  {path}")
            item.setData(Qt.ItemDataRole.UserRole, ("analysis", path))
            self.recent.addItem(item)
        for path in self.settings.get("recent_dumps", []):
            item = QListWidgetItem(f"🧠  {path}")
            item.setData(Qt.ItemDataRole.UserRole, ("dump", path))
            self.recent.addItem(item)
        has_any = self.recent.count() > 0
        self.recent.setVisible(has_any)
        self.recent_label.setVisible(has_any)

    def _remember(self, key: str, path: str) -> None:
        remember_recent(self.settings, key, path)
        save_settings(self.settings)
        self._refresh_recent()

    # ------------------------------------------------------------------ remembered window size
    def _page_key(self) -> str:
        return "dashboard" if self.dashboard_window is not None and self.stack.currentWidget() is self.dashboard_window else "home"

    def _save_page_geometry(self) -> None:
        layout_state.save_geometry(self.settings, self._page_key(), self)

    def _restore_page_geometry(self, key: str, width: int, height: int) -> None:
        if not layout_state.restore_geometry(self.settings, key, self):
            self.resize(width, height)

    # ------------------------------------------------------------------ navigation
    @safe_slot
    def show_home(self, *_):
        if self.controller.is_running:
            answer = QMessageBox.question(self, "Analysis running", "An analysis is still running. Cancel it and go back?")
            if answer != QMessageBox.StandardButton.Yes:
                return
            self.controller.cancel()
        self.resume_button.setVisible(self.current_result is not None)
        self._save_page_geometry()
        self.stack.setCurrentWidget(self.home_page)
        self._restore_page_geometry("home", 1050, 700)

    @safe_slot
    def resume_dashboard(self, *_):
        if self.dashboard_window is not None:
            self._save_page_geometry()
            self.stack.setCurrentWidget(self.dashboard_window)
            self._restore_page_geometry("dashboard", 1450, 900)

    @safe_slot
    def show_settings(self, *_):
        """Open the settings as a page of this window (not a pop-up); Apply, Cancel or Esc brings back the page you came from."""
        from app.windows.settings_window import SettingsWindow
        if getattr(self, "_settings_page", None) is not None:
            self.stack.setCurrentWidget(self._settings_page)
            return
        page = SettingsWindow(self)
        self._settings_page = page
        self._settings_from = self.stack.currentWidget()
        page.done.connect(self._close_settings)
        self.stack.addWidget(page)
        self.stack.setCurrentWidget(page)
        motion.fade_in(page, 240, start=0.0)
        page.nav.setFocus()

    @safe_slot
    def _close_settings(self, applied: bool = False, *_):
        page, came_from = getattr(self, "_settings_page", None), getattr(self, "_settings_from", None)
        if page is None:
            return
        self._settings_page = None
        if self.stack.currentWidget() is page:                       # (if an analysis finished meanwhile, the stack already shows something else: leave it)
            self.stack.setCurrentWidget(came_from if came_from is not None and self.stack.indexOf(came_from) >= 0 else self.home_page)
        self.stack.removeWidget(page)
        page.deleteLater()
        self.setStyleSheet(get_theme_style(self.settings.get("theme", "Dark"), self.settings.get("font_size", 10)))
        if applied and page.look_changed and self.dashboard_window is not None and hasattr(self.dashboard_window, "rebuild_views"):
            self.dashboard_window.rebuild_views()          # colours chosen inside the views follow the new font size

    @safe_slot
    def browse(self, *_):
        start = self.settings.get("last_dump_dir", "")
        path, _ = QFileDialog.getOpenFileName(self, "Select Memory Dump", start, self.engine.terms.image_filter)
        if path:
            self.path.setText(path)
            self.settings["last_dump_dir"] = os.path.dirname(path)

    # ------------------------------------------------------------------ analysis
    @safe_slot
    def run_analysis(self, *_):
        dump_path = self.path.text().strip().strip('"')
        try:
            dump_path = validate_dump(dump_path)
        except MemoryGraphError as exc:
            show_error(self, "Memory dump", exc.message)
            return
        self.start_analysis(dump_path)

    def start_analysis(self, dump_path: str) -> None:
        if self.controller.is_running:
            show_info(self, "Analysis running", "An analysis is already running. Cancel it first or wait until it finishes.")
            return
        self._mode = "analysis"
        self._last_request = ("analysis", dump_path)
        self._remember("recent_dumps", dump_path)
        self.progress_window.begin("Analyzing Memory Dump", dump_path)
        self.stack.setCurrentWidget(self.progress_window)
        if not self.controller.start(dump_path, self.settings):
            self.progress_window.show_failure("Could not start the analysis (another task is running).")

    @safe_slot
    def rerun_failed(self, *_):
        if self.current_result is None or self.controller.is_running:
            return
        self._mode = "rerun"
        self._last_request = ("rerun", None)
        self.progress_window.begin("Re-running failed plugins", self.current_result.dump_path)
        self.stack.setCurrentWidget(self.progress_window)
        self.controller.rerun_failed(self.current_result, self.settings)

    @safe_slot
    def run_plugins(self, names, view: str = "", *_):
        """Run plugins on the open investigation (for example windows.filescan from the Files view), then show ``view`` again."""
        if self.current_result is None or self.controller.is_running:
            return
        self._mode = "rerun"
        self._last_request = ("plugins", (list(names), view))
        self._open_view = view
        self.progress_window.begin("Running " + ", ".join(names), self.current_result.dump_path)
        self.stack.setCurrentWidget(self.progress_window)
        self.controller.run_plugins(self.current_result, self.settings, names)

    @safe_slot
    def retry_last(self, *_):
        if not self._last_request:
            self.show_home()
            return
        kind, argument = self._last_request
        if kind == "analysis":
            self.start_analysis(argument)
        elif kind == "load":
            self.load_analysis_file(argument)
        elif kind == "rerun":
            self.rerun_failed()
        elif kind == "plugins":
            self.run_plugins(*argument)

    # ------------------------------------------------------------------ results
    @safe_slot
    def on_finished(self, result):
        self.progress_window.finish_ok()
        if getattr(result, "target_os", "windows") in OS_IDS and result.target_os != self.settings.get("target_os"):
            self.os_switch.set_os(result.target_os)          # a saved investigation of the other operating system: the switch follows it (and so do the settings)
        self.show_dashboard(result)
        view, self._open_view = getattr(self, "_open_view", ""), ""
        if view and self.dashboard_window is not None and view in getattr(self.dashboard_window, "IDX", {}):
            self.dashboard_window.select_view(self.dashboard_window.IDX[view])

    @safe_slot
    def on_failed(self, message, details):
        log.error("Operation failed: %s", message)
        self.progress_window.show_failure(message, details)

    @safe_slot
    def on_cancelled(self, *_):
        self.progress_window.show_cancelled()

    def show_dashboard(self, result) -> None:
        """Always build a fresh dashboard for ``result`` (never reuse the previous investigation's view)."""
        from app.windows.dashboard_window import DashboardWindow
        self.current_result = result
        old = self.dashboard_window
        try:
            dashboard = DashboardWindow(result, home=self, settings=self.settings)
        except Exception as exc:  # noqa: BLE001
            log.exception("Dashboard construction failed")
            self.progress_window.show_failure(f"The results were produced but the dashboard could not be built: {short_message(exc)}", "")
            return
        self.dashboard_window = dashboard
        self.stack.addWidget(dashboard)
        self._save_page_geometry()
        self.stack.setCurrentWidget(dashboard)
        if old is not None:
            self.stack.removeWidget(old)
            old.deleteLater()
        self._restore_page_geometry("dashboard", 1450, 900)
        self.show()

    # ------------------------------------------------------------------ save / load
    @safe_slot
    def save_current_analysis(self, *_):
        if self.current_result is None:
            show_info(self, "Save Investigation", "Run or load an investigation before saving.")
            return
        if self._save_task is not None and self._save_task.running:
            return
        result = self.current_result
        base = os.path.splitext(os.path.basename(result.dump_path.replace("\\", "/")))[0] or "investigation"
        start = os.path.join(self.settings.get("last_analysis_dir", ""), f"{base}_analysis.json")
        file_name, _ = QFileDialog.getSaveFileName(self, "Save Investigation", start, "Investigation (*.json);;Compressed investigation (*.json.gz)")
        if not file_name:
            return
        if not file_name.lower().endswith((".json", ".gz")):
            file_name += ".json"
        self.save_button.setEnabled(False)
        self.setWindowTitle("MemoryGraph — saving…")
        task = BackgroundTask(lambda ctx: save_analysis_result(result, file_name), self)
        task.finished.connect(lambda path, f=file_name: self._save_done(f))
        task.failed.connect(self._save_failed)
        self._save_task = task
        task.start()

    @safe_slot
    def _save_done(self, file_name):
        self.save_button.setEnabled(True)
        self.setWindowTitle("MemoryGraph")
        self.settings["last_analysis_dir"] = os.path.dirname(file_name)
        if self.dashboard_window is not None and hasattr(self.dashboard_window, "clear_dirty"):
            self.dashboard_window.clear_dirty()
        self._remember("recent_analyses", file_name)
        show_info(self, "Save Investigation", f"Investigation saved to:\n{file_name}")

    @safe_slot
    def _save_failed(self, message, details):
        self.save_button.setEnabled(True)
        self.setWindowTitle("MemoryGraph")
        show_error(self, "Save Investigation", f"The investigation could not be saved.\n\n{message}", details)

    @safe_slot
    def load_previous_analysis(self, *_):
        start = self.settings.get("last_analysis_dir", "")
        file_name, _ = QFileDialog.getOpenFileName(self, "Load Existing Investigation", start,
                                                   "Investigation (*.json *.json.gz);;All Files (*)")
        if file_name:
            self.load_analysis_file(file_name)

    def load_analysis_file(self, file_name: str) -> None:
        if self.controller.is_running:
            show_info(self, "Busy", "Another task is running. Wait until it finishes.")
            return
        try:
            sniff_investigation_file(file_name)
        except NotAnInvestigationFile as exc:
            if exc.memory_image:
                answer = QMessageBox.question(
                    self, "This is a memory image",
                    f"{os.path.basename(file_name)} is a memory image, not a saved investigation.\n\n"
                    "'Load existing' opens the .json / .json.gz files MemoryGraph saves after an analysis.\n\nAnalyse this memory image now?")
                if answer == QMessageBox.StandardButton.Yes:
                    self.path.setText(file_name)
                    self.run_analysis()
            else:
                show_error(self, "Load Existing Investigation", str(exc))
            return
        except OSError as exc:
            show_error(self, "Load Existing Investigation", f"The file cannot be read:\n{file_name}\n\n{exc}")
            return
        self._mode = "loading"
        self._last_request = ("load", file_name)
        self._remember("recent_analyses", file_name)
        self.progress_window.begin("Loading Investigation", file_name, show_plugins=False)
        self.stack.setCurrentWidget(self.progress_window)
        self.controller.load(file_name, bool(self.settings.get("reanalyze_on_load", True)), self.settings)

    @safe_slot
    def open_recent(self, item, *_):
        data = item.data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        kind, path = data
        if kind == "analysis":
            if not os.path.isfile(path):
                show_error(self, "File not found", f"This investigation file no longer exists:\n{path}")
                return
            self.load_analysis_file(path)
        else:
            self.path.setText(path)

    # ------------------------------------------------------------------ shutdown
    def closeEvent(self, event):
        try:
            if self.controller.is_running:
                answer = QMessageBox.question(self, "Analysis running", "An analysis is still running. Cancel it and exit?")
                if answer != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
                self.controller.cancel()
            if getattr(self.dashboard_window, "case_dirty", False):
                answer = QMessageBox.question(
                    self, "Unsaved notes", "Your notes, bookmarks or triage decisions have not been saved with the investigation.\n\nExit anyway?")
                if answer != QMessageBox.StandardButton.Yes:
                    event.ignore()
                    return
            self._save_page_geometry()
            if self.dashboard_window is not None and hasattr(self.dashboard_window, "capture_layout"):
                self.dashboard_window.capture_layout()
            save_settings(self.settings)
        except Exception:  # noqa: BLE001 - never block closing the window
            log.exception("Error while closing")
        event.accept()
