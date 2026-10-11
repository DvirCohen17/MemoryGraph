"""Settings: appearance, Volatility 3 / 2, which plugin bundles to run, your indicators, performance.

A list on the left, one page on the right. Plugins are ticked as *bundles* (Processes, Network connections, Kernel integrity, ...), not one by one:
every bundle shows the plugins behind it, and the settings keys it writes are the same as before (see ``plugin_registry.apply_bundles``).
MemoryGraph never connects to the internet; the only network-looking setting is the folder of local symbol files for Volatility 3.
"""
from __future__ import annotations

from typing import Dict, List

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QFrame, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget,
    QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QVBoxLayout, QWidget,
)

from app.analysis import ioc as ioc_module, plugin_cache
from app.analysis.registry_core import Bundle
from app.engines import engine_for_settings
from app.analysis import plugin_timing
from app.analysis.volatility_runner import check_tool, compatibility_report, find_volatility
from app.errors import safe_slot
from app.paths import log_dir
from app.settings import save_settings, sanitize
from app.tasks import BackgroundTask
from app.theme import MAX_FONT_PT, MIN_FONT_PT, get_theme_style
from app.windows import motion
from app.windows.widgets import muted, show_info

_PAGES = ("Appearance", "Volatility", "Plugins", "Indicators", "Performance")
_PAGE_HINTS = (
    "Text size, window layout and how results are presented.",
    "The analysis tools MemoryGraph runs, and where their symbol files are. Nothing here connects to the internet.",
    "Which groups of plugins run on an image: more evidence costs more time.",
    "Your own lists of known-bad IPs, domains, hashes and rules, kept apart from the built-in rules.",
    "How many plugins run at once, when to give up on a stuck one, and the cache.",
)


def _small(text: str, tip: str = "") -> QPushButton:
    button = QPushButton(text)
    button.setObjectName("Small")
    if tip:
        button.setToolTip(tip)
    return button


def _path_row(edit: QLineEdit, *buttons: QPushButton) -> QHBoxLayout:
    row = QHBoxLayout()
    row.setSpacing(8)
    row.addWidget(edit, 1)
    for button in buttons:
        row.addWidget(button)
    return row


def member_summary(bundle: Bundle, registry) -> str:
    """The plugins behind a bundle, short: ``pslist · psscan · registry keys (Run, ...)``."""
    names: List[str] = []
    keys = False
    for name in bundle.members:
        spec = registry.get(name)
        if spec.plugin == "windows.registry.printkey":
            keys = True
            continue
        short = spec.volatility_plugin.replace("windows.malware.", "").replace("windows.registry.", "").replace("windows.", "")
        if short not in names:
            names.append(short)
    if keys:
        names.append("registry keys (Run, Winlogon, IFEO, AppInit, Active Setup, services)")
    return " · ".join(names)


class SettingsWindow(QWidget):
    """The settings *page*: it is shown inside the main window (in its page stack), not in a window of its own. ``done(applied)`` is emitted by Apply / Cancel / Esc;
    the main window then goes back to the page it came from."""

    done = Signal(bool)

    def __init__(self, parent=None):
        super().__init__()              # no Qt parent: the main window puts the page into its stack
        self.setWindowTitle("MemoryGraph Settings")
        self.setMinimumSize(640, 440)
        self.parent_window = parent
        self.settings = sanitize(getattr(parent, "settings", {}) or {})
        self.engine = engine_for_settings(self.settings)            # the operating system picked on the start window: its plugin groups, its words, its pages
        self.registry = self.engine.plugin_registry()
        self.setWindowTitle(f"MemoryGraph Settings — {self.engine.label}")
        self._test_task = None
        self._vol2_task = None
        self.look_changed = False        # True after Apply when theme or font size changed (views are rebuilt by the caller)
        self.scrolls: List[QScrollArea] = []
        self.checkboxes: Dict[str, QCheckBox] = {}
        self.bundle_boxes: Dict[str, QCheckBox] = {}
        self._bundle_touched: Dict[str, bool] = {}

        # the frame: a sidebar like the dashboard's on the left; on the right a page header, the page, and a footer bar with the buttons
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(232)
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(16, 24, 16, 18)
        side_layout.setSpacing(4)
        back = QPushButton("← Back")
        back.setToolTip("Go back without saving (Esc)")
        back.clicked.connect(self.reject)
        side_layout.addWidget(back)
        side_layout.addSpacing(14)
        brand = QLabel("Settings")
        brand.setObjectName("Brand")
        side_layout.addWidget(brand)
        chip = QLabel(f"{self.engine.label.upper()} PROFILE")
        chip.setObjectName("Eyebrow")
        side_layout.addWidget(chip)
        side_layout.addSpacing(14)
        self.nav = QListWidget()
        self.nav.setObjectName("SettingsNav")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.nav.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        side_layout.addWidget(self.nav, 1)
        side_layout.addWidget(muted("The plugin groups and symbol folders are for the operating system chosen on the start window; everything else is shared.", wrap=True))
        root.addWidget(side)

        right = QVBoxLayout()
        right.setContentsMargins(32, 26, 28, 20)
        right.setSpacing(10)
        self.page_title = QLabel("")
        self.page_title.setObjectName("Title")
        self.page_title.setStyleSheet("font-size: 20pt;")
        right.addWidget(self.page_title)
        self.page_subtitle = muted("")
        right.addWidget(self.page_subtitle)
        self.stack = motion.AnimatedStack()
        right.addWidget(self.stack, 1)
        builders = (self._page_appearance, self._page_volatility, self._page_plugins, self._page_indicators, self._page_performance)
        for name, build in zip(_PAGES, builders):
            self.nav.addItem(name)
            self.stack.addWidget(self._scroll_page(build()))
        self.nav.currentRowChanged.connect(self._show_page)
        self.nav.setCurrentRow(0)
        self.scroll = self.scrolls[0]

        line = QFrame()
        line.setObjectName("Separator")
        right.addWidget(line)
        buttons = QHBoxLayout()
        buttons.setSpacing(10)
        buttons.addWidget(muted("Esc goes back without saving.", wrap=False))
        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        apply_button = QPushButton("Apply and close")
        apply_button.setObjectName("Primary")
        apply_button.setDefault(True)
        apply_button.clicked.connect(self.apply_and_close)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(apply_button)
        right.addLayout(buttons)
        root.addLayout(right, 1)

    def accept(self) -> None:
        self.done.emit(True)

    def reject(self) -> None:
        self.done.emit(False)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.reject()
            return
        super().keyPressEvent(event)

    @safe_slot
    def _show_page(self, row: int, *_):
        if 0 <= row < len(_PAGES):
            self.stack.setCurrentIndex(row)
            self.page_title.setText(_PAGES[row])
            self.page_subtitle.setText(_PAGE_HINTS[row])

    # ------------------------------------------------------------------ pages
    def _scroll_page(self, page: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setWidget(page)
        self.scrolls.append(scroll)
        return scroll

    @staticmethod
    def _page(*groups: QWidget) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 12, 6)
        layout.setSpacing(16)
        for group in groups:
            layout.addWidget(group)
        layout.addStretch()
        return page

    def _page_appearance(self) -> QWidget:
        look = QGroupBox("Look")
        form = QFormLayout(look)
        form.setVerticalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.font_size = QSpinBox()
        self.font_size.setFixedWidth(150)
        self.font_size.setRange(MIN_FONT_PT, MAX_FONT_PT)
        self.font_size.setSuffix(" pt")
        self.font_size.setValue(int(self.settings["font_size"]))
        form.addRow("Font size", self.font_size)
        self.remember_layout = QCheckBox("Remember window sizes")
        self.remember_layout.setChecked(bool(self.settings["remember_layout"]))
        reset_layout = _small("Reset saved layout")
        reset_layout.clicked.connect(self.reset_layout)
        row = QHBoxLayout()
        row.addWidget(self.remember_layout, 1)
        row.addWidget(reset_layout)
        form.addRow(row)

        results = QGroupBox("Results")
        box = QVBoxLayout(results)
        box.setSpacing(8)
        for key, text, hint in (
            ("reanalyze_on_load", "Re-analyse when loading", "Saved investigations are checked again with the current rules, so improvements apply to old work."),
            ("preserve_plugin_output", "Keep the original plugin output", "Saved investigations keep Volatility's own rows (needed to re-analyse them later)."),
            ("show_evidence_provenance", "Show evidence provenance", "Findings say which plugin and row each piece of evidence came from."),
            ("group_process_duplicates", "Group repeated sibling processes", "Ten identical svchost-style siblings in the process tree are shown as one line."),
        ):
            check = QCheckBox(text)
            check.setChecked(bool(self.settings[key]))
            self.checkboxes[key] = check
            box.addWidget(check)
            tip = muted(hint)
            tip.setContentsMargins(26, 0, 0, 2)
            box.addWidget(tip)
        return self._page(look, results)

    def _page_volatility(self) -> QWidget:
        vol3 = QGroupBox("Volatility 3 — the main engine")
        layout = QVBoxLayout(vol3)
        layout.setSpacing(8)
        self.vol_path = QLineEdit(self.settings["volatility_path"])
        self.vol_path.setPlaceholderText("Leave empty to find it automatically (this Python environment, then PATH)")
        browse, test = _small("Browse…"), _small("Test")
        browse.clicked.connect(self.browse_volatility)
        test.clicked.connect(self.test_volatility)
        layout.addLayout(_path_row(self.vol_path, browse, test))
        self.test_result = muted("")
        layout.addWidget(self.test_result)
        layout.addWidget(muted("Symbol folders: " + self.engine.terms.symbols_hint))
        self.symbol_dirs = QLineEdit("; ".join(self.settings.get("symbol_dirs") or []))
        self.symbol_dirs.setPlaceholderText("Extra symbol folders (ISF .json / .json.xz files), separated by ;")
        add_dir = _small("Add folder…")
        add_dir.clicked.connect(self.add_symbol_dir)
        layout.addLayout(_path_row(self.symbol_dirs, add_dir))

        if not self.engine.capabilities.legacy_network_engine:
            return self._page(vol3)
        from app.engines.windows.analysis import vol2_runner
        vol2 = QGroupBox("Volatility 2 — network connections of Windows XP / 2003")
        layout2 = QVBoxLayout(vol2)
        layout2.setSpacing(8)
        layout2.addWidget(muted("Volatility 3 cannot read the network tables of Windows XP and 2003. With Volatility 2 set up, those images get their connections from it "
                                "automatically: the profile is chosen from the image itself. Use the standalone .exe, or vol.py (needs Python 2.7)."))
        self.vol2_path = QLineEdit(self.settings.get("vol2_path", ""))
        self.vol2_path.setPlaceholderText(f"Volatility 2 .exe or vol.py — empty: look in {vol2_runner.BUNDLED_DIR}")
        browse2, test2 = _small("Browse…"), _small("Test")
        browse2.clicked.connect(self.browse_vol2)
        test2.clicked.connect(self.test_vol2)
        layout2.addLayout(_path_row(self.vol2_path, browse2, test2))
        self.python2_path = QLineEdit(self.settings.get("python2_path", ""))
        self.python2_path.setPlaceholderText("Python 2.7 (only for vol.py) — empty: look for py -2 / python2")
        browse_py = _small("Browse…")
        browse_py.clicked.connect(self.browse_python2)
        layout2.addLayout(_path_row(self.python2_path, browse_py))
        self.vol2_deep = QCheckBox("Deep scan (connscan, sockscan)")
        self.vol2_deep.setChecked(bool(self.settings.get("vol2_deep_scan")))
        layout2.addWidget(self.vol2_deep)
        deep_hint = muted("Also finds closed and hidden connections, but scans the whole image: it takes minutes. Off: only the list walks "
                          "(connections, sockets), which take seconds.")
        deep_hint.setContentsMargins(26, 0, 0, 0)
        layout2.addWidget(deep_hint)
        self.vol2_result = muted("")
        layout2.addWidget(self.vol2_result)
        return self._page(vol3, vol2)

    def _page_plugins(self) -> QWidget:
        intro = QGroupBox("What to run")
        layout = QVBoxLayout(intro)
        layout.setSpacing(10)
        layout.addWidget(muted("Each tick runs a group of related plugins. Plugins that do not exist for the image's operating system version are skipped with a reason, "
                               "not reported as failures."))
        presets = QHBoxLayout()
        presets.addWidget(muted("Presets:", wrap=False))
        for text, tip, handler in (
                ("Quick triage", "Processes, network connections, and injected code / modules: the first look, in a fraction of the time of a full run. "
                                 "Run the other groups later from the dashboard (Run more plugins).", self.preset_quick),
                ("Recommended", "The defaults: everything that is usually worth the time.", self.preset_default),
                ("Everything", "Every group, including the slow ones.", self.preset_all)):
            button = _small(text)
            button.setToolTip(tip)
            button.clicked.connect(handler)
            presets.addWidget(button)
        presets.addStretch()
        layout.addLayout(presets)
        self.estimate_label = muted("")
        layout.addWidget(self.estimate_label)
        for bundle in self.registry.BUNDLES:
            layout.addWidget(self._bundle_row(bundle))
        yara = QHBoxLayout()
        self.yara_path = QLineEdit(self.settings.get("yara_rules_file", ""))
        self.yara_path.setPlaceholderText("YARA rule file for the YARA scan (.yar) — matches become IOC-006 findings")
        browse = _small("Browse…")
        browse.clicked.connect(self.browse_yara)
        layout.addLayout(_path_row(self.yara_path, browse))
        return self._page(intro)

    def _set_bundles(self, wanted) -> None:
        """Tick exactly the bundles ``wanted`` (the always-on ones stay on) and say how long that takes on an image of the usual size."""
        for bundle_id, box in self.bundle_boxes.items():
            bundle = next(b for b in self.registry.BUNDLES if b.id == bundle_id)
            if not bundle.locked:
                box.setChecked(bundle_id in wanted)
            self._bundle_touched[bundle_id] = True
        names = [name for b in self.registry.BUNDLES if b.id in wanted or b.locked for name in b.members]
        gb = 4.0
        self.estimate_label.setText(f"{len(names)} plugins; on a {gb:.0f} GB image about "
                                    f"{plugin_timing.describe(plugin_timing.estimate_total(names, int(gb * 1024 ** 3), 3))} with 3 plugins at a time (from earlier runs on this computer).")

    @safe_slot
    def preset_quick(self, *_):
        self._set_bundles({"network", "memory"})

    @safe_slot
    def preset_default(self, *_):
        self._set_bundles({b.id for b in self.registry.BUNDLES if b.default})

    @safe_slot
    def preset_all(self, *_):
        self._set_bundles({b.id for b in self.registry.BUNDLES})

    def _bundle_row(self, bundle: Bundle) -> QFrame:
        state = self.registry.bundle_state(bundle, self.settings)
        row = QFrame()
        row.setObjectName("BundleRow")
        box = QVBoxLayout(row)
        box.setContentsMargins(12, 10, 12, 10)
        box.setSpacing(3)
        check = QCheckBox(bundle.title + ("   (always on)" if bundle.locked else ""))
        check.setChecked(state == "on" or bundle.locked)
        check.setEnabled(not bundle.locked)
        check.toggled.connect(lambda _on, b=bundle.id: self._bundle_touched.__setitem__(b, True))
        self.bundle_boxes[bundle.id] = check
        box.addWidget(check)
        for text in (bundle.description, member_summary(bundle, self.registry) + (f" — {bundle.warning}" if bundle.warning else "")):
            label = muted(text)
            label.setContentsMargins(26, 0, 0, 0)
            box.addWidget(label)
        if state == "partial":
            note = muted("Some of these plugins are on and some off (from an earlier settings file). They stay as they are until you tick or untick this group.")
            note.setContentsMargins(26, 0, 0, 0)
            box.addWidget(note)
        return row

    def _page_indicators(self) -> QWidget:
        iocs = QGroupBox("Your IOC lists")
        layout = QVBoxLayout(iocs)
        layout.setSpacing(8)
        layout.addWidget(muted("Your own indicators, kept apart from the built-in rules: matches appear as IOC-* findings and never change the behavioural "
                               "rules or their scores. Lists are local files: text, STIX 2 or MISP."))
        self.ioc_list = QPlainTextEdit("\n".join(self.settings.get("ioc_files", [])))
        self.ioc_list.setPlaceholderText("One list file per line. Inside a list: IPs / CIDR, domains, MD5/SHA-1/SHA-256, mutex:, file:  (# comments)")
        self.ioc_list.setMinimumHeight(110)
        layout.addWidget(self.ioc_list)
        buttons = QHBoxLayout()
        add = _small("Add list…")
        add.clicked.connect(self.add_ioc_file)
        make = _small("Make YARA rules from this list…", "Search your domains, IP addresses and mutex names in process memory (windows.vadyarascan)")
        make.clicked.connect(self.make_yara_from_iocs)
        buttons.addWidget(add)
        buttons.addWidget(make)
        buttons.addStretch()
        layout.addLayout(buttons)
        return self._page(iocs)

    def _page_performance(self) -> QWidget:
        perf = QGroupBox("Speed and limits")
        form = QFormLayout(perf)
        form.setVerticalSpacing(12)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.parallel = QSpinBox()
        self.parallel.setFixedWidth(150)
        self.parallel.setRange(1, 8)
        self.parallel.setValue(int(self.settings["parallel_plugins"]))
        form.addRow("Plugins in parallel", self.parallel)
        self.idle = QSpinBox()
        self.idle.setFixedWidth(150)
        self.idle.setRange(1, 1440)
        self.idle.setSuffix(" min")
        self.idle.setValue(max(1, int(self.settings["idle_timeout_seconds"]) // 60))
        form.addRow("Stop a plugin after no activity for", self.idle)

        cache = QGroupBox("Cache and logs")
        box = QVBoxLayout(cache)
        box.setSpacing(8)
        self.use_cache = QCheckBox("Reuse finished plugin output")
        self.use_cache.setChecked(bool(self.settings["use_cache"]))
        box.addWidget(self.use_cache)
        cache_hint = muted("A second run of the same dump skips plugins that already finished: much faster re-runs.")
        cache_hint.setContentsMargins(26, 0, 0, 0)
        box.addWidget(cache_hint)
        row = QHBoxLayout()
        self.cache_label = QLabel(self._cache_text())
        clear = _small("Clear cache")
        clear.clicked.connect(self.clear_cache)
        logs = _small("Open log folder")
        logs.clicked.connect(self.open_logs)
        row.addWidget(self.cache_label, 1)
        row.addWidget(clear)
        row.addWidget(logs)
        box.addLayout(row)
        return self._page(perf, cache)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _cache_text() -> str:
        size = plugin_cache.size_bytes()
        return f"Cache size: {size / (1024 * 1024):.1f} MB"

    @safe_slot
    def clear_cache(self, *_):
        removed = plugin_cache.clear()
        self.cache_label.setText(f"Cleared {removed} cached plugin result(s). " + self._cache_text())

    @safe_slot
    def open_logs(self, *_):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(log_dir())))

    @safe_slot
    def add_symbol_dir(self, *_):
        path = QFileDialog.getExistingDirectory(self, "Folder with Volatility symbol files")
        if path:
            current = self.symbol_dirs.text().strip()
            self.symbol_dirs.setText((current + "; " if current else "") + path)

    @safe_slot
    def make_yara_from_iocs(self, *_):
        """Write a YARA file that finds the IOC list's domains / IPs / mutex names in memory, and use it for windows.vadyarascan."""
        files = [line.strip().strip('"') for line in self.ioc_list.toPlainText().splitlines() if line.strip()]
        iocs, problems = ioc_module.load_from_settings({"ioc_files": files})
        text, count = ioc_module.yara_rules_from_iocs(iocs) if iocs else ("", 0)
        if not count:
            message = "The IOC lists contain no domains, single IP addresses or mutex names to search for in memory."
            show_info(self, "YARA rules from IOC list", message + ("\n\n" + "\n".join(problems[:5]) if problems else ""))
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save YARA rules", "memorygraph_ioc.yar", "YARA rules (*.yar *.yara)")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        self.yara_path.setText(path)
        show_info(self, "YARA rules from IOC list",
                  f"{count} string(s) written to:\n{path}\n\nIt is now the YARA rule file for the YARA scan. Tick \"YARA scan of process memory\" under "
                  "Plugins (it is slow and needs yara-python); a match becomes an IOC-006 finding. Regenerate the file after changing the IOC lists.")

    @safe_slot
    def browse_yara(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Select YARA rule file", "", "YARA rules (*.yar *.yara);;All files (*)")
        if path:
            self.yara_path.setText(path)

    @safe_slot
    def add_ioc_file(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Select IOC list", "", "Text files (*.txt *.csv *.ioc *.json);;All files (*)")
        if path:
            current = self.ioc_list.toPlainText().strip()
            self.ioc_list.setPlainText((current + "\n" if current else "") + path)

    @safe_slot
    def browse_volatility(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Select Volatility 3 (vol / vol.exe / vol.py)", "", "All files (*)")
        if path:
            self.vol_path.setText(path)

    @safe_slot
    def browse_vol2(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Select Volatility 2 (standalone .exe or vol.py)", "", "Volatility 2 (*.exe *.py);;All files (*)")
        if path:
            self.vol2_path.setText(path)

    @safe_slot
    def browse_python2(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Select Python 2.7 (python.exe)", "", "Programs (*.exe);;All files (*)")
        if path:
            self.python2_path.setText(path)

    @safe_slot
    def test_volatility(self, *_):
        if self._test_task is not None and self._test_task.running:
            return
        path = self.vol_path.text().strip()
        self.test_result.setText("Testing… (starting Volatility can take up to a minute the first time)")

        def work(_ctx):
            tool = check_tool(find_volatility(path))
            provider = self.engine.make_provider({})
            wanted = {"|".join(self.registry.get(n).volatility_names) for n in provider.CORE_PLUGINS + provider.EXTENDED_PLUGINS + provider.OPTIONAL_PLUGINS}
            return compatibility_report(tool, sorted(wanted))

        task = BackgroundTask(work, self)
        task.finished.connect(self._test_ok)
        task.failed.connect(self._test_failed)
        self._test_task = task
        task.start()

    @safe_slot
    def _test_ok(self, text):
        self.test_result.setText(str(text))

    @safe_slot
    def _test_failed(self, message, _details):
        self.test_result.setText("✖ " + message)

    @safe_slot
    def test_vol2(self, *_):
        if self._vol2_task is not None and self._vol2_task.running:
            return
        path, python2 = self.vol2_path.text().strip(), self.python2_path.text().strip()
        self.vol2_result.setText("Testing…")

        def work(_ctx):
            from app.engines.windows.analysis import vol2_runner
            tool = vol2_runner.find_vol2(path, python2)
            if tool is None:
                return "Nothing is set and nothing was found in tools/volatility2: Windows XP / 2003 images will have no network connections."
            tool = vol2_runner.check_vol2(tool)
            return f"✔ Volatility {tool.version} found: {tool.description}"

        task = BackgroundTask(work, self)
        task.finished.connect(lambda text: self.vol2_result.setText(str(text)))
        task.failed.connect(lambda message, _d: self.vol2_result.setText("✖ " + message))
        self._vol2_task = task
        task.start()

    @safe_slot
    def apply_and_close(self, *_):
        previous_look = (self.settings.get("theme"), self.settings.get("font_size"))
        self.settings["theme"] = "Dark"
        self.settings["font_size"] = self.font_size.value()
        self.settings["remember_layout"] = self.remember_layout.isChecked()
        self.settings["volatility_path"] = self.vol_path.text().strip()
        self.settings["symbol_dirs"] = [d.strip() for d in self.symbol_dirs.text().split(";") if d.strip()]
        if hasattr(self, "vol2_path"):                              # the Volatility 2 box exists only for engines that use it (Windows)
            self.settings["vol2_path"] = self.vol2_path.text().strip()
            self.settings["python2_path"] = self.python2_path.text().strip()
            self.settings["vol2_deep_scan"] = self.vol2_deep.isChecked()
        self.registry.apply_bundles(self.settings, {
            bundle_id: ("on" if box.isChecked() else "off") if self._bundle_touched.get(bundle_id) or self.registry.bundle_state(
                next(b for b in self.registry.BUNDLES if b.id == bundle_id), self.settings) != "partial" else "keep"
            for bundle_id, box in self.bundle_boxes.items()})
        self.settings["yara_rules_file"] = self.yara_path.text().strip()
        self.settings["ioc_files"] = [line.strip().strip('"') for line in self.ioc_list.toPlainText().splitlines() if line.strip()]
        self.settings["parallel_plugins"] = self.parallel.value()
        self.settings["idle_timeout_seconds"] = self.idle.value() * 60
        self.settings["use_cache"] = self.use_cache.isChecked()
        for key, box in self.checkboxes.items():
            self.settings[key] = box.isChecked()
        self.settings = sanitize(self.settings)
        style = get_theme_style(self.settings["theme"], self.settings["font_size"])
        app = QApplication.instance()
        if app is not None:
            app.setStyleSheet(style)
        if self.parent_window is not None:
            self.parent_window.settings = dict(self.settings)
        save_settings(self.settings)
        self.look_changed = previous_look != (self.settings["theme"], self.settings["font_size"])
        self.accept()

    @safe_slot
    def reset_layout(self, *_):
        self.settings["layout"] = {}
        if self.parent_window is not None:
            self.parent_window.settings["layout"] = {}
        save_settings(self.settings)
        self.look_changed = False
