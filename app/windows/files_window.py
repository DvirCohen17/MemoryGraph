"""Files: the file objects ``windows.filescan`` found in memory, in an explorer-style window.

Folders and files are listed like in Windows Explorer: a folder tree on the left, the contents of the open folder on the right (subfolders first), back / forward /
up buttons and an address bar you can type a path into. Double-click a folder to open it. Selecting a file shows **only what is known about it** (path, volume,
where its FILE_OBJECT is, flags, who else refers to it, your notes): a file object in memory has no content until it is dumped. After **Dump**, the *Content* tab
shows what was recovered: hashes, type, PE structure, strings, and a hex view.

Dumping uses ``windows.dumpfiles`` (one Volatility run for all selected files). A file object only proves that the file was opened; whether its contents are still
in memory is known only after a dump.
"""
from __future__ import annotations

import os
from typing import Callable, Dict, List, Optional, Tuple, Union

from PySide6.QtCore import QItemSelectionModel, QTimer, Qt
from PySide6.QtGui import QGuiApplication, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QSplitter, QStackedWidget, QStyle, QTabWidget,
    QTextBrowser, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from app.analysis import case_state, ioc as ioc_module
from app.engines.windows.analysis import file_report
from app.engines.windows.analysis.dumper import VolatilityDumper
from app.engines.windows.analysis.fileindex import FileEntry, FileIndex, Folder, dump_files_for, entries_from_rows, flags_for, index_dump_dir
from app.analysis.volatility_runner import global_args
from app.errors import safe_slot
from app.settings import save_settings
from app.tasks import BackgroundTask
from app.util import norm_path
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import FlowLayout, TableModel, confirm, escape, make_table, muted, show_error, show_info

PLUGIN = "windows.filescan"
MAX_ROWS_SHOWN = 100000
MAX_DUMP_AT_ONCE = 500
COLUMNS = ["Mark", "Name", "Type", "Items", "Offset", "Flags", "Dumped", "Location"]
LOCATION_COLUMN = 7
_FLAG_COLOR = "#c77700"
Item = Union[FileEntry, Folder]


def _key(path: str) -> str:
    """Lower-case path without drive/device, comparable between filescan names, handle names and module paths."""
    text = norm_path(path)
    return text[2:] if len(text) > 2 and text[1] == ":" else text


class FilesView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self.index: Optional[FileIndex] = None
        self.location: Optional[Folder] = None
        self.history: List[Folder] = []
        self.history_pos = -1
        self.dump_dir = ""
        self.dumps: Dict[int, List[Tuple[str, str]]] = {}           # FILE_OBJECT address -> [(cache kind, path)]
        self.empty_dumps: set = set()                               # addresses dumped without any result (contents not in memory)
        self.reports: Dict[str, file_report.FileReport] = {}
        self._task: Optional[BackgroundTask] = None
        self._report_task: Optional[BackgroundTask] = None
        self._refs: Optional[Dict[str, List[str]]] = None
        self._iocs = None
        self._tree_items: Dict[int, QTreeWidgetItem] = {}
        self._tree_lock = False

        root = QVBoxLayout(self)
        root.setContentsMargins(25, 25, 25, 20)
        root.setSpacing(10)
        title = QLabel("Files")
        title.setObjectName("Title")
        root.addWidget(title)
        root.addWidget(muted("File objects found in memory by windows.filescan, browsed like Explorer. Selecting a file shows what is known about it; its content "
                             "is only available after you dump it."))
        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)
        self.stack.addWidget(self._empty_page())
        self.stack.addWidget(self._explorer_page())
        self.status = muted("", wrap=False)
        root.addWidget(self.status)
        self.reload()

    # ------------------------------------------------------------------ pages
    def _empty_page(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        self.empty_text = muted("")
        box.addWidget(self.empty_text)
        row = QHBoxLayout()
        self.run_button = QPushButton("Run windows.filescan now")
        self.run_button.setObjectName("Primary")
        self.run_button.clicked.connect(self.run_filescan)
        row.addWidget(self.run_button)
        row.addStretch()
        box.addLayout(row)
        box.addStretch()
        return page

    def _tool(self, icon: QStyle.StandardPixmap, tip: str) -> QToolButton:
        button = QToolButton()
        button.setObjectName("NavTool")
        button.setIcon(self.style().standardIcon(icon))
        button.setToolTip(tip)
        button.setAutoRaise(False)
        return button

    def _explorer_page(self) -> QWidget:
        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(0, 0, 0, 0)
        box.setSpacing(8)
        nav = QHBoxLayout()
        nav.setSpacing(6)
        self.back_button = self._tool(QStyle.StandardPixmap.SP_ArrowBack, "Back (Alt+Left)")
        self.forward_button = self._tool(QStyle.StandardPixmap.SP_ArrowForward, "Forward (Alt+Right)")
        self.up_button = self._tool(QStyle.StandardPixmap.SP_ArrowUp, "Up one level (Backspace)")
        self.address = QLineEdit()
        self.address.setPlaceholderText("Type a path such as \\Windows\\System32 and press Enter")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search this folder and below…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(180)
        self.search.setMaximumWidth(280)
        for widget in (self.back_button, self.forward_button, self.up_button):
            nav.addWidget(widget)
        nav.addWidget(self.address, 1)
        nav.addWidget(self.search)
        box.addLayout(nav)

        bar = FlowLayout()
        self.only_programs = QCheckBox("Programs and scripts only")
        self.only_flagged = QCheckBox("Flagged only")
        self.dump_button = QPushButton("Dump selected…")
        self.dump_button.setObjectName("Primary")
        self.dump_all_button = QPushButton("Dump all listed…")
        self.folder_button = QPushButton("Dump location…")
        self.folder_button.setToolTip("Choose the folder the dumped files are written to")
        for widget in (self.only_programs, self.only_flagged, self.dump_button, self.dump_all_button, self.folder_button):
            bar.addWidget(widget)
        box.addLayout(bar)
        self.dump_label = muted("", wrap=False)
        box.addWidget(self.dump_label)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Folders"])
        self.tree.setMinimumWidth(220)
        self.tree.setMinimumHeight(220)
        self.tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.splitter.addWidget(self.tree)
        right = QSplitter(Qt.Orientation.Vertical)
        self.model = TableModel(COLUMNS, [])
        self.view, self.proxy = make_table(self.model, [52, 260, 110, 110, 130, 220, 90, 320])
        # The list is ordered in Python when it is built (folders first, like Explorer); Qt's own sort only runs when a header is clicked.
        self.view.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.view.setMinimumHeight(240)                   # at least about eight rows of the folder
        right.addWidget(self.view)

        lower = QWidget()
        lower_box = QVBoxLayout(lower)
        lower_box.setContentsMargins(0, 0, 0, 0)
        actions = FlowLayout()
        self.dump_one_button = QPushButton("Dump this file…")
        self.hex_button = QPushButton("Open hex view")
        self.folder_open_button = QPushButton("Open dump folder")
        self.bookmark_button = QPushButton("☆ Bookmark")
        self.note_button = QPushButton("✎ Add note…")
        for widget in (self.dump_one_button, self.hex_button, self.folder_open_button, self.bookmark_button, self.note_button):
            actions.addWidget(widget)
        lower_box.addLayout(actions)
        self.tabs = QTabWidget()
        self.details = QTextBrowser()
        self.details.setMinimumHeight(150)
        self.tabs.addTab(self.details, "Properties")
        dumped = QSplitter(Qt.Orientation.Vertical)
        self.dumped_model = TableModel(["Cache", "File", "Size", "SHA-256"], [])
        self.dumped_view, self.dumped_proxy = make_table(self.dumped_model, [130, 330, 90, 520])
        self.dumped_view.setSortingEnabled(False)
        self.dumped_proxy.sort(-1)
        dumped.addWidget(self.dumped_view)
        self.report = QTextBrowser()
        dumped.addWidget(self.report)
        self.dumped_view.setMinimumHeight(90)
        dumped.setSizes([100, 340])
        dumped.setStretchFactor(1, 1)
        self.tabs.addTab(dumped, "Content (after dump)")
        lower_box.addWidget(self.tabs, 1)
        lower.setMinimumHeight(230)
        right.addWidget(lower)
        right.setSizes([380, 300])
        right.setStretchFactor(0, 3)
        right.setStretchFactor(1, 2)
        self.splitter.addWidget(right)
        self.splitter.setSizes([320, 900])
        self.splitter.setChildrenCollapsible(False)
        right.setChildrenCollapsible(False)
        box.addWidget(self.splitter, 1)

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(250)
        self._timer.timeout.connect(self.populate)
        self.search.textChanged.connect(lambda *_: self._timer.start())
        for check in (self.only_programs, self.only_flagged):
            check.toggled.connect(self.populate)
        self.tree.currentItemChanged.connect(self._tree_selected)
        self.view.selectionModel().selectionChanged.connect(self.selection_changed)
        self.view.selectionModel().currentRowChanged.connect(self.selection_changed)
        self.view.doubleClicked.connect(lambda index: self.open_item(self.proxy.payload_at(index)))
        self.view.customContextMenuRequested.connect(self._context_menu)
        self.dumped_view.selectionModel().currentRowChanged.connect(self.dumped_selected)
        self.back_button.clicked.connect(self.go_back)
        self.forward_button.clicked.connect(self.go_forward)
        self.up_button.clicked.connect(self.go_up)
        self.address.returnPressed.connect(self.address_entered)
        self.dump_button.clicked.connect(self.dump_selected)
        self.dump_one_button.clicked.connect(self.dump_selected)
        self.dump_all_button.clicked.connect(self.dump_all_shown)
        self.folder_button.clicked.connect(self.choose_dump_dir)
        self.hex_button.clicked.connect(self.open_hex)
        self.folder_open_button.clicked.connect(self.open_dump_folder)
        self.bookmark_button.clicked.connect(self.toggle_bookmark_current)
        self.note_button.clicked.connect(self.add_note_current)
        for keys, handler, widget in ((Qt.Key.Key_Backspace, self.go_up, self.view), (Qt.Key.Key_Return, self.open_current, self.view),
                                      (Qt.Key.Key_Enter, self.open_current, self.view), ("Alt+Left", self.go_back, self),
                                      ("Alt+Right", self.go_forward, self), ("Ctrl+L", self.focus_address, self), ("Ctrl+F", self.focus_search, self)):
            shortcut = QShortcut(QKeySequence(keys), widget)
            shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
            shortcut.activated.connect(handler)
        return page

    # ------------------------------------------------------------------ data
    def _settings(self) -> dict:
        dashboard = self.dashboard
        getter = getattr(dashboard, "live_settings", None)
        return getter() if callable(getter) else (getattr(dashboard, "settings", None) or {})

    def _plugin(self):
        return next((p for p in self.result.plugins if p.name == PLUGIN), None)

    @safe_slot
    def reload(self, *_):
        """(Re)build the view from the filescan result stored in the investigation."""
        plugin = self._plugin()
        self.run_button.setText("Run windows.filescan now")
        can_run = self.dashboard is not None and getattr(self.dashboard, "home", None) is not None and bool(self.result.dump_path)
        self.run_button.setEnabled(can_run)
        self.run_button.setToolTip("" if can_run else "Needs the memory image: open this view from an analysis that was started in MemoryGraph.")
        if plugin is None:
            self.empty_text.setText("windows.filescan has not been run for this investigation. It lists the file objects in memory (slow on big "
                                    "images, and the output is large). You can also tick \"Files and objects\" under Settings → Plugins to run it with every analysis.")
            self.stack.setCurrentIndex(0)
            return
        if plugin.status != "Completed":
            message = ((plugin.error or "").strip().splitlines() or ["no details"])[-1]
            self.empty_text.setText(f"windows.filescan did not complete: {message}\n\nRunning it again may help (see Plugin Output for the full message).")
            self.run_button.setText("Run windows.filescan again")
            self.stack.setCurrentIndex(0)
            return
        self.index = FileIndex(entries_from_rows(plugin.rows))
        self._refs = None
        self.stack.setCurrentIndex(1)
        self._build_tree()
        self.dump_dir = str(self._settings().get("files_dump_dir", "") or "")
        self._rescan_dumps()
        self._update_dump_label()
        self.history, self.history_pos = [], -1
        self.navigate(self.index.root)

    def _build_tree(self) -> None:
        self._tree_lock = True
        self.tree.clear()
        self._tree_items = {}
        folder_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        drive_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon)
        root = QTreeWidgetItem([f"This image ({len(self.index.files):,} files)"])
        root.setIcon(0, self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        root.setData(0, Qt.ItemDataRole.UserRole, self.index.root)
        self.tree.addTopLevelItem(root)
        self._tree_items[id(self.index.root)] = root

        def add(parent_item: QTreeWidgetItem, folder: Folder) -> None:
            for child in folder.subfolders():
                item = QTreeWidgetItem([f"{self.index.label(child)}  [{child.total():,}]"])
                item.setIcon(0, drive_icon if folder is self.index.root else folder_icon)
                item.setData(0, Qt.ItemDataRole.UserRole, child)
                parent_item.addChild(item)
                self._tree_items[id(child)] = item
                add(item, child)

        add(root, self.index.root)
        root.setExpanded(True)
        for number in range(root.childCount()):
            root.child(number).setExpanded(True)
        self._tree_lock = False

    # ------------------------------------------------------------------ navigation
    def navigate(self, folder: Folder, record: bool = True) -> None:
        """Open ``folder`` (and remember it for Back / Forward)."""
        if folder is None or self.index is None:
            return
        self.location = folder
        if record and not (0 <= self.history_pos < len(self.history) and self.history[self.history_pos] is folder):
            self.history = self.history[:self.history_pos + 1] + [folder]
            self.history_pos = len(self.history) - 1
        item = self._tree_items.get(id(folder))
        if item is not None:
            self._tree_lock = True
            self.tree.setCurrentItem(item)
            self._tree_lock = False
        self.address.setText("  ›  ".join(self.index.breadcrumb(folder)))
        self.back_button.setEnabled(self.history_pos > 0)
        self.forward_button.setEnabled(self.history_pos < len(self.history) - 1)
        self.up_button.setEnabled(folder.parent is not None)
        self.populate()

    @safe_slot
    def _tree_selected(self, current, _previous=None):
        if self._tree_lock or current is None:
            return
        folder = current.data(0, Qt.ItemDataRole.UserRole)
        if folder is not None and folder is not self.location:
            self.navigate(folder)

    @safe_slot
    def go_back(self, *_):
        if self.history_pos > 0:
            self.history_pos -= 1
            self.navigate(self.history[self.history_pos], record=False)

    @safe_slot
    def go_forward(self, *_):
        if self.history_pos < len(self.history) - 1:
            self.history_pos += 1
            self.navigate(self.history[self.history_pos], record=False)

    @safe_slot
    def go_up(self, *_):
        if self.location is not None and self.location.parent is not None:
            self.search.clear()
            self.navigate(self.location.parent)

    @safe_slot
    def address_entered(self, *_):
        folder = self.index.resolve(self.address.text()) if self.index is not None else None
        if folder is None:
            self.status.setText(f"“{self.address.text().strip()}” was not found in this image.")
            return
        self.search.clear()
        self.navigate(folder)

    @safe_slot
    def focus_address(self, *_):
        self.address.setFocus()
        self.address.selectAll()

    @safe_slot
    def focus_search(self, *_):
        self.search.setFocus()
        self.search.selectAll()

    @safe_slot
    def open_current(self, *_):
        self.open_item(self.proxy.payload_at(self.view.currentIndex()))

    def open_item(self, item: Optional[Item]) -> None:
        """Folders open; a dumped file opens in the hex view; any other file shows its properties."""
        if isinstance(item, Folder):
            self.search.clear()
            self.navigate(item)
        elif isinstance(item, FileEntry):
            if self.dumps.get(item.offset):
                self.open_hex()
            else:
                self.tabs.setCurrentIndex(0)

    # ------------------------------------------------------------------ the listing
    def _items(self) -> Tuple[List[Folder], List[FileEntry], bool]:
        """``(subfolders, files, search mode)`` of the open folder. A search or a filter lists matching files of the whole subtree."""
        folder = self.location or self.index.root
        words = self.search.text().lower().split()
        searching = bool(words) or self.only_programs.isChecked() or self.only_flagged.isChecked()
        if not searching:
            return folder.subfolders(), sorted(folder.files, key=lambda e: (e.name.lower(), e.path.lower())), False
        pool = folder.all_files()
        if words:
            pool = [e for e in pool if all(w in (e.device + e.path).lower() for w in words)]
        if self.only_programs.isChecked():
            pool = [e for e in pool if e.extension in (".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".cpl", ".com")]
        if self.only_flagged.isChecked():
            pool = [e for e in pool if flags_for(e)]
        return [], sorted(pool, key=lambda e: (e.name.lower(), e.path.lower())), True

    @safe_slot
    def populate(self, *_):
        if self.index is None:
            return
        self._timer.stop()
        keep = {id(p) for p in self._selected_items()}                # the list is rebuilt: keep what was selected
        current = self.proxy.payload_at(self.view.currentIndex())
        folders, files, searching = self._items()
        truncated = len(files) > MAX_ROWS_SHOWN
        files = files[:MAX_ROWS_SHOWN]
        case = case_state.ensure_case(self.result)
        starred = {t for t in case["bookmarks"] if str(t).startswith("file|")}
        noted = {n.get("target", "") for n in case["notes"] if str(n.get("target", "")).startswith("file|")}
        folder_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        file_icon = self.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        rows, items, colors, icons = [], [], {}, {}
        for folder in folders:
            icons[len(rows)] = folder_icon
            rows.append(["", folder.name, "File folder", f"{folder.total():,} file(s)", "", "", "", ""])
            items.append(folder)
        for entry in files:
            flags = flags_for(entry)
            if flags:
                colors[len(rows)] = _FLAG_COLOR
            icons[len(rows)] = file_icon
            rows.append([("★" if entry.target in starred else "") + ("✎" if entry.target in noted else ""), entry.name,
                         (entry.extension.lstrip(".").upper() + " file") if entry.extension else "File", "", f"{entry.offset:#x}", "; ".join(flags),
                         self._dump_state(entry), self._location_text(entry)])
            items.append(entry)
        self.model = TableModel(COLUMNS, rows, payloads=items, colors=colors, icons=icons, icon_column=1)
        self.proxy.setSourceModel(self.model)
        self.view.setColumnHidden(LOCATION_COLUMN, not searching)
        if keep:
            selection = self.view.selectionModel()
            for row in range(self.proxy.rowCount()):
                payload = self.proxy.payload_at(self.proxy.index(row, 0))
                if payload is not None and id(payload) in keep:
                    selection.select(self.proxy.index(row, 0), QItemSelectionModel.SelectionFlag.Select | QItemSelectionModel.SelectionFlag.Rows)
                    if payload is current:
                        self.view.setCurrentIndex(self.proxy.index(row, 0))
        flagged = sum(1 for e in files if flags_for(e))
        where = self.index.breadcrumb(self.location)[-1] if self.location is not None else ""
        self.status.setText((f"{len(files):,} matching file(s) in “{where}” and below" if searching
                             else f"{len(folders):,} folder(s), {len(files):,} file(s) in “{where}”")
                            + (f" (first {MAX_ROWS_SHOWN:,} of more: narrow the search)" if truncated else "")
                            + (f" · {flagged} flagged" if flagged else "")
                            + f" · {len(self.index.files):,} files and {len(self.index.entries) - len(self.index.files):,} folder objects in the image")
        self.selection_changed()

    @staticmethod
    def _location_text(entry: FileEntry) -> str:
        return entry.folder

    def _dump_state(self, entry: FileEntry) -> str:
        if self.dumps.get(entry.offset):
            return f"{len(self.dumps[entry.offset])} file(s)"
        return "not cached" if entry.offset in self.empty_dumps else ""

    # ------------------------------------------------------------------ selection / properties
    def _selected_items(self) -> List[Item]:
        rows = {index.row() for index in self.view.selectionModel().selectedRows()} if self.view.selectionModel() else set()
        return [p for p in (self.proxy.payload_at(self.proxy.index(r, 0)) for r in sorted(rows)) if p is not None]

    def _selected(self) -> List[FileEntry]:
        return [p for p in self._selected_items() if isinstance(p, FileEntry)]

    def _current(self) -> Optional[FileEntry]:
        payload = self.proxy.payload_at(self.view.currentIndex())
        if isinstance(payload, FileEntry):
            return payload
        files = self._selected()
        return files[0] if files and not isinstance(payload, Folder) else None

    @safe_slot
    def selection_changed(self, *_):
        entry = self._current()
        selected = self._selected()
        usable = entry is not None
        for widget in (self.dump_one_button, self.bookmark_button, self.note_button):
            widget.setEnabled(usable)
        self.dump_button.setEnabled(len(selected) > 0)
        self.dump_button.setText(f"Dump selected ({len(selected)})…" if len(selected) > 1 else "Dump selected…")
        self.dump_all_button.setEnabled(any(isinstance(self.proxy.payload_at(self.proxy.index(r, 0)), FileEntry) for r in range(self.proxy.rowCount())))
        if entry is None:
            payload = self.proxy.payload_at(self.view.currentIndex())
            self.details.setHtml(self._folder_html(payload if isinstance(payload, Folder) else self.location))
            self._show_dumped(None)
            self.hex_button.setEnabled(False)
            self.folder_open_button.setEnabled(False)
            return
        target = entry.target
        self.bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, target) else "☆ Bookmark")
        self.details.setHtml(self._properties_html(entry))
        self._show_dumped(entry)

    def _references(self) -> Dict[str, List[str]]:
        """{path key: ["handle: name (PID n)", "module: ..."]} from the investigation (processes' handles and loaded modules)."""
        if self._refs is None:
            refs: Dict[str, List[str]] = {}
            for proc in self.result.processes:
                for handle in proc.handles:
                    name = str(handle.get("name", "")) if isinstance(handle, dict) else ""
                    if name and handle.get("type", "").lower() == "file":
                        refs.setdefault(_key(name), []).append(f"open handle in {proc.name} (PID {proc.pid})")
                for dll in proc.dlls:
                    if dll.path:
                        refs.setdefault(_key(dll.path), []).append(f"loaded module in {proc.name} (PID {proc.pid})")
                if proc.path:
                    refs.setdefault(_key(proc.path), []).append(f"image of {proc.name} (PID {proc.pid})")
            self._refs = refs
        return self._refs

    def _ioc_set(self):
        if self._iocs is None:
            self._iocs = ioc_module.load_from_settings(self._settings())[0] or False
        return self._iocs or None

    @staticmethod
    def _table(rows) -> str:
        return "<table>" + "".join(f"<tr><td style='color:#76859a;padding-right:14px'>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in rows) + "</table>"

    def _folder_html(self, folder: Optional[Folder]) -> str:
        if folder is None or self.index is None:
            return "<p style='color:#76859a'>Select a file or a folder.</p>"
        files = folder.all_files()
        flagged = [e for e in files if flags_for(e)] if len(files) <= 20000 else []
        rows = [("Folder", self.index.label(folder) if folder is not self.index.root else "This image"),
                ("Path", " › ".join(self.index.breadcrumb(folder))),
                ("Contains", f"{len(folder.children):,} folder(s) and {len(folder.files):,} file(s) directly; {len(files):,} file(s) including subfolders"),
                ("Flagged files", f"{len(flagged):,}" if len(files) <= 20000 else "not counted (more than 20,000 files)"),
                ("Dumped files", f"{sum(1 for e in files if self.dumps.get(e.offset)):,}")]
        return self._table(rows) + "<p style='color:#76859a'>Double-click a folder to open it. Select a file to see what is known about it.</p>"

    def _properties_html(self, entry: FileEntry) -> str:
        """Everything known about a file object *without* its content: that only exists after a dump."""
        flags = flags_for(entry)
        volume = self.index.label(self.index.devices[entry.device.lower()]) if self.index and entry.device.lower() in self.index.devices else entry.device
        rows = [("Name", entry.name), ("Folder", entry.folder), ("Volume", volume or "—"), ("Full path", entry.full_name), ("FILE_OBJECT address", f"{entry.offset:#x}"),
                ("Type (by extension)", entry.extension or "none")]
        html = [self._table(rows)]
        if flags:
            html.append("<h3>Why it is flagged</h3><ul>" + "".join(f"<li>{escape(f)}</li>" for f in flags) +
                        "</ul><p style='color:#76859a'>Same logic as rule FILE-001: evidence that the file existed here, not that it was run.</p>")
        refs = self._references().get(_key(entry.path), [])
        html.append("<h3>Seen elsewhere in this investigation</h3>" + ("<ul>" + "".join(f"<li>{escape(r)}</li>" for r in list(dict.fromkeys(refs))[:12]) + "</ul>"
                    if refs else "<p style='color:#76859a'>No process handle, module or image in the analysed plugins refers to this path.</p>"))
        iocs = self._ioc_set()
        hits = iocs.match_file(entry.path) if iocs else []
        if hits:
            html.append("<h3>IOC match (your lists)</h3><ul>" + "".join(f"<li>{escape(h.describe())}</li>" for h in hits) + "</ul>")
        notes = case_state.notes_for(self.result, entry.target)
        if notes:
            html.append("<h3>Your notes</h3><ul>" + "".join(f"<li>{escape(n.get('text', ''))}</li>" for n in notes) + "</ul>")
        dumped = self.dumps.get(entry.offset)
        if dumped:
            html.append(f"<h3>Content</h3><p>{len(dumped)} dumped file(s) in {escape(self.dump_dir)}: see the “Content” tab.</p>")
        elif entry.offset in self.empty_dumps:
            html.append("<h3>Content</h3><p>windows.dumpfiles produced no file: the file object exists, but none of its contents were cached in "
                        "memory (or the object is not a file on disk).</p>")
        else:
            html.append("<h3>Content</h3><p style='color:#76859a'>Not dumped yet. This is all that is known from the file object itself: its content is not shown "
                        "until you dump it (“Dump this file…”). Volatility then recovers whatever part of the file is still cached in memory.</p>")
        return "".join(html)

    # ------------------------------------------------------------------ context menu
    def actions_for(self, item: Optional[Item]) -> List[Tuple[str, Callable[[], None]]]:
        """The right-click menu of a row as ``[(label, handler)]`` (a list, so it can be tested without opening a menu)."""
        if isinstance(item, Folder):
            return [("Open", lambda: self.open_item(item)), ("Dump all files in this folder…", lambda: self.dump_folder(item))]
        if isinstance(item, FileEntry):
            actions = [("Dump…", self.dump_selected)]
            if self.dumps.get(item.offset):
                actions.append(("Open hex view of the dump", self.open_hex))
            actions += [("Bookmark / remove bookmark", self.toggle_bookmark_current), ("Add note…", self.add_note_current),
                        ("Copy full path", lambda: QGuiApplication.clipboard().setText(item.full_name))]
            return actions
        return []

    @safe_slot
    def _context_menu(self, position):
        index = self.view.indexAt(position)
        if index.isValid() and not self.view.selectionModel().isSelected(index):
            self.view.selectRow(index.row())
        menu = QMenu(self)
        for label, handler in self.actions_for(self.proxy.payload_at(index)):
            menu.addAction(label, handler)
        if not menu.isEmpty():
            menu.exec(self.view.viewport().mapToGlobal(position))

    @safe_slot
    def dump_folder(self, folder: Folder, *_):
        entries = folder.all_files()
        if len(entries) > MAX_DUMP_AT_ONCE:
            show_info(self, "Dump folder", f"“{folder.name}” holds {len(entries):,} files; at most {MAX_DUMP_AT_ONCE} can be dumped at once. "
                                          "Open a subfolder, or search for what you need first.")
            return
        if entries and confirm(self, "Dump folder", f"Dump all {len(entries)} file(s) in “{folder.name}” and below? Volatility reads each one's cached pages "
                                                   "from the image; this can take several minutes."):
            self._dump(entries)

    # ------------------------------------------------------------------ dumped files + report
    def _show_dumped(self, entry: Optional[FileEntry]) -> None:
        files = self.dumps.get(entry.offset, []) if entry is not None else []
        rows, payloads = [], []
        for kind, path in files:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            report = self.reports.get(path)
            rows.append([kind, os.path.basename(path), f"{size:,}", report.sha256 if report else "(select to analyse)"])
            payloads.append(path)
        self.dumped_model = TableModel(["Cache", "File", "Size", "SHA-256"], rows, payloads=payloads)
        self.dumped_proxy.setSourceModel(self.dumped_model)
        self.hex_button.setEnabled(bool(files))
        self.folder_open_button.setEnabled(bool(files))
        self.tabs.setTabText(1, "Content (dumped)" if files else "Content (after dump)")
        if files:
            self.dumped_view.selectRow(0)
        else:
            self.report.setHtml("<p style='color:#76859a'>A file object holds no content. Dump the file to see its hashes, type, PE structure and strings here.</p>")

    @safe_slot
    def dumped_selected(self, *_):
        path = self.dumped_proxy.payload_at(self.dumped_view.currentIndex())
        if not path:
            return
        if path in self.reports:
            self.report.setHtml(self._report_html(self.reports[path]))
            return
        self.report.setHtml("<p>Analysing the dumped file…</p>")
        task = BackgroundTask(lambda ctx, p=path: file_report.build_report(p), self)
        task.finished.connect(lambda rep, p=path: self._report_ready(p, rep))
        task.failed.connect(lambda message, _d: self.report.setHtml(f"<p>The file could not be analysed: {escape(message)}</p>"))
        self._report_task = task
        task.start()

    @safe_slot
    def _report_ready(self, path: str, report) -> None:
        self.reports[path] = report
        current = self.dumped_proxy.payload_at(self.dumped_view.currentIndex())
        for row, payload in enumerate(self.dumped_model.payloads):
            if payload == path:
                self.dumped_model.rows[row][3] = report.sha256
                self.dumped_model.dataChanged.emit(self.dumped_model.index(row, 3), self.dumped_model.index(row, 3))
        if current == path:
            self.report.setHtml(self._report_html(report))

    def _report_html(self, rep: file_report.FileReport) -> str:
        html = []
        facts = [("Size", f"{rep.size:,} bytes"), ("Type", rep.kind), ("SHA-256", rep.sha256), ("MD5", rep.md5),
                 ("Entropy", f"{rep.entropy:.2f} bits/byte (8 = random / compressed)"), ("Zero bytes", f"{rep.zero_fraction:.0%}")]
        html.append("<table>" + "".join(f"<tr><td style='color:#76859a;padding-right:14px'>{k}</td><td>{escape(v)}</td></tr>" for k, v in facts) + "</table>")
        iocs = self._ioc_set()
        hits = (iocs.match_hash(rep.sha256) + iocs.match_hash(rep.md5)) if iocs else []
        if hits:
            html.append("<h3 style='color:#e5534b'>IOC HASH MATCH</h3><ul>" + "".join(f"<li>{escape(h.describe())}</li>" for h in hits) + "</ul>")
        if rep.notes:
            html.append("<ul>" + "".join(f"<li>{escape(n)}</li>" for n in rep.notes) + "</ul>")
        pe = rep.pe
        if pe is not None:
            html.append(f"<h3>PE: {escape(pe.machine)} {escape(pe.kind)}</h3>")
            info = [("Compile time (written by the builder, can be forged)", pe.timestamp or "—"), ("Entry point", f"{pe.entry_point:#x} in {pe.entry_section or '?'}"),
                    ("Image base", f"{pe.image_base:#x}"), ("Subsystem", pe.subsystem or "—"),
                    ("Certificate table", "present (signature NOT validated here)" if pe.signed else "none"),
                    ("Overlay (data after the last section)", f"{pe.overlay_size:,} bytes" if pe.overlay_size else "none")]
            html.append("<table>" + "".join(f"<tr><td style='color:#76859a;padding-right:14px'>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in info) + "</table>")
            if pe.warnings:
                html.append("<ul>" + "".join(f"<li>{escape(w)}</li>" for w in pe.warnings) + "</ul>")
            if pe.sections:
                head = "<tr><th align=left>Section</th><th align=left>Flags</th><th align=right>Virtual</th><th align=right>Raw</th><th align=right>Entropy</th><th align=left>Notes</th></tr>"
                body = "".join(f"<tr><td>{escape(s.name)}</td><td>{escape(s.flags)}</td><td align=right>{s.virtual_size:,}</td><td align=right>{s.raw_size:,}</td>"
                               f"<td align=right>{'' if s.entropy is None else s.entropy}</td><td style='color:#c77700'>&nbsp;{escape('; '.join(s.notes))}</td></tr>" for s in pe.sections)
                html.append(f"<h3>Sections</h3><table cellspacing=6>{head}{body}</table>")
            if pe.suspicious_imports:
                html.append("<h3>Imports worth a look</h3><p>" + escape(", ".join(pe.suspicious_imports)) +
                            "</p><p style='color:#76859a'>Common in both legitimate and malicious programs; context decides.</p>")
            if pe.imports:
                html.append(f"<h3>Imported DLLs ({len(pe.imports)})</h3><p>" + escape(", ".join(f"{d} ({n})" for d, n in sorted(pe.imports.items()))[:1500]) + "</p>")
            if pe.export_count:
                html.append(f"<h3>Exports ({pe.export_count:,})</h3><p>" + escape(", ".join(pe.exports[:40])) + (" …" if pe.export_count > 40 else "") + "</p>")
        for title, values in (("URLs", rep.urls), ("IP addresses", rep.ips), ("File paths", rep.paths), ("Registry keys", rep.registry)):
            if values:
                html.append(f"<h3>{title} in strings</h3><ul>" + "".join(f"<li>{escape(v[:200])}</li>" for v in values[:25]) + "</ul>")
        html.append(f"<h3>Strings (first {min(len(rep.strings), 150)} of those found)</h3><pre>" + escape("\n".join(s[:160] for s in rep.strings[:150])) + "</pre>")
        return "".join(html)

    # ------------------------------------------------------------------ dumping
    @safe_slot
    def choose_dump_dir(self, *_):
        path = QFileDialog.getExistingDirectory(self, "Folder for dumped files", self.dump_dir)
        if path:
            self._set_dump_dir(path)

    def _set_dump_dir(self, path: str) -> None:
        self.dump_dir = path
        settings = self._settings()
        settings["files_dump_dir"] = path
        save_settings(settings)
        self._rescan_dumps()
        self._update_dump_label()
        self.populate()

    def _update_dump_label(self) -> None:
        found = sum(len(v) for v in self.dumps.values())
        self.dump_label.setText(f"Dump location: {self.dump_dir or '(not chosen yet — you are asked at the first dump)'}"
                                + (f" · {found} dumped file(s) from this image found there" if found else ""))

    def _rescan_dumps(self) -> None:
        """Re-attach files ``windows.dumpfiles`` wrote earlier to their entries (the names carry the FILE_OBJECT address)."""
        self.dumps = {}
        if self.dump_dir and self.index is not None:
            known = {e.offset for e in self.index.files}
            self.dumps = {address: files for address, files in index_dump_dir(self.dump_dir).items() if address in known}

    def _ensure_dump_dir(self) -> bool:
        if self.dump_dir and os.path.isdir(self.dump_dir):
            return True
        path = QFileDialog.getExistingDirectory(self, "Choose a folder for the dumped files")
        if not path:
            return False
        self._set_dump_dir(path)
        return True

    @safe_slot
    def dump_selected(self, *_):
        selected = self._selected()
        if not selected and self._current() is not None:
            selected = [self._current()]
        self._dump(selected)

    @safe_slot
    def dump_all_shown(self, *_):
        entries = [p for p in (self.proxy.payload_at(self.proxy.index(r, 0)) for r in range(self.proxy.rowCount())) if isinstance(p, FileEntry)]
        if len(entries) > MAX_DUMP_AT_ONCE:
            show_info(self, "Dump all listed", f"{len(entries):,} files are listed; at most {MAX_DUMP_AT_ONCE} can be dumped at once. "
                                              "Narrow the list first (open a subfolder, search, or tick \"Programs and scripts only\").")
            return
        if entries and confirm(self, "Dump all listed", f"Dump {len(entries)} file(s)? Volatility reads each one's cached pages from the image; "
                                                       "this can take several minutes."):
            self._dump(entries)

    def _dump(self, entries: List[FileEntry]) -> None:
        if not entries or (self._task is not None and self._task.running):
            return
        if not self.result.dump_path or not os.path.isfile(self.result.dump_path):
            show_error(self, "Dump", f"The memory image is not available:\n{self.result.dump_path}")
            return
        if not self._ensure_dump_dir():
            return
        settings = self._settings()
        dumper = VolatilityDumper(self.result.dump_path, settings.get("volatility_path", ""), global_args(settings))
        folder, offsets = self.dump_dir, [e.offset for e in entries]
        self._set_busy(True, f"Dumping {len(entries)} file(s) with windows.dumpfiles… (Volatility loads the symbols first; this can take minutes)")
        task = BackgroundTask(lambda ctx: dumper.dump_file_objects(offsets, folder), self)
        task.finished.connect(lambda outcome, e=entries: self._dump_done(e, outcome))
        task.failed.connect(self._dump_failed)
        self._task = task
        task.start()

    def _set_busy(self, busy: bool, text: str = "") -> None:
        for widget in (self.dump_button, self.dump_all_button, self.dump_one_button):
            widget.setEnabled(not busy)
        self.status.setText(text)

    @safe_slot
    def _dump_done(self, entries: List[FileEntry], outcome) -> None:
        completed, command = outcome
        self._set_busy(False)
        written = 0
        for entry in entries:
            files = dump_files_for(self.dump_dir, entry.offset)
            if files:
                self.dumps[entry.offset] = files
                self.empty_dumps.discard(entry.offset)
                written += len(files)
            else:
                self.dumps.pop(entry.offset, None)
                self.empty_dumps.add(entry.offset)
        artifacts = getattr(completed, "artifacts", [])
        iocs = self._ioc_set()
        hits = [f"  {a.name}: {ioc.describe()}" for a in artifacts for ioc in ((iocs.match_hash(a.sha256) + iocs.match_hash(a.md5)) if iocs else [])]
        cached = sum(1 for e in entries if self.dumps.get(e.offset))
        message = (f"{cached} of {len(entries)} file(s) had contents in memory; {written} file(s) written to\n{self.dump_dir}\n"
                   f"(SHA-256 + MD5 of each are in {getattr(completed, 'manifest', '') or 'memorygraph_hashes.csv'}).")
        blocked = [a.name for a in artifacts if getattr(a, "error", "")]
        if blocked:
            message += (f"\n\n{len(blocked)} dumped file(s) could not be read back to hash them (an antivirus may have blocked them): "
                        + ", ".join(blocked[:4]) + (" …" if len(blocked) > 4 else ""))
        if cached < len(entries):
            message += f"\n\n{len(entries) - cached} file(s) produced nothing: their contents were not cached in memory, or the object is not a file on disk."
        if hits:
            message += "\n\nIOC HASH MATCH (your IOC list):\n" + "\n".join(hits)
        self._update_dump_label()
        self.populate()
        show_info(self, "Dump finished", message)

    @safe_slot
    def _dump_failed(self, message, details) -> None:
        self._set_busy(False)
        self.selection_changed()
        show_error(self, "Dump failed", message, details)

    @safe_slot
    def open_hex(self, *_):
        entry = self._current()
        path = self.dumped_proxy.payload_at(self.dumped_view.currentIndex())
        if entry is None or not path:
            return
        from app.models import MemoryRegion
        from app.windows.hex_view import HexViewDialog
        region = MemoryRegion(0, "file", "0x0", hex(max(os.path.getsize(path) - 1, 0)), "", "dumped file", False, False, False, False, PLUGIN)
        subject = {"title": f"{entry.name} (dumped)", "label": f"Dumped file {entry.path}", "target": entry.target, "path": path}
        view = HexViewDialog(region, None, self, result=self.result, dump_dir=self.dump_dir, subject=subject)
        view.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        view.show()
        self._hex_views = [v for v in getattr(self, "_hex_views", []) if v.isVisible()] + [view]

    @safe_slot
    def open_dump_folder(self, *_):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        if self.dump_dir and os.path.isdir(self.dump_dir):
            QDesktopServices.openUrl(QUrl.fromLocalFile(self.dump_dir))

    # ------------------------------------------------------------------ run filescan / notes
    @safe_slot
    def run_filescan(self, *_):
        runner = getattr(self.dashboard, "run_plugins", None)
        if callable(runner):
            runner([PLUGIN], "Files")

    @safe_slot
    def toggle_bookmark_current(self, *_):
        entry = self._current()
        if entry is not None:
            toggle_bookmark(self, self.result, "file", entry.target, f"{entry.name} — {entry.path}"[:140], 0)
            self.populate()

    @safe_slot
    def add_note_current(self, *_):
        entry = self._current()
        if entry is not None and ask_and_add_note(self, self.result, "file", entry.target, f"{entry.name} — {entry.path}"[:140], 0):
            self.populate()

    def select_target(self, target: str) -> bool:
        """Open the folder of the file a bookmark/note refers to and select the file (called from Case Notes)."""
        if self.index is None:
            return False
        entry = next((e for e in self.index.files if e.target == target), None)
        if entry is None:
            return False
        self.search.clear()
        self.only_programs.setChecked(False)
        self.only_flagged.setChecked(False)
        self.navigate(self.index.folder_for(entry))
        for row in range(self.proxy.rowCount()):
            if self.proxy.payload_at(self.proxy.index(row, 0)) is entry:
                self.view.selectRow(row)
                self.view.scrollTo(self.proxy.index(row, 0))
                return True
        return False
