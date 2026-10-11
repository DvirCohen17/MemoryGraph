"""Registry: browse the registry keys that Volatility read for this investigation, and fetch more.

Every ``windows.registry.printkey`` result in the investigation (Run keys, Winlogon / IFEO / AppInit, Active Setup, the Services key, ...) is merged into one tree:
hive -> keys -> values. The tree is instant because it only reads what is already stored. **Fetch another key…** asks Volatility for a key that is not there yet
(it takes as long as one plugin run, because Volatility loads the symbols first) and adds it to the investigation, so it is saved with it.
Nothing here writes to the image or the registry; the values are shown as they were in the memory image.
"""
from __future__ import annotations

import os
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSplitter, QStyle, QTextBrowser, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

from app.engines.windows.analysis.registry_tree import CUSTOM_PREFIX, KeyNode, RegistryTree
from app.analysis.volatility_runner import check_tool, find_volatility, global_args, run_plugin
from app.errors import safe_slot
from app.tasks import BackgroundTask
from app.windows.widgets import FlowLayout, TableModel, escape, make_table, muted, show_error, show_info

MAX_TREE_KEYS = 20000


class FetchKeyDialog(QDialog):
    """Asks for a key path (and whether to read its subkeys too)."""

    def __init__(self, parent=None, start: str = ""):
        super().__init__(parent)
        self.setWindowTitle("Fetch a registry key")
        layout = QVBoxLayout(self)
        layout.addWidget(muted("Volatility reads one key (and optionally everything below it) from the memory image. Type the path inside the hive, "
                               "for example Microsoft\\Windows\\CurrentVersion\\Run, or Software\\Microsoft\\Windows\\CurrentVersion\\Run for a user hive."))
        form = QFormLayout()
        self.key = QLineEdit(start)
        self.key.setPlaceholderText("Microsoft\\Windows\\CurrentVersion\\Run")
        self.recurse = QCheckBox("Also read all subkeys (can be large)")
        form.addRow("Key", self.key)
        form.addRow("", self.recurse)
        layout.addLayout(form)
        row = QHBoxLayout()
        cancel = QPushButton("Cancel")
        ok = QPushButton("Fetch")
        ok.setObjectName("Primary")
        cancel.clicked.connect(self.reject)
        ok.clicked.connect(self.accept)
        row.addStretch()
        row.addWidget(cancel)
        row.addWidget(ok)
        layout.addLayout(row)


class RegistryView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self.tree_data: Optional[RegistryTree] = None
        self.matches: List = []
        self.match_pos = -1
        self._task: Optional[BackgroundTask] = None
        self._items = {}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Registry")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("The registry keys Volatility read for this investigation, merged into one tree. Values are shown as they were in the memory image."))
        bar = FlowLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find a key, value name or data…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self.next_button = QPushButton("Find next")
        self.fetch_button = QPushButton("Fetch another key…")
        self.fetch_button.setObjectName("Primary")
        for widget in (self.search, self.next_button, self.fetch_button):
            bar.addWidget(widget)
        layout.addLayout(bar)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Keys"])
        self.tree.setMinimumHeight(220)
        self.tree.setMinimumWidth(220)
        splitter.addWidget(self.tree)
        right = QSplitter(Qt.Orientation.Vertical)
        self.info = QTextBrowser()
        self.info.setMaximumHeight(170)
        self.info.setMinimumHeight(110)
        right.addWidget(self.info)
        self.model = TableModel(["Name", "Type", "Data"], [])
        self.values, self.proxy = make_table(self.model, [220, 120, 700])
        self.values.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        right.addWidget(self.values)
        right.setSizes([110, 500])
        splitter.addWidget(right)
        splitter.setSizes([320, 900])
        layout.addWidget(splitter, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)

        self.tree.currentItemChanged.connect(self._key_selected)
        self.search.returnPressed.connect(self.find_first)
        self.search.textChanged.connect(lambda *_: setattr(self, "matches", []))
        self.next_button.clicked.connect(self.find_next)
        self.fetch_button.clicked.connect(self.fetch_dialog)
        self.reload()

    # ------------------------------------------------------------------ tree
    @safe_slot
    def reload(self, *_):
        self.tree_data = RegistryTree(self.result.plugins)
        self.tree.clear()
        self._items = {}
        folder = self.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        drive = self.style().standardIcon(QStyle.StandardPixmap.SP_DriveHDIcon)
        built = 0

        def add(parent_item, node: KeyNode) -> None:
            nonlocal built
            for child in node.subkeys():
                if built >= MAX_TREE_KEYS:
                    return
                built += 1
                item = QTreeWidgetItem([child.name])
                item.setIcon(0, folder)
                item.setData(0, Qt.ItemDataRole.UserRole, child)
                parent_item.addChild(item)
                self._items[child.full_path.lower()] = item
                add(item, child)

        for root in self.tree_data.roots():
            item = QTreeWidgetItem([root.name])
            item.setIcon(0, drive)
            item.setData(0, Qt.ItemDataRole.UserRole, root)
            self.tree.addTopLevelItem(item)
            self._items[root.full_path.lower()] = item
            add(item, root)
            item.setExpanded(True)
        data = self.tree_data
        self.status.setText(f"{len(data.hives)} hive(s), {data.keys:,} key(s), {data.values:,} value(s) read by Volatility"
                            + (f" (the tree shows the first {MAX_TREE_KEYS:,} keys)" if built >= MAX_TREE_KEYS else "")
                            if data.hives else "No registry key was read yet. Tick “Persistence” under Settings → Plugins, or use Fetch another key…")
        if data.hives and self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else:
            self.info.setHtml("<p style='color:#76859a'>Use <b>Fetch another key…</b> to read a key from the memory image.</p>")
            self._show_values(None)

    @safe_slot
    def _key_selected(self, current, _previous=None):
        node = current.data(0, Qt.ItemDataRole.UserRole) if current is not None else None
        self._show_values(node)

    def _show_values(self, node: Optional[KeyNode], highlight: str = "") -> None:
        if node is None:
            self.model = TableModel(["Name", "Type", "Data"], [])
            self.proxy.setSourceModel(self.model)
            return
        rows = [[v.name, v.type, v.data] for v in sorted(node.values, key=lambda v: v.name.lower())]
        self.model = TableModel(["Name", "Type", "Data"], rows)
        self.proxy.setSourceModel(self.model)
        fetched = [s.replace("windows.registry.printkey ", "") for s in node.sources]
        self.info.setHtml(f"<p><b>{escape(node.full_path)}</b></p><p style='color:#7a899e'>Last written: {escape(node.last_write or 'unknown')} · "
                          f"{len(node.children):,} subkey(s) · {len(node.values):,} value(s)<br>Read by: {escape(', '.join(fetched) or '—')}</p>")
        if highlight:
            for row in range(self.proxy.rowCount()):
                if self.proxy.index(row, 0).data() == highlight:
                    self.values.selectRow(row)
                    break

    # ------------------------------------------------------------------ search
    @safe_slot
    def find_first(self, *_):
        self.matches = self.tree_data.find(self.search.text()) if self.tree_data else []
        self.match_pos = -1
        self.status.setText(f"{len(self.matches):,} match(es) for “{self.search.text().strip()}”" if self.matches else "Nothing matches.")
        self.find_next()

    @safe_slot
    def find_next(self, *_):
        if not self.matches and self.search.text().strip():
            self.matches = self.tree_data.find(self.search.text()) if self.tree_data else []
            self.match_pos = -1
        if not self.matches:
            return
        self.match_pos = (self.match_pos + 1) % len(self.matches)
        node, value = self.matches[self.match_pos]
        item = self._items.get(node.full_path.lower())
        if item is not None:
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item)
        self._show_values(node, value.name if value else "")
        self.status.setText(f"Match {self.match_pos + 1} of {len(self.matches):,}: {node.full_path}" + (f" → {value.name}" if value else ""))

    # ------------------------------------------------------------------ fetching another key
    def _settings(self) -> dict:
        getter = getattr(self.dashboard, "live_settings", None)
        return (getter() if callable(getter) else getattr(self.dashboard, "settings", None)) or {}

    @safe_slot
    def fetch_dialog(self, *_):
        item = self.tree.currentItem()
        node = item.data(0, Qt.ItemDataRole.UserRole) if item is not None else None
        dialog = FetchKeyDialog(self, node.path if node is not None and node.path else "")
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.key.text().strip():
            self.fetch_key(dialog.key.text().strip(), dialog.recurse.isChecked())

    def fetch_key(self, key: str, recurse: bool = False) -> None:
        """Read ``key`` from the memory image with ``windows.registry.printkey`` (in the background) and add the rows to the investigation."""
        if self._task is not None and self._task.running:
            return
        if not self.result.dump_path or not os.path.isfile(self.result.dump_path):
            show_error(self, "Fetch a registry key", f"The memory image is not available:\n{self.result.dump_path}")
            return
        settings = self._settings()
        name = f"{CUSTOM_PREFIX}{key}{' (with subkeys)' if recurse else ''}]"
        self.fetch_button.setEnabled(False)
        self.status.setText(f"Reading {key} from the memory image… (Volatility loads the symbols first)")

        def work(_ctx):
            tool = check_tool(find_volatility(settings.get("volatility_path", "")))
            tool.global_args = global_args(settings)
            return run_plugin(tool, self.result.dump_path, name, volatility_plugin="windows.registry.printkey",
                              args=["--key", key] + (["--recurse"] if recurse else []))

        task = BackgroundTask(work, self)
        task.finished.connect(lambda res, k=key: self._fetched(k, res))
        task.failed.connect(self._fetch_failed)
        self._task = task
        task.start()

    @safe_slot
    def _fetched(self, key: str, res) -> None:
        self.fetch_button.setEnabled(True)
        if res.status != "Completed":
            show_error(self, "Fetch a registry key", ((res.error or "failed").strip().splitlines() or ["failed"])[-1][:300], res.error or "")
            self.status.setText("")
            return
        self.result.plugins = [p for p in self.result.plugins if p.name != res.name] + [res]
        if hasattr(self.dashboard, "mark_dirty"):
            self.dashboard.mark_dirty()
        self.reload()
        keyed = sum(1 for r in res.rows if isinstance(r, dict) and r.get("Type") != "Key")
        self.status.setText(f"{key}: {len(res.rows):,} row(s) read ({keyed:,} value(s)); added to the investigation")
        node = self.tree_data.lookup(next((f"{n.hive}\\{n.path}" for n in [self._first_node(res)] if n), ""))
        item = self._items.get(node.full_path.lower()) if node else None
        if item is not None:
            self.tree.setCurrentItem(item)

    def _first_node(self, res) -> Optional[KeyNode]:
        from app.engines.windows.analysis.registry_tree import split_key
        for row in res.rows:
            if isinstance(row, dict) and row.get("Key"):
                hive, path = split_key(row["Key"])
                return KeyNode(path.rsplit("\\", 1)[-1], hive, path)
        return None

    @safe_slot
    def _fetch_failed(self, message, details) -> None:
        self.fetch_button.setEnabled(True)
        self.status.setText("")
        show_error(self, "Fetch a registry key", message, details)
