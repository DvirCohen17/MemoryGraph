"""Process tree: a compact, collapsible Process-Explorer style tree with a detail panel.

The old view drew every process as a node on a huge canvas. This one:
  * is a real tree (expand/collapse), roots visible, branches with findings opened automatically,
  * groups repeated harmless siblings ("svchost.exe ×12") into one collapsible row,
  * colours rows by risk and shows a findings column,
  * filters by text and "only suspicious", with the lineage kept so the context is not lost,
  * shows a detail panel (lineage, facts, findings, counters) for the selected process and
  * opens the full process window by double-click / Enter / button.
"""
from __future__ import annotations

import os
from collections import defaultdict
from typing import Dict, List, Optional

from PySide6.QtCore import QTimer, Qt, QUrl
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPushButton, QSplitter,
    QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from app.analysis import case_state, ioc as ioc_module
from app.engines import engine_for
from app.analysis.indicators.base import parent_of
from app.analysis.volatility_runner import global_args
from app.analysis.indicators.scoring import active_findings, risk_by_pid, severity_rank
from app.analysis.pipeline import refresh_image_hash_findings
from app.errors import safe_slot
from app.tasks import BackgroundTask
from app.windows.case_actions import ask_and_add_note, notify_triage_changed, toggle_bookmark
from app.theme import SEVERITY_COLORS
from app.util import format_time, time_key
from app.windows.widgets import FlowLayout, badge_html, confirm, decoded_command_html, escape, muted, severity_color, show_error, show_info

PID_ROLE = Qt.ItemDataRole.UserRole
GROUP_ROLE = Qt.ItemDataRole.UserRole + 1
GROUP_MIN = 4          # siblings with the same name are grouped from this count on
MAX_DEPTH = 120        # safety net against malformed parent links


def short_time(value: str) -> str:
    text = format_time(value)
    return text[:-4] if text.endswith(" UTC") else text


class ProcessTreeView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.engine = engine_for(result)
        self.dashboard = parent
        self.by_pid = {p.pid: p for p in result.processes}
        self._load_findings()
        self.items: Dict[int, QTreeWidgetItem] = {}
        self._open_windows = []
        self._build_relations()

        root = QVBoxLayout(self)
        root.setContentsMargins(25, 25, 25, 20)
        root.setSpacing(10)
        title = QLabel("Process Tree")
        title.setObjectName("Title")
        root.addWidget(title)
        root.addWidget(muted("Parent → child hierarchy. Select a process for a summary; double-click (or press Enter) for full details. "
                             "Branches that contain findings open automatically."))

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, PID, user, path or command line…")
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)
        smart = QPushButton("Smart expand")
        expand = QPushButton("Expand all")
        collapse = QPushButton("Collapse all")
        for button in (smart, expand, collapse):
            bar.addWidget(button)
        root.addLayout(bar)
        options = FlowLayout(h_spacing=14)               # wraps on narrow windows
        self.only_suspicious = QCheckBox("Only suspicious")
        self.hide_exited = QCheckBox("Hide exited")
        self.group = QCheckBox("Group repeated siblings")
        self.group.setChecked(True)
        for box in (self.only_suspicious, self.hide_exited, self.group):
            options.addWidget(box)
        self.hash_button = QPushButton("Hash all process images…")
        self.hash_button.setToolTip("Dump every process's executable once, hash it, keep the list in the investigation and check it against your IOC hashes")
        self.export_hashes_button = QPushButton("Export image hashes…")
        for button in (self.hash_button, self.export_hashes_button):
            options.addWidget(button)
            button.setVisible(self.engine.capabilities.process_images)     # hashing every process image is an engine feature (Windows today)
        root.addLayout(options)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.tree = QTreeWidget()
        self.tree.setColumnCount(5)
        self.tree.setHeaderLabels(["Process", "PID", "User", "Started", "Findings"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setIndentation(18)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((300, 70, 170, 150, 120)):
            self.tree.setColumnWidth(column, width)
        splitter.addWidget(self.tree)

        side = QWidget()
        side_layout = QVBoxLayout(side)
        side_layout.setContentsMargins(0, 0, 0, 0)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.setOpenExternalLinks(False)
        side_layout.addWidget(self.detail, 1)
        self.open_button = QPushButton("Open full process details…")
        self.open_button.setObjectName("Primary")
        self.open_button.setEnabled(False)
        side_layout.addWidget(self.open_button)
        marks = QHBoxLayout()
        self.bookmark_button = QPushButton("☆ Bookmark")
        self.bookmark_button.setToolTip("Bookmark this process (listed in Case Notes, saved with the investigation)")
        self.note_button = QPushButton("✎ Add note…")
        for button in (self.bookmark_button, self.note_button):
            button.setEnabled(False)
            marks.addWidget(button)
        side_layout.addLayout(marks)
        splitter.addWidget(side)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        splitter.setSizes([820, 520])
        root.addWidget(splitter, 1)

        self.status = muted("", wrap=False)
        root.addWidget(self.status)

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(180)
        self._debounce.timeout.connect(self.rebuild)
        self.search.textChanged.connect(lambda *_: self._debounce.start())
        for box in (self.only_suspicious, self.hide_exited, self.group):
            box.toggled.connect(lambda *_: self.rebuild())
        smart.clicked.connect(self.smart_expand)
        expand.clicked.connect(self.tree.expandAll)
        collapse.clicked.connect(self.tree.collapseAll)
        self.tree.currentItemChanged.connect(self.on_selection)
        # itemActivated already covers double-click (on Windows) and Enter; connecting itemDoubleClicked as
        # well made one double-click emit both signals and open two windows.
        self.tree.itemActivated.connect(self.on_activate)
        self.detail.anchorClicked.connect(self.on_link)
        self.open_button.clicked.connect(self.open_current)
        self.hash_button.clicked.connect(self.hash_images)
        self.export_hashes_button.clicked.connect(self.export_image_hashes)
        self._hash_task = None
        self._update_hash_buttons()
        self.bookmark_button.clicked.connect(self.toggle_bookmark_current)
        self.note_button.clicked.connect(self.add_note_current)

        self.rebuild()
        self.detail.setHtml("<p style='color:#76859a'>Select a process to see its summary.</p>")

    def _process_images(self):
        """The process-image hashing module of the engine (only called when ``capabilities.process_images`` is true: Windows)."""
        from app.engines.windows.analysis import process_images
        return process_images

    def _load_findings(self) -> None:
        """Risk and per-process findings from the findings that are not hidden by triage (false positive / baseline)."""
        self.risks = risk_by_pid(self.result.indications)
        self.findings: Dict[int, list] = defaultdict(list)
        for ind in active_findings(self.result.indications):
            if ind.process_pid:
                self.findings[ind.process_pid].append(ind)

    @safe_slot
    def refresh_after_triage(self, *_):
        """Dashboard hook: a finding was re-judged. Recompute risk colours and the detail panel, keep the selection."""
        self._load_findings()
        if hasattr(self, "interesting"):
            for proc in reversed(self._preorder()):
                own = self._severity(proc.pid) in ("Medium", "High") or proc.hidden
                self.interesting[proc.pid] = own or any(self.interesting.get(c.pid, False) for c in self.children.get(proc.pid, []))
        self.rebuild()
        self.on_selection(self.tree.currentItem(), None)

    # ------------------------------------------------------------------ relations
    def _build_relations(self) -> None:
        procs = sorted(self.result.processes, key=lambda p: (time_key(p.create_time), p.pid))
        self.parent_pid: Dict[int, Optional[int]] = {}
        self.children: Dict[int, list] = defaultdict(list)
        self.roots: list = []
        for proc in procs:
            parent = parent_of(self.by_pid, proc)
            self.parent_pid[proc.pid] = parent.pid if parent else None
            if parent is None:
                self.roots.append(proc)
            else:
                self.children[parent.pid].append(proc)
        # Any process not reachable from a root is part of a parent cycle: promote it to a root.
        reachable, stack = set(), [p.pid for p in self.roots]
        while stack:
            pid = stack.pop()
            if pid in reachable:
                continue
            reachable.add(pid)
            stack.extend(c.pid for c in self.children.get(pid, []))
        for proc in procs:
            if proc.pid not in reachable:
                self.roots.append(proc)
                self.parent_pid[proc.pid] = None
                reachable.add(proc.pid)
                stack = [c.pid for c in self.children.get(proc.pid, [])]
                while stack:
                    pid = stack.pop()
                    if pid not in reachable:
                        reachable.add(pid)
                        stack.extend(c.pid for c in self.children.get(pid, []))

        # does this process or any descendant carry a Medium+ finding?
        self.interesting: Dict[int, bool] = {}
        for proc in reversed(self._preorder()):
            own = self._severity(proc.pid) in ("Medium", "High") or proc.hidden
            self.interesting[proc.pid] = own or any(self.interesting.get(c.pid, False) for c in self.children.get(proc.pid, []))

    def _preorder(self) -> list:
        order, seen, stack = [], set(), list(reversed(self.roots))
        while stack:
            proc = stack.pop()
            if proc.pid in seen:
                continue
            seen.add(proc.pid)
            order.append(proc)
            stack.extend(reversed(self.children.get(proc.pid, [])))
        return order

    def _severity(self, pid: int) -> str:
        risk = self.risks.get(pid)
        return risk.severity if risk else ""

    # ------------------------------------------------------------------ filtering
    def _matches(self, proc, text: str) -> bool:
        haystack = " ".join((proc.name, str(proc.pid), proc.user, proc.path, proc.command_line)).lower()
        return text in haystack

    def _visible_set(self):
        text = self.search.text().strip().lower()
        suspicious_only = self.only_suspicious.isChecked()
        hide_exited = self.hide_exited.isChecked()
        filtering = bool(text) or suspicious_only
        if not filtering and not hide_exited:
            return None, False
        visible = set()
        for proc in self.result.processes:
            if hide_exited and proc.exited and self._severity(proc.pid) not in ("Medium", "High"):
                continue
            if text and not self._matches(proc, text):
                continue
            if suspicious_only and self._severity(proc.pid) not in ("Medium", "High") and not proc.hidden:
                continue
            visible.add(proc.pid)
        for pid in list(visible):             # keep ancestors so the lineage stays readable
            up, guard = self.parent_pid.get(pid), 0
            while up is not None and up not in visible and guard < MAX_DEPTH:
                visible.add(up)
                up = self.parent_pid.get(up)
                guard += 1
        return visible, filtering

    # ------------------------------------------------------------------ building
    @safe_slot
    def rebuild(self, *_):
        selected = self.current_pid()
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            self.items = {}
            visible, filtering = self._visible_set()
            placed = set()
            shown = 0
            for proc in self.roots:
                if visible is not None and proc.pid not in visible:
                    continue
                shown += self._add(None, proc, visible, filtering, placed, 0)
            if filtering:
                self.tree.expandAll()
            else:
                self.smart_expand()
        finally:
            self.tree.setUpdatesEnabled(True)
        flagged = sum(1 for p in self.result.processes if self._severity(p.pid) in ("Medium", "High"))
        self.status.setText(f"{len(self.result.processes)} processes · {flagged} with Medium/High findings · showing {shown}")
        if selected in self.items:
            self.tree.setCurrentItem(self.items[selected])

    def _add(self, parent_item, proc, visible, filtering, placed, depth) -> int:
        if proc.pid in placed or depth > MAX_DEPTH:
            return 0
        placed.add(proc.pid)
        item = self._make_item(proc)
        (parent_item.addChild(item) if parent_item is not None else self.tree.addTopLevelItem(item))
        self.items[proc.pid] = item
        count = 1
        kids = [k for k in self.children.get(proc.pid, []) if (visible is None or k.pid in visible) and k.pid not in placed]
        singles, groups = self._split_groups(kids, filtering)
        for kid in singles:
            count += self._add(item, kid, visible, filtering, placed, depth + 1)
        for name, members in groups:
            group_item = QTreeWidgetItem([f"{name}  ×{len(members)}", "", "", "", ""])
            group_item.setData(0, GROUP_ROLE, [m.pid for m in members])
            group_item.setForeground(0, QBrush(QColor("#7a899e")))
            item.addChild(group_item)
            for member in members:
                count += self._add(group_item, member, visible, filtering, placed, depth + 2)
        return count

    def _split_groups(self, kids, filtering):
        if not self.group.isChecked() or filtering or len(kids) < GROUP_MIN:
            return kids, []
        by_name: Dict[str, list] = defaultdict(list)
        for kid in kids:
            plain = (not self.children.get(kid.pid)) and not self.interesting.get(kid.pid, False)
            if plain:
                by_name[kid.name.lower()].append(kid)
        grouped_names = {n for n, members in by_name.items() if len(members) >= GROUP_MIN}
        singles, order = [], []
        for kid in kids:
            key = kid.name.lower()
            if key in grouped_names and kid in by_name[key]:
                if key not in order:
                    order.append(key)
            else:
                singles.append(kid)
        return singles, [(by_name[k][0].name, by_name[k]) for k in order]

    def _make_item(self, proc) -> QTreeWidgetItem:
        risk = self.risks.get(proc.pid)
        severity = risk.severity if risk else ""
        marker = "⚠ " if proc.hidden else ""
        bookmarked, annotated = case_state.has_marks(self.result, case_state.process_target(proc))
        marker += ("★ " if bookmarked else "") + ("✎ " if annotated else "")
        findings_text = ""
        if risk and risk.count:
            findings_text = f"{severity or 'Info'} · {risk.count}"
        item = QTreeWidgetItem([
            f"{marker}{proc.name}", str(proc.pid), proc.user or "", short_time(proc.create_time) if proc.create_time else "", findings_text,
        ])
        item.setData(0, PID_ROLE, proc.pid)
        if severity in ("Medium", "High"):
            item.setForeground(0, QBrush(QColor(severity_color(severity))))
        if findings_text:
            item.setForeground(4, QBrush(QColor(severity_color(severity))))
            titles = "\n".join(f"[{f.severity}] {f.rule_id}: {f.title}" for f in self.findings.get(proc.pid, [])[:12])
            item.setToolTip(4, titles)
        if proc.exited:
            for column in range(5):
                item.setForeground(column, QBrush(QColor("#5c6b7c")))
            font = item.font(0)
            font.setItalic(True)
            item.setFont(0, font)
            item.setToolTip(0, f"Exited {proc.exit_time}")
        tooltip = proc.path or proc.command_line
        if tooltip and not proc.exited:
            item.setToolTip(0, tooltip)
        return item

    @safe_slot
    def smart_expand(self, *_):
        self.tree.collapseAll()
        for pid, item in self.items.items():
            if item.parent() is None or self.interesting.get(pid, False):
                item.setExpanded(True)
            parent = item.parent()
            # a group row containing an interesting process must be open too
            if parent is not None and parent.data(0, GROUP_ROLE) is not None and self.interesting.get(pid, False):
                parent.setExpanded(True)

    # ------------------------------------------------------------------ selection / details
    def current_pid(self) -> Optional[int]:
        item = self.tree.currentItem()
        pid = item.data(0, PID_ROLE) if item is not None else None
        return pid if isinstance(pid, int) else None

    def select_pid(self, pid: int) -> bool:
        item = self.items.get(pid)
        if item is None:
            return False
        parent = item.parent()
        while parent is not None:
            parent.setExpanded(True)
            parent = parent.parent()
        self.tree.setCurrentItem(item)
        self.tree.scrollToItem(item)
        return True

    @safe_slot
    def on_selection(self, current, _previous):
        if current is None:
            self.open_button.setEnabled(False)
            self.bookmark_button.setEnabled(False)
            self.note_button.setEnabled(False)
            return
        group = current.data(0, GROUP_ROLE)
        if group is not None:
            self.open_button.setEnabled(False)
            self.bookmark_button.setEnabled(False)
            self.note_button.setEnabled(False)
            links = ", ".join(f'<a href="pid:{pid}">{pid}</a>' for pid in group)
            self.detail.setHtml(f"<h3>{escape(current.text(0))}</h3><p>Repeated siblings with the same name and no findings. PIDs: {links}</p>")
            return
        pid = current.data(0, PID_ROLE)
        proc = self.by_pid.get(pid)
        if proc is None:
            return
        self.open_button.setEnabled(True)
        self.note_button.setEnabled(True)
        self.bookmark_button.setEnabled(True)
        self.bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, case_state.process_target(proc)) else "☆ Bookmark")
        self.detail.setHtml(self.summary_html(proc))

    def summary_html(self, proc) -> str:
        risk = self.risks.get(proc.pid)
        severity = risk.severity if risk else ""
        lineage, up, guard = [], self.parent_pid.get(proc.pid), 0
        while up is not None and guard < MAX_DEPTH:
            ancestor = self.by_pid.get(up)
            if ancestor is None:
                break
            lineage.append(ancestor)
            up = self.parent_pid.get(up)
            guard += 1
        crumbs = " › ".join(f'<a href="pid:{a.pid}">{escape(a.name)}</a>' for a in reversed(lineage))
        crumbs = (crumbs + " › " if crumbs else "") + f"<b>{escape(proc.name)}</b>"
        external = sum(1 for c in proc.network if c.remote_address and c.remote_address not in ("*", "::", "0.0.0.0"))
        rows = [
            ("Image", proc.path or "unknown"), ("Command line", proc.command_line or "not available"),
            ("User", proc.user or "unknown"), ("Parent PID", proc.ppid),
            ("Session", proc.session if proc.session >= 0 else "—"),
            ("Started", short_time(proc.create_time) if proc.create_time else "unknown"),
            ("Exited", short_time(proc.exit_time) if proc.exit_time else "still running at capture"),
        ]
        facts = "".join(f"<tr><td style='color:#76859a;padding-right:12px;vertical-align:top'>{k}</td><td>{escape(v)}</td></tr>" for k, v in rows)
        counters = (f"{len(proc.dlls)} modules · {len(proc.handles)} named handles · {len(proc.network)} connections "
                    f"({external} with a remote endpoint) · {len(proc.memory_regions)} malfind regions · {proc.threads} threads")
        html = [f"<h2 style='margin-bottom:2px'>{escape(proc.name)} <span style='color:#76859a'>PID {proc.pid}</span></h2>"]
        if severity:
            html.append(f"<p>{badge_html(severity, f'{severity} risk')} &nbsp; score {risk.score if risk else 0}</p>")
        if proc.hidden:
            html.append("<p style='color:#c77700'>⚠ Found by psscan but missing from pslist (possibly unlinked/hidden).</p>")
        html.append(f"<p style='color:#7a899e'>{crumbs}</p><table>{facts}</table><p style='color:#76859a'>{counters}</p>")
        html.append(decoded_command_html(proc.command_line, proc.pid))
        findings = sorted(self.findings.get(proc.pid, []), key=lambda f: (-severity_rank(f.severity), -f.score))
        if findings:
            html.append("<h3>Findings</h3>")
            for f in findings[:12]:
                reason = f"<br><span style='color:#7a899e'>{escape(f.reasons[0])}</span>" if f.reasons else ""
                html.append(f"<p>{badge_html(f.severity, f.severity)} <b>{escape(f.rule_id)}</b> {escape(f.title)}{reason}</p>")
        kids = self.children.get(proc.pid, [])
        if kids:
            links = ", ".join(f'<a href="pid:{k.pid}">{escape(k.name)} ({k.pid})</a>' for k in kids[:20])
            more = f" … and {len(kids) - 20} more" if len(kids) > 20 else ""
            html.append(f"<h3>Children</h3><p>{links}{more}</p>")
        notes = case_state.notes_for(self.result, case_state.process_target(proc))
        if notes:
            body = "".join(f"<li>{escape(n.get('text', ''))} <span style='color:#76859a'>({escape(n.get('time', ''))})</span></li>" for n in notes)
            html.append(f"<h3>Your notes</h3><ul>{body}</ul>")
        return "".join(html)

    @safe_slot
    def toggle_bookmark_current(self, *_):
        pid = self.current_pid()
        proc = self.by_pid.get(pid) if pid is not None else None
        if proc is None:
            return
        toggle_bookmark(self, self.result, "process", case_state.process_target(proc), f"{proc.name} (PID {proc.pid})", proc.pid)
        self._refresh_marks(proc.pid)

    @safe_slot
    def add_note_current(self, *_):
        pid = self.current_pid()
        proc = self.by_pid.get(pid) if pid is not None else None
        if proc is None:
            return
        if ask_and_add_note(self, self.result, "process", case_state.process_target(proc), f"{proc.name} (PID {proc.pid})", proc.pid):
            self._refresh_marks(proc.pid)

    def _refresh_marks(self, pid: int) -> None:
        """Update the ★/✎ markers and the detail panel without rebuilding the tree (keeps expansion and scroll)."""
        proc = self.by_pid.get(pid)
        item = self.items.get(pid)
        if proc is not None and item is not None:
            item.setText(0, self._make_item(proc).text(0))
        self.on_selection(self.tree.currentItem(), None)

    @safe_slot
    def on_link(self, url: QUrl):
        text = url.toString()
        if text.startswith("pid:"):
            try:
                pid = int(text[4:])
            except ValueError:
                return
            if not self.select_pid(pid):
                self.search.clear()
                self.only_suspicious.setChecked(False)
                self.rebuild()
                self.select_pid(pid)

    @safe_slot
    def on_activate(self, item, _column=0):
        pid = item.data(0, PID_ROLE) if item is not None else None
        if isinstance(pid, int):
            self.open_pid(pid)

    @safe_slot
    def open_current(self, *_):
        pid = self.current_pid()
        if pid is not None:
            self.open_pid(pid)

    # ------------------------------------------------------------------ hashes of the process images
    def _update_hash_buttons(self) -> None:
        count = len(self._process_images().stored(self.result))
        self.export_hashes_button.setEnabled(count > 0)
        self.export_hashes_button.setText(f"Export image hashes ({count})…" if count else "Export image hashes…")

    @safe_slot
    def hash_images(self, *_):
        """Dump every process's image with one Volatility run, hash the files and check them against the IOC list."""
        if self._hash_task is not None and self._hash_task.running:
            return
        if not self.result.dump_path or not os.path.isfile(self.result.dump_path):
            show_error(self, "Hash process images", "The memory image is not available:\n" + str(self.result.dump_path))
            return
        folder = QFileDialog.getExistingDirectory(self, "Folder for the dumped process images")
        if not folder:
            return
        question = (f"Dump the executable of all {len(self.result.processes)} processes into\n{folder}\nand hash them? "
                    "This reads each process's image from the memory image and can take several minutes.")
        if not confirm(self, "Hash all process images", question):
            return
        settings = self._live_settings()
        dumper = self.engine.make_dumper(self.result.dump_path, settings.get("volatility_path", ""), global_args(settings))
        self.hash_button.setEnabled(False)
        self.status.setText("Dumping and hashing the process images… (Volatility loads the symbols first)")
        task = BackgroundTask(lambda ctx: dumper.dump_all_process_images(folder), self)
        task.finished.connect(lambda outcome, f=folder: self._hashes_done(f, outcome))
        task.failed.connect(self._hashes_failed)
        self._hash_task = task
        task.start()

    def _live_settings(self) -> dict:
        getter = getattr(self.dashboard, "live_settings", None)
        return (getter() if callable(getter) else getattr(self.dashboard, "settings", None)) or {}

    @safe_slot
    def _hashes_done(self, folder, outcome) -> None:
        completed, _command = outcome
        self.hash_button.setEnabled(True)
        entries = self._process_images().entries_from_artifacts(getattr(completed, "artifacts", []), self.result.processes)
        self._process_images().store(self.result, entries, folder)
        iocs, _problems = ioc_module.load_from_settings(self._live_settings())
        matches = refresh_image_hash_findings(self.result, iocs)
        self.status.setText("")
        self._update_hash_buttons()
        notify_triage_changed(self)
        missing = len(self.result.processes) - len(entries)
        lines = [f"{len(entries)} process image(s) dumped and hashed (SHA-256 + MD5 in {getattr(completed, 'manifest', '') or 'memorygraph_hashes.csv'})."]
        if missing > 0:
            lines.append(f"{missing} process(es) could not be dumped (kernel processes, exited or protected processes, unreadable headers).")
        blocked = self._process_images().unreadable(getattr(completed, "artifacts", []))
        if blocked:
            lines.append(f"{len(blocked)} dumped file(s) could not be read back to hash them, probably because an antivirus blocked them "
                         f"(that is common for malware): {', '.join(blocked[:6])}{' …' if len(blocked) > 6 else ''}. Their processes have no hash in the list.")
        if matches:
            lines.append(f"\nIOC HASH MATCH: {matches} finding(s) added (IOC-007).")
        elif iocs and iocs.of("hash"):
            lines.append("\nNo image matches your IOC hashes.")
        else:
            lines.append("\nYour IOC list has no hashes, so nothing was checked. The hashes are kept in the investigation and can be exported.")
        show_info(self, "Hash all process images", "\n".join(lines))

    @safe_slot
    def _hashes_failed(self, message, details) -> None:
        self.hash_button.setEnabled(True)
        self.status.setText("")
        show_error(self, "Hash all process images", message, details)

    @safe_slot
    def export_image_hashes(self, *_):
        path, _ = QFileDialog.getSaveFileName(self, "Export process image hashes", "process_image_hashes.csv", "CSV (*.csv)")
        if path:
            count = self._process_images().export_csv(self.result, path)
            show_info(self, "Export image hashes", f"{count} hash(es) written to:\n{path}")

    def open_pid(self, pid: int) -> None:
        proc = self.by_pid.get(pid)
        if proc is None:
            return
        from app.windows.process_window import ProcessWindow
        for existing in self._open_windows:        # never stack a second window for the same process
            if existing.process.pid == pid:
                existing.show()
                existing.raise_()
                existing.activateWindow()
                return
        settings = getattr(self.dashboard, "settings", None) or {}
        iocs, _problems = ioc_module.load_from_settings(settings)
        window = ProcessWindow(proc, self, dump_path=self.result.dump_path, findings=self.findings.get(pid, []),
                               volatility_path=settings.get("volatility_path", ""), iocs=iocs,
                               global_args=global_args(settings))
        window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self._open_windows.append(window)
        window.destroyed.connect(lambda *_a, w=window: self._open_windows.remove(w) if w in self._open_windows else None)
        window.show()
