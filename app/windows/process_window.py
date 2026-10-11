"""Full details of one process, organised in tabs (Summary, Modules, Network, Memory, Handles, Identity)."""
from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QSplitter,
    QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from app.analysis import case_state
from app.engines import engine_for
from app.analysis.indicators.scoring import severity_rank
from app.errors import safe_slot
from app.tasks import BackgroundTask
from app.util import format_time, to_int
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import (
    TableModel, badge_html, decoded_command_html, escape, make_table, muted, section_title, show_error, show_info,
)


class ProcessWindow(QDialog):
    def __init__(self, process, parent=None, dump_path: str = "", findings: Optional[list] = None, volatility_path: str = "", iocs=None, global_args=()):
        super().__init__(parent)
        self.process = process
        self.iocs = iocs          # IocSet or None: dumped files are checked against its hash entries
        owner = parent
        while owner is not None and not hasattr(owner, "result"):
            owner = owner.parent() if hasattr(owner, "parent") else None
        self.result = getattr(owner, "result", None)
        self.engine = engine_for(self.result)          # the operating system of this investigation (its words, its dumper, its idea of a risky folder)
        self.dump_path = dump_path or getattr(self.result, "dump_path", "")
        self.volatility_path = volatility_path
        self.global_args = list(global_args)
        self.findings = list(findings or [])
        self._task = None
        self.last_dump_dir = ""            # where "Dump malfind pages" last wrote: the hex view looks there for a region's dump file
        self.setWindowTitle(f"Process — {process.name} ({process.pid})")
        self.resize(1180, 820)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 14)
        title = QLabel(process.name)
        title.setObjectName("Title")
        layout.addWidget(title)
        session = process.session if process.session >= 0 else "—"
        subtitle = QLabel(f"PID {process.pid}  •  Parent PID {process.ppid}  •  {process.user or 'Unknown user'}  •  session {session}")
        subtitle.setObjectName("Subtitle")
        layout.addWidget(subtitle)

        actions = QHBoxLayout()
        self.buttons: List[QPushButton] = []
        for label, handler, primary in (
            ("Dump process image", self.dump_process, True), (self.engine.terms.dump_modules, self.dump_dlls, False),
            ("Dump malfind pages", self.dump_memory, False), ("Dump file handles", self.dump_handles, False),
        ):
            button = QPushButton(label)
            if primary:
                button.setObjectName("Primary")
            button.clicked.connect(handler)
            actions.addWidget(button)
            self.buttons.append(button)
        provenance = QPushButton("Field provenance")
        provenance.clicked.connect(self.show_provenance)
        actions.addWidget(provenance)
        actions.addStretch()
        layout.addLayout(actions)
        self.action_status = muted("", wrap=False)
        layout.addWidget(self.action_status)

        tabs = QTabWidget()
        tabs.addTab(self._summary_tab(), "Summary")
        story_tab = self._story_tab()
        tabs.addTab(story_tab, f"Story ({self.story_count})")
        tabs.addTab(self._modules_tab(), f"{self.engine.terms.modules_tab} ({len(process.dlls)})")
        tabs.addTab(self._network_tab(), f"Network ({len(process.network)})")
        tabs.addTab(self._memory_tab(), f"Memory ({len(process.memory_regions)})")
        tabs.addTab(self._handles_tab(), f"{self.engine.terms.handles} ({sum(process.handle_summary.values()) or len(process.handles)})")
        tabs.addTab(self._identity_tab(), f"Identity ({len(process.groups)})")
        layout.addWidget(tabs, 1)

        close = QPushButton("Close")
        close.clicked.connect(self.close)
        layout.addWidget(close, 0, Qt.AlignmentFlag.AlignRight)

    # ------------------------------------------------------------------ tabs
    def _story_tab(self) -> QWidget:
        """Everything known about this process on one clock: who started it, what was written or run around it, its connections, what it started."""
        from app.analysis import story
        items = story.build(self.result, self.process.pid) if self.result is not None else []
        self.story_count = len(items)
        browser = QTextBrowser()
        self.story = browser
        if not items:
            browser.setHtml("<p style='color:#76859a'>Nothing is known about this process beyond the Summary.</p>")
            return browser
        colours = {"finding": "#e5a24b", "start": "#7aa7ff", "network": "#9ad1a0", "child": "#c0a2ff", "exit": "#76859a"}
        rows = []
        for item in items:
            when = story.display_time(item) or "—"
            rel = story.describe_offset(item.seconds)
            badge = badge_html(item.severity) + " " if item.severity else ""
            rows.append(f"<tr><td style='color:#76859a;padding-right:10px;white-space:nowrap'>{escape(when)}</td>"
                        f"<td style='padding-right:10px;white-space:nowrap;color:#76859a'>{escape(rel)}</td>"
                        f"<td style='padding-right:10px;color:{colours.get(item.kind, '#b6c2d4')}'>{escape(item.kind)}</td>"
                        f"<td>{badge}{escape(item.text)}"
                        + (f"<br><span style='color:#76859a'>{escape(item.source)}</span>" if item.source else "") + "</td></tr>")
        browser.setHtml("<p style='color:#76859a'>What the plugins reported about this process, in time order (the second column is relative to its start). "
                        "It arranges the evidence; it is not a verdict.</p><table cellspacing='6'>" + "".join(rows) + "</table>")
        return browser

    def _summary_tab(self) -> QWidget:
        p = self.process
        widget = QWidget()
        layout = QVBoxLayout(widget)
        found_by = {"pslist": "windows.pslist (active list)", "psscan": "windows.psscan only (not in pslist)",
                    "pstree": "windows.pstree"}.get(p.source, p.source)
        facts = [
            ("Image", p.path or "unknown"), ("Image base", p.image_base or "unknown"), ("Offset", p.offset or "unknown"),
            ("Started", format_time(p.create_time) if p.create_time else "unknown"),
            ("Exited", format_time(p.exit_time) if p.exit_time else "still running at capture"),
            ("Threads", p.threads or "unknown"), ("WOW64 (32-bit)", "yes" if p.wow64 else "no"), ("Found by", found_by),
        ]
        body = "".join(f"<tr><td style='color:#76859a;padding-right:14px'>{k}</td><td>{escape(v)}</td></tr>" for k, v in facts)
        card = QTextBrowser()
        card.setHtml(f"<table>{body}</table>")
        card.setMaximumHeight(230)
        layout.addWidget(card)
        layout.addWidget(section_title("Command line"))
        command = QPlainTextEdit(p.command_line or "Not available (windows.cmdline did not return it for this process).")
        command.setReadOnly(True)
        command.setMaximumHeight(90)
        layout.addWidget(command)
        decoded = decoded_command_html(p.command_line, p.pid)
        if decoded:
            decoded_view = QTextBrowser()
            decoded_view.setHtml(decoded)
            decoded_view.setMaximumHeight(200)
            layout.addWidget(decoded_view)
        layout.addWidget(section_title("Findings"))
        findings = QTextBrowser()
        if not self.findings:
            findings.setHtml("<p style='color:#76859a'>No findings were raised for this process.</p>")
        else:
            html = []
            for f in sorted(self.findings, key=lambda x: (-severity_rank(x.severity), -x.score)):
                reasons = "".join(f"<li>{escape(r)}</li>" for r in f.reasons[:6])
                evidence = "".join(f"<li><code>{escape(e)}</code></li>" for e in f.evidence[:5])
                html.append(f"<p>{badge_html(f.severity)} <b>{escape(f.rule_id)}</b> — {escape(f.title)}"
                            f"<br><span style='color:#7a899e'>{escape(f.summary)}</span></p><ul>{reasons}{evidence}</ul>")
            findings.setHtml("".join(html))
        layout.addWidget(findings, 1)
        return widget

    def _modules_tab(self) -> QWidget:
        p = self.process
        widget = QWidget()
        layout = QVBoxLayout(widget)
        bar = QHBoxLayout()
        search = QLineEdit()
        search.setPlaceholderText("Filter modules…")
        search.setClearButtonEnabled(True)
        bar.addWidget(search, 1)
        self.only_unusual = QCheckBox("Only modules outside Windows/Program Files")
        bar.addWidget(self.only_unusual)
        layout.addLayout(bar)
        rows, payloads, colors = [], [], {}
        for index, dll in enumerate(p.dlls):
            if self.engine.is_risky_path(dll.path):
                note = "temp/download folder"
                colors[index] = "#c77700"
            elif dll.path and not self.engine.is_trusted_path(dll.path):
                note = "outside system folders"
            else:
                note = ""
            rows.append([dll.name, dll.path, dll.base, dll.size, dll.load_time[:19].replace("T", " ") if dll.load_time else "",
                         self._dll_marks(dll), note])
            payloads.append((dll, bool(note)))
        self.modules_model = TableModel(["Module", "Path", "Base", "Size", "Loaded", "Marks", "Note"], rows, payloads=payloads, colors=colors)
        self.modules_view, self.modules_proxy = make_table(self.modules_model, [190, 470, 130, 80, 150, 60, 160])
        layout.addWidget(self.modules_view, 1)
        search.textChanged.connect(self.modules_proxy.set_text)
        self.only_unusual.toggled.connect(self._toggle_unusual)
        marks = QHBoxLayout()
        self.dll_bookmark_button = QPushButton("☆ Bookmark module")
        self.dll_note_button = QPushButton("✎ Add note…")
        for button in (self.dll_bookmark_button, self.dll_note_button):
            button.setEnabled(False)
            marks.addWidget(button)
        self.dll_note_info = muted("Select a module to bookmark it or add a note (listed in Case Notes)." if self.result is not None
                                   else "Bookmarks and notes are available when the process is opened from an investigation.")
        marks.addWidget(self.dll_note_info, 1)
        layout.addLayout(marks)
        self.modules_view.selectionModel().currentRowChanged.connect(self._on_dll_selected)
        self.dll_bookmark_button.clicked.connect(self.toggle_dll_bookmark)
        self.dll_note_button.clicked.connect(self.add_dll_note)
        layout.addWidget(muted("“Dump DLLs” extracts every module of this process into the folder you choose."))
        return widget

    # -- bookmarks and notes on modules
    def _dll_marks(self, dll) -> str:
        if self.result is None:
            return ""
        starred, noted = case_state.has_marks(self.result, case_state.dll_target(self.process, dll))
        return ("★" if starred else "") + ("✎" if noted else "")

    def _current_dll(self):
        payload = self.modules_proxy.payload_at(self.modules_view.currentIndex())
        return payload[0] if payload else None

    def _dll_label(self, dll) -> str:
        return f"{dll.name} in {self.process.name} (PID {self.process.pid})"

    def _refresh_dll_marks(self) -> None:
        for number, dll in enumerate(self.process.dlls):
            if number < len(self.modules_model.rows):
                self.modules_model.rows[number][5] = self._dll_marks(dll)
        if self.modules_model.rows:
            self.modules_model.dataChanged.emit(self.modules_model.index(0, 5), self.modules_model.index(len(self.modules_model.rows) - 1, 5))
        self._on_dll_selected()

    @safe_slot
    def _on_dll_selected(self, *_):
        dll = self._current_dll()
        usable = dll is not None and self.result is not None
        self.dll_bookmark_button.setEnabled(usable)
        self.dll_note_button.setEnabled(usable)
        if not usable:
            return
        target = case_state.dll_target(self.process, dll)
        self.dll_bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, target) else "☆ Bookmark module")
        notes = case_state.notes_for(self.result, target)
        self.dll_note_info.setText("Your notes: " + " · ".join(escape(n.get("text", "")) for n in notes) if notes else "No notes on this module.")

    @safe_slot
    def toggle_dll_bookmark(self, *_):
        dll = self._current_dll()
        if dll is not None and self.result is not None:
            toggle_bookmark(self, self.result, "dll", case_state.dll_target(self.process, dll), self._dll_label(dll)[:140], self.process.pid)
            self._refresh_dll_marks()

    @safe_slot
    def add_dll_note(self, *_):
        dll = self._current_dll()
        if dll is not None and self.result is not None and ask_and_add_note(
                self, self.result, "dll", case_state.dll_target(self.process, dll), self._dll_label(dll)[:140], self.process.pid):
            self._refresh_dll_marks()

    @safe_slot
    def _toggle_unusual(self, checked=False):
        self.modules_proxy.set_predicate((lambda payload, _values: bool(payload and payload[1])) if checked else None)

    def _network_tab(self) -> QWidget:
        p = self.process
        widget = QWidget()
        layout = QVBoxLayout(widget)
        rows = [[c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port, c.state,
                 c.created[:19].replace("T", " ") if c.created else "", ", ".join(c.source_plugins)] for c in p.network]
        model = TableModel(["Proto", "Local address", "Local port", "Remote address", "Remote port", "State", "Created", "Source"], rows)
        view, _proxy = make_table(model, [70, 180, 90, 180, 100, 120, 160, 180])
        layout.addWidget(view)
        if not rows:
            layout.addWidget(muted("No network connections were attributed to this process."))
        return widget

    def _memory_tab(self) -> QWidget:
        p = self.process
        widget = QWidget()
        layout = QVBoxLayout(widget)
        splitter = QSplitter(Qt.Orientation.Vertical)
        rows = [[r.range, r.size, r.protection, "Yes" if r.private else "No", r.tag, r.source_plugin] for r in p.memory_regions]
        model = TableModel(["Range", "Size", "Protection", "Private", "Tag", "Source"], rows, payloads=list(p.memory_regions))
        self.region_view, self.region_proxy = make_table(model, [300, 90, 220, 70, 70, 160])
        splitter.addWidget(self.region_view)
        self.region_text = QPlainTextEdit()
        self.region_text.setReadOnly(True)
        self.region_text.setStyleSheet("QPlainTextEdit{font-family:Consolas,'Courier New',monospace;}")
        self.region_text.setPlainText("Select a region to preview its first bytes and disassembly." if rows
                                      else "No executable private regions were reported by malfind.")
        splitter.addWidget(self.region_text)
        splitter.setSizes([260, 300])
        layout.addWidget(splitter, 1)
        bar = QHBoxLayout()
        self.hex_button = QPushButton("Open hex view…")
        self.hex_button.setEnabled(False)
        bar.addWidget(self.hex_button)
        bar.addWidget(muted("Offsets, search, inspector and a disassembly of every loaded byte. Double-click a region to open it."), 1)
        layout.addLayout(bar)
        self.region_view.selectionModel().currentRowChanged.connect(self._show_region)
        self.region_view.doubleClicked.connect(self.open_hex_view)
        self.hex_button.clicked.connect(self.open_hex_view)
        return widget

    @safe_slot
    def open_hex_view(self, *_):
        region = self.region_proxy.payload_at(self.region_view.currentIndex())
        if region is None:
            return
        from app.windows.hex_view import HexViewDialog
        view = HexViewDialog(region, self.process, self, result=self.result, dump_dir=self.last_dump_dir)
        view.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        view.show()
        self._hex_views = [v for v in getattr(self, "_hex_views", []) if v.isVisible()] + [view]

    @safe_slot
    def _show_region(self, *_):
        region = self.region_proxy.payload_at(self.region_view.currentIndex())
        self.hex_button.setEnabled(region is not None)
        if region is None:
            return
        details = region.details or {}
        hexdump = details.get("Hexdump") or details.get("hexdump") or "(no hexdump stored)"
        disasm = details.get("Disasm") or details.get("disasm") or "(no disassembly stored)"
        self.region_text.setPlainText(f"Region {region.range}  {region.protection}\n\n--- Hexdump ---\n{hexdump}\n\n--- Disassembly ---\n{disasm}")

    def _handles_tab(self) -> QWidget:
        p = self.process
        widget = QWidget()
        layout = QVBoxLayout(widget)
        if p.handle_summary:
            top = sorted(p.handle_summary.items(), key=lambda kv: -kv[1])[:12]
            layout.addWidget(muted("Handle counts by type: " + ", ".join(f"{k} {v}" for k, v in top)))
        search = QLineEdit()
        search.setPlaceholderText("Filter handles (type, name)…")
        search.setClearButtonEnabled(True)
        layout.addWidget(search)
        rows = []
        for h in p.handles:
            if not isinstance(h, dict):
                continue
            access = to_int(h.get("access"), 0) or 0
            rows.append([h.get("type", ""), h.get("name", ""), h.get("value", ""), f"0x{access:x}" if access else ""])
        model = TableModel(["Type", "Name", "Handle", "Access"], rows)
        view, proxy = make_table(model, [120, 640, 100, 100])
        layout.addWidget(view, 1)
        search.textChanged.connect(proxy.set_text)
        layout.addWidget(muted("Only named handles (and every process/thread/file/key/mutant handle) are kept here; "
                               "the full list is in Plugin Output → windows.handles."))
        return widget

    def _identity_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.addWidget(muted(f"Process owner: {self.process.user or 'unknown'}. Groups from windows.getsids:"))
        model = TableModel(["Security identifier"], [[g] for g in self.process.groups])
        view, _proxy = make_table(model, [800])
        layout.addWidget(view, 1)
        return widget

    # ------------------------------------------------------------------ actions
    def _set_busy(self, busy: bool, text: str = "") -> None:
        for button in self.buttons:
            button.setEnabled(not busy)
        self.action_status.setText(text)

    def _run_dump(self, label: str, action) -> None:
        if self._task is not None and self._task.running:
            return
        output_dir = QFileDialog.getExistingDirectory(self, "Choose dump output directory")
        if not output_dir:
            return
        self._set_busy(True, f"{label} running… this can take several minutes for large processes.")
        task = BackgroundTask(lambda ctx: action(output_dir), self)
        task.finished.connect(lambda result, d=output_dir, l=label: self._dump_done(l, d, result))
        task.failed.connect(lambda message, details, l=label: self._dump_failed(l, message, details))
        self._task = task
        task.start()

    @safe_slot
    def _dump_done(self, label, output_dir, result):
        self._set_busy(False, f"{label} finished.")
        if label == "Memory page dump":
            self.last_dump_dir = output_dir
        completed, command = result
        artifacts = getattr(completed, "artifacts", [])
        if artifacts:
            listing = "\n".join(f"  {a.sha256 or '(' + (getattr(a, 'error', '') or 'not hashed') + ')'}  {a.name}" for a in artifacts[:12])
            more = f"\n  … and {len(artifacts) - 12} more" if len(artifacts) > 12 else ""
            hashes = (f"\n\n{len(artifacts)} file(s) written. SHA-256 (full list with MD5 in {getattr(completed, 'manifest', '')}):\n"
                      f"{listing}{more}")
            hits = [f"  {a.name}: {ioc.describe()}" for a in artifacts for ioc in (self.iocs.match_hash(a.sha256) + self.iocs.match_hash(a.md5))] if self.iocs else []
            if hits:
                hashes += "\n\n⚠ IOC HASH MATCH (your IOC list):\n" + "\n".join(hits)
        else:
            hashes = "\n\nNo new files were written (the plugin found nothing to dump)."
        show_info(self, label, f"Dump completed.\n\nOutput directory:\n{output_dir}{hashes}\n\nCommand:\n{' '.join(command)}")

    @safe_slot
    def _dump_failed(self, label, message, details):
        self._set_busy(False, f"{label} failed.")
        show_error(self, f"{label} failed", message, details)

    def _dumper(self):
        return self.engine.make_dumper(self.dump_path, self.volatility_path, self.global_args)

    @safe_slot
    def dump_process(self, *_):
        self._run_dump("Process dump", lambda out: self._dumper().dump_process(self.process.pid, out))

    @safe_slot
    def dump_dlls(self, *_):
        self._run_dump("DLL dump", lambda out: self._dumper().dump_dlls(self.process.pid, out))

    @safe_slot
    def dump_memory(self, *_):
        if not self.process.memory_regions:
            show_info(self, "Dump malfind pages", "malfind reported no executable private regions for this process.")
            return
        self._run_dump("Memory page dump", lambda out: self._dumper().dump_malfind_pages(self.process.pid, out))

    @safe_slot
    def dump_handles(self, *_):
        if not self.process.handles:
            show_info(self, "Dump file handles", "No handle records were normalized for this process.")
            return
        self._run_dump("Handle/file dump", lambda out: self._dumper().dump_handles(self.process.pid, out))

    @safe_slot
    def show_provenance(self, *_):
        lines = [f"{field}: {data}" for field, data in self.process.provenance.items()]
        show_info(self, "Field provenance", "\n".join(lines) or "No field provenance is available.")
