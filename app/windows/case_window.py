"""Case Notes: bookmarks, notes, triage decisions and baselines of this investigation, with export."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)

from app.analysis import case_state
from app.engines import engine_for
from app.errors import safe_slot
from app.windows.case_actions import notify_case_changed, notify_triage_changed
from app.windows.widgets import FlowLayout, TableModel, make_table, muted, show_error, show_info


class CaseView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.engine = engine_for(result)
        self.dashboard = parent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Case Notes")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Your work on this investigation: bookmarks, notes, findings you reviewed or marked as false positive, and "
                               "known-good baselines. It is saved with the investigation (Save Investigation) and survives re-analysis."))
        bar = FlowLayout()
        actions = [("Export notes (Markdown)…", self.export_notes), ("Import baseline…", self.import_baseline),
                   ("Export baseline from all findings…", lambda: self.export_baseline(False)),
                   ("Export baseline from false positives…", lambda: self.export_baseline(True))]
        if self.engine.capabilities.known_good:
            actions += [("Export known-good modules…", self.export_known_good), ("Install known-good list…", self.install_known_good)]
        for text, handler in actions:
            button = QPushButton(text)
            button.clicked.connect(lambda _=False, h=handler: h())
            bar.addWidget(button)
        layout.addLayout(bar)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)
        self.refresh_after_triage()

    # ------------------------------------------------------------------ content
    def _table(self, columns, rows, payloads, widths, empty_text):
        page = QWidget()
        box = QVBoxLayout(page)
        if not rows:
            box.addWidget(muted(empty_text))
        model = TableModel(columns, rows, payloads=payloads)
        view, _proxy = make_table(model, widths)
        view.doubleClicked.connect(lambda index, p=_proxy: self._open(p.payload_at(index)))
        box.addWidget(view, 1)
        actions = QHBoxLayout()
        remove = QPushButton("Remove selected")
        remove.clicked.connect(lambda _=False, v=view, p=_proxy: self._remove(p.payload_at(v.currentIndex())))
        actions.addWidget(remove)
        actions.addWidget(muted("Double-click a row to jump to its process (or, for a plugin row, to that row in Plugin Output)."), 1)
        box.addLayout(actions)
        return page

    @safe_slot
    def refresh_after_triage(self, *_):
        case = case_state.ensure_case(self.result)
        current = self.tabs.currentIndex()
        self.tabs.clear()
        marks = [(t, m) for t, m in case["bookmarks"].items()]
        self.tabs.addTab(self._table(
            ["Kind", "Label", "PID", "Bookmarked"], [[m.get("kind", ""), m.get("label", ""), m.get("pid") or "", m.get("time", "")] for _t, m in marks],
            [("bookmark", t, m) for t, m in marks], [100, 520, 70, 200], "No bookmarks yet. Use the ☆ buttons in the Process Tree, a process's Modules tab, Network, Timeline and Plugin Output."),
            f"Bookmarks ({len(marks)})")
        notes = sorted(case["notes"], key=lambda n: n.get("time", ""))
        self.tabs.addTab(self._table(
            ["Kind", "About", "PID", "Note", "Written"], [[n.get("kind", ""), n.get("label", ""), n.get("pid") or "", n.get("text", ""), n.get("time", "")] for n in notes],
            [("note", n.get("id"), n) for n in notes], [90, 260, 60, 520, 190], "No notes yet. Use “Add note…” in the Process Tree, a process's Modules tab, Network, Timeline, Plugin Output or a finding."),
            f"Notes ({len(notes)})")
        decided = sorted(case["findings"].items(), key=lambda kv: kv[1].get("time", ""))
        live = {case_state.finding_key(i, next((p for p in self.result.processes if p.pid == i.process_pid), None)) for i in self.result.indications}
        self.tabs.addTab(self._table(
            ["Decision", "Rule", "Finding", "Process", "Reason", "Decided", "Still produced"],
            [[case_state.STATUS_LABEL.get(e.get("status", ""), e.get("status", "")), f"{e.get('rule_id', '')} {self.engine.rule_name(e.get('rule_id', ''))}".strip(),
              e.get("title", ""), (e.get("process", "") + (f" ({e['pid']})" if e.get("pid") else "")).strip(), e.get("note", ""), e.get("time", ""),
              "yes" if k in live else "no (rules changed or plugin missing)"] for k, e in decided],
            [("finding", k, e) for k, e in decided], [120, 260, 380, 150, 220, 180, 160],
            "No findings were reviewed yet. Open a finding in Indications to mark it as reviewed or false positive."),
            f"Triage decisions ({len(decided)})")
        baselines = case["baselines"]
        self.tabs.addTab(self._table(
            ["Baseline", "Known-good findings", "Source dump", "Imported", "Suppressing now"],
            [[b.get("name", ""), len(b.get("signatures", [])), b.get("source_dump", ""), b.get("imported", ""),
              sum(1 for i in self.result.indications if i.triage == "baseline" and b.get("name", "") in i.triage_note)] for b in baselines],
            [("baseline", b.get("name"), b) for b in baselines], [200, 150, 420, 190, 130],
            "No baselines. Analyse a clean dump of the same system, use “Export baseline from all findings…”, then import it here."),
            f"Baselines ({len(baselines)})")
        self.tabs.setCurrentIndex(min(current, self.tabs.count() - 1) if current >= 0 else 0)
        suppressed = sum(1 for i in self.result.indications if i.triage == "baseline")
        fps = sum(1 for i in self.result.indications if i.triage == "false_positive")
        self.status.setText(f"{fps} finding(s) hidden as false positive · {suppressed} suppressed by baselines")

    # ------------------------------------------------------------------ actions
    @safe_slot
    def _open(self, payload):
        if not payload:
            return
        kind, key, data = payload
        target = key if kind == "bookmark" else (data.get("target", "") if kind == "note" and isinstance(data, dict) else "")
        if str(target).startswith("row|") and hasattr(self.dashboard, "select_view") and hasattr(self.dashboard, "IDX"):
            view = self.dashboard.select_view(self.dashboard.IDX["Plugin Output"])       # a plugin row: jump to that row
            if hasattr(view, "show_plugin_by_name") and view.show_plugin_by_name(str(target).split("|")[1]):
                view.select_row_target(str(target))
            return
        if str(target).startswith("file|") and hasattr(self.dashboard, "select_view") and hasattr(self.dashboard, "IDX"):
            view = self.dashboard.select_view(self.dashboard.IDX["Files"])               # a file: show it in the explorer
            if hasattr(view, "select_target") and view.select_target(str(target)):
                return
        pid = data.get("pid") if isinstance(data, dict) else 0
        if pid and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(int(pid))

    @safe_slot
    def _remove(self, payload):
        if not payload:
            return
        kind, key, data = payload
        case = case_state.ensure_case(self.result)
        if kind == "bookmark":
            case["bookmarks"].pop(key, None)
            notify_case_changed(self)
        elif kind == "note":
            case_state.delete_note(self.result, key)
            notify_case_changed(self)
        elif kind == "finding":
            case["findings"].pop(key, None)         # forgetting a decision re-opens the finding
            case_state.apply_case(self.result)
            notify_triage_changed(self)
        elif kind == "baseline":
            case_state.remove_baseline(self.result, key)
            notify_triage_changed(self)
        self.refresh_after_triage()

    @safe_slot
    def export_notes(self, *_):
        path, _ = QFileDialog.getSaveFileName(self, "Export case notes", "case_notes.md", "Markdown (*.md)")
        if path:
            try:
                case_state.export_markdown(self.result, path)
            except OSError as exc:
                show_error(self, "Export case notes", f"The file could not be written.\n\n{exc}")
                return
            show_info(self, "Export case notes", f"Case notes written to:\n{path}")

    @safe_slot
    def export_baseline(self, only_false_positives: bool):
        path, _ = QFileDialog.getSaveFileName(self, "Export baseline", "baseline.json", "MemoryGraph baseline (*.json)")
        if not path:
            return
        try:
            count = case_state.export_baseline(self.result, path, only_false_positives=only_false_positives)
        except OSError as exc:
            show_error(self, "Export baseline", f"The file could not be written.\n\n{exc}")
            return
        show_info(self, "Export baseline", f"{count} known-good finding(s) written to:\n{path}\n\nImport it into another investigation of the same system to suppress them.")

    @safe_slot
    def export_known_good(self, *_):
        """The modules every program of THIS (clean) system has loaded, as a list other investigations of the same Windows can use."""
        from app.engines.windows.analysis import known_good
        path, _ = QFileDialog.getSaveFileName(self, "Export known-good modules", "known-good.json", "MemoryGraph known-good list (*.json)")
        if not path:
            return
        data = known_good.build(self.result)
        try:
            count = known_good.save(data, path)
        except OSError as exc:
            show_error(self, "Export known-good modules", f"The file could not be written.\n\n{exc}")
            return
        show_info(self, "Export known-good modules", f"{count} module name(s) of {len(data['modules'])} program(s) written to:\n{path}\n\nOnly export this from a system you know is clean: "
                  "everything in it is treated as normal. Install it (Install known-good list…) on the computer where you investigate.")

    @safe_slot
    def install_known_good(self, *_):
        from app.engines.windows.analysis import known_good
        path, _ = QFileDialog.getOpenFileName(self, "Install known-good list", "", "MemoryGraph known-good list (*.json);;All files (*)")
        if not path:
            return
        try:
            name, count = known_good.install(path)
        except ValueError as exc:
            show_error(self, "Install known-good list", str(exc))
            return
        show_info(self, "Install known-good list", f"'{name}' ({count} module names) is installed. It applies to every analysis of the same Windows version from now on "
                  "(re-analyse this investigation to use it now).")

    @safe_slot
    def import_baseline(self, *_):
        path, _ = QFileDialog.getOpenFileName(self, "Import baseline", "", "MemoryGraph baseline (*.json);;All files (*)")
        if not path:
            return
        try:
            name, count = case_state.import_baseline(self.result, path)
        except ValueError as exc:
            show_error(self, "Import baseline", str(exc))
            return
        notify_triage_changed(self)
        self.refresh_after_triage()
        suppressed = sum(1 for i in self.result.indications if i.triage == "baseline")
        show_info(self, "Import baseline", f"Baseline '{name}' with {count} known-good finding(s) applied; {suppressed} finding(s) in this investigation are now suppressed (hidden, not deleted).")
