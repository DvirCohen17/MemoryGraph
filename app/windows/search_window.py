"""Global search across processes, modules, endpoints, findings, users and plugins."""
from __future__ import annotations

from PySide6.QtWidgets import QDialog, QLabel, QLineEdit, QPlainTextEdit, QVBoxLayout, QWidget

from app.errors import safe_slot
from app.windows.widgets import TableModel, make_table, muted

MAX_RESULTS = 5000


class RelatedDetails(QDialog):
    def __init__(self, title, text, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(820, 600)
        layout = QVBoxLayout(self)
        box = QPlainTextEdit(text)
        box.setReadOnly(True)
        layout.addWidget(box)


class GlobalSearchView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        title = QLabel("Global Investigation Search")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Search processes, PIDs, DLLs, endpoints, rules, users and plugin names. Double-click a result to inspect related evidence."))
        self.query = QLineEdit()
        self.query.setPlaceholderText("Search anything in the investigation…")
        self.query.setClearButtonEnabled(True)
        layout.addWidget(self.query)
        self.model = TableModel(["Type", "Value", "PID", "Details"], [])
        self.view = None
        self.holder = QVBoxLayout()
        layout.addLayout(self.holder, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)
        self.query.textChanged.connect(self.refresh)
        self.refresh("")

    def _collect(self, text: str):
        q = (text or "").strip().lower()

        def match(*values):
            return not q or any(q in str(v or "").lower() for v in values)

        rows, payloads = [], []

        def add(kind, value, pid, details, payload):
            if len(rows) < MAX_RESULTS:
                rows.append([kind, value, pid, details])
                payloads.append(payload)

        for p in self.result.processes:
            if match(p.pid, p.name, p.path, p.command_line, p.user):
                add("Process", f"{p.name} ({p.pid})", p.pid, p.path or p.command_line, ("process", p))
            if q:   # modules and endpoints only when searching (thousands of rows otherwise)
                for dll in p.dlls:
                    if match(dll.name, dll.path, dll.base):
                        add("DLL", dll.name, p.pid, dll.path, ("dll", p, dll))
                for conn in p.network:
                    if match(conn.local, conn.remote, conn.local_address, conn.remote_address, conn.process, conn.pid):
                        add("Endpoint", conn.remote or conn.local, p.pid, f"{conn.process}: {conn.local} → {conn.remote}", ("network", p, conn))
        for ind in self.result.indications:
            if match(ind.rule_id, ind.title, ind.process_name, ind.process_pid, ind.severity):
                add("Finding", ind.rule_id, ind.process_pid, f"[{ind.severity}] {ind.title}", ("indication", ind))
        for user in self.result.users:
            if match(user):
                add("User", user, "", "Security identity", ("text", user))
        for plugin in self.result.plugins:
            if match(plugin.name, plugin.status):
                add("Plugin", plugin.name, "", plugin.status, ("plugin", plugin))
        return rows, payloads

    @safe_slot
    def refresh(self, text=""):
        rows, payloads = self._collect(text if isinstance(text, str) else self.query.text())
        self.model = TableModel(["Type", "Value", "PID", "Details"], rows, payloads=payloads)
        if self.view is not None:
            self.holder.removeWidget(self.view)
            self.view.deleteLater()
        self.view, self.proxy = make_table(self.model, [110, 320, 70, 600])
        self.view.doubleClicked.connect(self.open_result)
        self.holder.addWidget(self.view)
        suffix = f" (showing the first {MAX_RESULTS})" if len(rows) >= MAX_RESULTS else ""
        self.status.setText(f"{len(rows)} result(s){suffix}")

    @safe_slot
    def open_result(self, index):
        payload = self.proxy.payload_at(index)
        if not payload:
            return
        kind = payload[0]
        if kind == "process":
            if self.dashboard is not None and hasattr(self.dashboard, "show_process"):
                self.dashboard.show_process(payload[1].pid)
        elif kind == "dll":
            _, process, dll = payload
            RelatedDetails(f"DLL — {dll.name}", self._dll_text(dll), self).exec()
        elif kind == "network":
            _, process, conn = payload
            RelatedDetails(f"Endpoint — {conn.remote or conn.local}", self._network_text(conn), self).exec()
        elif kind == "indication":
            from app.windows.indications_window import IndicationDetails
            show = getattr(self.dashboard, "show_process", None)
            proc = next((p for p in self.result.processes if p.pid == payload[1].process_pid), None)
            IndicationDetails(payload[1], self, show, command_line=proc.command_line if proc else "", result=self.result).exec()
        elif kind == "plugin":
            plugin = payload[1]
            RelatedDetails(f"Plugin — {plugin.name}", plugin.raw_output or f"{len(plugin.rows)} rows. Open Plugin Output to browse them.", self).exec()

    def _dll_text(self, dll) -> str:
        matches = []
        for proc in self.result.processes:
            if any(d.name.lower() == dll.name.lower() and (not dll.path or d.path.lower() == dll.path.lower()) for d in proc.dlls):
                matches.append(proc)
        lines = [f"DLL: {dll.name}", f"Path: {dll.path}", f"Base: {dll.base}", f"Size: {dll.size}", "", "Processes that loaded this DLL:"]
        lines.extend(f"  • {p.name} (PID {p.pid}) — {p.path}" for p in matches[:200])
        if not matches:
            lines.append("  • No additional matching process records")
        return "\n".join(lines)

    def _network_text(self, conn) -> str:
        matches = []
        for proc in self.result.processes:
            if any(c.remote == conn.remote and c.local == conn.local for c in proc.network):
                matches.append(proc)
        lines = [f"Endpoint: {conn.remote or conn.local}", f"Local: {conn.local}", f"Remote: {conn.remote}", f"State: {conn.state}",
                 f"Protocol: {conn.protocol}", "", "Processes associated with this endpoint:"]
        lines.extend(f"  • {p.name} (PID {p.pid}) — {p.path}" for p in matches)
        if not matches:
            lines.append("  • No additional matching process record")
        return "\n".join(lines)
