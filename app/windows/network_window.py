"""Network connections (deduplicated across netscan/netstat) with practical filters."""
from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QVBoxLayout, QWidget

from app.analysis.indicators.base import is_public_ip
from app.errors import safe_slot
from app.analysis import case_state
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import TableModel, compact_combo, escape, make_table, muted

_NOISE_ADDRESSES = {"", "*", "0.0.0.0", "::", "[::]"}


class NetworkView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        connections = list(result.connections) or [c for p in result.processes for c in p.network]
        process_names = {p.pid: p.name for p in result.processes}

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        title = QLabel("Network Activity")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Connections from windows.netscan and windows.netstat, merged. An endpoint alone is not treated as malicious."))

        controls = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter process, PID, address, port…")
        self.search.setClearButtonEnabled(True)
        controls.addWidget(self.search, 1)
        self.state = compact_combo(QComboBox(), 14)
        self.state.addItem("All states")
        self.state.addItems(sorted({c.state for c in connections if c.state}))
        controls.addWidget(self.state)
        self.external = QCheckBox("External only")
        self.hide_listen = QCheckBox("Hide listening / unconnected")
        controls.addWidget(self.external)
        controls.addWidget(self.hide_listen)
        layout.addLayout(controls)

        rows, sorts, payloads = [], [], []
        for c in connections:
            name = c.process or process_names.get(c.pid, "") or "Unknown"
            external = bool(c.remote_address) and is_public_ip(c.remote_address)
            rows.append([c.pid if c.pid >= 0 else "", name, c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port,
                         c.state, c.created[:19].replace("T", " ") if c.created else "", "external" if external else ""])
            sorts.append([c.pid, name.lower(), c.protocol, c.local_address, _port(c.local_port), c.remote_address, _port(c.remote_port),
                          c.state, c.created, 1 if external else 0])
            payloads.append((c, external))
        colors = {i: "#2ec4a6" for i, (_c, ext) in enumerate(payloads) if ext}
        self.model = TableModel(["PID", "Process", "Proto", "Local address", "Local port", "Remote address", "Remote port", "State", "Created", "Scope"],
                                rows, sort_rows=sorts, payloads=payloads, colors=colors)
        self.view, self.proxy = make_table(self.model, [60, 160, 80, 170, 90, 170, 100, 120, 150, 80], sort_column=0)
        layout.addWidget(self.view, 1)
        marks = QHBoxLayout()
        self.bookmark_button = QPushButton("☆ Bookmark connection")
        self.note_button = QPushButton("✎ Add note…")
        for button in (self.bookmark_button, self.note_button):
            button.setEnabled(False)
            marks.addWidget(button)
        self.note_info = muted("Select a connection to bookmark it or add a note (listed in Case Notes).")
        marks.addWidget(self.note_info, 1)
        layout.addLayout(marks)
        self.summary = muted("", wrap=False)
        layout.addWidget(self.summary)
        self.view.selectionModel().currentRowChanged.connect(self.on_select)
        self.bookmark_button.clicked.connect(self.toggle_bookmark_current)
        self.note_button.clicked.connect(self.add_note_current)

        self.search.textChanged.connect(self.apply)
        self.state.currentIndexChanged.connect(self.apply)
        self.external.toggled.connect(self.apply)
        self.hide_listen.toggled.connect(self.apply)
        self.apply()

    def _current(self):
        payload = self.proxy.payload_at(self.view.currentIndex())
        return payload[0] if payload else None

    def _label(self, conn) -> str:
        return f"{conn.process or 'PID ' + str(conn.pid)} {conn.protocol} {conn.local} → {conn.remote or '*'} {conn.state}".strip()

    @safe_slot
    def on_select(self, *_):
        conn = self._current()
        self.bookmark_button.setEnabled(conn is not None)
        self.note_button.setEnabled(conn is not None)
        if conn is None:
            return
        target = case_state.network_target(conn)
        self.bookmark_button.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, target) else "☆ Bookmark connection")
        notes = case_state.notes_for(self.result, target)
        self.note_info.setText("Your notes: " + " · ".join(escape(n.get("text", "")) for n in notes) if notes else "No notes on this connection.")

    @safe_slot
    def toggle_bookmark_current(self, *_):
        conn = self._current()
        if conn is not None:
            toggle_bookmark(self, self.result, "network", case_state.network_target(conn), self._label(conn)[:140], max(conn.pid, 0))
            self.on_select()

    @safe_slot
    def add_note_current(self, *_):
        conn = self._current()
        if conn is not None and ask_and_add_note(self, self.result, "network", case_state.network_target(conn), self._label(conn)[:140], max(conn.pid, 0)):
            self.on_select()

    @safe_slot
    def apply(self, *_):
        state = self.state.currentText()
        external_only = self.external.isChecked()
        hide_listen = self.hide_listen.isChecked()

        def predicate(payload, _values):
            if payload is None:
                return True
            conn, external = payload
            if state != "All states" and conn.state != state:
                return False
            if external_only and not external:
                return False
            if hide_listen and (conn.state.upper() == "LISTENING" or conn.remote_address in _NOISE_ADDRESSES):
                return False
            return True

        self.proxy.set_predicate(predicate)
        self.proxy.set_text(self.search.text())
        self.summary.setText(f"{self.proxy.rowCount()} of {self.model.rowCount()} connections shown")


def _port(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1
