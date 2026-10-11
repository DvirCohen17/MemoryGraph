"""Injection: for every process with a memory-level sign, the evidence from all plugins in one story.

Left, the processes ranked by how many kinds of evidence they have; right, the story of the selected one in three parts: what is in the process, who could
have put it there, and what the process did afterwards. A chain is a way of reading what the plugins reported, not a verdict: operating-system
processes hold write-capable handles into other processes all the time and are left out of "who could have done it".
"""
from __future__ import annotations

from typing import List

from PySide6.QtCore import QUrl, Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QPushButton, QSplitter, QTextBrowser, QVBoxLayout, QWidget

from app.engines.windows.analysis import injection
from app.engines.windows.analysis.injection import Chain
from app.errors import safe_slot
from app.windows.widgets import TableModel, badge_html, escape, make_table, muted, severity_color


class InjectionView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self.chains: List[Chain] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Injection")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Processes with at least one memory-level sign (executable private memory, an image in no loader list, a thread outside any module, "
                               "hollowing, a rewritten PEB, patched ETW), with everything else known about them from the plugins that ran. A chain is a way of "
                               "reading the evidence, not a verdict."))
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.model = TableModel(["Process", "PID", "Evidence", "Score"], [])
        self.table, self.proxy = make_table(self.model, [150, 60, 330, 60])
        self.table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
        splitter.addWidget(self.table)
        side = QWidget()
        box = QVBoxLayout(side)
        box.setContentsMargins(0, 0, 0, 0)
        self.story = QTextBrowser()
        self.story.setOpenLinks(False)
        self.story.setOpenExternalLinks(False)
        box.addWidget(self.story, 1)
        row = QHBoxLayout()
        self.open_button = QPushButton("Open process details…")
        self.open_button.setObjectName("Primary")
        self.open_button.setEnabled(False)
        row.addWidget(self.open_button)
        row.addStretch()
        box.addLayout(row)
        splitter.addWidget(side)
        splitter.setSizes([560, 700])
        layout.addWidget(splitter, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)
        self.table.selectionModel().currentRowChanged.connect(self.show_chain)
        self.table.doubleClicked.connect(lambda index: self.open_process(self.proxy.payload_at(index)))
        self.story.anchorClicked.connect(self.on_link)
        self.open_button.clicked.connect(lambda *_: self.open_process(self._current()))
        self.refresh_after_triage()

    @safe_slot
    def refresh_after_triage(self, *_):
        """Rebuild the chains (a finding marked as false positive no longer counts)."""
        self.chains = injection.build_chains(self.result)
        rows = [[c.process, c.pid, ", ".join(injection.KIND_LABEL.get(k, k) for k in sorted(c.kinds - {"child"})) or "—", c.score] for c in self.chains]
        self.model = TableModel(["Process", "PID", "Evidence", "Score"], rows, payloads=list(self.chains))
        self.proxy.setSourceModel(self.model)
        self.status.setText(f"{len(self.chains)} process(es) with memory-level signs" if self.chains else
                            "No process has a memory-level sign. (Run the Injected code, Deep check and Malware hunting groups under Settings → Plugins for more.)")
        if self.chains:
            self.table.selectRow(0)
        else:
            self.story.setHtml("<p style='color:#76859a'>Nothing to show.</p>")
            self.open_button.setEnabled(False)

    def _current(self):
        return self.proxy.payload_at(self.table.currentIndex())

    @safe_slot
    def show_chain(self, *_):
        chain = self._current()
        self.open_button.setEnabled(chain is not None)
        if chain is None:
            return
        html = [f"<h2>{escape(chain.process)} (PID {chain.pid})</h2>", f"<p style='color:#7a899e'>{escape(injection.parent_line(self.result, chain.pid))}</p>"]
        phase = ""
        number = 0
        for step in chain.steps:
            if step.phase != phase:
                phase = step.phase
                html.append(f"<h3>{escape(phase)}</h3>")
            number += 1
            who = f" <a href='pid:{step.pid}'>open PID {step.pid}</a>" if step.pid and step.pid != chain.pid and step.kind in ("handle", "child") else ""
            html.append(f"<p>{number}. {badge_html(step.severity)} {escape(step.text)}{who}"
                        f"<br><span style='color:#76859a'>{escape(injection.KIND_LABEL.get(step.kind, step.kind))}"
                        f"{' · ' + escape(step.source) if step.source else ''}</span></p>")
        html.append("<p style='color:#76859a'>Several kinds of evidence on one process are stronger than any one of them. Handles held by operating-system processes "
                    "are left out: they are normal.</p>")
        self.story.setHtml("".join(html))

    @safe_slot
    def on_link(self, url: QUrl):
        text = url.toString()
        if text.startswith("pid:") and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(int(text[4:]))

    @safe_slot
    def open_process(self, chain):
        if chain is not None and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(chain.pid)
