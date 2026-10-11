"""Indications: investigation leads, grouped by process and ranked by risk.

The previous list showed every finding as one flat row (hundreds for a normal system). Here:
  * Low-priority findings are hidden by default (they still count towards a process score),
  * findings are grouped under their process, ordered by risk score,
  * rules can be filtered by name, and
  * the detail dialog explains *why* a rule fired and what the rule looks for.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QTextBrowser,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from app.analysis import case_state
from app.engines import engine_for, get_engine
from app.analysis.indicators.scoring import active_findings, is_active, risk_by_pid, severity_rank
from app.errors import safe_slot
from app.windows.case_actions import ask_and_add_note, notify_triage_changed
from app.windows.widgets import FlowLayout, badge_html, compact_combo, decoded_command_html, escape, info_card, muted, severity_color

FINDING_ROLE = Qt.ItemDataRole.UserRole
PROCESS_ROLE = Qt.ItemDataRole.UserRole + 1

SEVERITY_FILTERS = [("Medium and High (recommended)", 2), ("High only", 3), ("Low, Medium and High", 1)]


class IndicationDetails(QDialog):
    def __init__(self, indication, parent=None, on_show_process=None, command_line: str = "", result=None):
        super().__init__(parent)
        self.indication = indication
        self.engine = engine_for(result) if result is not None else get_engine()      # the operating system the finding is from
        self.on_show_process = on_show_process
        self.result = result          # given: the triage buttons are shown
        self.changed = False          # True once the investigator changed the triage state or added a note
        self.setWindowTitle(indication.title)
        self.resize(860, 720)
        layout = QVBoxLayout(self)
        title = QLabel(indication.title)
        title.setObjectName("Title")
        title.setWordWrap(True)
        layout.addWidget(title)
        meta = (f"{indication.severity} priority  •  confidence: {indication.confidence}  •  rule: {indication.rule_id} "
                f"({self.engine.rule_name(indication.rule_id)})  •  score {indication.score}")
        if indication.process_pid:
            meta += f"  •  {indication.process_name} (PID {indication.process_pid})"
        sub = QLabel(meta)
        sub.setObjectName("Subtitle")
        sub.setWordWrap(True)
        layout.addWidget(sub)

        view = QTextBrowser()
        html = [f"<p>{badge_html(indication.severity, indication.severity)} {escape(indication.summary)}</p>"]
        rule = self.engine.rule_catalog().get(indication.rule_id)
        if rule is not None and rule.description:
            html.append(f"<p style='color:#76859a'><b>What this rule looks for:</b> {escape(rule.description)}</p>")
        for heading, items in (("Why this was raised", indication.reasons), ("Evidence", indication.evidence),
                               ("Source plugins", indication.source_plugins), ("Related processes", indication.related_processes)):
            if items:
                body = "".join(f"<li>{escape(x)}</li>" for x in items)
                html.append(f"<h3>{heading}</h3><ul>{body}</ul>")
        if indication.evidence_items:
            body = "".join(f"<li>{escape(e.type)}.{escape(e.field)} = {escape(e.value)} [{escape(e.source_plugin)}, row {e.row_index}]</li>"
                           for e in indication.evidence_items)
            html.append(f"<h3>Structured evidence</h3><ul>{body}</ul>")
        # the evidence line is cut at 600 characters, so decode from the process's full command line when we have it
        cmd = command_line or next((e[len("Command line: "):] for e in indication.evidence if e.startswith("Command line: ")), "")
        html.append(decoded_command_html(cmd, indication.process_pid))
        techniques = self.engine.attack_for(indication.rule_id)
        if techniques:
            parts = []
            for t in techniques:                                    # details come from the local file app/engines/windows/data/attack_techniques.json
                info = t.info
                detail = ""
                if info.summary:
                    detail = (f"<br><span style='color:#7a899e'>{escape(', '.join(info.tactics))}. {escape(info.summary)}</span>"
                              + (f"<br><span style='color:#7a899e'><b>Look for:</b> {escape(info.look_for)}</span>" if info.look_for else ""))
                parts.append(f"<li><b>{escape(t.id)}</b> — {escape(t.name)}{detail}</li>")
            html.append(f"<h3>MITRE ATT&amp;CK</h3><ul>{''.join(parts)}</ul><p style='color:#76859a'>Techniques this behaviour is commonly "
                        f"associated with (descriptions are stored locally, no internet needed). A tag is context for the investigator, "
                        f"not evidence that the technique was used.</p>")
        html.append("<p style='color:#76859a'>Indications are investigation leads, not malware verdicts.</p>")
        view.setHtml("".join(html))
        layout.addWidget(view, 1)

        if result is not None:
            self._add_triage_controls(layout)

        row = QHBoxLayout()
        if indication.process_pid and on_show_process is not None:
            show = QPushButton("Show in process tree")
            show.clicked.connect(self.show_process)
            row.addWidget(show)
        row.addStretch()
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

    # ------------------------------------------------------------------ triage
    def _add_triage_controls(self, layout) -> None:
        ind = self.indication
        label = case_state.STATUS_LABEL.get(ind.triage, "Open")
        text = f"Triage: {label}" + (f" — {ind.triage_note}" if ind.triage_note else "")
        status = QLabel(text)
        status.setObjectName("Muted")
        status.setWordWrap(True)
        layout.addWidget(status)
        self.reason = QLineEdit()
        self.reason.setPlaceholderText("Reason or note for this decision (optional, saved with the investigation)")
        layout.addWidget(self.reason)
        row = QHBoxLayout()
        for caption, handler, tip in (
            ("Mark reviewed", lambda: self._decide(case_state.REVIEWED), "You looked at it; it stays visible and keeps counting."),
            ("False positive — hide", lambda: self._decide(case_state.FALSE_POSITIVE),
             "Hide it and take it out of scores and counts. It stays in the investigation (Case Notes) and can be re-opened."),
            ("Reopen", lambda: self._decide(case_state.OPEN), "Make it an open finding again (also overrides a baseline)."),
            ("Add note…", self._add_note, "Attach a note to this finding without changing its status."),
        ):
            button = QPushButton(caption)
            button.setToolTip(tip)
            button.clicked.connect(lambda _=False, h=handler: h())
            row.addWidget(button)
        layout.addLayout(row)

    @safe_slot
    def _decide(self, status: str, *_):
        case_state.set_finding_status(self.result, self.indication, status, self.reason.text())
        self.changed = True
        notify_triage_changed(self)
        self.accept()

    @safe_slot
    def _add_note(self, *_):
        proc = next((p for p in self.result.processes if p.pid == self.indication.process_pid), None)
        key = case_state.finding_key(self.indication, proc)
        label = f"{self.indication.rule_id} {self.indication.title}"
        if ask_and_add_note(self, self.result, "finding", key, label, self.indication.process_pid):
            self.changed = True

    @safe_slot
    def show_process(self, *_):
        self.accept()
        if self.on_show_process:
            self.on_show_process(self.indication.process_pid)


class IndicationsView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.engine = engine_for(result)
        self.dashboard = parent
        self.by_pid = {p.pid: p for p in result.processes}
        self.risks = risk_by_pid(result.indications)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Investigation Indications")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Leads generated from normalized evidence, grouped by process and ranked by risk. "
                               "They are not automatic malware verdicts."))

        self.cards = QHBoxLayout()
        layout.addLayout(self.cards)
        self._fill_cards()

        controls = QHBoxLayout()
        self.severity = compact_combo(QComboBox(), 20)
        for label, _rank in SEVERITY_FILTERS:
            self.severity.addItem(label)
        controls.addWidget(QLabel("Show:"))
        controls.addWidget(self.severity)
        self.rule = compact_combo(QComboBox(), 20)
        self.rule.addItem("All rules", "")
        families = {i.category for i in result.indications if i.category in ("ioc", "baseline")}
        if families:                                     # your own reference data (IOC lists, baselines) can be viewed apart from the built-in rules
            self.rule.addItem("Behavioural rules only", "family:behavioural")
            if "ioc" in families:
                self.rule.addItem("IOC matches only (your lists)", "family:ioc")
            if "baseline" in families:
                self.rule.addItem("Baseline differences only", "family:baseline")
        for rule_id in sorted({i.rule_id for i in result.indications if i.rule_id}):
            self.rule.addItem(f"{rule_id} — {self.engine.rule_name(rule_id)}", rule_id)
        controls.addWidget(self.rule)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search process, rule, title, evidence, ATT&CK id (e.g. T1055)…")
        self.search.setClearButtonEnabled(True)
        controls.addWidget(self.search, 1)
        self.group = QCheckBox("Group by process")
        self.group.setChecked(True)
        controls.addWidget(self.group)
        layout.addLayout(controls)

        extra = FlowLayout(h_spacing=12)           # wraps on narrow windows instead of widening the whole dashboard
        self.only_open = QCheckBox("Only not yet reviewed")
        extra.addWidget(self.only_open)
        self.show_hidden = QCheckBox("Show false positives / baseline-suppressed")
        extra.addWidget(self.show_hidden)
        for caption, status in (("Mark shown as reviewed…", case_state.REVIEWED), ("Mark shown as false positive…", case_state.FALSE_POSITIVE)):
            button = QPushButton(caption)
            button.setToolTip("Bulk triage: applies to the open findings that pass the current filters")
            button.clicked.connect(lambda _=False, s=status: self.bulk_triage(s))
            extra.addWidget(button)
        layout.addLayout(extra)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(7)
        self.tree.setHeaderLabels(["Process / finding", "Severity", "Rule", "Confidence", "Score", "Evidence from", "ATT&CK"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        header = self.tree.header()
        header.setStretchLastSection(True)
        for column, width in enumerate((500, 90, 120, 90, 70, 200)):
            self.tree.setColumnWidth(column, width)
        layout.addWidget(self.tree, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)
        layout.addWidget(muted("Double-click a finding for its evidence and reasoning, or a process row to open its details."))

        self.severity.currentIndexChanged.connect(self.refresh)
        self.rule.currentIndexChanged.connect(self.refresh)
        self.search.textChanged.connect(self.refresh)
        self.group.toggled.connect(self.refresh)
        self.only_open.toggled.connect(self.refresh)
        self.show_hidden.toggled.connect(self.refresh)
        self.tree.itemDoubleClicked.connect(self.open_item)
        self.refresh()

    def _fill_cards(self) -> None:
        while self.cards.count():
            item = self.cards.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        active = active_findings(self.result.indications)
        counts = {s: sum(1 for i in active if i.severity == s) for s in ("High", "Medium", "Low")}
        self.cards.addWidget(info_card("High", counts["High"], "High"))
        self.cards.addWidget(info_card("Medium", counts["Medium"], "Medium"))
        self.cards.addWidget(info_card("Low (hidden by default)", counts["Low"], "Low"))
        self.cards.addWidget(info_card("Processes flagged", sum(1 for r in self.risks.values() if r.severity in ("Medium", "High"))))
        hidden = len(self.result.indications) - len(active)
        if hidden:
            self.cards.addWidget(info_card("Hidden (false positive / baseline)", hidden))

    @safe_slot
    def bulk_triage(self, status: str, *_):
        """Apply one decision to every open finding that passes the current filters (asks first; nothing is deleted)."""
        targets = [i for i in self._filtered() if not i.triage]
        label = case_state.STATUS_LABEL[status].lower()
        if not targets:
            QMessageBox.information(self, "Bulk triage", "There are no open findings in the current view.")
            return
        reason, ok = QInputDialog.getText(self, "Bulk triage", f"{len(targets)} open finding(s) shown will be marked as {label}.\n"
                                          "Reason (optional, saved with each decision):")
        if not ok:
            return
        for ind in targets:
            case_state.set_finding_status(self.result, ind, status, reason, reapply=False)
        case_state.apply_case(self.result)
        notify_triage_changed(self)

    @safe_slot
    def refresh_after_triage(self, *_):
        """Called by the dashboard after a finding was re-judged: recompute scores and cards, keep filters."""
        self.risks = risk_by_pid(self.result.indications)
        self._fill_cards()
        self.refresh()

    # ------------------------------------------------------------------ data
    def _filtered(self) -> List:
        minimum = SEVERITY_FILTERS[max(0, self.severity.currentIndex())][1]
        rule = self.rule.currentData() or ""
        query = self.search.text().strip().lower()
        show_hidden = self.show_hidden.isChecked()
        only_open = self.only_open.isChecked()
        out = []
        for ind in self.result.indications:
            if severity_rank(ind.severity) < minimum:
                continue
            if not show_hidden and not is_active(ind):
                continue
            if only_open and ind.triage:
                continue
            if rule == "family:ioc" and ind.category != "ioc":
                continue
            if rule == "family:baseline" and ind.category != "baseline":
                continue
            if rule == "family:behavioural" and ind.category in ("ioc", "baseline"):
                continue
            if rule and not rule.startswith("family:") and ind.rule_id != rule:
                continue
            if query:
                text = " ".join([ind.title, ind.rule_id, ind.process_name, str(ind.process_pid), ind.summary,
                                 " ".join(ind.reasons), " ".join(ind.evidence),
                                 " ".join(f"{t.id} {t.name}" for t in self.engine.attack_for(ind.rule_id))]).lower()
                if query not in text:
                    continue
            out.append(ind)
        return out

    @safe_slot
    def refresh(self, *_):
        findings = self._filtered()
        self.tree.setUpdatesEnabled(False)
        try:
            self.tree.clear()
            if not self.result.indications:
                self.tree.addTopLevelItem(QTreeWidgetItem(["No investigation indications were generated for this analysis."]))
            elif not findings:
                self.tree.addTopLevelItem(QTreeWidgetItem(["Nothing matches the current filters. Choose “Low, Medium and High” to see everything."]))
            elif self.group.isChecked():
                self._fill_grouped(findings)
            else:
                for ind in findings:
                    self.tree.addTopLevelItem(self._finding_item(ind, with_process=True))
        finally:
            self.tree.setUpdatesEnabled(True)
        active = active_findings(self.result.indications)
        hidden_low = sum(1 for i in active if i.severity == "Low") if self.severity.currentIndex() == 0 else 0
        note = f" · {hidden_low} low-priority finding(s) hidden" if hidden_low else ""
        decided = len(self.result.indications) - len(active)
        if decided and not self.show_hidden.isChecked():
            note += f" · {decided} false positive / baseline-suppressed hidden"
        self.status.setText(f"{len(findings)} finding(s) shown of {len(self.result.indications)}{note}")

    def _fill_grouped(self, findings: List) -> None:
        groups: Dict[int, List] = defaultdict(list)
        for ind in findings:
            groups[ind.process_pid].append(ind)
        ordered = sorted(groups.items(), key=lambda kv: (-(self.risks[kv[0]].score if kv[0] in self.risks else 0), kv[0]))
        for pid, items in ordered:
            proc = self.by_pid.get(pid)
            risk = self.risks.get(pid)
            name = proc.name if proc else (items[0].process_name or "System-wide")
            label = f"{name} (PID {pid})" if pid else "System-wide findings"
            severity = risk.severity if risk else max((i.severity for i in items), key=severity_rank)
            top = QTreeWidgetItem([label, severity, "", "", f"{risk.score if risk else ''}", f"{len(items)} finding(s)"])
            top.setData(0, PROCESS_ROLE, pid)
            font = top.font(0)
            font.setBold(True)
            top.setFont(0, font)
            top.setForeground(1, QBrush(QColor(severity_color(severity))))
            self.tree.addTopLevelItem(top)
            for ind in sorted(items, key=lambda i: (-severity_rank(i.severity), -i.score)):
                top.addChild(self._finding_item(ind))
            top.setExpanded(severity_rank(severity) >= 2)

    def _finding_item(self, ind, with_process: bool = False) -> QTreeWidgetItem:
        text = f"{ind.process_name} (PID {ind.process_pid}) — {ind.title}" if with_process and ind.process_pid else ind.title
        marker = {"reviewed": "✓ ", "false_positive": "✗ ", "baseline": "⊘ "}.get(ind.triage, "")
        item = QTreeWidgetItem([marker + text, ind.severity, ind.rule_id, ind.confidence, f"{ind.score:g}", ", ".join(s.replace("windows.", "") for s in ind.source_plugins),
                                ", ".join(t.id for t in self.engine.attack_for(ind.rule_id))])
        item.setData(0, FINDING_ROLE, ind)
        item.setForeground(1, QBrush(QColor(severity_color(ind.severity))))
        if not is_active(ind):
            item.setForeground(0, QBrush(QColor("#5c6b7c")))
        item.setToolTip(0, ind.summary + (f"\n[{case_state.STATUS_LABEL.get(ind.triage, '')}] {ind.triage_note}" if ind.triage else ""))
        item.setToolTip(2, self.engine.rule_name(ind.rule_id))
        return item

    # ------------------------------------------------------------------ actions
    @safe_slot
    def open_item(self, item, _column=0):
        ind = item.data(0, FINDING_ROLE)
        if ind is not None:
            proc = self.by_pid.get(ind.process_pid)
            IndicationDetails(ind, self, self._show_process, command_line=proc.command_line if proc else "", result=self.result).exec()
            return
        pid = item.data(0, PROCESS_ROLE)
        if pid:
            self._show_process(pid)

    def _show_process(self, pid: int) -> None:
        if self.dashboard is not None and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(pid)
