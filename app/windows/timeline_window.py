"""Investigation timeline.

* an activity chart (log scale, so quiet periods stay visible next to the boot-time burst)
  with severity markers and the memory-capture time; drag on it to select a time range,
* filters: category, "only flagged processes", free text, quick ranges relative to the capture,
* a table with the time relative to capture (Δ), colouring by process risk,
* a detail panel with the event's fields and provenance, and CSV export of what is shown.
"""
from __future__ import annotations

import csv
import math
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QSplitter,
    QTextBrowser, QVBoxLayout, QWidget,
)

from app.errors import safe_slot
from app.theme import CATEGORY_COLORS, SEVERITY_COLORS
from app.util import format_delta, format_time, parse_time
from app.analysis import case_state
from app.windows.case_actions import ask_and_add_note, toggle_bookmark
from app.windows.widgets import (
    FlowLayout, TableModel, badge_html, compact_combo, escape, make_table, muted, severity_color, show_error, show_info,
)

_FALLBACK_COLORS = ["#ff7eb6", "#7ee0ff", "#c3e88d", "#f78c6c", "#82aaff", "#ffcb6b"]


def category_color(category: str, known: List[str]) -> str:
    if category in CATEGORY_COLORS:
        return CATEGORY_COLORS[category]
    others = [c for c in known if c not in CATEGORY_COLORS]
    return _FALLBACK_COLORS[others.index(category) % len(_FALLBACK_COLORS)] if category in others else "#8290a3"


class ActivityChart(QWidget):
    """Stacked histogram of events over time with drag-to-select."""

    rangeChanged = Signal(object)    # (start_epoch, end_epoch) or None

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(150)
        self.setMaximumHeight(190)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._points: List[Tuple[float, str, str]] = []
        self._categories: List[str] = []
        self._capture: Optional[float] = None
        self._t0 = 0.0
        self._t1 = 1.0
        self._selection: Optional[Tuple[float, float]] = None
        self._drag_start: Optional[float] = None
        self._margin = (46, 12, 14, 24)    # left, top, right, bottom
        self.setToolTip("Drag to select a time range. Double-click to clear the selection.")

    def set_events(self, points: List[Tuple[float, str, str]], categories: List[str], capture: Optional[float]) -> None:
        self._points = points
        self._categories = categories
        self._capture = capture
        if points:
            epochs = [p[0] for p in points]
            self._t0, self._t1 = min(epochs), max(epochs)
            if capture is not None:
                self._t0, self._t1 = min(self._t0, capture), max(self._t1, capture)
            if self._t1 <= self._t0:
                self._t1 = self._t0 + 1
        self._selection = None
        self.update()

    def clear_selection(self) -> None:
        self._selection = None
        self.update()
        self.rangeChanged.emit(None)

    # -- geometry
    def _plot(self) -> QRectF:
        left, top, right, bottom = self._margin
        return QRectF(left, top, max(10, self.width() - left - right), max(10, self.height() - top - bottom))

    def _x_of(self, t: float) -> float:
        plot = self._plot()
        return plot.left() + (t - self._t0) / (self._t1 - self._t0) * plot.width()

    def _t_of(self, x: float) -> float:
        plot = self._plot()
        ratio = min(1.0, max(0.0, (x - plot.left()) / plot.width()))
        return self._t0 + ratio * (self._t1 - self._t0)

    # -- painting
    def paintEvent(self, event):
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.fillRect(self.rect(), QColor("#0e151d"))
            plot = self._plot()
            if not self._points:
                painter.setPen(QColor("#8290a3"))
                painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "No timeline events")
                return
            bins = max(20, int(plot.width() // 9))
            width = (self._t1 - self._t0) / bins
            counts = [dict() for _ in range(bins)]
            severity = ["" for _ in range(bins)]
            rank = {"": 0, "Medium": 1, "High": 2}
            for epoch, category, sev in self._points:
                index = min(bins - 1, int((epoch - self._t0) / width))
                counts[index][category] = counts[index].get(category, 0) + 1
                if rank.get(sev, 0) > rank.get(severity[index], 0):
                    severity[index] = sev
            peak = max((sum(c.values()) for c in counts), default=1) or 1
            scale = math.log1p(peak)
            painter.setPen(QPen(QColor("#1c2733"), 1))
            for fraction in (0.25, 0.5, 0.75, 1.0):
                y = plot.bottom() - plot.height() * fraction
                painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            bar_w = plot.width() / bins
            for i, bucket in enumerate(counts):
                total = sum(bucket.values())
                if not total:
                    continue
                full = plot.height() * math.log1p(total) / scale
                y = plot.bottom()
                for category in self._categories:
                    amount = bucket.get(category, 0)
                    if not amount:
                        continue
                    h = full * amount / total
                    painter.fillRect(QRectF(plot.left() + i * bar_w + 1, y - h, max(1.0, bar_w - 2), h),
                                     QColor(category_color(category, self._categories)))
                    y -= h
                if severity[i]:
                    painter.setBrush(QColor(SEVERITY_COLORS[severity[i]]))
                    painter.setPen(Qt.PenStyle.NoPen)
                    painter.drawEllipse(QPointF(plot.left() + i * bar_w + bar_w / 2, plot.bottom() - full - 6), 3.5, 3.5)
            # capture marker
            if self._capture is not None:
                x = self._x_of(self._capture)
                pen = QPen(QColor("#ffd166"), 1, Qt.PenStyle.DashLine)
                painter.setPen(pen)
                painter.drawLine(QPointF(x, plot.top()), QPointF(x, plot.bottom()))
                painter.setPen(QColor("#ffd166"))
                label_width = painter.fontMetrics().horizontalAdvance("memory capture")
                label_x = x + 5 if x + 5 + label_width <= plot.right() else x - 5 - label_width          # beside the line, on the side that has room
                painter.drawText(QPointF(label_x, plot.top() + 11), "memory capture")
            # selection
            if self._selection is not None:
                a, b = sorted((self._x_of(self._selection[0]), self._x_of(self._selection[1])))
                painter.fillRect(QRectF(a, plot.top(), max(2.0, b - a), plot.height()), QColor(75, 145, 255, 60))
                painter.setPen(QPen(QColor("#4b91ff"), 1))
                painter.drawRect(QRectF(a, plot.top(), max(2.0, b - a), plot.height()))
            # axes labels
            painter.setPen(QColor("#8290a3"))
            font = QFont(self.font())
            font.setPointSize(8)
            painter.setFont(font)
            painter.drawText(QPointF(plot.left(), self.height() - 6), format_time(self._t0, False))
            end_text = format_time(self._t1, False)
            painter.drawText(QPointF(plot.right() - painter.fontMetrics().horizontalAdvance(end_text), self.height() - 6), end_text)
            painter.drawText(QPointF(4, plot.top() + 10), f"{peak}")
            painter.drawText(QPointF(4, plot.bottom()), "0")
            # legend
            x = plot.left() + 8
            for category in self._categories:
                painter.fillRect(QRectF(x, plot.top() - 1, 8, 8), QColor(category_color(category, self._categories)))
                painter.setPen(QColor("#9eacbc"))
                painter.drawText(QPointF(x + 12, plot.top() + 7), category)
                x += 24 + painter.fontMetrics().horizontalAdvance(category)
        finally:
            painter.end()

    # -- mouse selection
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self._points:
            self._drag_start = self._t_of(event.position().x())
            self._selection = (self._drag_start, self._drag_start)
            self.update()

    def mouseMoveEvent(self, event):
        if self._drag_start is not None:
            self._selection = (self._drag_start, self._t_of(event.position().x()))
            self.update()

    def mouseReleaseEvent(self, event):
        if self._drag_start is None:
            return
        start, end = sorted((self._drag_start, self._t_of(event.position().x())))
        self._drag_start = None
        if abs(self._x_of(end) - self._x_of(start)) < 4:
            self.clear_selection()
            return
        self._selection = (start, end)
        self.update()
        self.rangeChanged.emit((start, end))

    def mouseDoubleClickEvent(self, event):
        self.clear_selection()


class TimelineView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        self.capture = parse_time(result.capture_time)
        self.capture_epoch = self.capture.timestamp() if self.capture else None
        self.range: Optional[Tuple[float, float]] = None

        events = [(e, parse_time(e.timestamp)) for e in result.timeline]
        events = [(e, t.timestamp()) for e, t in events if t is not None]
        events.sort(key=lambda item: item[1])
        self.categories = []
        for event, _t in events:
            category = event.category or event.event_type or "Other"
            if category not in self.categories:
                self.categories.append(category)
        order = [c for c in ("Process", "Network", "Module", "System") if c in self.categories]
        self.categories = order + [c for c in self.categories if c not in order]

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(8)
        title = QLabel("Investigation Timeline")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("Every fact appears once. Select a range on the chart to zoom the table; the Δ column is the time relative "
                               "to the moment the memory was captured."))

        self.chart = ActivityChart()
        layout.addWidget(self.chart)

        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search events, process, PID…")
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)
        self.quick = compact_combo(QComboBox(), 16)
        self.quick.addItems(["Whole timeline", "Last 15 min before capture", "Last hour before capture", "Last 24 h before capture"])
        self.quick.setEnabled(self.capture_epoch is not None)
        bar.addWidget(self.quick)
        self.clear_range = QPushButton("Clear range")
        bar.addWidget(self.clear_range)
        self.export = QPushButton("Export CSV")
        bar.addWidget(self.export)
        layout.addLayout(bar)
        # second row wraps: the number of event categories depends on the plugins that ran, so it must not widen the window
        flow = FlowLayout(h_spacing=12)
        self.category_boxes: Dict[str, QCheckBox] = {}
        for category in self.categories:
            box = QCheckBox(category)
            box.setChecked(category not in ("Module", "File time"))        # module loads are numerous and file times are old: opt-in
            self.category_boxes[category] = box
            flow.addWidget(box)
        self.flagged_only = QCheckBox("Only flagged processes")
        flow.addWidget(self.flagged_only)
        self.bookmark_event = QPushButton("☆ Bookmark event")
        self.note_event = QPushButton("✎ Note…")
        for button in (self.bookmark_event, self.note_event):
            button.setEnabled(False)
            flow.addWidget(button)
        layout.addLayout(flow)

        splitter = QSplitter(Qt.Orientation.Vertical)
        rows, sorts, payloads, colors = [], [], [], {}
        for index, (event, epoch) in enumerate(events):
            delta = (epoch - self.capture_epoch) if self.capture_epoch is not None else None
            category = event.category or event.event_type or "Other"
            rows.append([format_time(event.timestamp), format_delta(delta) if delta is not None else "", category,
                         event.description, event.pid or "", event.process, event.source_plugin])
            sorts.append([epoch, delta if delta is not None else 0.0, category.lower(), event.description.lower(),
                          event.pid or 0, (event.process or "").lower(), (event.source_plugin or "").lower()])
            payloads.append((event, epoch, category))
            if event.severity:
                colors[index] = severity_color(event.severity)
        self.model = TableModel(["Time (UTC)", "Δ capture", "Category", "Event", "PID", "Process", "Source"], rows,
                                sort_rows=sorts, payloads=payloads, colors=colors)
        self.view, self.proxy = make_table(self.model, [210, 100, 90, 540, 70, 150, 150], sort_column=0)
        splitter.addWidget(self.view)
        self.detail = QTextBrowser()
        self.detail.setMinimumHeight(130)
        self.detail.setHtml("<p style='color:#76859a'>Select an event to see its details.</p>")
        splitter.addWidget(self.detail)
        splitter.setSizes([420, 170])
        layout.addWidget(splitter, 1)
        self.summary = muted("", wrap=False)
        layout.addWidget(self.summary)

        self.chart.set_events([(epoch, cat, event.severity) for event, epoch, cat in payloads], self.categories, self.capture_epoch)
        self.chart.rangeChanged.connect(self.on_range)
        self.search.textChanged.connect(self.on_filter_changed)
        for box in self.category_boxes.values():
            box.toggled.connect(self.on_filter_changed)
        self.flagged_only.toggled.connect(self.on_filter_changed)
        self.quick.currentIndexChanged.connect(self.on_quick)
        self.clear_range.clicked.connect(self.chart.clear_selection)
        self.export.clicked.connect(self.export_csv)
        self.bookmark_event.clicked.connect(self.toggle_event_bookmark)
        self.note_event.clicked.connect(self.add_event_note)
        self.view.selectionModel().currentRowChanged.connect(self.on_select)
        self.apply_filters()

    # ------------------------------------------------------------------ filtering
    @safe_slot
    def on_filter_changed(self, *_):
        self.apply_filters()

    @safe_slot
    def on_range(self, selection):
        self.range = selection
        if selection is not None and self.quick.currentIndex() != 0:
            self.quick.blockSignals(True)
            self.quick.setCurrentIndex(0)
            self.quick.blockSignals(False)
        self.apply_filters()

    @safe_slot
    def on_quick(self, index):
        if index <= 0 or self.capture_epoch is None:
            self.chart.clear_selection()
            return
        span = {1: 15 * 60, 2: 3600, 3: 86400}.get(index, 0)
        self.range = (self.capture_epoch - span, self.capture_epoch + 1)
        self.chart._selection = self.range
        self.chart.update()
        self.apply_filters()

    def apply_filters(self) -> None:
        allowed = {c for c, box in self.category_boxes.items() if box.isChecked()}
        flagged = self.flagged_only.isChecked()
        selection = self.range

        def predicate(payload, _values) -> bool:
            if payload is None:
                return True
            event, epoch, category = payload
            if category not in allowed:
                return False
            if flagged and not event.severity:
                return False
            if selection is not None and not (selection[0] <= epoch <= selection[1]):
                return False
            return True

        self.proxy.set_predicate(predicate)
        self.proxy.set_text(self.search.text())
        total = self.model.rowCount()
        shown = self.proxy.rowCount()
        text = f"{shown} of {total} events shown"
        if selection is not None:
            text += f" · range {format_time(selection[0])} → {format_time(selection[1])}"
        if "Module" in self.category_boxes and not self.category_boxes["Module"].isChecked():
            text += " · module loads hidden (tick Module to include them)"
        self.summary.setText(text)

    # ------------------------------------------------------------------ details
    @safe_slot
    def on_select(self, *_):
        payload = self.proxy.payload_at(self.view.currentIndex())
        if payload is None:
            return
        event, epoch, _category = payload
        target = case_state.event_target(event)
        self.bookmark_event.setEnabled(True)
        self.note_event.setEnabled(True)
        self.bookmark_event.setText("★ Bookmarked (click to remove)" if case_state.is_bookmarked(self.result, target) else "☆ Bookmark event")
        html = [f"<h3>{escape(event.event_type)}</h3><p>{escape(event.description)}</p>"]
        if event.severity:
            html.append(f"<p>{badge_html(event.severity, f'process risk: {event.severity}')}</p>")
        rows = [("Time", format_time(event.timestamp))]
        if self.capture_epoch is not None:
            rows.append(("Relative to capture", format_delta(epoch - self.capture_epoch)))
        rows += [("Source plugin", event.source_plugin or "—"), ("PID", event.pid or "—")]
        rows += [(k, v) for k, v in (event.details or {}).items() if v not in (None, "")]
        table = "".join(f"<tr><td style='color:#76859a;padding-right:12px;vertical-align:top'>{escape(k)}</td><td>{escape(v)}</td></tr>" for k, v in rows)
        html.append(f"<table>{table}</table>")
        prov = (event.provenance or {}).get("timestamp") or {}
        if prov:
            html.append(f"<p style='color:#76859a'>Provenance: {escape(prov.get('plugin', ''))} row {escape(prov.get('row_index', '?'))}</p>")
        notes = case_state.notes_for(self.result, target)
        if notes:
            html.append("<h3>Your notes</h3><ul>" + "".join(f"<li>{escape(n.get('text', ''))}</li>" for n in notes) + "</ul>")
        self.detail.setHtml("".join(html))

    def _selected_event(self):
        payload = self.proxy.payload_at(self.view.currentIndex())
        return payload[0] if payload else None

    @safe_slot
    def toggle_event_bookmark(self, *_):
        event = self._selected_event()
        if event is not None:
            toggle_bookmark(self, self.result, "event", case_state.event_target(event),
                            f"{format_time(event.timestamp)} {event.description}"[:140], event.pid)
            self.on_select()

    @safe_slot
    def add_event_note(self, *_):
        event = self._selected_event()
        if event is not None and ask_and_add_note(self, self.result, "event", case_state.event_target(event),
                                                  f"{format_time(event.timestamp)} {event.description}"[:140], event.pid):
            self.on_select()

    @safe_slot
    def export_csv(self, *_):
        path, _ = QFileDialog.getSaveFileName(self, "Export timeline", "timeline.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.model.columns)
                for row in range(self.proxy.rowCount()):
                    source = self.proxy.mapToSource(self.proxy.index(row, 0)).row()
                    writer.writerow(self.model.row_values(source))
        except OSError as exc:
            show_error(self, "Export failed", f"Could not write the file:\n{path}\n\n{exc}")
            return
        show_info(self, "Export timeline", f"Exported {self.proxy.rowCount()} events to:\n{path}")
