"""Process lifetimes: one lane per process from its start to its exit (or to the memory capture while it was still running).

It answers the questions a table cannot: what was alive at the same time, what started right before the capture, which short-lived
process belongs to a long-running parent. Bars are coloured by the process risk (findings hidden by triage do not count), processes
found only by psscan are outlined with a dashed line, and the capture time is marked. Double-click a lane to open the process in the tree.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import List, Optional, Tuple

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QPushButton, QScrollArea, QToolTip, QVBoxLayout, QWidget,
)

from app.analysis.indicators.scoring import risk_by_pid, severity_rank
from app.errors import safe_slot
from app.theme import PALETTE, SEVERITY_COLORS
from app.util import format_time, parse_time
from app.windows.widgets import FlowLayout, compact_combo, muted, show_error, show_info

ROW_H = 22
LABEL_W = 250
AXIS_H = 34
PAD_R = 24


@dataclass
class Lane:
    pid: int
    name: str
    start: float
    end: float
    running: bool          # no exit time: the bar runs to the capture
    severity: str
    hidden: bool
    tooltip: str
    ppid: int = 0


def build_lanes(result) -> Tuple[List[Lane], Optional[float], int]:
    """(lanes, capture epoch, number of processes without a usable start time)."""
    capture = parse_time(result.capture_time)
    capture_epoch = capture.timestamp() if capture else None
    risks = risk_by_pid(result.indications)
    lanes, skipped = [], 0
    for proc in result.processes:
        start = parse_time(proc.create_time)
        if start is None:
            skipped += 1
            continue
        exit_time = parse_time(proc.exit_time)
        running = exit_time is None
        end = exit_time.timestamp() if exit_time else (capture_epoch if capture_epoch is not None else start.timestamp())
        end = max(end, start.timestamp())
        risk = risks.get(proc.pid)
        severity = risk.severity if risk and severity_rank(risk.severity) >= 1 else ""
        lines = [f"{proc.name} (PID {proc.pid}, parent {proc.ppid})", f"Started {format_time(proc.create_time)}",
                 f"Exited {format_time(proc.exit_time)}" if exit_time else "Still running at capture" if capture_epoch is not None else "No exit time",
                 f"User {proc.user}" if proc.user else ""]
        if risk and risk.count:
            lines.append(f"{risk.severity or 'Info'} risk, {risk.count} finding(s)")
        if proc.hidden:
            lines.append("Found by psscan only (not in pslist)")
        lanes.append(Lane(proc.pid, proc.name, start.timestamp(), end, running, severity, proc.hidden,
                          "\n".join(l for l in lines if l), proc.ppid))
    return lanes, capture_epoch, skipped


class LaneCanvas(QWidget):
    activated = Signal(int)          # pid, on double-click
    rangeRequested = Signal(float, float)       # Ctrl+wheel zoom: the new visible time range

    def __init__(self, parent=None):
        super().__init__(parent)
        self.lanes: List[Lane] = []
        self.capture: Optional[float] = None
        self.t0 = 0.0
        self.t1 = 1.0
        self.selected: Optional[int] = None
        self.setMouseTracking(True)
        self.setMinimumWidth(700)

    def set_data(self, lanes: List[Lane], capture: Optional[float], t0: float, t1: float) -> None:
        self.lanes, self.capture = lanes, capture
        self.t0, self.t1 = t0, max(t1, t0 + 1)
        self.setFixedHeight(AXIS_H + ROW_H * max(1, len(lanes)) + 10)
        self.update()

    # -- geometry
    def _x(self, t: float) -> float:
        width = max(1.0, self.width() - LABEL_W - PAD_R)
        return LABEL_W + (min(max(t, self.t0), self.t1) - self.t0) / (self.t1 - self.t0) * width

    def lane_at(self, y: float) -> Optional[Lane]:
        index = int((y - AXIS_H) // ROW_H)
        return self.lanes[index] if 0 <= index < len(self.lanes) else None

    def bar_rect(self, lane: Lane, index: int) -> QRectF:
        top = AXIS_H + index * ROW_H
        x0, x1 = self._x(lane.start), self._x(lane.end)
        return QRectF(x0, top + 5, max(3.0, x1 - x0), ROW_H - 10)

    # -- painting (palette-driven so it follows the light and the dark theme)
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        pal = self.palette()
        painter.fillRect(self.rect(), QColor(PALETTE["field"]))
        text, grid = QColor(PALETTE["text_dim"]), QColor("#233250")          # the colours of the theme, not of the system palette
        font = QFont(self.font())
        font.setPointSizeF(max(7.0, self.font().pointSizeF() - 1))
        painter.setFont(font)
        if not self.lanes:
            painter.setPen(text)
            painter.drawText(QRectF(20, 10, self.width() - 40, 40), "No process with a usable start time matches the filters.")
            return
        span = self.t1 - self.t0
        grid_line = QColor(grid)
        grid_line.setAlpha(110)
        painter.setPen(QPen(grid_line, 1, Qt.PenStyle.DotLine))
        for i in range(0, 7):
            t = self.t0 + span * i / 6
            x = self._x(t)
            painter.drawLine(QPointF(x, AXIS_H - 6), QPointF(x, self.height()))
            label_x = min(max(x - 45, 0.0), self.width() - 90.0)                       # the first and the last label stay inside the widget
            label = datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%m-%d %H:%M" if span > 3 * 3600 else "%H:%M:%S")
            painter.setPen(text)
            painter.drawText(QRectF(label_x, 2, 90, AXIS_H - 10), Qt.AlignmentFlag.AlignCenter, label)
            painter.setPen(QPen(grid_line, 1, Qt.PenStyle.DotLine))
        for index, lane in enumerate(self.lanes):
            top = AXIS_H + index * ROW_H
            if index % 2:
                shade = QColor(grid)
                shade.setAlpha(34)
                painter.fillRect(QRectF(0, top, self.width(), ROW_H), shade)
            if lane.pid == self.selected:
                accent = QColor(SEVERITY_COLORS["Low"])
                accent.setAlpha(60)
                painter.fillRect(QRectF(0, top, self.width(), ROW_H), accent)
            painter.setPen(text)
            painter.drawText(QRectF(8, top, LABEL_W - 14, ROW_H), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                             painter.fontMetrics().elidedText(f"{lane.name} ({lane.pid})", Qt.TextElideMode.ElideRight, LABEL_W - 14))
            if lane.end < self.t0 or lane.start > self.t1:
                continue
            if lane.severity:
                color = QColor(SEVERITY_COLORS.get(lane.severity, SEVERITY_COLORS[""]))
            else:
                color = QColor("#5d7298")                  # calm slate for a process with no finding
            bar = self.bar_rect(lane, index)
            painter.setPen(QPen(color.darker(135), 1, Qt.PenStyle.DashLine if lane.hidden else Qt.PenStyle.SolidLine))
            fill = QLinearGradient(bar.topLeft(), bar.bottomLeft())
            fill.setColorAt(0.0, color.lighter(118))
            fill.setColorAt(1.0, color.darker(112))
            painter.setBrush(fill)
            painter.drawRoundedRect(bar, 4, 4)
            if not lane.running:                       # exited: a tick at the end of the bar
                painter.setPen(QPen(text, 2))
                painter.drawLine(QPointF(bar.right(), top + 3), QPointF(bar.right(), top + ROW_H - 3))
        # parent -> child connectors: a thin line at the child's start from the parent's lane to the child's lane
        row_of = {lane.pid: i for i, lane in enumerate(self.lanes)}
        connector = QColor(text)
        connector.setAlpha(110)
        painter.setPen(QPen(connector, 1))
        for index, lane in enumerate(self.lanes):
            parent_index = row_of.get(lane.ppid)
            if parent_index is None or parent_index == index or self.lanes[parent_index].start > lane.start:
                continue
            if lane.start < self.t0 or lane.start > self.t1:
                continue
            x = self._x(lane.start)
            painter.drawLine(QPointF(x, AXIS_H + parent_index * ROW_H + ROW_H / 2), QPointF(x, AXIS_H + index * ROW_H + ROW_H / 2))
        if self.capture is not None and self.t0 <= self.capture <= self.t1:
            x = self._x(self.capture)
            painter.setPen(QPen(QColor(SEVERITY_COLORS["Medium"]), 1.5, Qt.PenStyle.DashLine))
            painter.drawLine(QPointF(x, AXIS_H - 6), QPointF(x, self.height()))
            painter.drawText(QRectF(x + 3, self.height() - 16, 120, 14), "memory captured")

    # -- interaction
    def wheelEvent(self, event):
        """Ctrl + wheel zooms the time axis around the mouse pointer; the plain wheel scrolls the lanes (handled by the scroll area)."""
        if not (event.modifiers() & Qt.KeyboardModifier.ControlModifier) or not self.lanes:
            event.ignore()
            return
        factor = 0.75 if event.angleDelta().y() > 0 else 1 / 0.75
        width = max(1.0, self.width() - LABEL_W - PAD_R)
        fraction = min(1.0, max(0.0, (event.position().x() - LABEL_W) / width))
        centre = self.t0 + (self.t1 - self.t0) * fraction
        span = max(5.0, (self.t1 - self.t0) * factor)
        start = centre - span * fraction
        self.rangeRequested.emit(start, start + span)
        event.accept()

    def mouseMoveEvent(self, event):
        lane = self.lane_at(event.position().y())
        if lane is not None:
            QToolTip.showText(event.globalPosition().toPoint(), lane.tooltip, self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, event):
        lane = self.lane_at(event.position().y())
        self.selected = lane.pid if lane else None
        self.update()

    def mouseDoubleClickEvent(self, event):
        lane = self.lane_at(event.position().y())
        if lane is not None:
            self.activated.emit(lane.pid)


class LifetimesView(QWidget):
    def __init__(self, result, parent=None):
        super().__init__(parent)
        self.result = result
        self.dashboard = parent
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(10)
        title = QLabel("Process Lifetimes")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("One lane per process, from its start to its exit; running processes extend to the memory capture (dashed line). "
                               "Bars are coloured by risk; a dashed outline means the process was found by psscan only. "
                               "Hover for details, double-click to open the process."))
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter by name, PID or user…")
        self.search.setClearButtonEnabled(True)
        bar.addWidget(self.search, 1)
        self.order = compact_combo(QComboBox(), 14)
        self.order.addItems(["Order: start time", "Order: risk", "Order: name"])
        bar.addWidget(self.order)
        self.window = compact_combo(QComboBox(), 18)
        self.window.addItems(["Whole capture", "Last 24 h before capture", "Last 6 h before capture", "Last hour before capture", "Last 15 min before capture"])
        self.window.setEnabled(False)       # enabled once a capture time is known (see _load)
        bar.addWidget(self.window)
        layout.addLayout(bar)
        options = FlowLayout(h_spacing=14)
        self.flagged = QCheckBox("Only flagged")
        self.hide_exited = QCheckBox("Hide exited")
        for box in (self.flagged, self.hide_exited):
            options.addWidget(box)
        self.reset_zoom_button = QPushButton("Reset zoom")
        self.reset_zoom_button.setToolTip("Ctrl + mouse wheel zooms the time axis around the pointer")
        self.reset_zoom_button.setVisible(False)
        self.save_button = QPushButton("Save image…")
        for button in (self.reset_zoom_button, self.save_button):
            options.addWidget(button)
        layout.addLayout(options)
        self.zoom = None                  # manual (Ctrl+wheel) time range; overrides the window choice above
        self.canvas = LaneCanvas()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self.canvas)
        layout.addWidget(scroll, 1)
        self.status = muted("", wrap=False)
        layout.addWidget(self.status)

        self.search.textChanged.connect(self.refresh)
        self.order.currentIndexChanged.connect(self.refresh)
        self.window.currentIndexChanged.connect(self.reset_zoom)
        self.reset_zoom_button.clicked.connect(self.reset_zoom)
        self.save_button.clicked.connect(self.save_image)
        self.canvas.rangeRequested.connect(self.on_zoom)
        self.flagged.toggled.connect(self.refresh)
        self.hide_exited.toggled.connect(self.refresh)
        self.canvas.activated.connect(self.open_process)
        self._load()
        self.refresh()

    def _load(self) -> None:
        self.all_lanes, self.capture, self.skipped = build_lanes(self.result)
        self.users = {p.pid: (p.user or "").lower() for p in self.result.processes}
        self.window.setEnabled(self.capture is not None)

    @safe_slot
    def refresh_after_triage(self, *_):
        self._load()
        self.refresh()

    @safe_slot
    def refresh(self, *_):
        query = self.search.text().strip().lower()
        lanes = []
        for lane in self.all_lanes:
            if query and query not in f"{lane.name} {lane.pid} {self.users.get(lane.pid, '')}".lower():
                continue
            if self.flagged.isChecked() and severity_rank(lane.severity) < 2:
                continue
            if self.hide_exited.isChecked() and not lane.running and severity_rank(lane.severity) < 2:
                continue
            lanes.append(lane)
        mode = self.order.currentIndex()
        if mode == 1:
            lanes.sort(key=lambda l: (-severity_rank(l.severity), l.start, l.pid))
        elif mode == 2:
            lanes.sort(key=lambda l: (l.name.lower(), l.start))
        else:
            lanes.sort(key=lambda l: (l.start, l.pid))
        everything = self.all_lanes or lanes
        t0 = min((l.start for l in everything), default=0.0)
        t1 = max([l.end for l in everything] + ([self.capture] if self.capture else []), default=t0 + 1)
        span = {1: 86400, 2: 6 * 3600, 3: 3600, 4: 900}.get(self.window.currentIndex())
        outside = 0
        if self.zoom is not None:
            t0, t1 = self.zoom
            inside = [l for l in lanes if l.end >= t0 and l.start <= t1]
            outside, lanes = len(lanes) - len(inside), inside
        elif span and self.capture is not None:
            t0, t1 = self.capture - span, self.capture + span * 0.02
            inside = [l for l in lanes if l.end >= t0 and l.start <= t1]       # lanes that ended before the window are not shown
            outside, lanes = len(lanes) - len(inside), inside
        self.canvas.set_data(lanes, self.capture, t0, t1)
        note = f" · {self.skipped} process(es) without a start time not shown" if self.skipped else ""
        note += f" · {outside} outside the chosen window" if outside else ""
        note += " · zoomed with Ctrl + wheel" if self.zoom is not None else ""
        self.reset_zoom_button.setVisible(self.zoom is not None)
        self.status.setText(f"{len(lanes)} of {len(self.all_lanes)} process lanes shown{note}")

    @safe_slot
    def on_zoom(self, t0: float, t1: float, *_):
        if not self.all_lanes:
            return
        low = min(l.start for l in self.all_lanes)
        high = max([l.end for l in self.all_lanes] + ([self.capture] if self.capture else []))
        pad = max(5.0, (high - low) * 0.02)
        if t1 - t0 >= (high - low) + 2 * pad:          # zoomed out past the whole capture: back to the normal view
            self.zoom = None
        else:
            self.zoom = (max(low - pad, t0), min(high + pad, t1))
        self.refresh()

    @safe_slot
    def reset_zoom(self, *_):
        self.zoom = None
        self.refresh()

    @safe_slot
    def save_image(self, *_):
        path, _ = QFileDialog.getSaveFileName(self, "Save process lifetimes as an image", "process_lifetimes.png", "PNG image (*.png)")
        if not path:
            return
        if not self.canvas.grab().save(path):
            show_error(self, "Save image", f"The image could not be written to:\n{path}")
        else:
            show_info(self, "Save image", f"Saved {len(self.canvas.lanes)} lanes to:\n{path}")

    @safe_slot
    def open_process(self, pid: int):
        if self.dashboard is not None and hasattr(self.dashboard, "show_process"):
            self.dashboard.show_process(pid)
