"""The operating-system switch of the start window: two big options (Windows / Linux) with a thumb that slides between them.

The thumb glides with a little overshoot while its colour turns from blue to amber, the chosen icon grows and the other one dims, and a soft glow pulses once. It is a single
widget that paints itself, so it follows the theme of the window around it and needs no image files. Click either side, or use the arrow keys / Space / Enter when it has the
focus. ``changed(os_id)`` is emitted when the choice changes; ``set_os`` changes it from code. ``ANIMATED = False`` (the tests do this) makes every change instant.
"""
from __future__ import annotations

from typing import Dict, Optional

from PySide6.QtCore import Property, QEasingCurve, QPointF, QPropertyAnimation, QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import QSizePolicy, QWidget

ANIMATED = True
SLIDE_MS = 520
GLOW_MS = 800

WINDOWS_COLOUR = QColor("#4f8cff")
LINUX_COLOUR = QColor("#f5b13a")
TRACK = QColor("#0d1421")
TRACK_BORDER = QColor("#25344f")


def _mix(a: QColor, b: QColor, t: float) -> QColor:
    t = max(0.0, min(1.0, t))
    return QColor(int(a.red() + (b.red() - a.red()) * t), int(a.green() + (b.green() - a.green()) * t), int(a.blue() + (b.blue() - a.blue()) * t))


def paint_windows_icon(p: QPainter, box: QRectF, colour: QColor) -> None:
    """The four-pane window flag, a little waved like the logo."""
    gap = box.width() * 0.07
    w, h = (box.width() - gap) / 2, (box.height() - gap) / 2
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(colour))
    for row in (0, 1):
        for col in (0, 1):
            x = box.left() + col * (w + gap)
            y = box.top() + row * (h + gap)
            skew = (-0.06 if col == 0 else 0.06) * box.height()
            p.drawPolygon(QPolygonF([QPointF(x, y + skew), QPointF(x + w, y - skew), QPointF(x + w, y + h - skew), QPointF(x, y + h + skew)]))


def paint_linux_icon(p: QPainter, box: QRectF, body: QColor, belly: QColor = QColor("#f3f4f6")) -> None:
    """A small penguin: dark body, light belly, round head with eyes, orange beak and feet."""
    cx, w, h = box.center().x(), box.width(), box.height()
    orange = QColor("#f6a21c")
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QBrush(orange))                                                       # feet
    p.drawEllipse(QRectF(cx - w * 0.36, box.bottom() - h * 0.12, w * 0.30, h * 0.12))
    p.drawEllipse(QRectF(cx + w * 0.06, box.bottom() - h * 0.12, w * 0.30, h * 0.12))
    p.setBrush(QBrush(body))                                                         # body
    p.drawEllipse(QRectF(cx - w * 0.38, box.top() + h * 0.30, w * 0.76, h * 0.66))
    p.drawEllipse(QRectF(cx - w * 0.27, box.top() + h * 0.02, w * 0.54, h * 0.50))     # head
    p.setBrush(QBrush(belly))                                                        # belly
    p.drawEllipse(QRectF(cx - w * 0.24, box.top() + h * 0.46, w * 0.48, h * 0.46))
    p.drawEllipse(QRectF(cx - w * 0.17, box.top() + h * 0.17, w * 0.15, h * 0.15))     # eyes: white ...
    p.drawEllipse(QRectF(cx + w * 0.02, box.top() + h * 0.17, w * 0.15, h * 0.15))
    p.setBrush(QBrush(QColor("#10141b")))                                            # ... and pupils
    p.drawEllipse(QRectF(cx - w * 0.12, box.top() + h * 0.20, w * 0.07, h * 0.09))
    p.drawEllipse(QRectF(cx + w * 0.05, box.top() + h * 0.20, w * 0.07, h * 0.09))
    p.setBrush(QBrush(orange))                                                       # beak
    beak = QPainterPath()
    beak.moveTo(cx - w * 0.10, box.top() + h * 0.33)
    beak.quadTo(cx, box.top() + h * 0.44, cx + w * 0.10, box.top() + h * 0.33)
    beak.quadTo(cx, box.top() + h * 0.30, cx - w * 0.10, box.top() + h * 0.33)
    p.drawPath(beak)


class OsSwitch(QWidget):
    changed = Signal(str)

    def __init__(self, options: Optional[Dict[str, str]] = None, current: str = "windows", parent=None):
        """``options``: ``{os id: label}`` in display order (exactly two); the default is Windows and Linux."""
        super().__init__(parent)
        self._options = dict(options or {"windows": "Windows", "linux": "Linux"})
        self._ids = list(self._options)[:2]
        self._pos = 0.0
        self._glow = 0.0
        self._hover = -1
        self._index = 0 if current not in self._ids else self._ids.index(current)
        self._pos = float(self._index)
        self._slide = QPropertyAnimation(self, b"position", self)
        self._slide.setDuration(SLIDE_MS)
        curve = QEasingCurve(QEasingCurve.Type.OutBack)
        curve.setOvershoot(0.55)                                   # a small, smooth overshoot: it settles instead of bouncing
        self._slide.setEasingCurve(curve)
        self._pulse = QPropertyAnimation(self, b"glow", self)
        self._pulse.setDuration(GLOW_MS)
        self._pulse.setStartValue(1.0)
        self._pulse.setEndValue(0.0)
        self._pulse.setEasingCurve(QEasingCurve.Type.OutCubic)
        self.setMinimumSize(360, 84)
        self.setMaximumWidth(520)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName("Operating system of the memory image")
        self.setAccessibleDescription("Choose Windows or Linux. Left and right arrow keys change the choice.")
        self.setToolTip("Which operating system the memory image is from. The settings change with it; you can switch back at any time.")

    # ------------------------------------------------------------------ the choice
    @property
    def os_id(self) -> str:
        return self._ids[self._index]

    def set_os(self, os_id: str, animate: bool = True, emit: bool = True) -> None:
        if os_id not in self._ids:
            return
        index = self._ids.index(os_id)
        if index == self._index and abs(self._pos - index) < 1e-6:
            return
        changed = index != self._index
        self._index = index
        self._slide.stop()
        if animate and ANIMATED:
            self._slide.setStartValue(self._pos)
            self._slide.setEndValue(float(index))
            self._slide.start()
            self._pulse.stop()
            self._pulse.start()
        else:
            self._pos = float(index)
            self.update()
        if changed and emit:
            self.changed.emit(os_id)

    # ------------------------------------------------------------------ animated properties
    def _get_position(self) -> float:
        return self._pos

    def _set_position(self, value: float) -> None:
        self._pos = float(value)
        self.update()

    def _get_glow(self) -> float:
        return self._glow

    def _set_glow(self, value: float) -> None:
        self._glow = float(value)
        self.update()

    position = Property(float, _get_position, _set_position)
    glow = Property(float, _get_glow, _set_glow)

    # ------------------------------------------------------------------ painting
    def _half(self, index: int) -> QRectF:
        track = self._track()
        return QRectF(track.left() + index * track.width() / 2, track.top(), track.width() / 2, track.height())

    def _track(self) -> QRectF:
        return QRectF(2, 2, self.width() - 4, self.height() - 4)

    def paintEvent(self, _event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing, True)
        track = self._track()
        radius = track.height() / 2
        accent = _mix(WINDOWS_COLOUR, LINUX_COLOUR, min(1.0, max(0.0, self._pos)))
        # track
        p.setPen(QPen(TRACK_BORDER, 1.4))
        p.setBrush(QBrush(TRACK))
        p.drawRoundedRect(track, radius, radius)
        # a faint highlight under the side the mouse is over (when it is not the chosen one)
        half = track.width() / 2
        inset = 5.0
        if 0 <= self._hover != self._index:
            hint = QColor(255, 255, 255, 16)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(hint))
            side = QRectF(track.left() + inset + self._hover * half, track.top() + inset, half - 2 * inset, track.height() - 2 * inset)
            p.drawRoundedRect(side, side.height() / 2, side.height() / 2)
        # thumb with a soft glow that pulses when the choice changes
        thumb = QRectF(track.left() + inset + self._pos * half, track.top() + inset, half - 2 * inset, track.height() - 2 * inset)
        if self._glow > 0.01:
            for grow, alpha in ((14, 28), (9, 46), (5, 70)):
                halo = QColor(accent)
                halo.setAlpha(int(alpha * self._glow))
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(QBrush(halo))
                p.drawRoundedRect(thumb.adjusted(-grow * self._glow, -grow * self._glow, grow * self._glow, grow * self._glow), radius, radius)
        gradient = QLinearGradient(thumb.topLeft(), thumb.bottomLeft())
        gradient.setColorAt(0.0, accent.lighter(125))
        gradient.setColorAt(1.0, accent.darker(115))
        p.setPen(QPen(accent.lighter(150), 1.0))
        p.setBrush(QBrush(gradient))
        p.drawRoundedRect(thumb, thumb.height() / 2, thumb.height() / 2)
        # the two options
        font = QFont(self.font())
        font.setPointSizeF(max(11.0, self.font().pointSizeF() + 3))
        font.setBold(True)
        p.setFont(font)
        for index, os_id in enumerate(self._ids):
            area = self._half(index)
            closeness = 1.0 - min(1.0, abs(self._pos - index))                  # 1 when the thumb is on this side
            icon_size = 34.0 * (1.0 + 0.16 * closeness)
            label = self._options[os_id]
            metrics = p.fontMetrics()
            text_width = metrics.horizontalAdvance(label)
            total = icon_size + 12 + text_width
            left = area.center().x() - total / 2
            icon_box = QRectF(left, area.center().y() - icon_size / 2, icon_size, icon_size)
            p.setOpacity(0.5 + 0.5 * closeness if self._hover != index or closeness > 0.5 else 0.8)
            if os_id == "linux":
                paint_linux_icon(p, icon_box, QColor("#1b1f27") if closeness < 0.5 else QColor("#232833"))
            else:
                paint_windows_icon(p, icon_box, QColor("#ffffff") if closeness > 0.5 else QColor("#7fb0ff"))
            text_colour = _mix(QColor("#9fb0c8"), QColor("#10141b") if os_id == "linux" else QColor("#ffffff"), closeness)
            p.setPen(QPen(text_colour))
            p.drawText(QRectF(left + icon_size + 12, area.top(), text_width + 4, area.height()), int(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft), label)
            p.setOpacity(1.0)
        if self.hasFocus():
            p.setPen(QPen(QColor("#9ec3ff"), 1.6, Qt.PenStyle.DashLine))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawRoundedRect(track.adjusted(-1, -1, 1, 1), radius, radius)
        p.end()

    # ------------------------------------------------------------------ input
    def _index_at(self, x: float) -> int:
        return 0 if x < self.width() / 2 else 1

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.set_os(self._ids[self._index_at(event.position().x())])
            self.setFocus(Qt.FocusReason.MouseFocusReason)

    def mouseMoveEvent(self, event) -> None:
        hover = self._index_at(event.position().x())
        if hover != self._hover:
            self._hover = hover
            self.update()

    def leaveEvent(self, _event) -> None:
        self._hover = -1
        self.update()

    def keyPressEvent(self, event) -> None:
        key = event.key()
        if key in (Qt.Key.Key_Left, Qt.Key.Key_Up):
            self.set_os(self._ids[0])
        elif key in (Qt.Key.Key_Right, Qt.Key.Key_Down):
            self.set_os(self._ids[1])
        elif key in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.set_os(self._ids[1 - self._index])
        else:
            super().keyPressEvent(event)

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        self.update()

    def focusOutEvent(self, event) -> None:
        super().focusOutEvent(event)
        self.update()
