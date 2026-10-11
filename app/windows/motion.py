"""Movement: everything in the interface that is animated, in one place.

Qt style sheets are still pictures, so the motion is done here with property animations that the event loop runs at the screen's rate:

* ``fade_in``            a widget appears (the page you switched to, the first cards of the start window)
* ``stagger_in``         several widgets appear one after the other
* ``AnimatedStack``      a stacked widget whose page change is a short fade
* ``animate_geometry``   a widget glides to a new place (the marker in the navigation)
* ``animate_value``      a progress bar runs to its new value instead of jumping
* ``GlowFilter``         the primary buttons glow while the mouse is over them

``ENABLED = False`` makes everything instant (the tests do this; it is also the place to add a "reduce motion" setting).
"""
from __future__ import annotations

from typing import Iterable

from PySide6.QtCore import QEasingCurve, QEvent, QObject, QPropertyAnimation, QRect, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsDropShadowEffect, QGraphicsOpacityEffect, QProgressBar, QPushButton, QStackedWidget, QWidget

ENABLED = True
FADE_MS = 190
GLIDE_MS = 300


def _keep(owner: QObject, name: str, animation: QPropertyAnimation) -> QPropertyAnimation:
    """Remember the running animation on its owner (one per property: a new one replaces the old) so Python does not collect it while it runs."""
    previous = getattr(owner, name, None)
    if previous is not None and previous is not animation:
        try:
            previous.stop()
        except RuntimeError:                      # the old animation's C++ object is already gone
            pass
    setattr(owner, name, animation)
    return animation


def fade_in(widget: QWidget, ms: int = FADE_MS, start: float = 0.0, delay: int = 0) -> None:
    """Fade ``widget`` in from ``start`` to fully visible. Nothing happens when motion is off or the widget is not on screen."""
    if not ENABLED or widget is None or not widget.isVisible():
        return
    effect = QGraphicsOpacityEffect(widget)
    effect.setOpacity(start)
    widget.setGraphicsEffect(effect)
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(ms)
    animation.setStartValue(start)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)

    def done() -> None:
        # the effect is removed afterwards: a lasting effect makes a big widget render off screen on every repaint
        if widget.graphicsEffect() is effect:
            widget.setGraphicsEffect(None)

    animation.finished.connect(done)
    _keep(widget, "_fade_animation", animation)
    if delay:
        from PySide6.QtCore import QTimer
        QTimer.singleShot(delay, animation.start)
    else:
        animation.start()


def stagger_in(widgets: Iterable[QWidget], ms: int = 320, step: int = 80) -> None:
    """Fade the widgets in one after the other, each ``step`` ms after the one before."""
    if not ENABLED:
        return
    for index, widget in enumerate(widgets):
        if widget is not None and widget.isVisible():
            effect = QGraphicsOpacityEffect(widget)
            effect.setOpacity(0.0)
            widget.setGraphicsEffect(effect)
            fade_in_later(widget, effect, ms, index * step)


def fade_in_later(widget: QWidget, effect: QGraphicsOpacityEffect, ms: int, delay: int) -> None:
    from PySide6.QtCore import QTimer
    animation = QPropertyAnimation(effect, b"opacity", widget)
    animation.setDuration(ms)
    animation.setStartValue(0.0)
    animation.setEndValue(1.0)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    animation.finished.connect(lambda: widget.setGraphicsEffect(None) if widget.graphicsEffect() is effect else None)
    _keep(widget, "_fade_animation", animation)
    QTimer.singleShot(delay, animation.start)


def animate_geometry(widget: QWidget, target: QRect, ms: int = GLIDE_MS) -> None:
    """Glide ``widget`` to ``target`` (instantly when motion is off)."""
    if not ENABLED or not widget.isVisible():
        widget.setGeometry(target)
        return
    animation = QPropertyAnimation(widget, b"geometry", widget)
    animation.setDuration(ms)
    animation.setStartValue(widget.geometry())
    animation.setEndValue(target)
    animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
    _keep(widget, "_glide_animation", animation).start()


def animate_value(bar: QProgressBar, value: int, ms: int = 380) -> None:
    """Run a progress bar to ``value`` (never backwards by animation: a restart goes to its value at once)."""
    value = int(value)
    if not ENABLED or not bar.isVisible() or value < bar.value():
        bar.setValue(value)
        return
    animation = QPropertyAnimation(bar, b"value", bar)
    animation.setDuration(ms)
    animation.setStartValue(bar.value())
    animation.setEndValue(value)
    animation.setEasingCurve(QEasingCurve.Type.OutCubic)
    _keep(bar, "_value_animation", animation).start()


class AnimatedStack(QStackedWidget):
    """A stacked widget that fades the page you switch to."""

    def setCurrentIndex(self, index: int) -> None:
        changed = index != self.currentIndex()
        super().setCurrentIndex(index)
        if changed:
            fade_in(self.currentWidget(), FADE_MS, start=0.25)


class GlowFilter(QObject):
    """Application-wide event filter: a primary button glows (a soft shadow in the accent colour that grows) while the mouse is over it."""

    GLOW = QColor(111, 143, 255, 190)

    def eventFilter(self, obj, event) -> bool:
        kind = event.type()
        if kind in (QEvent.Type.Enter, QEvent.Type.Leave) and ENABLED and isinstance(obj, QPushButton) and obj.objectName() == "Primary":
            self._glow(obj, kind == QEvent.Type.Enter)
        return False

    def _glow(self, button: QPushButton, on: bool) -> None:
        effect = button.graphicsEffect()
        if on and not button.isEnabled():
            return
        if not isinstance(effect, QGraphicsDropShadowEffect):
            if not on:
                return
            effect = QGraphicsDropShadowEffect(button)
            effect.setOffset(0, 0)
            effect.setColor(self.GLOW)
            effect.setBlurRadius(0)
            button.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"blurRadius", button)
        animation.setDuration(260 if on else 220)
        animation.setStartValue(effect.blurRadius())
        animation.setEndValue(30.0 if on else 0.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        if not on:
            animation.finished.connect(lambda: button.setGraphicsEffect(None) if isinstance(button.graphicsEffect(), QGraphicsDropShadowEffect) and
                                       button.graphicsEffect().blurRadius() < 0.5 else None)
        _keep(button, "_glow_animation", animation).start()
