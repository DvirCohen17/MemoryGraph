"""Keep every window inside the screen it opens on.

Windows are created with a comfortable default size (for example 1450x900) which does not fit a laptop screen or a scaled display.
Instead of making each window full screen, an application-wide filter looks at every top-level window when it is shown and, only if it is
larger than the screen's usable area (the screen minus the taskbar), shrinks it to ``FRACTION`` of that area and moves it back on screen.
Windows that already fit are left alone, and so are maximized windows, pop-ups, tooltips and the splash screen.
"""
from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QWidget

FRACTION = 0.92
_SKIP = (Qt.WindowType.ToolTip, Qt.WindowType.Popup, Qt.WindowType.SplashScreen, Qt.WindowType.Sheet, Qt.WindowType.Drawer)


def _screen_of(widget: QWidget):
    try:
        screen = widget.screen()
    except Exception:  # noqa: BLE001 - very old Qt
        screen = None
    return screen or QGuiApplication.primaryScreen()


def fit_window(widget: QWidget, fraction: float = FRACTION) -> bool:
    """Shrink and/or move ``widget`` so it fits the usable area of its screen. Returns True when anything changed."""
    if not widget.isWindow() or widget.isMaximized() or widget.isFullScreen() or widget.windowType() in _SKIP:
        return False
    screen = _screen_of(widget)
    if screen is None:
        return False
    area = screen.availableGeometry()
    frame_extra_w = max(0, widget.frameGeometry().width() - widget.width())      # title bar and borders (0 before the first show)
    frame_extra_h = max(0, widget.frameGeometry().height() - widget.height())
    max_w = max(200, int(area.width() * fraction) - frame_extra_w)
    max_h = max(150, int(area.height() * fraction) - frame_extra_h)
    changed = False
    if widget.width() > max_w or widget.height() > max_h:
        widget.resize(min(widget.width(), max_w), min(widget.height(), max_h))
        changed = True
    frame = widget.frameGeometry()
    x = min(max(frame.x(), area.left()), max(area.left(), area.right() - frame.width() + 1))
    y = min(max(frame.y(), area.top()), max(area.top(), area.bottom() - frame.height() + 1))
    if (x, y) != (frame.x(), frame.y()):
        widget.move(widget.x() + (x - frame.x()), widget.y() + (y - frame.y()))
        changed = True
    return changed


class ScreenFit(QObject):
    """Application event filter: fits each top-level window to the screen the first time (and every time) it is shown."""

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.Show and isinstance(obj, QWidget) and obj.isWindow():
            try:
                fit_window(obj)
            except Exception:  # noqa: BLE001 - never let window placement break showing a window
                pass
        return False


def install(app) -> ScreenFit:
    fitter = ScreenFit(app)
    app.installEventFilter(fitter)
    app._screen_fit = fitter          # keep a reference for the application's lifetime
    return fitter
