"""Windows open inside the screen without becoming full screen, and no view forces a window wider than a laptop screen."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")
from PySide6.QtCore import Qt                       # noqa: E402
from PySide6.QtGui import QFontDatabase             # noqa: E402

SEGOE = [os.path.join(r"C:\Windows\Fonts", name) for name in ("segoeui.ttf", "segoeuib.ttf")]


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture()
def real_fonts(app):
    """The offscreen platform has no fonts (text measures about twice as wide). Use Segoe UI, the font the app uses, when present."""
    if not all(os.path.isfile(path) for path in SEGOE):
        pytest.skip("Segoe UI is not installed: widths cannot be measured realistically")
    for path in SEGOE:
        QFontDatabase.addApplicationFont(path)
    from app.theme import get_theme_style
    app.setStyleSheet(get_theme_style("Dark", 10))
    yield
    app.setStyleSheet("")


def usable(app):
    return app.primaryScreen().availableGeometry()


# ============================================================================= the fitting itself
def test_oversized_window_is_shrunk_to_the_screen_but_not_made_full_screen(app):
    from app.windows.screen_fit import FRACTION, fit_window
    area = usable(app)
    window = QtWidgets.QWidget()
    window.resize(area.width() * 3, area.height() * 3)
    window.show()
    assert fit_window(window)
    assert window.width() <= area.width() * FRACTION + 1 and window.height() <= area.height() * FRACTION + 1
    assert not window.isMaximized() and not window.isFullScreen()
    assert window.width() > area.width() * 0.5                                # still a big window, only fitted


def test_windows_that_already_fit_are_left_alone_and_off_screen_ones_are_moved_back(app):
    from app.windows.screen_fit import fit_window
    area = usable(app)
    small = QtWidgets.QWidget()
    small.resize(300, 200)
    small.move(area.left() + 20, area.top() + 20)
    small.show()
    assert not fit_window(small) and (small.width(), small.height()) == (300, 200)
    small.move(area.right() + 500, area.bottom() + 500)                       # e.g. restored from a second monitor that is gone
    assert fit_window(small)
    frame = small.frameGeometry()
    assert area.left() <= frame.left() and frame.right() <= area.right() and area.top() <= frame.top() and frame.bottom() <= area.bottom()


def test_special_windows_are_skipped(app):
    from app.windows.screen_fit import fit_window
    area = usable(app)
    popup = QtWidgets.QWidget(None, Qt.WindowType.Popup)
    popup.resize(area.width() * 2, 100)
    assert not fit_window(popup)
    tool_tip = QtWidgets.QWidget(None, Qt.WindowType.ToolTip)
    tool_tip.resize(area.width() * 2, 100)
    assert not fit_window(tool_tip)
    parent = QtWidgets.QWidget()                                              # (kept alive: the child dies with its parent)
    child = QtWidgets.QWidget(parent)
    child.resize(area.width() * 2, 100)
    assert not fit_window(child)                                              # only top-level windows


def test_installed_filter_fits_dialogs_when_they_are_shown(app):
    from app.windows import screen_fit
    fitter = screen_fit.install(app)
    try:
        area = usable(app)
        dialog = QtWidgets.QDialog()
        dialog.resize(area.width() * 2, area.height() * 2)
        dialog.show()
        app.processEvents()
        assert dialog.width() <= area.width() and dialog.height() <= area.height()
        dialog.close()
    finally:
        app.removeEventFilter(fitter)


# ============================================================================= layouts and labels that stay narrow
def test_flow_layout_wraps_and_only_needs_the_widest_item(app):
    from app.windows.widgets import FlowLayout
    host = QtWidgets.QWidget()
    flow = FlowLayout(host, h_spacing=10, v_spacing=5)
    buttons = [QtWidgets.QPushButton(f"button number {i}") for i in range(8)]
    for button in buttons:
        flow.addWidget(button)
    widest = max(b.sizeHint().width() for b in buttons)
    assert flow.minimumSize().width() == widest                                # not the sum of all eight
    wide_height, narrow_height = flow.heightForWidth(2000), flow.heightForWidth(widest * 2 + 30)
    assert narrow_height > wide_height * 2                                     # wrapped onto more lines
    host.resize(widest * 2 + 30, narrow_height)
    host.show()
    app.processEvents()
    assert all(b.geometry().right() <= host.width() for b in buttons) and len({b.y() for b in buttons}) >= 3


def test_elided_label_shortens_long_text_instead_of_widening(app):
    from app.windows.widgets import ElidedLabel, muted
    label = ElidedLabel("C:\\very\\long\\path\\" + "folder\\" * 40 + "memory.raw")
    assert label.minimumSizeHint().width() <= 24 and label.sizeHint().width() > 300
    assert isinstance(muted("x", wrap=False), ElidedLabel) and not isinstance(muted("x"), ElidedLabel)
    label.resize(120, 20)
    label.show()
    app.processEvents()
    assert not label.grab().isNull() and "memory.raw" in label.text()          # full text kept (tooltip) when it is shortened


# ============================================================================= the real windows
def test_dashboard_with_every_view_open_fits_a_laptop_screen(app, real_fonts):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.resize(1500, 800)
    window.show()
    for name in window.IDX:
        window.select_view(window.IDX[name])
        app.processEvents()
    assert window.minimumSizeHint().width() <= 1000, window.minimumSizeHint()      # was 1662 before the control bars wrapped
    window.close()


def test_settings_window_content_fits_its_default_width_and_height_is_bounded(app, real_fonts):
    from app.windows import screen_fit
    from app.windows.settings_window import SettingsWindow
    fitter = screen_fit.install(app)
    try:
        dialog = SettingsWindow()
        dialog.resize(760, 520)                                                        # the settings are a page of the main window: test at its smallest size
        dialog.show()
        app.processEvents()
        area = usable(app)
        assert dialog.height() <= area.height() and dialog.width() <= area.width()
        for page, scroll in enumerate(dialog.scrolls):                                 # every page: no sideways scrolling at the default width
            dialog.nav.setCurrentRow(page)
            app.processEvents()
            content, viewport = scroll.widget().minimumSizeHint().width(), scroll.viewport().width()
            assert content <= viewport, (page, content, viewport)
            assert not scroll.horizontalScrollBar().isVisible(), page
        wrapped = [l for l in dialog.findChildren(QtWidgets.QLabel) if l.wordWrap() and l.objectName() == "Muted"]
        assert len(wrapped) >= 20                                                    # every bundle and every group explains itself in wrapping text
        dialog.close()
    finally:
        app.removeEventFilter(fitter)


def test_other_windows_fit_and_keep_their_proportions(app, real_fonts):
    from app.windows import screen_fit
    from app.windows.home_window import HomeWindow
    from app.windows.indications_window import IndicationDetails
    from app.windows.process_window import ProcessWindow
    fitter = screen_fit.install(app)
    try:
        result = load_fixture_result()
        area = usable(app)
        for window in (HomeWindow(), ProcessWindow(result.processes[3], None, dump_path="x.raw"),
                       IndicationDetails(result.indications[0], None, None, result=result)):
            window.show()
            app.processEvents()
            frame = window.frameGeometry()
            assert frame.height() <= area.height() and frame.width() <= area.width() and frame.top() >= area.top() and frame.left() >= area.left(), type(window).__name__
            window.close()
    finally:
        app.removeEventFilter(fitter)
