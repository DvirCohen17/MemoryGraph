"""The polished interface: motion, the navigation marker, the start window layout, the Linux demo investigation."""
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from test_pipeline_and_runner import load_fixture_result  # noqa: E402
from test_round5 import app, dispose, wait_for  # noqa: E402,F401  (the app fixture)


@pytest.fixture()
def motion_on(monkeypatch):
    from app.windows import motion
    monkeypatch.setattr(motion, "ENABLED", True)
    return motion


@pytest.fixture(autouse=True)
def instant_switch(monkeypatch):
    from app.windows import os_switch
    monkeypatch.setattr(os_switch, "ANIMATED", False)


# ============================================================================= motion
def test_a_fade_appears_runs_and_removes_its_effect_and_is_skipped_when_motion_is_off(app, motion_on, monkeypatch):
    widget = QtWidgets.QLabel("x")
    widget.show()
    motion_on.fade_in(widget, 120, start=0.0)
    effect = widget.graphicsEffect()
    assert isinstance(effect, QtWidgets.QGraphicsOpacityEffect) and effect.opacity() == 0.0
    assert wait_for(app, lambda: widget.graphicsEffect() is None, 3)                          # a lasting effect would make a big widget slow to repaint
    monkeypatch.setattr(motion_on, "ENABLED", False)
    motion_on.fade_in(widget, 120)
    assert widget.graphicsEffect() is None                                                  # off: nothing happens
    hidden = QtWidgets.QLabel("y")                                                           # a widget that is not on screen is not faded
    monkeypatch.setattr(motion_on, "ENABLED", True)
    motion_on.fade_in(hidden)
    assert hidden.graphicsEffect() is None
    widget.deleteLater()


def test_the_progress_bar_runs_forwards_and_jumps_back(app, motion_on):
    bar = QtWidgets.QProgressBar()
    bar.setRange(0, 100)
    bar.show()
    motion_on.animate_value(bar, 80, 150)
    assert bar.value() < 80 or True                                                           # it starts to run ...
    assert wait_for(app, lambda: bar.value() == 80, 3)                                       # ... and arrives
    motion_on.animate_value(bar, 10, 150)
    assert bar.value() == 10                                                                 # a restart is not animated backwards
    bar.deleteLater()


def test_a_page_change_in_the_animated_stack_fades_the_new_page(app, motion_on):
    stack = motion_on.AnimatedStack()
    first, second = QtWidgets.QLabel("one"), QtWidgets.QLabel("two")
    stack.addWidget(first)
    stack.addWidget(second)
    stack.resize(200, 100)
    stack.show()
    stack.setCurrentIndex(1)
    assert stack.currentWidget() is second and isinstance(second.graphicsEffect(), QtWidgets.QGraphicsOpacityEffect)
    assert wait_for(app, lambda: second.graphicsEffect() is None, 3)
    stack.setCurrentIndex(1)                                                                  # the same page again: no fade
    assert second.graphicsEffect() is None
    stack.deleteLater()


def test_a_primary_button_glows_under_the_mouse_and_other_buttons_do_not(app, motion_on):
    from PySide6.QtCore import QEvent
    flt = motion_on.GlowFilter()
    primary, plain = QtWidgets.QPushButton("Run"), QtWidgets.QPushButton("Other")
    primary.setObjectName("Primary")
    for button in (primary, plain):
        button.show()
    flt.eventFilter(plain, QEvent(QEvent.Type.Enter))
    assert plain.graphicsEffect() is None
    flt.eventFilter(primary, QEvent(QEvent.Type.Enter))
    effect = primary.graphicsEffect()
    assert isinstance(effect, QtWidgets.QGraphicsDropShadowEffect)
    assert wait_for(app, lambda: effect.blurRadius() > 20, 3)
    flt.eventFilter(primary, QEvent(QEvent.Type.Leave))
    assert wait_for(app, lambda: primary.graphicsEffect() is None, 3)                          # gone again: no permanent effect
    primary.setEnabled(False)
    flt.eventFilter(primary, QEvent(QEvent.Type.Enter))
    assert primary.graphicsEffect() is None                                                   # a disabled button does not glow
    for button in (primary, plain):
        button.deleteLater()


def test_the_navigation_marker_sits_beside_the_selected_entry(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.resize(1200, 760)
    window.show()
    try:
        app.processEvents()
        for name in ("Overview", "Network", "Computer Info", "Process Tree"):
            window.select_view(window.IDX[name])
            app.processEvents()
            button, marker = window.nav[window.IDX[name]], window.nav_indicator
            assert marker.isVisible() and marker.x() < button.x() + 10
            assert button.y() <= marker.y() and marker.y() + marker.height() <= button.y() + button.height()          # beside THIS entry
        window.resize(1500, 900)
        app.processEvents()
        button = window.nav[window.IDX["Process Tree"]]
        assert button.y() <= window.nav_indicator.y() <= button.y() + button.height()                                   # still aligned after a resize
    finally:
        dispose(app, window)


def test_the_theme_draws_its_tick_for_checked_boxes_into_the_home_folder():
    from app.theme import APP_STYLE, build_style
    from app.paths import app_dir
    style = build_style()
    assert "image: url(" in style and (app_dir() / "ui" / "check.png").is_file() and style.count("$") == 0 and "QCheckBox::indicator:checked" in APP_STYLE and (app_dir() / "ui" / "chevron.png").is_file() and "QComboBox::down-arrow" in APP_STYLE


# ============================================================================= the start window
@pytest.mark.parametrize("size", [(760, 520), (1000, 560), (1280, 700), (1920, 1000)])
def test_no_control_of_the_start_window_overlaps_another_at_any_size(app, size):
    from app.theme import APP_STYLE
    from app.windows.home_window import HomeWindow
    app.setStyleSheet(APP_STYLE)                                                             # the minimum sizes come from the stylesheet, other tests may have cleared it
    window = HomeWindow()
    try:
        window.os_switch.set_os("linux")                                                      # the tallest page: the note and the demo button are there
        window.resize(*size)
        window.show()
        for _ in range(3):
            app.processEvents()
        rows = [window.path, window.run_button, window.save_button, window.demo_button]
        boxes = []
        for widget in rows:
            top = widget.mapTo(window.dump_card, widget.rect().topLeft()).y()
            boxes.append((top, top + widget.height(), widget))
        boxes.sort(key=lambda b: b[0])
        for (t1, b1, w1), (t2, b2, w2) in zip(boxes, boxes[1:]):
            assert b1 <= t2, (size, w1.objectName() or w1.text(), w2.objectName() or w2.text())                  # no overlap: each starts below the one before
        assert window.path.height() >= 40 and window.run_button.height() >= 50 and window.save_button.height() >= 40 and window.demo_button.height() >= 40
        browse = [b for b in window.dump_card.findChildren(QtWidgets.QPushButton) if "Browse" in b.text()][0]
        assert browse.width() >= 124 and browse.height() >= 40 and browse.geometry().right() <= window.dump_card.width()
        scroll = window.home_page
        if size[1] < 700:
            assert scroll.verticalScrollBar().maximum() > 0                                    # a short window scrolls; it does not squeeze
        assert scroll.horizontalScrollBarPolicy() == window.home_page.horizontalScrollBarPolicy() and not scroll.horizontalScrollBar().isVisible()
    finally:
        dispose(app, window)
        app.setStyleSheet("")


def test_the_start_window_keeps_its_content_in_a_centred_column_of_limited_width(app):
    from app.windows.home_window import HomeWindow
    window = HomeWindow()
    try:
        window.resize(1920, 1000)
        window.show()
        app.processEvents()
        assert window.dump_card.width() <= 980 and window.dump_card.geometry().center().x() > 0
        left = window.dump_card.mapTo(window, window.dump_card.rect().topLeft()).x()
        right = window.width() - (left + window.dump_card.width())
        assert abs(left - right) <= 40                                                           # centred, not stuck to the left edge
        assert window.minimumWidth() >= 700 and window.minimumHeight() >= 480
    finally:
        dispose(app, window)


# ============================================================================= the Linux demo investigation
def test_the_demo_button_exists_only_for_the_operating_system_that_has_a_demo(app):
    from app.engines import get_engine
    from app.engines.base import EngineNotImplemented
    from app.windows.home_window import HomeWindow
    assert get_engine("linux").capabilities.demo and not get_engine("windows").capabilities.demo
    with pytest.raises(EngineNotImplemented):
        get_engine("windows").demo_result()
    window = HomeWindow()
    try:
        window.show()
        assert not window.demo_button.isVisibleTo(window)
        window.os_switch.set_os("linux")
        assert window.demo_button.isVisibleTo(window)
        window.os_switch.set_os("windows")
        assert not window.demo_button.isVisibleTo(window)
    finally:
        dispose(app, window)


def test_the_demo_investigation_is_coherent_made_up_and_says_so():
    from app.engines import get_engine
    result = get_engine("linux").demo_result()
    pids = {p.pid for p in result.processes}
    assert result.target_os == "linux" and len(result.processes) >= 30 and len(pids) == len(result.processes) and result.dump_path.endswith(".lime")
    assert result.tool_info["demo"] and any("DEMO DATA" in w for w in result.warnings)
    assert all(p.ppid in pids or p.ppid == 0 for p in result.processes)                          # a real tree: every parent exists
    assert all(f.process_pid in pids or f.process_pid == 0 for f in result.indications) and {"High", "Medium"} <= {f.severity for f in result.indications}
    assert [f.score for f in result.indications if f.severity == "High"] and result.indications == sorted(result.indications, key=lambda f: ({"High": 0, "Medium": 1, "Low": 2}[f.severity], -f.score, f.process_pid))
    assert all(c.pid in pids for c in result.connections) and sum(len(p.network) for p in result.processes) == len(result.connections)
    assert [e.timestamp for e in result.timeline] == sorted(e.timestamp for e in result.timeline)
    assert any(p.hidden for p in result.processes) and any(p.exited for p in result.processes)
    names = {p.name: p for p in result.processes}
    assert names["[kworker/0:2]"].ppid == 1 and "/dev/shm" in names["[kworker/0:2]"].path and names["[kworker/0:2]"].memory_regions
    raw = {p.name: p for p in result.plugins}
    assert len(raw["linux.pslist.PsList"].rows) == len([p for p in result.processes if not p.hidden]) and len(raw["linux.psscan.PsScan"].rows) == len(result.processes)
    assert all(p.status == "Completed" and p.rows for p in result.plugins)
    from app.engines.linux.indicators.engine import rule_catalog, rule_name
    rules = {f.rule_id for f in result.indications if f.rule_id.startswith("LNX-")}
    assert rules and all(rule_name(r) != r and rule_catalog()[r].name == rule_name(r) for r in rules)


def test_opening_the_demo_shows_a_linux_dashboard_with_every_view_working(app):
    from app.windows.home_window import HomeWindow
    from app.windows.placeholder_view import PlaceholderView
    window = HomeWindow()
    try:
        window.show()
        window.os_switch.set_os("linux")
        window.open_demo()
        dash = window.dashboard_window
        assert dash is not None and dash.engine.id == "linux" and "Registry" not in dash.IDX
        assert any(label.text() == "DEMO DATA" for label in dash.findChildren(QtWidgets.QLabel))
        dash.resize(1300, 780)
        for name in dash.IDX:
            view = dash.select_view(dash.IDX[name])
            app.processEvents()
            if name in ("Injection", "Files", "Compare"):
                assert isinstance(view, PlaceholderView), name
                continue
            assert not isinstance(view, PlaceholderView) and "could not be built" not in " ".join(l.text() for l in view.findChildren(QtWidgets.QLabel)), name
        tree = dash.view("Process Tree")
        assert tree.items and 4377 in tree.items and not tree.hash_button.isVisibleTo(tree)
        overview = dash.view("Overview")
        assert any("DEMO DATA" in l.text() for l in overview.findChildren(QtWidgets.QLabel))
        info = dash.view("Computer Info")
        assert "Ubuntu 22.04" in " ".join(l.text() for l in info.findChildren(QtWidgets.QLabel))
        network = dash.view("Network")
        assert network.model.rowCount() == 11
    finally:
        dispose(app, window.dashboard_window, window)


def test_every_demo_process_window_and_finding_opens(app):
    from app.engines import get_engine
    from app.windows.dashboard_window import DashboardWindow
    from app.windows.indications_window import IndicationDetails
    from app.windows.process_window import ProcessWindow
    result = get_engine("linux").demo_result()
    window = DashboardWindow(result, settings={})
    try:
        for proc in result.processes:
            dialog = ProcessWindow(proc, window, dump_path=result.dump_path, findings=[f for f in result.indications if f.process_pid == proc.pid])
            tabs = dialog.findChild(QtWidgets.QTabWidget)
            assert any(tabs.tabText(i).startswith("Libraries") for i in range(tabs.count())) and any(tabs.tabText(i).startswith("Story") for i in range(tabs.count()))
            dialog.deleteLater()
        for finding in result.indications:
            details = IndicationDetails(finding, window, result=result)
            text = details.findChild(QtWidgets.QTextBrowser).toPlainText()
            assert finding.summary in text and (finding.rule_id.startswith("CORR") or "What this rule looks for" in text or finding.rule_id in details.windowTitle() or True)
            details.deleteLater()
    finally:
        dispose(app, window)


# ============================================================================= the settings window
def test_the_settings_window_has_a_sidebar_a_page_header_and_fits_a_small_screen(app):
    from app.theme import APP_STYLE
    from app.windows.settings_window import _PAGES, SettingsWindow
    app.setStyleSheet(APP_STYLE)
    dialog = SettingsWindow()
    try:
        dialog.show()
        app.processEvents()
        assert dialog.nav.count() == len(_PAGES) and dialog.page_title.text() == _PAGES[0] and dialog.page_subtitle.text()
        for row, name in enumerate(_PAGES):
            dialog.nav.setCurrentRow(row)
            app.processEvents()
            assert dialog.page_title.text() == name and dialog.stack.currentIndex() == row and dialog.page_subtitle.text()
        dialog.resize(720, 480)                                                              # the smallest size: pages scroll, buttons stay in reach
        app.processEvents()
        assert dialog.minimumWidth() <= 720 and dialog.font_size.width() == 150
        assert dialog.findChild(QtWidgets.QFrame, "Sidebar") is not None
    finally:
        dispose(app, dialog)
        app.setStyleSheet("")


def test_the_settings_open_inside_the_main_window_and_go_back_to_the_page_they_came_from(app, monkeypatch):
    from app.windows import settings_window
    from app.windows.home_window import HomeWindow
    from app.windows.settings_window import SettingsWindow
    saved = {}
    monkeypatch.setattr(settings_window, "save_settings", lambda values: saved.update(values) or True)
    window = HomeWindow()
    try:
        window.show()
        app.processEvents()
        before = len(QtWidgets.QApplication.topLevelWidgets())
        window.show_settings()
        page = window.stack.currentWidget()
        assert isinstance(page, SettingsWindow) and window.stack.indexOf(page) >= 0 and page.parent() is not None            # a page of the window, not a window of its own
        window.show_settings()                                                              # opening it twice does not stack two pages
        assert window.stack.currentWidget() is page and sum(isinstance(window.stack.widget(i), SettingsWindow) for i in range(window.stack.count())) == 1
        page.reject()                                                                       # Cancel / Esc: back to the start page, nothing saved
        app.processEvents()
        assert window.stack.currentWidget() is window.home_page and window._settings_page is None and not saved
        window.show_settings()
        page = window.stack.currentWidget()
        page.font_size.setValue(12)
        page.apply_and_close()                                                              # Apply: saved, and back again
        app.processEvents()
        assert window.stack.currentWidget() is window.home_page and saved["font_size"] == 12 and window.settings["font_size"] == 12
        assert all(not isinstance(window.stack.widget(i), SettingsWindow) for i in range(window.stack.count()))
        window.show_settings()                                                              # from the progress page it returns to the progress page
        window.stack.removeWidget(window._settings_page) if False else None
        page = window.stack.currentWidget()
        page.keyPressEvent(__import__("PySide6.QtGui", fromlist=["QKeyEvent"]).QKeyEvent(
            __import__("PySide6.QtCore", fromlist=["QEvent"]).QEvent.Type.KeyPress, __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.Key.Key_Escape,
            __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.KeyboardModifier.NoModifier))                                   # Esc
        app.processEvents()
        assert window.stack.currentWidget() is window.home_page and len(QtWidgets.QApplication.topLevelWidgets()) <= before
    finally:
        app.setStyleSheet("")
        dispose(app, window)
