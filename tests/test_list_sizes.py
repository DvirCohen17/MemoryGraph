"""Every list in every dashboard view stays big enough to read on a laptop-sized window (a user's screenshot showed the Files list squeezed to its header row)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

QtWidgets = pytest.importorskip("PySide6.QtWidgets")

from test_pipeline_and_runner import load_fixture_result  # noqa: E402
from test_round5 import app, dispose, filescan_rows, plugin  # noqa: E402,F401


def lists_of(view):
    found = []
    for w in view.findChildren(QtWidgets.QAbstractItemView):
        if isinstance(w, QtWidgets.QHeaderView) or not w.isVisibleTo(view):
            continue
        if w.parentWidget() is not None and w.parentWidget().objectName() == "qt_scrollarea_viewport":
            continue
        found.append(w)
    return found


@pytest.mark.parametrize("size", [(1280, 640), (1100, 600)])
def test_no_list_is_squeezed_to_its_header_and_each_view_scrolls_instead(app, size):
    from app.analysis.pipeline import reanalyze
    from app.windows.dashboard_window import DashboardWindow
    result = load_fixture_result()
    result.plugins.append(plugin("windows.filescan", filescan_rows()))
    result = reanalyze(result)
    window = DashboardWindow(result, settings={})
    window.resize(*size)
    window.show()
    try:
        for name in window.IDX:
            view = window.select_view(window.IDX[name])
            for _ in range(3):
                app.processEvents()
            scroll = window.stack.currentWidget()
            assert isinstance(scroll, QtWidgets.QScrollArea) and scroll.widget() is view       # the page scrolls when it does not fit
            for lst in lists_of(view):
                assert lst.viewport().height() >= 140 and lst.viewport().width() >= 150, (name, type(lst).__name__, lst.viewport().size())
        files = window.view("Files")
        assert files.view.viewport().height() >= 200                                          # the Files list shows at least about seven rows
    finally:
        dispose(app, window)


def test_a_large_window_gives_the_extra_room_to_the_lists_not_to_empty_space(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.resize(1500, 1000)
    window.show()
    try:
        small = window.select_view(window.IDX["Network"])
        for _ in range(3):
            app.processEvents()
        assert small.view.viewport().height() > 450                                           # it fills the page: no scrollbar, no wasted space
        assert not window.stack.currentWidget().verticalScrollBar().isVisible()
    finally:
        dispose(app, window)
