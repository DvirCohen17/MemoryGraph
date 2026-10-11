"""Themes and font size, remembered layout, process-lifetime lanes, bulk triage, ATT&CK column, LDR-001 (headless)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_case_and_ioc import by_rule, plugin, with_plugins
from test_pipeline_and_runner import load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")
from PySide6.QtCore import QEvent, QPointF, Qt, qInstallMessageHandler   # noqa: E402
from PySide6.QtGui import QMouseEvent                                   # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture()
def dark_after(app):
    yield
    from app.theme import get_theme_style
    get_theme_style("Dark")                      # theme tokens are module state: leave them as other tests expect


@pytest.fixture()
def dashboard(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(established=True), settings={})
    window.show()
    app.processEvents()
    yield window
    window.close()
    app.processEvents()


# ============================================================================= themes and fonts
def test_the_stylesheet_is_one_dark_theme_built_from_the_palette_and_parsed_by_qt(app, dark_after):
    from app.theme import APP_STYLE, PALETTE, THEME_CHOICES, get_theme_style, resolve_theme
    assert THEME_CHOICES == ["Dark"] and resolve_theme("Light") == "Dark" and resolve_theme("System") == "Dark" and resolve_theme("nonsense") == "Dark"
    assert "$" not in APP_STYLE                                                  # every palette token was filled in
    for token in ("bg", "surface", "accent", "accent2", "border", "text", "muted"):
        assert PALETTE[token] in APP_STYLE, token
    assert APP_STYLE.count("QPushButton#Primary") >= 4 and "QFrame#NavIndicator" in APP_STYLE and "QLabel, QCheckBox, QRadioButton" in APP_STYLE
    problems = []
    previous = qInstallMessageHandler(lambda mode, ctx, message: problems.append(message))
    try:
        for name in ("Dark", "Light"):                                           # older names still work: they mean the dark theme
            for size in (8, 10, 14, 18):
                app.setStyleSheet(get_theme_style(name, size))
    finally:
        qInstallMessageHandler(previous)
        app.setStyleSheet("")
    assert not [m for m in problems if "parse" in m.lower() or "unknown property" in m.lower()], problems
    assert get_theme_style("Light") == get_theme_style("Dark")


def test_the_colour_tokens_the_views_import_are_stable_dicts():
    from app.theme import CATEGORY_COLORS, SEVERITY_BACKGROUNDS, SEVERITY_COLORS
    from app.windows.widgets import severity_color
    assert SEVERITY_COLORS["High"] != SEVERITY_COLORS["Medium"] != SEVERITY_COLORS["Low"] and set(SEVERITY_BACKGROUNDS) == {"High", "Medium", "Low"}
    assert severity_color("High") == SEVERITY_COLORS["High"] and {"Process", "Network", "Module", "System"} <= set(CATEGORY_COLORS)


def test_font_scaling_and_limits():
    from app.theme import APP_STYLE, scale_fonts
    assert scale_fonts(APP_STYLE, 10) == APP_STYLE
    big = scale_fonts("* { font-size: 10pt; } #t { font-size: 27pt; }", 14)
    assert "font-size: 14pt" in big and "font-size: 38pt" in big
    assert "font-size: 18pt" in scale_fonts("* { font-size: 10pt; }", 99)         # clamped to 18pt
    assert "font-size: 8pt" in scale_fonts("* { font-size: 10pt; }", 1)


def test_theme_and_font_settings_are_sanitised():
    from app.settings import sanitize
    values = sanitize({"theme": "Neon", "font_size": 99, "layout": "oops", "remember_layout": 0})
    assert values["theme"] == "Dark" and values["font_size"] == 18 and values["layout"] == {} and values["remember_layout"] is False
    assert sanitize({"font_size": "x"})["font_size"] == 10 and sanitize({"theme": "Light"})["theme"] == "Dark"            # there is one theme


def test_settings_window_applies_font_and_resets_layout_and_has_no_theme_choice(app, monkeypatch, dark_after):
    import app.windows.settings_window as module

    class Parent(QtWidgets.QWidget):
        settings = {"layout": {"windows": {"home": "x"}}, "theme": "Light", "font_size": 10}

    saved = {}
    monkeypatch.setattr(module, "save_settings", lambda values: saved.update(values) or True)
    parent = Parent()
    dialog = module.SettingsWindow(parent)
    assert not hasattr(dialog, "theme")
    dialog.font_size.setValue(13)
    dialog.remember_layout.setChecked(False)
    dialog.apply_and_close()
    assert saved["theme"] == "Dark" and saved["font_size"] == 13 and saved["remember_layout"] is False and dialog.look_changed
    assert parent.settings["font_size"] == 13
    dialog.reset_layout()
    assert saved["layout"] == {} and parent.settings["layout"] == {}


# ============================================================================= remembered layout
def test_geometry_and_splitters_round_trip(app):
    from app.windows import layout_state
    settings = {}
    window = QtWidgets.QWidget()
    window.setGeometry(40, 30, 600, 400)            # (the headless screen is only 800x600)
    window.show()
    layout_state.save_geometry(settings, "home", window)
    window.setGeometry(0, 0, 400, 300)
    assert layout_state.restore_geometry(settings, "home", window) and window.width() == 600 and window.height() == 400
    assert not layout_state.restore_geometry(settings, "other", window)

    host = QtWidgets.QWidget()
    splitter = QtWidgets.QSplitter(Qt.Orientation.Horizontal, host)
    splitter.addWidget(QtWidgets.QLabel("a"))
    splitter.addWidget(QtWidgets.QLabel("b"))
    box = QtWidgets.QVBoxLayout(host)
    box.addWidget(splitter)
    host.resize(1000, 300)
    host.show()
    splitter.setSizes([700, 300])
    layout_state.capture_splitters(settings, "View", host)
    splitter.setSizes([100, 900])
    layout_state.apply_splitters(settings, "View", host)
    first, second = splitter.sizes()
    assert first > second * 1.5                                                        # back to the wide left panel


def test_layout_memory_is_optional_and_ignores_stale_or_garbled_entries(app):
    from app.windows import layout_state
    host = QtWidgets.QWidget()
    splitter = QtWidgets.QSplitter(host)
    splitter.addWidget(QtWidgets.QLabel("a"))
    splitter.addWidget(QtWidgets.QLabel("b"))
    off = {"remember_layout": False}
    layout_state.capture_splitters(off, "V", host)
    layout_state.save_geometry(off, "home", host)
    assert off.get("layout", {}).get("splitters", {}) == {} and off.get("layout", {}).get("windows", {}) == {}
    before = splitter.sizes()
    for bad in ({"layout": {"splitters": {"V": [[1, 2, 3]]}}},                       # a panel was added/removed since
                {"layout": {"splitters": {"V": "garbage"}}}, {"layout": "garbage"}, {"layout": {"splitters": {"V": [["a", "b"]]}}},
                {"layout": {"splitters": {"V": [[0, 0]]}}}, {"layout": {"windows": {"home": "not-base64!!"}}}):
        layout_state.apply_splitters(dict(bad), "V", host)
        layout_state.restore_geometry(dict(bad), "home", host)
    assert splitter.sizes() == before


def test_dashboard_captures_and_restores_splitter_positions(app):
    from app.windows.dashboard_window import DashboardWindow
    settings = {}
    first = DashboardWindow(load_fixture_result(), settings=settings)
    first.resize(1500, 900)
    first.show()
    tree = first.select_view(first.IDX["Process Tree"])
    app.processEvents()
    splitter = tree.findChildren(QtWidgets.QSplitter)[0]
    splitter.setSizes([300, 900])
    first.capture_layout()
    assert settings["layout"]["splitters"]["Process Tree"][0] == splitter.sizes()
    first.close()
    second = DashboardWindow(load_fixture_result(), settings=settings)
    second.resize(1500, 900)
    second.show()
    tree2 = second.select_view(second.IDX["Process Tree"])
    app.processEvents()
    sizes = tree2.findChildren(QtWidgets.QSplitter)[0].sizes()
    assert sizes[0] < sizes[1]                                                         # the default is 820 : 520, restored is 300 : 900
    second.close()


# ============================================================================= process lifetimes
def test_lanes_reflect_start_exit_capture_and_risk():
    from app.windows.lifetimes_window import build_lanes
    result = load_fixture_result(established=True)
    lanes, capture, skipped = build_lanes(result)
    assert capture is not None and len(lanes) + skipped == len(result.processes) and lanes
    assert all(l.end >= l.start for l in lanes)
    by_pid = {l.pid: l for l in lanes}
    assert by_pid[3828].hidden and by_pid[3828].severity == "Medium" and "psscan" in by_pid[3828].tooltip
    exited = [p for p in result.processes if p.exit_time]
    running = by_pid[4]
    assert running.running and running.end == capture
    if exited:
        assert not by_pid[exited[0].pid].running


def test_lanes_stop_counting_findings_hidden_by_triage():
    from app.analysis import case_state
    from app.windows.lifetimes_window import build_lanes
    result = load_fixture_result(established=True)
    case_state.set_finding_status(result, next(i for i in result.indications if i.rule_id == "PT-003" and i.process_pid == 3828), "false_positive")
    assert {l.pid: l for l in build_lanes(result)[0]}[3828].severity == ""


def test_lifetimes_view_filters_windows_and_opens_the_process(app, dashboard):
    from app.windows.lifetimes_window import AXIS_H, ROW_H
    view = dashboard.select_view(dashboard.IDX["Lifetimes"])
    app.processEvents()
    total = len(view.canvas.lanes)
    assert total > 10 and view.window.isEnabled() and "process lanes shown" in view.status.text()
    view.search.setText("svchost")
    assert 0 < len(view.canvas.lanes) < total and all("svchost" in l.name.lower() for l in view.canvas.lanes)
    view.search.setText("")
    view.flagged.setChecked(True)
    assert view.canvas.lanes and all(l.severity in ("Medium", "High") for l in view.canvas.lanes)
    view.flagged.setChecked(False)
    view.window.setCurrentIndex(4)                                                    # last 15 minutes before the capture
    assert len(view.canvas.lanes) < total and "outside the chosen window" in view.status.text()
    view.window.setCurrentIndex(0)
    view.order.setCurrentIndex(1)                                                     # by risk: flagged processes first
    assert view.canvas.lanes[0].severity in ("Medium", "High")
    view.order.setCurrentIndex(0)
    row = 2
    event = QMouseEvent(QEvent.Type.MouseButtonDblClick, QPointF(300, AXIS_H + ROW_H * row + 4), QPointF(300, AXIS_H + ROW_H * row + 4),
                        Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    expected = view.canvas.lanes[row].pid
    view.canvas.mouseDoubleClickEvent(event)
    app.processEvents()
    assert dashboard.stack.currentIndex() == dashboard.IDX["Process Tree"]
    assert dashboard.view("Process Tree").current_pid() == expected


def test_lifetimes_view_follows_triage_and_paints(app, dashboard):
    from app.analysis import case_state
    view = dashboard.select_view(dashboard.IDX["Lifetimes"])
    ind = next(i for i in dashboard.result.indications if i.rule_id == "PT-003" and i.process_pid == 3828)
    assert next(l for l in view.canvas.lanes if l.pid == 3828).severity == "Medium"
    case_state.set_finding_status(dashboard.result, ind, "false_positive")
    dashboard.triage_changed()
    assert next(l for l in view.canvas.lanes if l.pid == 3828).severity == ""
    assert not view.grab().isNull()                                                    # the canvas paints without raising


# ============================================================================= dashboard, bulk triage, ATT&CK column
def test_theme_change_rebuilds_the_open_views(app, dashboard):
    before = dashboard.select_view(dashboard.IDX["Indications"])
    dashboard.rebuild_views()
    after = dashboard.stack.widget(dashboard.IDX["Indications"])
    assert after is not before and dashboard.stack.currentIndex() == dashboard.IDX["Indications"]
    assert not dashboard._built[0]                                                     # the others rebuild when visited


def test_attack_column_and_search(app, dashboard):
    view = dashboard.select_view(dashboard.IDX["Indications"])
    assert view.tree.headerItem().text(6) == "ATT&CK"
    view.group.setChecked(False)
    items = [view.tree.topLevelItem(i) for i in range(view.tree.topLevelItemCount())]
    assert any(item.text(2) == "PT-003" and item.text(6) == "T1014" for item in items)
    view.search.setText("T1014")
    assert view._filtered() and all(i.rule_id in ("PT-003", "DRV-001", "DRV-002", "SSDT-001", "CBK-001") for i in view._filtered())
    view.search.setText("T9999")
    assert view._filtered() == []


def test_bulk_triage_marks_only_open_findings_that_are_shown(app, dashboard, monkeypatch):
    view = dashboard.select_view(dashboard.IDX["Indications"])
    shown = view._filtered()
    assert shown and any(i.severity == "Low" for i in dashboard.result.indications)    # Low findings are filtered out by default
    from app.analysis import case_state
    already = shown[0]
    case_state.set_finding_status(dashboard.result, already, "reviewed")                # a decision made earlier must be kept
    asked = []
    monkeypatch.setattr(QtWidgets.QInputDialog, "getText", staticmethod(lambda *a, **k: (asked.append(a[2]) or "bulk reason", True)))
    view.bulk_triage("false_positive")
    app.processEvents()
    assert "marked as false positive" in asked[0] and f"{len(shown) - 1} open" in asked[0]
    assert already.triage == "reviewed"
    assert all(i.triage == "false_positive" and i.triage_note == "bulk reason" for i in shown[1:])
    assert all(i.triage == "" for i in dashboard.result.indications if i.severity == "Low")
    assert dashboard.case_dirty and view._filtered() == [already]


def test_bulk_triage_can_be_cancelled_and_handles_nothing_to_do(app, dashboard, monkeypatch):
    view = dashboard.select_view(dashboard.IDX["Indications"])
    monkeypatch.setattr(QtWidgets.QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False)))
    view.bulk_triage("reviewed")
    assert all(i.triage == "" for i in dashboard.result.indications) and not dashboard.case_dirty
    view.search.setText("no such thing anywhere")
    infos = []
    monkeypatch.setattr(QtWidgets.QMessageBox, "information", staticmethod(lambda *a, **k: infos.append(a[2])))
    view.bulk_triage("reviewed")
    assert infos and "no open findings" in infos[0]


# ============================================================================= LDR-001
def test_unlinked_module_rule():
    none = {"InLoad": False, "InInit": False, "InMem": False}
    rows = [{"Pid": 7252, "Process": "taskhostw.exe", "Base": 0x10000, "MappedPath": "\\Users\\bob\\AppData\\Local\\Temp\\evil.dll", **none},
            {"Pid": 7252, "Process": "taskhostw.exe", "Base": 0x20000, "MappedPath": "\\Windows\\System32\\kernel32.dll", "InLoad": True, "InInit": True, "InMem": True},
            {"Pid": 7252, "Process": "taskhostw.exe", "Base": 0x30000, "MappedPath": "\\Windows\\System32\\apisetschema.dll", **none},
            {"Pid": 7252, "Process": "taskhostw.exe", "Base": 0x40000, "MappedPath": "\\Windows\\System32\\ntdll.dll", **none},           # WOW64 process: normal
            {"Pid": 4, "Process": "System", "Base": 0x50000, "MappedPath": "\\Windows\\System32\\odd.dll", **none},
            {"Pid": 4, "Process": "System", "Base": 0x60000, "MappedPath": "", **none},                                                    # no file: not an image
            {"Pid": 356, "Process": "smss.exe", "Base": 0x70000, "MappedPath": "\\Windows\\System32\\half.dll", "InLoad": True, "InInit": False, "InMem": False}]
    result = with_plugins(plugin("windows.ldrmodules", rows))
    next(p for p in result.processes if p.pid == 7252).wow64 = True                         # (set on the result that is evaluated)
    found = {f.process_pid: f for f in by_rule(result, "LDR-001")}
    assert set(found) == {7252}                      # the System process has no loader lists at all: its mappings cannot be judged (seen on a real XP image)
    assert found[7252].severity == "Medium" and found[7252].evidence[0].startswith("\\Users\\bob\\AppData\\Local\\Temp\\evil.dll (base 0x10000)")
    assert found[7252].evidence_items[0].source_plugin == "windows.ldrmodules" and found[7252].evidence_items[0].row_index == 0
    assert by_rule(with_plugins(plugin("windows.ldrmodules", rows[:2][1:])), "LDR-001") == []
    # not a WOW64 process: its ntdll.dll "in no list" means the loader lists were only partly readable (real Windows 10 image), so nothing is reported
    assert by_rule(with_plugins(plugin("windows.ldrmodules", rows)), "LDR-001") == []


def test_ldrmodules_is_registered_and_runs_through_the_provider():
    from app.engines.windows.analysis import plugin_registry as registry
    from app.engines.windows.indicators.attack import attack_for
    from app.engines.windows.analysis.real_provider import RealProvider
    assert "windows.ldrmodules" in RealProvider.OPTIONAL_PLUGINS and registry.get("windows.ldrmodules").used_by == ("LDR-001",)
    assert "windows.ldrmodules" in RealProvider({"optional_plugins": ["windows.ldrmodules"]}).plugin_names
    assert [t.id for t in attack_for("LDR-001")] == ["T1055"]
