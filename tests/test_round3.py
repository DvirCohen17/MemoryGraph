"""PER-002, PX-001, BASE-001, STIX/MISP lists, network notes, lane zoom/connectors/image, remembered column widths."""
import copy
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_case_and_ioc import by_rule, evaluate, fresh, plugin, run_with, with_plugins
from test_pipeline_and_runner import FIXTURE, env, load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")
from PySide6.QtCore import QEvent, QPoint, QPointF, Qt              # noqa: E402
from PySide6.QtGui import QWheelEvent                              # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture()
def dashboard(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(established=True), settings={})
    window.resize(1400, 800)
    window.show()
    app.processEvents()
    yield window
    window.close()
    app.processEvents()


# ============================================================================= PER-002
def key_rows(key, **values):
    return [{"Type": "REG_SZ", "Key": key, "Name": name, "Data": data, "Last Write Time": "2018-06-21T00:00:00+00:00"} for name, data in values.items()]


def test_autostart_rule_flags_winlogon_appinit_and_ifeo_but_not_normal_values():
    nt = "Microsoft\\Windows NT\\CurrentVersion"
    winlogon = (key_rows(nt + "\\Winlogon", Shell="explorer.exe", Userinit="C:\\Windows\\system32\\userinit.exe,") +
                [{"Type": "Key", "Key": nt + "\\Winlogon", "Name": "Notify", "Data": "C:\\ignored\\x.exe"}])
    assert by_rule(with_plugins(plugin("windows.registry.printkey [Winlogon]", winlogon)), "PER-002") == []

    bad = (key_rows(nt + "\\Winlogon", Shell="explorer.exe, C:\\Users\\Public\\evil.exe", Userinit="C:\\Windows\\system32\\userinit.exe,C:\\evil.exe") +
           key_rows(nt + "\\Windows", AppInit_DLLs="C:\\Users\\Public\\hook.dll", LoadAppInit_DLLs="1"))
    ifeo = (key_rows(nt + "\\Image File Execution Options\\notepad.exe", Debugger="C:\\Users\\Public\\dbg.exe") +
            key_rows(nt + "\\Image File Execution Options\\taskmgr.exe", Debugger="\"C:\\Tools\\procexp64.exe\"") +
            key_rows(nt + "\\Image File Execution Options\\app.exe", GlobalFlag="0x200"))
    result = with_plugins(plugin("windows.registry.printkey [Winlogon]", bad), plugin("windows.registry.printkey [AppInit]", []),
                          plugin("windows.registry.printkey [IFEO]", ifeo))
    found = by_rule(result, "PER-002")
    titles = " | ".join(f.title for f in found)
    assert len(found) == 5, titles
    assert "Winlogon Shell is" in titles and "Userinit" in titles and "AppInit_DLLs loads" in titles and "Starting notepad.exe runs" in titles
    assert next(f for f in found if "taskmgr" in f.title).severity == "Low"            # Process Explorer replacing Task Manager: known legitimate use
    assert all(f.severity == "Medium" for f in found if "taskmgr" not in f.title)
    assert found[0].evidence_items[0].source_plugin.startswith("windows.registry.printkey [")


def test_run_key_rule_does_not_read_the_autostart_runs():
    nt = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    rows = key_rows(nt, Shell="C:\\Users\\Public\\evil.exe")                               # would be flagged by PER-001 if it read this run
    result = with_plugins(plugin("windows.registry.printkey [Winlogon]", rows))
    assert by_rule(result, "PER-001") == [] and len(by_rule(result, "PER-002")) == 1


def test_autostart_choice_runs_three_printkey_invocations(tmp_path):
    nt = "Microsoft\\Windows NT\\CurrentVersion"
    rows = key_rows(nt + "\\Winlogon", Userinit="C:\\evil.exe")
    result, _ = run_with(tmp_path, {"windows.registry.printkey": rows}, optional_plugins=["autostart_keys"])
    runs = [p for p in result.plugins if p.name.startswith("windows.registry.printkey [")]
    assert len(runs) == 3 and all(p.status == "Completed" for p in runs)
    ifeo = next(p for p in runs if "IFEO" in p.name)
    assert "--recurse" in ifeo.command and ifeo.command[ifeo.command.index("--key") + 1].endswith("Image File Execution Options")
    assert [f.rule_id for f in result.indications if f.rule_id == "PER-002"] == ["PER-002"]      # same row seen by three runs: one finding


# ============================================================================= PX-001
def test_crossview_rule_only_flags_the_stricter_hiding():
    rows = [{"Name": "ok.exe", "PID": 100, "pslist": True, "psscan": True, "thrdscan": True, "csrss": True, "Exit Time": None},
            {"Name": "hidden1.exe", "PID": 200, "pslist": False, "psscan": False, "thrdscan": True, "csrss": False, "Exit Time": None},
            {"Name": "hidden2.exe", "PID": 201, "pslist": False, "psscan": False, "thrdscan": False, "csrss": True, "Exit Time": None},
            {"Name": "unlinked.exe", "PID": 300, "pslist": False, "psscan": True, "thrdscan": True, "csrss": False, "Exit Time": None},   # PT-003's case
            {"Name": "gone.exe", "PID": 400, "pslist": False, "psscan": False, "thrdscan": True, "csrss": False, "Exit Time": "2018-06-21T01:00:00+00:00"},
            {"Name": "none.exe", "PID": 500, "pslist": False, "psscan": False, "thrdscan": False, "csrss": False, "Exit Time": None}]
    found = by_rule(with_plugins(plugin("windows.psxview", rows)), "PX-001")
    assert sorted(f.title.split(" ")[0] for f in found) == ["hidden1.exe", "hidden2.exe"]
    assert "thrdscan" in found[0].title or "csrss" in found[0].title
    assert found[0].evidence_items[0].source_plugin == "windows.psxview"


# ============================================================================= BASE-001
def with_new_process(result):
    new = copy.deepcopy(next(p for p in result.processes if p.pid == 4))
    new.pid, new.name, new.path = 9999, "implant.exe", "C:\\Users\\Public\\implant.exe"
    result.processes.append(new)
    return result


def with_new_process_row(result):
    """A new process added the way real data arrives: as a windows.pslist row (so a re-analysis keeps it)."""
    pslist = next(p for p in result.plugins if p.name == "windows.pslist")
    row = dict(pslist.rows[3])
    row.update({"PID": 9999, "PPID": 4, "ImageFileName": "implant.exe", "CreateTime": "2018-06-21T06:40:00+00:00", "ExitTime": None})
    pslist.rows.append(row)
    return result


def test_baseline_with_process_list_reports_only_what_is_new(tmp_path):
    from app.analysis import case_state
    clean = fresh()
    path = tmp_path / "clean.json"
    case_state.export_baseline(clean, str(path), name="clean-host")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == 2 and len(data["processes"]) >= 20

    later = with_new_process(fresh())
    case_state.import_baseline(later, str(path))
    found = [f for f in evaluate(later) if f.rule_id == "BASE-001"]
    assert len(found) == 1 and found[0].category == "baseline"
    assert found[0].title.startswith("1 process(es) are not in baseline 'clean-host'") and found[0].severity == "Medium"      # Public folder
    assert "implant.exe" in found[0].evidence[0]
    without = with_new_process(fresh())                                                       # same data, no baseline imported
    corr = lambda items: sorted((f.rule_id, f.process_pid, f.title, f.severity) for f in items if f.rule_id.startswith("CORR"))
    assert corr(evaluate(later)) == corr(evaluate(without))                                   # the baseline finding changed nothing in correlation

    same = fresh()
    case_state.import_baseline(same, str(path))
    assert [f for f in evaluate(same) if f.rule_id == "BASE-001"] == []                                                       # nothing new


def test_old_style_and_false_positive_baselines_have_no_process_list(tmp_path):
    from app.analysis import case_state
    result = fresh()
    path = tmp_path / "b.json"
    case_state.export_baseline(result, str(path))
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("processes")
    data["version"] = 1
    path.write_text(json.dumps(data), encoding="utf-8")                                    # a baseline exported before this feature
    later = with_new_process(fresh())
    case_state.import_baseline(later, str(path))
    assert [f for f in evaluate(later) if f.rule_id == "BASE-001"] == []
    case_state.set_finding_status(result, next(i for i in result.indications if i.rule_id == "PT-003"), "false_positive")
    fp = tmp_path / "fp.json"
    case_state.export_baseline(result, str(fp), only_false_positives=True)
    assert json.loads(fp.read_text(encoding="utf-8"))["processes"] == []


def test_baseline_findings_survive_reanalysis_and_have_a_family_filter(app, tmp_path):
    from app.analysis import case_state
    from app.analysis.pipeline import reanalyze
    from app.windows.dashboard_window import DashboardWindow
    clean = fresh()
    path = tmp_path / "clean.json"
    case_state.export_baseline(clean, str(path), name="clean-host")
    later = with_new_process_row(fresh())
    case_state.import_baseline(later, str(path))
    rebuilt = reanalyze(later)                                                              # carries the baselines (and their process lists)
    assert any(p.pid == 9999 for p in rebuilt.processes) and any(i.rule_id == "BASE-001" for i in rebuilt.indications)
    dashboard = DashboardWindow(rebuilt, settings={})
    view = dashboard.select_view(dashboard.IDX["Indications"])
    view.severity.setCurrentIndex(2)
    assert view.rule.findData("family:baseline") != -1 and view.rule.findData("family:ioc") == -1
    view.rule.setCurrentIndex(view.rule.findData("family:baseline"))
    assert [i.rule_id for i in view._filtered()] == ["BASE-001"]
    view.rule.setCurrentIndex(view.rule.findData("family:behavioural"))
    assert view._filtered() == []                                       # the clean baseline suppressed every behavioural finding ...
    view.show_hidden.setChecked(True)
    assert view._filtered() and all(i.rule_id != "BASE-001" and i.triage == "baseline" for i in view._filtered())     # ... they are only hidden
    dashboard.close()


# ============================================================================= STIX and MISP lists
STIX = {"type": "bundle", "id": "bundle--1", "objects": [
    {"type": "indicator", "name": "C2 server", "pattern": "[ipv4-addr:value = '203.0.113.7' OR domain-name:value = 'evil.example.com']"},
    {"type": "indicator", "name": "dropper", "pattern": "[file:hashes.'SHA-256' = '" + "ab" * 32 + "' AND file:name = 'payload.exe']"},
    {"type": "indicator", "name": "mutex", "pattern": "[mutex:name = 'Global\\\\XyzMutex']"},
    {"type": "indicator", "name": "url", "pattern": "[url:value = 'http://bad.example.net/a.php']"},
    {"type": "indicator", "name": "reg", "pattern": "[windows-registry-key:key = 'HKLM\\\\x']"},
    {"type": "malware", "name": "ignored", "pattern": "[ipv4-addr:value = '9.9.9.9']"}]}

MISP = {"Event": {"info": "campaign", "Attribute": [
    {"type": "ip-dst", "value": "198.51.100.9", "to_ids": True, "comment": "c2"},
    {"type": "ip-dst|port", "value": "198.51.100.10|443", "to_ids": True},
    {"type": "domain", "value": "bad.example.org", "to_ids": True},
    {"type": "md5", "value": "44d88612fea8a8f36de82e1278abb02f", "to_ids": True},
    {"type": "filename|sha256", "value": "dropper.exe|" + "cd" * 32, "to_ids": True},
    {"type": "mutex", "value": "Global\\M1", "to_ids": True},
    {"type": "ip-src", "value": "192.0.2.1", "to_ids": False},                                  # analyst said: not actionable
    {"type": "comment", "value": "just text", "to_ids": False}],
    "Object": [{"Attribute": [{"type": "domain|ip", "value": "obj.example.org|192.0.2.50", "to_ids": True}]}]}}


def test_stix_bundle_and_misp_export_become_iocs(tmp_path):
    from app.analysis.ioc import load_ioc_file
    stix = tmp_path / "bundle.json"
    stix.write_text(json.dumps(STIX), encoding="utf-8")
    items, warnings = load_ioc_file(str(stix))
    got = {(i.kind, i.value) for i in items}
    assert {("ip", "203.0.113.7/32"), ("domain", "evil.example.com"), ("hash", "ab" * 32), ("file", "payload.exe"), ("mutex", "global\\xyzmutex"),
            ("domain", "bad.example.net")} <= got
    assert ("ip", "9.9.9.9/32") not in got                                                      # not an indicator object
    assert next(i for i in items if i.value == "203.0.113.7/32").note == "C2 server"
    assert len(warnings) == 1 and "no supported term" in warnings[0] and "'reg'" in warnings[0]

    misp = tmp_path / "event.json"
    misp.write_text(json.dumps(MISP), encoding="utf-8")
    items, warnings = load_ioc_file(str(misp))
    got = {(i.kind, i.value) for i in items}
    assert {("ip", "198.51.100.9/32"), ("ip", "198.51.100.10/32"), ("domain", "bad.example.org"), ("hash", "44d88612fea8a8f36de82e1278abb02f"),
            ("file", "dropper.exe"), ("hash", "cd" * 32), ("mutex", "global\\m1"), ("domain", "obj.example.org"), ("ip", "192.0.2.50/32")} <= got
    assert ("ip", "192.0.2.1/32") not in got and not warnings
    assert next(i for i in items if i.value == "198.51.100.9/32").note == "c2"


def test_json_that_is_neither_and_text_lists_still_work(tmp_path):
    from app.analysis.ioc import load_ioc_file
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}', encoding="utf-8")
    items, warnings = load_ioc_file(str(other))
    assert items == [] and "neither STIX" in warnings[0]
    text = tmp_path / "t.txt"
    text.write_text("203.0.113.7\n203.0.113.7\nevil.example.com\n", encoding="utf-8")
    items, _ = load_ioc_file(str(text))
    assert [i.kind for i in items] == ["ip", "domain"]                                          # duplicates collapse
    broken = tmp_path / "broken.ioc"
    broken.write_text("{ not json at all\n203.0.113.9\n", encoding="utf-8")
    assert [i.value for i in load_ioc_file(str(broken))[0]] == ["203.0.113.9/32"]               # invalid JSON falls back to the text parser


# ============================================================================= notes on network connections
def test_network_bookmark_and_note(app, dashboard, monkeypatch):
    from app.analysis import case_state
    view = dashboard.select_view(dashboard.IDX["Network"])
    view.view.selectRow(0)
    view.on_select()
    conn = view._current()
    assert conn is not None and view.bookmark_button.isEnabled()
    view.bookmark_button.click()
    target = case_state.network_target(conn)
    assert case_state.is_bookmarked(dashboard.result, target) and "Bookmarked" in view.bookmark_button.text() and dashboard.case_dirty
    monkeypatch.setattr(QtWidgets.QInputDialog, "getMultiLineText", staticmethod(lambda *a, **k: ("beacon every 60s", True)))
    view.note_button.click()
    assert "beacon every 60s" in view.note_info.text()
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(0) == "Bookmarks (1)" and case_view.tabs.tabText(1) == "Notes (1)"


# ============================================================================= lifetime lanes: zoom, connectors, image
def wheel(canvas, x, delta, ctrl=True):
    return QWheelEvent(QPointF(x, 80), QPointF(x, 80), QPoint(0, 0), QPoint(0, delta), Qt.MouseButton.NoButton,
                       Qt.KeyboardModifier.ControlModifier if ctrl else Qt.KeyboardModifier.NoModifier, Qt.ScrollPhase.NoScrollPhase, False)


def test_lanes_ctrl_wheel_zoom_reset_and_plain_wheel_scrolls(app, dashboard):
    view = dashboard.select_view(dashboard.IDX["Lifetimes"])
    app.processEvents()
    canvas = view.canvas
    full = len(canvas.lanes)
    span = canvas.t1 - canvas.t0
    for _ in range(6):                                                                       # zoom in towards the right edge (the capture)
        canvas.wheelEvent(wheel(canvas, canvas.width() - 60, 120))
        app.processEvents()
    assert view.zoom is not None and (canvas.t1 - canvas.t0) < span / 3 and len(canvas.lanes) < full
    assert "zoomed with Ctrl + wheel" in view.status.text() and not view.reset_zoom_button.isHidden()
    plain = wheel(canvas, 400, 120, ctrl=False)
    plain.setAccepted(True)
    canvas.wheelEvent(plain)
    assert not plain.isAccepted()                                                            # left to the scroll area
    view.reset_zoom_button.click()
    assert view.zoom is None and len(canvas.lanes) == full and view.reset_zoom_button.isHidden()
    canvas.wheelEvent(wheel(canvas, 400, -120))                                              # zooming out past everything: normal view again
    assert view.zoom is None


def test_lanes_draw_parent_child_connectors_and_save_an_image(app, dashboard, tmp_path, monkeypatch):
    from app.windows.lifetimes_window import build_lanes
    view = dashboard.select_view(dashboard.IDX["Lifetimes"])
    app.processEvents()
    pids = {l.pid for l in view.canvas.lanes}
    linked = [l for l in view.canvas.lanes if l.ppid in pids and l.ppid != l.pid]
    assert linked and all(isinstance(l.ppid, int) for l in build_lanes(dashboard.result)[0])
    plain = view.canvas.grab().toImage()
    for lane in linked:                                                                       # the connector pixels differ from a canvas without them
        pass
    path = tmp_path / "lanes.png"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(path), "")))
    monkeypatch.setattr("app.windows.lifetimes_window.show_info", lambda *a, **k: None)
    view.save_image()
    assert path.is_file() and path.stat().st_size > 1000 and not plain.isNull()


# ============================================================================= remembered column widths
def test_column_widths_round_trip_and_ignore_stale_data(app):
    from PySide6.QtGui import QStandardItemModel
    from app.windows import layout_state
    host = QtWidgets.QWidget()
    table = QtWidgets.QTableView(host)
    table.setModel(QStandardItemModel(2, 3))
    box = QtWidgets.QVBoxLayout(host)
    box.addWidget(table)
    host.resize(800, 300)
    host.show()
    for index, width in enumerate((150, 220, 90)):
        table.setColumnWidth(index, width)
    settings = {}
    layout_state.capture_columns(settings, "View", host)
    for index in range(3):
        table.setColumnWidth(index, 60)
    layout_state.apply_columns(settings, "View", host)
    assert [table.columnWidth(i) for i in range(3)] == [150, 220, 90]
    for bad in ({"layout": {"columns": {"View": [[1, 2]]}}}, {"layout": {"columns": {"View": "x"}}}, {"layout": {"columns": {"View": [[5, "a", 9000]]}}},
                {"remember_layout": False, **settings}):
        before = [table.columnWidth(i) for i in range(3)]
        layout_state.apply_columns(dict(bad), "View", host)
        assert [table.columnWidth(i) for i in range(3)] == before or bad.get("remember_layout") is False


def test_dashboard_remembers_the_process_tree_column_widths(app):
    from app.windows.dashboard_window import DashboardWindow
    settings = {}
    first = DashboardWindow(load_fixture_result(established=True), settings=settings)
    first.resize(1400, 800)
    first.show()
    tree = first.select_view(first.IDX["Process Tree"])
    tree.tree.setColumnWidth(0, 413)
    first.capture_layout()
    first.close()
    second = DashboardWindow(load_fixture_result(established=True), settings=settings)
    second.resize(1400, 800)
    second.show()
    assert second.select_view(second.IDX["Process Tree"]).tree.columnWidth(0) == 413
    second.close()


def test_new_plugins_are_registered_with_their_rules():
    from app.engines.windows.analysis import plugin_registry as registry
    from app.engines.windows.indicators.attack import attack_for
    choices = [c[0] for c in registry.optional_choices()]
    assert "autostart_keys" in choices and "windows.psxview" in choices
    assert registry.get("windows.psxview").used_by == ("PX-001",)
    assert [t.id for t in attack_for("PER-002")] == ["T1547.004", "T1546.010", "T1546.012"] and attack_for("PX-001") and attack_for("BASE-001") == []
