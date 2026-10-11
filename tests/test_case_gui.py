"""GUI: triage, notes, bookmarks, Case Notes view, Settings (headless)."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


@pytest.fixture()
def dashboard(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(established=True))
    window.show()
    app.processEvents()
    yield window
    window.close()
    app.processEvents()


def click(widget, text):
    button = next(b for b in widget.findChildren(QtWidgets.QPushButton) if b.text().startswith(text))
    button.click()


def answer_note(monkeypatch, text="my note", ok=True):
    monkeypatch.setattr(QtWidgets.QInputDialog, "getMultiLineText", staticmethod(lambda *a, **k: (text, ok)))


def test_false_positive_flow_updates_every_view(app, dashboard):
    from app.analysis.indicators.scoring import risk_by_pid
    from app.windows.indications_window import IndicationDetails
    view = dashboard.select_view(dashboard.IDX["Indications"])
    ind = next(i for i in dashboard.result.indications if i.rule_id == "PT-003" and i.process_pid == 3828)
    before = sum(1 for r in risk_by_pid(dashboard.result.indications).values() if r.severity in ("Medium", "High"))
    dialog = IndicationDetails(ind, view, None, result=dashboard.result)
    dialog.reason.setText("lab host")
    click(dialog, "False positive")
    app.processEvents()

    assert dialog.changed and ind.triage == "false_positive" and ind.triage_note == "lab host"
    assert dashboard.case_dirty and not dashboard.dirty_label.isHidden()
    after = sum(1 for r in risk_by_pid(dashboard.result.indications).values() if r.severity in ("Medium", "High"))
    assert after == before - 1 and f"({after})" in dashboard.nav[dashboard.IDX["Indications"]].text()
    assert ind not in view._filtered()                                           # hidden by default ...
    view.show_hidden.setChecked(True)
    assert ind in view._filtered()                                               # ... shown on request
    assert not dashboard._built[0]                                               # Overview is dropped and rebuilt on the next visit ...
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(2) == "Triage decisions (1)"
    overview = dashboard.select_view(0)
    assert dashboard._built[0] and overview is not None                          # ... from the new scores


def test_only_not_yet_reviewed_and_family_filters(app, dashboard):
    from app.analysis import case_state
    view = dashboard.select_view(dashboard.IDX["Indications"])
    ind = next(i for i in dashboard.result.indications if i.rule_id == "PT-003" and i.process_pid == 3828)
    view.severity.setCurrentIndex(2)                                              # Low, Medium and High
    case_state.set_finding_status(dashboard.result, ind, "reviewed")
    dashboard.triage_changed()
    assert ind in view._filtered()                                                # reviewed findings stay visible ...
    view.only_open.setChecked(True)
    assert ind not in view._filtered()                                            # ... unless you only want the unreviewed ones
    assert view.rule.findData("family:ioc") == -1                                 # no IOC findings: no family choice offered


def test_process_tree_bookmark_and_note(app, dashboard, monkeypatch):
    from app.analysis import case_state
    tree = dashboard.select_view(dashboard.IDX["Process Tree"])
    assert tree.select_pid(4)
    app.processEvents()
    proc = tree.by_pid[4]
    target = case_state.process_target(proc)
    tree.bookmark_button.click()
    assert case_state.is_bookmarked(dashboard.result, target) and tree.items[4].text(0).startswith("★")
    assert dashboard.case_dirty
    answer_note(monkeypatch, "talks to odd host")
    tree.note_button.click()
    assert "talks to odd host" in tree.detail.toPlainText() and "✎" in tree.items[4].text(0)
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(0) == "Bookmarks (1)" and case_view.tabs.tabText(1) == "Notes (1)"
    answer_note(monkeypatch, "", ok=False)                                         # cancelling adds nothing
    dashboard.select_view(dashboard.IDX["Process Tree"])
    tree.note_button.click()
    assert len(case_state.notes_for(dashboard.result, target)) == 1
    tree.bookmark_button.click()                                                   # toggles off
    assert not case_state.is_bookmarked(dashboard.result, target) and not tree.items[4].text(0).startswith("★")


def test_timeline_event_bookmark_and_note(app, dashboard, monkeypatch):
    from app.analysis import case_state
    view = dashboard.select_view(dashboard.IDX["Timeline"])
    view.view.selectRow(0)
    view.on_select()
    event = view._selected_event()
    assert event is not None and view.bookmark_event.isEnabled()
    view.bookmark_event.click()
    answer_note(monkeypatch, "start of the activity")
    view.note_event.click()
    target = case_state.event_target(event)
    assert case_state.is_bookmarked(dashboard.result, target) and "start of the activity" in view.detail.toPlainText()


def test_case_view_remove_reopens_a_decision_and_exports(app, dashboard, tmp_path, monkeypatch):
    from app.analysis import case_state
    ind = next(i for i in dashboard.result.indications if i.rule_id == "PT-003" and i.process_pid == 3828)
    case_state.set_finding_status(dashboard.result, ind, "false_positive", "x")
    dashboard.triage_changed()
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(2) == "Triage decisions (1)"
    key = next(iter(dashboard.result.case["findings"]))
    case_view._remove(("finding", key, dashboard.result.case["findings"][key]))     # what "Remove selected" does
    assert ind.triage == "" and case_view.tabs.tabText(2) == "Triage decisions (0)"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "n.md"), "")))
    monkeypatch.setattr("app.windows.case_window.show_info", lambda *a, **k: None)
    case_view.export_notes()
    assert (tmp_path / "n.md").read_text(encoding="utf-8").startswith("# MemoryGraph case notes")


def test_baseline_import_through_the_case_view(app, dashboard, tmp_path, monkeypatch):
    from app.analysis import case_state
    path = tmp_path / "clean.json"
    case_state.export_baseline(load_fixture_result(established=True), str(path), name="clean")
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    monkeypatch.setattr(QtWidgets.QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(path), "")))
    monkeypatch.setattr("app.windows.case_window.show_info", lambda *a, **k: None)
    case_view.import_baseline()
    assert all(i.triage == "baseline" for i in dashboard.result.indications) and case_view.tabs.tabText(3) == "Baselines (1)"
    view = dashboard.select_view(dashboard.IDX["Indications"])
    assert view._filtered() == [] and "hidden" in view.status.text()
    assert not dashboard._built[0]                                                # Overview will be rebuilt without the suppressed findings


def test_unsaved_case_work_is_tracked_and_cleared_on_save(app, dashboard):
    assert not dashboard.case_dirty
    dashboard.case_changed()
    assert dashboard.case_dirty
    dashboard.clear_dirty()
    assert not dashboard.case_dirty and dashboard.dirty_label.isHidden()


def test_settings_window_bundles_yara_and_ioc_lists(app, monkeypatch):
    from app.engines.windows.analysis import plugin_registry as registry
    import app.windows.settings_window as settings_module
    saved = {}
    monkeypatch.setattr(settings_module, "save_settings", lambda values: saved.update(values) or True)
    dialog = settings_module.SettingsWindow()
    assert list(dialog.bundle_boxes) == [b.id for b in registry.BUNDLES] and not dialog.bundle_boxes["processes"].isEnabled()       # the process list is always on
    assert [i for i, box in dialog.bundle_boxes.items() if box.isChecked()] == ["processes", "network", "memory", "handles"]      # the old defaults
    dialog.bundle_boxes["persistence"].setChecked(True)
    dialog.bundle_boxes["yara"].setChecked(True)
    dialog.yara_path.setText("C:\\rules\\mine.yar")
    dialog.ioc_list.setPlainText("C:\\intel\\a.txt\n\n\"C:\\intel\\b.txt\"\n")
    dialog.apply_and_close()
    assert "windows.vadyarascan" in saved["optional_plugins"] and {"run_keys", "autostart_keys", "more_run_keys", "service_keys"} <= set(saved["optional_plugins"])
    assert saved["optional_plugins"] == [cid for cid, *_ in registry.optional_choices() if cid in saved["optional_plugins"]]          # registry order
    assert saved["yara_rules_file"] == "C:\\rules\\mine.yar" and saved["ioc_files"] == ["C:\\intel\\a.txt", "C:\\intel\\b.txt"]


def test_dump_result_reports_hash_ioc_matches(app, monkeypatch):
    import subprocess
    from app.engines.windows.analysis.dumper import DumpedFile
    from app.analysis.ioc import IocSet, parse_ioc_text
    import app.windows.process_window as process_module
    result = load_fixture_result(established=True)
    digest = "a" * 64
    iocs = IocSet(parse_ioc_text(digest + "   # known dropper\n", "intel.txt")[0])
    messages = []
    monkeypatch.setattr(process_module, "show_info", lambda parent, title, text: messages.append(text))
    window = process_module.ProcessWindow(result.processes[0], None, dump_path="x.raw", iocs=iocs)
    completed = subprocess.CompletedProcess(["vol"], 0, "", "")
    completed.artifacts = [DumpedFile("pid.4.dmp", 3, digest, "b" * 32), DumpedFile("other.dmp", 3, "c" * 64, "d" * 32)]
    completed.manifest = "out\\memorygraph_hashes.csv"
    window._dump_done("Process dump", "out", (completed, ["vol"]))
    text = messages[0]
    assert "IOC HASH MATCH" in text and "pid.4.dmp" in text and "known dropper" in text and "other.dmp: " not in text
    assert "memorygraph_hashes.csv" in text and ("a" * 64) in text
