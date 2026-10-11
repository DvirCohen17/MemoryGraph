"""Registry browser (tree merge, search, fetching another key) and process-injection chains."""
import json
import os
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, env, load_fixture_result, make_dump
from test_roadmap_features import plugin
from test_round5 import app, dispose, wait_for  # noqa: F401  (the app fixture)

SOFTWARE = "\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\software\\Microsoft\\Windows\\CurrentVersion"


def run_rows():
    return [
        {"Key": f"{SOFTWARE}\\Run", "Name": "Updater", "Type": "REG_SZ", "Data": "C:\\Users\\Public\\upd.exe", "Last Write Time": "2024-01-02 03:04:05"},
        {"Key": f"{SOFTWARE}\\Run", "Name": "Updater", "Type": "REG_SZ", "Data": "C:\\Users\\Public\\upd.exe", "Last Write Time": "2024-01-02 03:04:05"},
        {"Key": f"{SOFTWARE}\\Run", "Name": "Other", "Type": "REG_SZ", "Data": "C:\\Windows\\other.exe"},
        {"Key": f"{SOFTWARE}", "Name": "RunOnce", "Type": "Key", "Last Write Time": "2024-01-01 00:00:00"},
    ]


def user_rows():
    return [{"Key": "\\??\\C:\\Documents and Settings\\Administrator\\NTUSER.DAT\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Name": "evil",
             "Type": "REG_SZ", "Data": "C:\\temp\\evil.exe"}]


# ============================================================================= registry tree (no GUI)
def test_key_paths_are_reduced_to_a_hive_and_the_path_inside_it():
    from app.engines.windows.analysis.registry_tree import UNKNOWN_HIVE, split_key
    assert split_key(f"{SOFTWARE}\\Run") == ("SOFTWARE", "Microsoft\\Windows\\CurrentVersion\\Run")
    assert split_key("\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\SAM\\Domains") == ("SAM", "Domains")
    assert split_key("\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services") == ("SYSTEM", "ControlSet001\\Services")
    assert split_key(user_rows()[0]["Key"])[0] == "NTUSER.DAT (Administrator)"
    assert split_key("ControlSet001\\Services\\Foo") == (UNKNOWN_HIVE, "ControlSet001\\Services\\Foo")


def test_printkey_results_are_merged_into_one_tree_without_duplicates_and_failed_ones_are_ignored():
    from app.engines.windows.analysis.registry_tree import RegistryTree
    plugins = [plugin("windows.registry.printkey [Run keys]", run_rows()), plugin("windows.registry.printkey [custom: x]", user_rows()),
               plugin("windows.registry.printkey [broken]", run_rows(), status="Failed"), plugin("windows.pslist", [{"PID": 4}])]
    tree = RegistryTree(plugins)
    assert [r.name for r in tree.roots()] == ["NTUSER.DAT (Administrator)", "SOFTWARE"]
    run = tree.lookup("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
    assert [(v.name, v.data) for v in run.values] == [("Updater", "C:\\Users\\Public\\upd.exe"), ("Other", "C:\\Windows\\other.exe")]
    assert run.last_write == "2024-01-02 03:04:05" and run.sources == ["windows.registry.printkey [Run keys]"]
    assert tree.lookup("software\\microsoft\\windows\\currentversion\\runonce").last_write == "2024-01-01 00:00:00"   # a "Key" row is a subkey, not a value
    assert tree.values == 3 and tree.lookup("SOFTWARE\\Nothing") is None and tree.lookup("") is None
    assert [(n.full_path.split("\\")[0], v.name if v else None) for n, v in tree.find("evil")] == [("NTUSER.DAT (Administrator)", "evil")]
    assert tree.find("   ") == []
    names = {(n.name, v.name if v else None) for n, v in tree.find("run updater")}
    assert ("Run", "Updater") in names


# ============================================================================= registry view
@pytest.fixture()
def registry_dashboard(app, tmp_path):
    from app.windows.dashboard_window import DashboardWindow
    result = load_fixture_result()
    result.plugins.append(plugin("windows.registry.printkey [Run keys]", run_rows()))
    result.dump_path = make_dump(tmp_path)
    window = DashboardWindow(result, settings={"volatility_path": str(FAKE_VOL)})
    window.resize(1400, 800)
    window.show()
    app.processEvents()
    yield window, tmp_path
    dispose(app, window)


def test_registry_view_shows_hives_keys_and_values_and_finds_text(app, registry_dashboard):
    window, _ = registry_dashboard
    view = window.select_view(window.IDX["Registry"])
    assert view.tree.topLevelItemCount() == 1 and view.tree.topLevelItem(0).text(0) == "SOFTWARE"
    assert "1 hive(s)" in view.status.text()
    view.search.setText("upd.exe")
    view.find_first()
    assert view.tree.currentItem().text(0) == "Run" and "Match 1 of 1" in view.status.text()
    rows = [[view.proxy.index(r, c).data() for c in range(3)] for r in range(view.proxy.rowCount())]
    assert ["Updater", "REG_SZ", "C:\\Users\\Public\\upd.exe"] in rows and len(rows) == 2
    assert "Last written: 2024-01-02 03:04:05" in view.info.toPlainText()
    view.search.setText("nothing like this")
    view.find_first()
    assert "Nothing matches" in view.status.text()


def test_fetching_another_key_runs_printkey_adds_it_to_the_investigation_and_marks_it_changed(app, registry_dashboard):
    window, tmp_path = registry_dashboard
    view = window.select_view(window.IDX["Registry"])
    fixture = tmp_path / "fixture.json"
    key = "Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
    fixture.write_text(json.dumps({f"windows.registry.printkey {key}": [
        {"Key": f"\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\software\\{key}", "Name": "Userinit", "Type": "REG_SZ", "Data": "C:\\Windows\\system32\\userinit.exe,"}]}),
        encoding="utf-8")
    log = tmp_path / "args.log"
    window.case_dirty = False
    with env(FAKE_VOL_FIXTURE=str(fixture), FAKE_VOL_ARGLOG=str(log)):
        view.fetch_key(key, recurse=True)
        assert not view.fetch_button.isEnabled()
        assert wait_for(app, lambda: view.fetch_button.isEnabled())
    assert "--key " + key in log.read_text(encoding="utf-8") and "--recurse" in log.read_text(encoding="utf-8") and "--offline" in log.read_text(encoding="utf-8")
    assert any(p.name == f"windows.registry.printkey [custom: {key} (with subkeys)]" for p in view.result.plugins)
    assert window.case_dirty and view.tree_data.lookup(f"SOFTWARE\\{key}").values[0].name == "Userinit"
    assert view.tree.currentItem().text(0) == "Winlogon"
    # a missing image is explained, not started
    messages = []
    import app.windows.registry_window as rw
    original = rw.show_error
    rw.show_error = lambda parent, title, text, details="": messages.append(text)
    try:
        view.result.dump_path = str(tmp_path / "gone.mem")
        view.fetch_key("Run")
    finally:
        rw.show_error = original
    assert messages and "not available" in messages[0] and view.fetch_button.isEnabled()


def test_a_failing_fetch_reports_the_error_and_changes_nothing(app, registry_dashboard):
    window, tmp_path = registry_dashboard
    view = window.select_view(window.IDX["Registry"])
    before = list(view.result.plugins)
    messages = []
    import app.windows.registry_window as rw
    original = rw.show_error
    rw.show_error = lambda parent, title, text, details="": messages.append(text)
    try:
        with env(FAKE_VOL_FIXTURE=str(tmp_path / "none.json"), FAKE_VOL_FAIL="windows.registry.printkey"):
            view.fetch_key("Software\\X")
            assert wait_for(app, lambda: view.fetch_button.isEnabled())
    finally:
        rw.show_error = original
    assert messages and view.result.plugins == before


# ============================================================================= injection chains
def handle_row(holder_pid, holder, target, kind="Process", mask=0x1F0FFF):
    return {"PID": holder_pid, "Process": holder, "Type": kind, "GrantedAccess": mask, "Details": f"Pid {target}", "Name": f"Pid {target}"}


def chain_result(handles):
    from app.analysis.pipeline import reanalyze
    result = load_fixture_result()
    result.plugins = [p for p in result.plugins if p.name != "windows.handles"] + [plugin("windows.handles", handles)]
    return reanalyze(result)


def test_access_masks_decide_which_process_handles_could_inject():
    from app.engines.windows.analysis.injection import access_names, process_access_can_inject
    assert process_access_can_inject(0x1F0FFF) and process_access_can_inject(0x0002)           # everything / CREATE_THREAD
    assert process_access_can_inject(0x0008 | 0x0020) and not process_access_can_inject(0x0008)   # VM_OPERATION alone cannot write
    assert not process_access_can_inject(0x0400 | 0x0010)                                        # query + read only
    assert access_names(0x0008 | 0x0020) == ["VM_OPERATION", "VM_WRITE"]


def test_a_process_with_a_memory_sign_gets_a_chain_with_the_writer_and_what_it_did_next():
    from app.engines.windows.analysis import injection
    result = chain_result([handle_row(880, "CCC.exe", 7252)])
    target = next(c for c in injection.build_chains(result) if c.pid == 7252)
    phases = [(s.phase, s.kind) for s in target.steps]
    assert ("In the process", "memory") in phases and ("Who could have done it", "handle") in phases and ("What it did afterwards", "child") in phases
    handle = next(s for s in target.steps if s.kind == "handle")
    assert "CCC.exe (PID 880)" in handle.text and handle.pid == 880 and "0x1f0fff" in handle.text
    assert [s.phase for s in target.steps] == sorted((s.phase for s in target.steps), key=["In the process", "Who could have done it", "What it did afterwards"].index)
    assert target.score > injection.build_chains(chain_result([]))[0].score


def test_operating_system_handle_holders_weak_masks_and_self_handles_are_not_evidence():
    from app.engines.windows.analysis import injection
    for rows in ([handle_row(844, "svchost.exe", 7252)], [handle_row(880, "CCC.exe", 7252, mask=0x0400 | 0x0010)], [handle_row(7252, "taskhostw.exe", 7252)]):
        chain = next(c for c in injection.build_chains(chain_result(rows)) if c.pid == 7252)
        assert "handle" not in chain.kinds, rows


def test_a_handle_into_a_clean_process_alone_does_not_make_a_chain_and_the_writer_gets_an_afterwards_step():
    from app.engines.windows.analysis import injection
    result = chain_result([handle_row(880, "CCC.exe", 2192), handle_row(7252, "taskhostw.exe", 880)])
    chains = {c.pid: c for c in injection.build_chains(result)}
    assert 2192 not in chains and 880 not in chains                                  # neither has a sign in itself
    result = chain_result([handle_row(7252, "taskhostw.exe", 880)])
    assert any(s.kind == "handle" and s.phase == "What it did afterwards" and s.pid == 880 for s in injection.build_chains(result)[0].steps)


def test_a_false_positive_decision_removes_the_sign_from_the_chain():
    from app.engines.windows.analysis import injection
    result = chain_result([])
    mal = [f for f in result.indications if f.process_pid == 7252 and f.rule_id in injection.EVIDENCE_RULES]
    for finding in mal:
        finding.triage = "false_positive"
    after = injection.build_chains(result)
    assert all(not (c.pid == 7252 and any(s.source in {f.rule_id for f in mal} for s in c.steps)) for c in after)


def test_chains_are_empty_without_any_memory_sign():
    from app.engines.windows.analysis import injection
    result = chain_result([])
    result.memory_regions = []
    for finding in result.indications:
        finding.triage = "false_positive"
    assert injection.build_chains(result) == []
    assert injection.parent_line(result, 999999) == "" and "taskhostw.exe" in injection.parent_line(result, 7252)


# ============================================================================= injection view
def test_injection_view_lists_chains_tells_the_story_and_follows_triage(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(chain_result([handle_row(880, "CCC.exe", 7252)]), settings={})
    window.resize(1400, 800)
    window.show()
    try:
        view = window.select_view(window.IDX["Injection"])
        assert view.proxy.rowCount() >= 1 and view.proxy.index(0, 0).data() == "taskhostw.exe" and view.open_button.isEnabled()
        story = view.story.toPlainText()
        assert "taskhostw.exe (PID 7252)" in story and "Who could have done it" in story and "CCC.exe (PID 880)" in story and "What it did afterwards" in story
        assert "executable private memory" in view.proxy.index(0, 2).data() and "write-capable handle" in view.proxy.index(0, 2).data()
        opened = []
        window.show_process = lambda pid: opened.append(pid)
        view.on_link(__import__("PySide6.QtCore", fromlist=["QUrl"]).QUrl("pid:880"))
        view.open_process(view._current())
        assert opened == [880, 7252]
        for finding in view.result.indications:
            finding.triage = "false_positive"
        view.result.memory_regions = []
        view.refresh_after_triage()
        assert view.proxy.rowCount() == 0 and not view.open_button.isEnabled() and "No process has a memory-level sign" in view.status.text()
    finally:
        dispose(app, window)
