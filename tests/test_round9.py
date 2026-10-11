"""Second source for High findings, known-good lists, behavioural lead, transient processes, callback cross-check, plugin timing, process story, tool info."""
import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, env, load_fixture_result, make_dump, run_provider
from test_round5 import app, dispose  # noqa: F401  (the app fixture)
from test_round7 import plugin_result, rule_findings, with_rows

B = chr(92)


def path(*parts):
    return B.join(["C:"] + list(parts))


def first_pid(result, exclude=("system",)):
    return next(p.pid for p in result.processes if p.pid > 4 and p.name.lower() not in exclude)


# ============================================================================= a High finding needs a second plugin
def test_a_single_plugin_high_is_medium_until_a_second_plugin_points_at_the_same_process():
    pid = first_pid(load_fixture_result())
    result = with_rows("windows.malware.hollowprocesses", [{"PID": pid, "Process": "x.exe", "Notes": "There is no VAD starting at the base address"}])
    result.memory_regions = [r for r in result.memory_regions if r.pid != pid]
    found = rule_findings(result, "MAL-001")
    assert [f.severity for f in found] == ["Medium"] and found[0].confidence == "Low" and any("High needs two independent sources" in r for r in found[0].reasons)
    # an independent finding of another plugin on the same process (here: an unlisted image from a user folder, found by ldrmodules) makes it High again, and says so
    result.plugins.append(plugin_result("windows.ldrmodules", [{"Pid": pid, "Process": "x.exe", "Base": 0x10000, "InInit": False, "InLoad": False, "InMem": False,
                                                                "MappedPath": B.join(["", "Users", "bob", "AppData", "Local", "Temp", "evil.dll"])}]))
    again = rule_findings(result, "MAL-001")
    assert [f.severity for f in again] == ["High"] and any("Corroborated by another plugin" in r and "LDR-001" in r for r in again[0].reasons)


def test_the_second_source_helper_counts_only_other_plugins_and_other_rules():
    from app.analysis.indicators.corroboration import require_second_source, second_source
    from app.models import Indication
    mk = lambda rule, sev, plugins, pid=7, cat="memory": Indication(title=rule, severity=sev, process_pid=pid, rule_id=rule, source_plugins=plugins, category=cat, confidence="Medium")
    hollow = mk("MAL-001", "High", ["windows.malware.hollowprocesses"])
    same_plugin = mk("MAL-099", "Medium", ["windows.malware.hollowprocesses"])          # the same plugin again: not a second source
    assert second_source(hollow, [hollow, same_plugin]) == []
    other_process = mk("MEM-001", "Low", ["windows.malfind"], pid=8)
    ioc = mk("IOC-006", "High", ["windows.vadyarascan"], cat="ioc")                      # the investigator's own data is not a source
    assert second_source(hollow, [other_process, ioc]) == []
    malfind = mk("MEM-001", "Low", ["windows.malfind"])
    assert second_source(hollow, [malfind]) == [malfind]
    assert require_second_source([hollow, malfind]) == [] and hollow.severity == "High" and any("Corroborated" in r for r in hollow.reasons)
    lonely = mk("MAL-007", "High", ["windows.etwpatch"])
    assert require_second_source([lonely]) == [lonely] and lonely.severity == "Medium" and lonely.confidence == "Low" and lonely.score < 6
    kernel = mk("MAL-006", "High", ["windows.driverirp"], pid=0, cat="kernel")
    driver = mk("DRV-002", "Medium", ["windows.driverscan", "windows.modules"], pid=0, cat="kernel")
    assert require_second_source([kernel, driver]) == [] and kernel.severity == "High"


# ============================================================================= MEM-001 reads what the process has mapped
def test_executable_regions_in_a_dotnet_host_are_explained_by_the_memory_map_not_only_by_dlllist():
    from app.models import MemoryRegion
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4)
    proc.dlls = []                                                                               # an empty dlllist (real Windows 10: taskhostw.exe)
    result.memory_regions = [MemoryRegion(proc.pid, proc.name, "0x7ff66cd00000", "0x7ff66cd9ffff", "655360", "PAGE_EXECUTE_READWRITE", True, True, True, True, "windows.malfind",
                                          {"Hexdump": "d8 ff ff ff ff ff ff ff 08 00 00 00 00 00 00 00"})]
    before = [f for f in rule_findings(result, "MEM-001") if f.process_pid == proc.pid]
    assert before and before[0].severity == "Medium"
    result.plugins.append(plugin_result("windows.ldrmodules", [{"Pid": proc.pid, "Process": proc.name, "Base": 0x7FF900000000, "InInit": False, "InLoad": False, "InMem": False,
                                                                "MappedPath": B + "Windows" + B + "System32" + B + "mscoreei.dll"}]))
    after = [f for f in rule_findings(result, "MEM-001") if f.process_pid == proc.pid]
    assert after and after[0].severity == "Low" and "JIT/runtime" in " ".join(after[0].reasons)


# ============================================================================= known-good lists, and one finding for the trusted noise
def ldr_rows(pid, name, images):
    return [{"Pid": pid, "Process": name, "Base": 0x7FF900000000 + i * 0x10000, "InInit": False, "InLoad": False, "InMem": False, "MappedPath": p} for i, p in enumerate(images)]


def test_trusted_system_images_are_one_low_finding_and_images_elsewhere_stay_one_finding_per_process():
    result = load_fixture_result()
    pids = [p.pid for p in result.processes if p.pid > 4][:3]
    sysdll = lambda n: B.join(["", "Windows", "System32", n])
    rows = ldr_rows(pids[0], "a.exe", [sysdll("wldp.dll"), sysdll("nlaapi.dll")]) + ldr_rows(pids[1], "b.exe", [sysdll("devobj.dll")]) \
        + ldr_rows(pids[2], "c.exe", [B.join(["", "Users", "bob", "AppData", "Local", "Temp", "evil.dll"])])
    result.plugins.append(plugin_result("windows.ldrmodules", rows))
    found = [f for f in rule_findings(result, "LDR-001")]
    quiet = [f for f in found if f.process_pid == 0]
    loud = [f for f in found if f.process_pid == pids[2]]
    assert len(quiet) == 1 and quiet[0].severity == "Low" and "2 process(es)" in quiet[0].title and len(quiet[0].evidence) == 2
    assert len(loud) == 1 and loud[0].severity == "Medium" and "evil.dll" in loud[0].evidence[0]
    assert len(found) == 2


def test_a_known_good_list_made_on_a_clean_system_silences_what_is_normal_on_that_windows(tmp_path):
    from app.engines.windows.analysis import known_good
    clean = load_fixture_result()
    pid = first_pid(clean)
    proc = next(p for p in clean.processes if p.pid == pid)
    sysdll = B.join(["", "Windows", "System32", "wldp.dll"])
    clean.plugins.append(plugin_result("windows.ldrmodules", ldr_rows(pid, proc.name, [sysdll])))
    data = known_good.build(clean, "clean machine")
    assert data["format"] == known_good.FORMAT and "wldp.dll" in data["modules"][proc.name.lower()] and data["nt"][0] == 10
    target = tmp_path / "kg.json"
    assert known_good.save(data, str(target)) >= 1
    suspect = load_fixture_result()
    suspect.plugins.append(plugin_result("windows.ldrmodules", ldr_rows(pid, proc.name, [sysdll])))
    assert [f for f in rule_findings(suspect, "LDR-001")]                                         # without the list: reported
    name, count = known_good.install(str(target))
    assert name == "clean machine" and count >= 1
    assert rule_findings(suspect, "LDR-001") == []                                                # with it: normal for this program on this Windows
    other = load_fixture_result()
    for row in other.system_info:                                                                  # another Windows (7): the list does not apply
        if str(row.get("Variable", "")).lower() == "ntminorversion":
            row["Value"] = "1"
        if str(row.get("Variable", "")).lower() == "ntmajorversion":
            row["Value"] = "6"
    assert not known_good.for_result(other) and known_good.for_result(suspect)
    with pytest.raises(ValueError):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"format": "something else"}), encoding="utf-8")
        known_good.install(str(bad))


# ============================================================================= PT-003: a process caught while the image was written
def hidden_result(created, capture="2018-06-21 06:50:50+00:00"):
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4)
    for p in result.processes:
        p.hidden = False
    proc.hidden, proc.exited, proc.exit_time, proc.create_time = True, False, "", created
    result.capture_time = capture
    return result, proc


def test_a_process_created_after_the_acquisition_started_is_low_an_older_unlinked_one_is_medium():
    result, proc = hidden_result("2018-06-21T06:51:27+00:00")
    low = [f for f in rule_findings(result, "PT-003") if f.process_pid == proc.pid]
    assert [f.severity for f in low] == ["Low"] and "mid-creation" in " ".join(low[0].reasons)
    result, proc = hidden_result("2018-06-08T00:12:27+00:00")
    result.plugins.append(plugin_result("windows.psxview", [{"PID": proc.pid, "Name": proc.name, "pslist": False, "psscan": True, "thrdscan": True, "csrss": True, "Exit Time": ""}]))
    old = [f for f in rule_findings(result, "PT-003") if f.process_pid == proc.pid]
    assert [f.severity for f in old] == ["Medium"] and old[0].confidence == "High" and "unlinked while alive" in " ".join(old[0].reasons)


# ============================================================================= CBK-001: is the value an address of executable user memory?
def test_a_user_mode_callback_is_checked_against_the_executable_memory_of_the_processes():
    row = lambda value: {"Callback": value, "Detail": None, "Module": None, "Symbol": None, "Type": "IoRegisterFsRegistrationChange"}
    vad = lambda start, end, protection: {"PID": 400, "Process": "x.exe", "Start VPN": start, "End VPN": end, "Protection": protection, "File": None, "PrivateMemory": 1}
    result = with_rows("windows.callbacks", [row(0x1375C085)])
    result.memory_regions = []
    assert [f.severity for f in rule_findings(result, "CBK-001")] == ["Medium"]                    # nothing to check it against (no vadinfo): Medium
    for r in result.system_info:
        if str(r.get("Variable", "")).lower() == "is64bit":
            r["Value"] = "False"
    result.plugins.append(plugin_result("windows.vadinfo", [vad(0x13000000, 0x13FFFFFF, "PAGE_READONLY"), vad(0x2000000, 0x2FFFFFF, "PAGE_EXECUTE_READWRITE")]))
    low = rule_findings(result, "CBK-001")
    assert [f.severity for f in low] == ["Low"] and "holds no executable code" in low[0].title        # in no executable region: not the address of any code
    result.plugins = [p for p in result.plugins if p.name != "windows.vadinfo"]
    result.plugins.append(plugin_result("windows.vadinfo", [vad(0x13000000, 0x13FFFFFF, "PAGE_EXECUTE_READWRITE")]))
    high = rule_findings(result, "CBK-001")
    assert [f.severity for f in high] == ["High"] and "executable memory of a process" in high[0].title


# ============================================================================= BEH-001
def beh_result(image_path, network=None, parent_name=None):
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4)
    proc.path, proc.exited, proc.network, proc.dlls = image_path, False, list(network or []), []
    result.memory_regions = [r for r in result.memory_regions if r.pid != proc.pid]
    if parent_name:
        parent = next(p for p in result.processes if p.pid != proc.pid and p.pid > 4)
        parent.name, proc.ppid = parent_name, parent.pid
    return result, proc


def test_a_program_running_from_the_users_own_folders_is_a_low_lead_and_medium_with_a_second_sign():
    from app.engines.windows.indicators.rules.behaviour import user_folder_of
    from app.models import NetworkConnection
    desktop = path("Users", "bob", "Desktop", "Lab12-03.exe")
    result, proc = beh_result(desktop)
    found = [f for f in rule_findings(result, "BEH-001") if f.process_pid == proc.pid]
    assert [f.severity for f in found] == ["Low"] and "Desktop" in found[0].title and "not evidence of anything" in found[0].summary
    xp = path("Documents and Settings", "Administrator", "Desktop", "PracticalMalwareAnalysis-Labs", "Lab12-03.exe")
    assert user_folder_of(xp) == "Desktop" and user_folder_of(path("Users", "bob", "Documents", "tool.exe")) == "Documents"
    for not_a_lead in (path("Users", "bob", "AppData", "Local", "Temp", "x.exe"), path("Users", "bob", "Downloads", "x.exe"), path("Users", "Public", "x.exe"),
                       path("Windows", "System32", "cmd.exe"), path("Program Files", "App", "a.exe"), path("Users", "bob", "AppData", "Local", "Programs", "a", "a.exe"), ""):
        assert user_folder_of(not_a_lead) == "", not_a_lead
    remote = NetworkConnection(proc.pid, proc.name, "10.0.0.5", "50000", "93.184.216.34", "443", "ESTABLISHED", "TCPv4")
    result, proc = beh_result(desktop, network=[remote])
    found = [f for f in rule_findings(result, "BEH-001") if f.process_pid == proc.pid]
    assert [f.severity for f in found] == ["Medium"] and "talks to a public address" in " ".join(found[0].reasons)
    result, proc = beh_result(desktop, parent_name="WINWORD.EXE")
    assert [f.severity for f in rule_findings(result, "BEH-001") if f.process_pid == proc.pid] == ["Medium"]
    result, proc = beh_result(path("Windows", "System32", "notepad.exe"))
    assert [f for f in rule_findings(result, "BEH-001") if f.process_pid == proc.pid] == []


def test_the_behavioural_lead_is_not_a_second_source_for_a_high_finding():
    from app.analysis.indicators.corroboration import second_source
    from app.models import Indication
    hollow = Indication(title="h", severity="High", process_pid=5, rule_id="MAL-001", source_plugins=["windows.malware.hollowprocesses"], category="memory")
    beh = Indication(title="b", severity="Low", process_pid=5, rule_id="BEH-001", source_plugins=["windows.pstree"], category="behaviour")
    assert second_source(hollow, [beh]) == []


# ============================================================================= plugin timing
def test_plugin_durations_are_learned_and_the_slowest_plugins_start_first():
    from app.analysis import plugin_timing as timing
    gb = 5 * 1024 ** 3
    names = ["windows.pslist", "windows.handles", "windows.cmdline", "windows.malfind", "windows.callbacks"]
    assert timing.order(names, gb)[:2] == ["windows.handles", "windows.malfind"]
    assert timing.estimate_total(names, gb, 1) > timing.estimate_total(names, gb, 3) >= max(timing.expected(n, gb) for n in names)
    timing.record("windows.cmdline", 4000.0, gb)                      # this computer is slow at it: it moves to the front
    assert timing.order(names, gb)[0] == "windows.cmdline" and timing.seconds_per_gb("windows.cmdline") > 100
    timing.record("windows.cmdline", 0.0, gb)                        # nothing is recorded for a zero duration
    assert "about" in timing.describe(1800) and timing.describe(20) == "under a minute"


def test_a_run_records_what_each_plugin_took_and_announces_an_estimate(tmp_path):
    messages = []
    from app.engines.windows.analysis.real_provider import RealProvider
    from test_pipeline_and_runner import FIXTURE, settings
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE)):
        result = RealProvider(settings(tmp_path)).run(make_dump(tmp_path), lambda text, value: messages.append(text), None, None)
        learned = json.loads((tmp_path / "home" / "timings.json").read_text(encoding="utf-8"))
    assert "windows.pslist" in learned and any(m.startswith("Estimated time:") for m in messages)
    assert result.tool_info.get("Volatility 3") and result.tool_info.get("analysed")


# ============================================================================= process story, tool info, data quality
def test_the_story_of_a_process_puts_parent_start_children_and_findings_on_one_clock():
    from app.analysis import story
    result = load_fixture_result()
    taskhost = next(p for p in result.processes if p.pid == 7252)
    items = story.build(result, 7252)
    kinds = [i.kind for i in items]
    assert kinds[0] == "finding" or "start" in kinds
    assert "start" in kinds and "parent" in kinds and kinds.count("child") >= 1
    start = next(i for i in items if i.kind == "start")
    assert story.describe_offset(start.seconds) == "+0 s" and "taskhostw.exe (PID 7252) started by" in start.text
    child = next(i for i in items if i.kind == "child")
    assert child.seconds is not None and child.seconds > 0 and "ngentask.exe" in child.text
    assert story.describe_offset(-200) == "-3 min" and story.describe_offset(7200) == "+2.0 h" and story.describe_offset(None) == ""
    assert story.build(result, 999999) == [] and taskhost.pid == 7252
    # a DLL load time after the capture is a damaged value (real Windows 10 dlllist) and is not part of the story
    dll = taskhost.dlls[0] if taskhost.dlls else None
    if dll is not None:
        dll.load_time = "2328-06-15 06:16:01+00:00"
        assert not [i for i in story.build(result, 7252) if i.kind == "module"]


def test_the_process_window_has_a_story_tab(app):
    from app.windows.dashboard_window import DashboardWindow
    from test_round5 import dispose
    window = DashboardWindow(load_fixture_result(), settings={})
    try:
        tree = window.select_view(window.IDX["Process Tree"])
        tree.open_process(7252) if hasattr(tree, "open_process") else None
        from app.windows.process_window import ProcessWindow
        proc = next(p for p in window.result.processes if p.pid == 7252)
        dialog = ProcessWindow(proc, window, dump_path=window.result.dump_path, findings=[])
        text = dialog.story.toPlainText()
        assert "taskhostw.exe (PID 7252) started by" in text and "ngentask.exe" in text and dialog.story_count >= 3
        dialog.deleteLater()
    finally:
        dispose(app, window)


def test_tool_info_is_saved_and_loaded_and_loader_list_problems_are_reported_once(tmp_path):
    from app.models import load_analysis_result, save_analysis_result
    from app.analysis.pipeline import data_quality_warnings
    result = load_fixture_result()
    result.tool_info = {"Volatility 3": "2.28.2 (vol.exe)", "analysed": "2026-10-08 12:00:00"}
    target = str(tmp_path / "r.json.gz")
    save_analysis_result(result, target)
    assert load_analysis_result(target).tool_info == result.tool_info
    pid = first_pid(result)
    sysdll = lambda n: B.join(["", "Windows", "System32", n])
    result.plugins.append(plugin_result("windows.ldrmodules", ldr_rows(pid, "svchost.exe", [sysdll("kernelbase.dll")])))
    result.capture_time = "2018-06-01 00:00:00+00:00"
    warnings = data_quality_warnings(result)
    assert any("loader lists of 1 process(es) were only partly readable" in w for w in warnings)
    assert any("were created after the capture time" in w for w in warnings)


def test_the_quick_triage_preset_ticks_processes_network_and_injected_code_only(app):
    from app.engines.windows.analysis import plugin_registry as registry
    from app.windows.settings_window import SettingsWindow
    window = SettingsWindow()
    try:
        window.preset_quick()
        assert {i for i, box in window.bundle_boxes.items() if box.isChecked()} == {"processes", "network", "memory"}
        assert "plugins" in window.estimate_label.text() and "min" in window.estimate_label.text()
        window.preset_all()
        assert all(box.isChecked() for box in window.bundle_boxes.values())
        window.preset_default()
        assert {i for i, box in window.bundle_boxes.items() if box.isChecked()} == {b.id for b in registry.BUNDLES if b.default or b.locked}
    finally:
        window.deleteLater()
