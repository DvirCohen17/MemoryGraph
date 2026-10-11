"""Hashes of process images (IOC-007) and YARA rules made from the IOC list."""
import hashlib
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, env, load_fixture_result, make_dump
from test_case_and_ioc import by_rule, evaluate

QtWidgets = pytest.importorskip("PySide6.QtWidgets")


def artifact(name, content):
    from app.engines.windows.analysis.dumper import DumpedFile
    return DumpedFile(name, len(content), hashlib.sha256(content).hexdigest(), hashlib.md5(content).hexdigest())


def iocs_from(text):
    from app.analysis.ioc import IocSet, parse_ioc_text
    return IocSet(parse_ioc_text(text, "intel.txt")[0])


# ============================================================================= process image hashes
def test_dump_names_are_parsed_and_attributed_to_processes():
    from app.engines.windows.analysis import process_images
    assert process_images.parse_dump_name("1988.explorer.exe.0x7ff6a0000000.dmp") == {"pid": 1988, "image_name": "explorer.exe", "image_base": "0x7ff6a0000000"}
    assert process_images.parse_dump_name("pid.4.System.0x400000.dmp")["pid"] == 4 and process_images.parse_dump_name("notes.txt") is None
    assert process_images.parse_dump_name("C:\\out\\12.a.b.c.exe.0x1000.dmp")["image_name"] == "a.b.c.exe"
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4 and p.path)
    entries = process_images.entries_from_artifacts(
        [artifact(f"{proc.pid}.{proc.name}.0x10000.dmp", b"MZ-one"), artifact("999999.ghost.exe.0x2000.dmp", b"MZ-two"), artifact("memorygraph_hashes.csv", b"x")],
        result.processes)
    assert [(e["pid"], e["process"]) for e in entries] == sorted([(proc.pid, proc.name), (999999, "ghost.exe")])
    known = next(e for e in entries if e["pid"] == proc.pid)
    assert known["path"] == proc.path and known["create_time"] == proc.create_time and known["sha256"] == hashlib.sha256(b"MZ-one").hexdigest()


def test_image_hashes_live_in_the_case_and_ioc_007_matches_them(tmp_path):
    from app.engines.windows.analysis import process_images
    from app.analysis.pipeline import reanalyze, refresh_image_hash_findings
    from app.models import load_analysis_result, save_analysis_result
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4)
    bad, good = b"MZ-dropper-body", b"MZ-fine"
    entries = process_images.entries_from_artifacts(
        [artifact(f"{proc.pid}.{proc.name}.0x10000.dmp", bad), artifact(f"{result.processes[-1].pid}.{result.processes[-1].name}.0x20000.dmp", good)], result.processes)
    assert process_images.store(result, entries, str(tmp_path)) == 2 and len(process_images.stored(result)) == 2
    iocs = iocs_from(hashlib.sha256(bad).hexdigest() + "   # known dropper\n")
    assert refresh_image_hash_findings(result, iocs) == 1
    finding = next(f for f in result.indications if f.rule_id == "IOC-007")
    assert finding.process_pid == proc.pid and finding.category == "ioc" and finding.severity == "High" and "known dropper" in " ".join(finding.reasons)
    assert finding.evidence_items[0].type == "image_hash" and finding.evidence_items[0].value == hashlib.sha256(bad).hexdigest()
    assert refresh_image_hash_findings(result, iocs) == 1 and sum(1 for f in result.indications if f.rule_id == "IOC-007") == 1       # idempotent
    # the MD5 form of the hash matches too, and no list means no findings
    assert refresh_image_hash_findings(result, iocs_from(hashlib.md5(bad).hexdigest() + "\n")) == 1
    assert refresh_image_hash_findings(result, None) == 0 and not any(f.rule_id == "IOC-007" for f in result.indications)
    # saved with the investigation and reproduced by a full re-analysis (the rules are rebuilt from the case data)
    save_analysis_result(result, str(tmp_path / "inv.json"))
    loaded = load_analysis_result(str(tmp_path / "inv.json"))
    assert len(process_images.stored(loaded)) == 2
    assert [f.process_pid for f in reanalyze(loaded, iocs=iocs).indications if f.rule_id == "IOC-007"] == [proc.pid]
    assert not any(f.rule_id == "IOC-007" for f in reanalyze(loaded).indications)                  # no IOC list: the family is absent
    assert [f.rule_id for f in evaluate(loaded, iocs) if f.category == "ioc"].count("IOC-007") == 1


def test_image_hash_list_exports_as_csv(tmp_path):
    from app.engines.windows.analysis import process_images
    result = load_fixture_result()
    process_images.store(result, process_images.entries_from_artifacts([artifact(f"{result.processes[1].pid}.x.exe.0x1.dmp", b"abc")], result.processes))
    out = tmp_path / "hashes.csv"
    assert process_images.export_csv(result, str(out)) == 1
    lines = out.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "pid,process,path,size_bytes,sha256,md5,image_base" and hashlib.sha256(b"abc").hexdigest() in lines[1]


def test_dump_all_images_is_one_pslist_run_without_a_pid(tmp_path):
    from app.engines.windows.analysis.dumper import VolatilityDumper
    with env(FAKE_VOL_FIXTURE=str(tmp_path / "none.json")):
        (tmp_path / "none.json").write_text('{"windows.pslist": []}', encoding="utf-8")
        completed, command = VolatilityDumper(make_dump(tmp_path), str(FAKE_VOL), ["--offline"]).dump_all_process_images(str(tmp_path / "out"))
    assert command.count("windows.pslist") == 1 and command[-1] == "--dump" and "--pid" not in command and "--offline" in command


def test_process_tree_hash_button_stores_matches_and_refreshes_the_findings(tmp_path, monkeypatch):
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    import subprocess
    import app.windows.process_tree_window as ptw
    from app.engines.windows.analysis import process_images
    from app.windows.dashboard_window import DashboardWindow
    ioc_file = tmp_path / "intel.txt"
    bad = b"MZ-dropper-body"
    ioc_file.write_text(hashlib.sha256(bad).hexdigest() + "  # known dropper\n", encoding="utf-8")
    window = DashboardWindow(load_fixture_result(), settings={"ioc_files": [str(ioc_file)]})
    window.show()
    view = window.select_view(window.IDX["Process Tree"])
    assert not view.export_hashes_button.isEnabled() and view.hash_button.isEnabled()
    messages = []
    monkeypatch.setattr(ptw, "show_info", lambda parent, title, text: messages.append(text))
    proc = next(p for p in window.result.processes if p.pid > 4)
    completed = subprocess.CompletedProcess(["vol"], 0, "", "")
    completed.artifacts = [artifact(f"{proc.pid}.{proc.name}.0x10000.dmp", bad)]
    completed.manifest = "out\\memorygraph_hashes.csv"
    flagged_before = window._flagged_count()
    view._hashes_done(str(tmp_path), (completed, ["vol"]))
    assert "IOC HASH MATCH: 1 finding" in messages[-1] and "1 process image(s) dumped and hashed" in messages[-1]
    assert len(process_images.stored(window.result)) == 1 and view.export_hashes_button.isEnabled() and "(1)" in view.export_hashes_button.text()
    assert any(f.rule_id == "IOC-007" and f.process_pid == proc.pid for f in window.result.indications) and window.case_dirty
    assert window._flagged_count() >= flagged_before
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "h.csv"), "")))
    view.export_image_hashes()
    assert (tmp_path / "h.csv").read_text(encoding="utf-8").count("\n") == 2
    window.close()
    window.deleteLater()
    app.processEvents()


# ============================================================================= YARA rules from the IOC list
IOC_TEXT = """# intel
evil-domain.test
Another.Example.org
198.51.100.7
203.0.113.0/24
mutex:Global\\EvilMutex "quote
10.0.0.1:8080
"""


def test_generated_yara_rules_compile_and_find_domains_ips_and_mutexes_in_memory():
    yara = pytest.importorskip("yara")
    from app.analysis.ioc import yara_rules_from_iocs
    iocs = iocs_from(IOC_TEXT)
    text, count = yara_rules_from_iocs(iocs)
    assert count >= 4 and "rule IOC_Domains" in text and "rule IOC_Ips" in text and "rule IOC_Mutexes" in text
    assert "203.0.113.0" not in text                                                    # a CIDR range cannot be searched as text
    rules = yara.compile(source=text)                                                   # the file is valid YARA, quotes and backslashes escaped
    haystack = (b"junk GET http://EVIL-domain.test/a.php junk " + "another.example.org".encode("utf-16-le") + b" connect 198.51.100.7 " +
                b'global\\evilmutex "quote')
    matched = {m.rule for m in rules.match(data=haystack)}
    assert matched == {"IOC_Domains", "IOC_Ips", "IOC_Mutexes"}                          # domains: any case; UTF-16 too
    assert {m.rule for m in rules.match(data=b"only 10.0.0.2 here")} == set()
    empty_text, empty_count = yara_rules_from_iocs(iocs_from("# nothing\n" + "a" * 64 + "\n"))
    assert empty_count == 0 and "rule " not in empty_text


def test_settings_button_writes_the_rules_and_sets_the_yara_file(tmp_path, monkeypatch):
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    import app.windows.settings_window as sw
    intel = tmp_path / "intel.txt"
    intel.write_text(IOC_TEXT, encoding="utf-8")
    monkeypatch.setattr(sw, "save_settings", lambda values: True)
    messages = []
    monkeypatch.setattr(sw, "show_info", lambda parent, title, text: messages.append(text))
    target = tmp_path / "ioc.yar"
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(target), "")))
    dialog = sw.SettingsWindow()
    dialog.ioc_list.setPlainText(str(intel))
    dialog.make_yara_from_iocs()
    assert target.is_file() and "rule IOC_Domains" in target.read_text(encoding="utf-8") and dialog.yara_path.text() == str(target)
    assert "YARA scan" in messages[-1]
    dialog.ioc_list.setPlainText("")
    dialog.make_yara_from_iocs()
    assert "contain no domains" in messages[-1]
    dialog.close()


# ============================================================================= rule fixes found by running a real Windows XP image
from test_roadmap_features import plugin
from test_case_and_ioc import with_plugins


def set_nt_version(result, major):
    for row in result.system_info:
        if str(row.get("Variable", "")).lower() == "ntmajorversion":
            row["Value"] = str(major)
    return result


def test_services_and_lsass_under_winlogon_are_normal_on_windows_xp_only():
    import copy
    result = load_fixture_result()
    winlogon = next((p for p in result.processes if p.name.lower() == "winlogon.exe"), None)
    if winlogon is None:
        winlogon = copy.deepcopy(next(p for p in result.processes if p.pid > 4))
        winlogon.pid, winlogon.name = 9001, "winlogon.exe"
        result.processes.append(winlogon)
    winlogon.create_time = "2018-06-21T09:00:00+00:00"
    for name in ("services.exe", "lsass.exe"):
        proc = next(p for p in result.processes if p.name.lower() == name)
        proc.ppid, proc.create_time = winlogon.pid, "2018-06-21T10:00:00+00:00"
    modern = [f.title for f in by_rule(set_nt_version(result, 10), "PT-001")]
    assert any("services.exe started by unexpected parent winlogon.exe" in t for t in modern) and any("lsass.exe started by" in t for t in modern)
    legacy = [f.title for f in by_rule(set_nt_version(result, 5), "PT-001")]
    assert not any("services.exe started by" in t or "lsass.exe started by" in t for t in legacy)
    lsass = next(p for p in result.processes if p.name.lower() == "lsass.exe")
    lsass.ppid = next(p for p in result.processes if p.pid > 4 and p.name.lower() not in ("winlogon.exe", "lsass.exe")).pid
    assert any("lsass.exe started by" in f.title for f in by_rule(result, "PT-001"))             # a wrong parent is still reported on XP


def test_the_xp_ifeo_placeholder_is_not_a_finding_but_a_real_debugger_still_is():
    nt = "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"
    rows = [{"Type": "REG_SZ", "Key": nt + "Your Image File Name Here without a path", "Name": "Debugger", "Data": "ntsd -d", "Last Write Time": "2018-06-21T00:00:00+00:00"},
            {"Type": "REG_SZ", "Key": nt + "notepad.exe", "Name": "Debugger", "Data": "C:\\Users\\Public\\dbg.exe", "Last Write Time": "2018-06-21T00:00:00+00:00"}]
    found = by_rule(with_plugins(plugin("windows.registry.printkey [IFEO]", rows)), "PER-002")
    assert [f.title for f in found] == ["Starting notepad.exe runs 'C:\\Users\\Public\\dbg.exe' instead"]


def test_ldrmodules_ignores_data_mappings_fonts_and_the_system_process_but_keeps_executable_ones():
    ldr = lambda pid, name, base, path: {"Pid": pid, "Process": name, "Base": base, "InLoad": False, "InInit": False, "InMem": False, "MappedPath": path}
    vad = lambda pid, start, protection: {"PID": pid, "Start VPN": start, "Protection": protection}
    pid = next(p.pid for p in load_fixture_result().processes if p.pid > 4)
    rows = [ldr(pid, "a.exe", 0x10000, "\\Windows\\Fonts\\vgaoem.fon"),                      # not a program image
            ldr(pid, "a.exe", 0x20000, "\\Windows\\system32\\oleaccrc.dll"),                 # opened as data: read-only mapping
            ldr(pid, "a.exe", 0x30000, "\\Users\\Public\\inject.dll"),                       # executable and unlisted: the real thing
            ldr(4, "System", 0x7C900000, "\\Windows\\system32\\ntdll.dll"),                  # System has no loader lists
            ldr(pid, "a.exe", 0x40000, "\\Windows\\system32\\unknown_mapping.dll")]          # no vadinfo row: kept
    vads = [vad(pid, 0x20000, "PAGE_READONLY"), vad(pid, 0x30000, "PAGE_EXECUTE_WRITECOPY")]
    found = by_rule(with_plugins(plugin("windows.ldrmodules", rows), plugin("windows.vadinfo", vads)), "LDR-001")
    assert len(found) == 1 and found[0].severity == "Medium" and "2 image(s)" in found[0].title
    shown = " ".join(found[0].evidence)
    assert "inject.dll" in shown and "unknown_mapping.dll" in shown and "oleaccrc" not in shown and "vgaoem" not in shown and "ntdll" not in shown
    without_vad = by_rule(with_plugins(plugin("windows.ldrmodules", rows)), "LDR-001")                     # no vadinfo: only the file type / System filters apply
    text = " ".join(without_vad[0].evidence)
    assert "oleaccrc.dll" in text and "vgaoem" not in text


def test_known_xp_shared_section_is_low_but_an_injected_pe_at_the_same_address_is_not():
    from app.models import MemoryRegion

    def finding_for(hexdump, nt=10):
        result = set_nt_version(load_fixture_result(), nt)
        proc = next(p for p in result.processes if p.pid > 4)
        result.memory_regions = [MemoryRegion(proc.pid, proc.name, "0x7f6f0000", "0x7f7effff", "1.0 MB", "PAGE_EXECUTE_READWRITE", True, True, True, True,
                                              "windows.malfind", {"Hexdump": hexdump}, {}, "Vad")]
        return [f for f in evaluate(result) if f.rule_id == "MEM-001" and f.process_pid == proc.pid][0]
    set_nt_version(load_fixture_result(), 5)                                                 # (the fixture is Windows 10: build the XP case below)
    plain = "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
    assert finding_for(plain).severity == "Medium"                                           # the 0x7f6f0000 region is only normal on NT 5.x
    low = finding_for(plain, 5)
    assert low.severity == "Low" and "0x7f6f0000" in " ".join(low.reasons)
    assert finding_for("4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00", 5).severity == "High"     # an injected PE at that address is still High


def test_callbacks_into_user_mode_are_medium_duplicates_are_listed_once_and_code_bytes_are_not_a_hook():
    cb = lambda kind, address, module=None, detail=None: {"Type": kind, "Callback": address, "Module": module, "Detail": detail, "Symbol": None}
    rows = [cb("IoRegisterFsRegistrationChange", 0x1375C085), cb("IoRegisterFsRegistrationChange", 0x1375C085), cb("GenericKernelCallback", 0xF41B53E8),
            cb("GenericKernelCallback", 0xF41B53E8), cb("IoRegisterShutdownNotification", 0xF0000000, "VIDEOPRT", "\\Driver\\x")]
    result = with_plugins(plugin("windows.callbacks", rows))
    bits = [r for r in result.system_info if r.get("Variable") == "Is64Bit"]
    assert bits, "the fixture has an Is64Bit row"
    for row in bits:
        row["Value"] = "False"
    found = {("user" if "user-mode" in f.title else "kernel"): f for f in by_rule(result, "CBK-001")}
    assert set(found) == {"user", "kernel"} and {f.severity for f in found.values()} == {"Medium"}              # no High: one unverified plugin value
    assert found["user"].evidence == ["IoRegisterFsRegistrationChange @ 0x1375c085"] and found["kernel"].evidence == ["GenericKernelCallback @ 0xf41b53e8"]
    for row in bits:                                                                             # 64-bit: 0xf41b53e8 is also below the kernel range
        row["Value"] = "True"
    assert {f.severity for f in by_rule(result, "CBK-001")} == {"Medium"} and all("user-mode" in f.title for f in by_rule(result, "CBK-001"))
    code = with_plugins(plugin("windows.callbacks", [cb("GenericKernelCallback", 0x894808708948)]))        # real Windows 10 value: the bytes 48 89 08 70 48 89
    low = by_rule(code, "CBK-001")
    assert [f.severity for f in low] == ["Low"] and "code bytes" in low[0].title
    modules = plugin("windows.modules", [{"Base": 0x1000, "Name": "ok.sys"}])
    scan = plugin("windows.modscan", [{"Base": 0x2000, "Name": "gone.sys", "Path": "N/A"}, {"Base": 0x3000, "Name": "bad.sys", "Path": "\u2630\u4141\ubfb0\u0205"},
                                      {"Base": 0x4000, "Name": "x.sys", "Path": "N"}])
    drv = by_rule(with_plugins(modules, scan), "DRV-001")
    text = " ".join(drv[0].evidence)
    assert "(unreadable name)" in text and "path=N" not in text and "N/A" not in text


# ============================================================================= an antivirus blocks a dumped malware sample (seen on a real image)
def test_one_unreadable_dumped_file_does_not_cost_the_hashes_of_the_others(tmp_path, monkeypatch):
    import app.engines.windows.analysis.dumper as dumper
    from app.engines.windows.analysis import process_images
    (tmp_path / "10.good.exe.0x400000.dmp").write_bytes(b"MZ-good")
    (tmp_path / "11.sample.exe.0x400000.dmp").write_bytes(b"MZ-sample")
    real = dumper.hash_file

    def blocked(path):
        if "sample" in path:
            raise OSError(22, "Invalid argument", path)           # what Windows reports when Defender blocks the file
        return real(path)
    monkeypatch.setattr(dumper, "hash_file", blocked)
    files = dumper.hash_new_files(str(tmp_path), {})
    by_name = {f.name: f for f in files}
    assert by_name["10.good.exe.0x400000.dmp"].readable and by_name["10.good.exe.0x400000.dmp"].sha256 == hashlib.sha256(b"MZ-good").hexdigest()
    bad = by_name["11.sample.exe.0x400000.dmp"]
    assert not bad.readable and "could not be read" in bad.error and bad.sha256 == "" and bad.size == len(b"MZ-sample")
    result = load_fixture_result()
    entries = process_images.entries_from_artifacts(files, result.processes)
    assert [e["pid"] for e in entries] == [10] and process_images.unreadable(files) == ["11.sample.exe.0x400000.dmp"]
    manifest = dumper.write_manifest(str(tmp_path), [f for f in files if f.readable], "windows.pslist", 0, "x.raw", ["vol"])
    text = open(manifest, encoding="utf-8").read()
    assert "10.good.exe" in text and "11.sample.exe" not in text                      # only what was really hashed goes into the evidence list


def test_the_hash_message_names_files_an_antivirus_blocked(tmp_path, monkeypatch):
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    import subprocess
    import app.windows.process_tree_window as ptw
    from app.engines.windows.analysis.dumper import DumpedFile
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.show()
    view = window.select_view(window.IDX["Process Tree"])
    messages = []
    monkeypatch.setattr(ptw, "show_info", lambda parent, title, text: messages.append(text))
    proc = next(p for p in window.result.processes if p.pid > 4)
    completed = subprocess.CompletedProcess(["vol"], 0, "", "")
    completed.artifacts = [artifact(f"{proc.pid}.{proc.name}.0x1.dmp", b"ok"), DumpedFile("9999.blocked.exe.0x1.dmp", 5, "", "", "could not be read (Invalid argument)")]
    completed.manifest = ""
    view._hashes_done(str(tmp_path), (completed, ["vol"]))
    assert "1 process image(s) dumped and hashed" in messages[-1] and "1 dumped file(s) could not be read back" in messages[-1] and "9999.blocked.exe" in messages[-1]
    window.close()
    window.deleteLater()
    app.processEvents()


# ============================================================================= timeline and failure messages (found on the Windows XP image)
def test_known_plugins_without_an_event_source_do_not_leak_into_the_timeline():
    """vadyarascan / vadinfo rows carry the process's CreateTime: the generic 'any plugin with a time column' path used to add them as events."""
    from app.engines.windows.analysis.timeline_builder import build_timeline
    result = load_fixture_result()
    proc = next(p for p in result.processes if p.pid > 4)
    rows = [{"PID": proc.pid, "ImageFileName": proc.name, "CreateTime": proc.create_time, "Rule": "R", "Component": "$a", "Value": "00"}]
    result.plugins.append(plugin("windows.vadyarascan", rows))
    result.plugins.append(plugin("windows.someunknownplugin", [{"PID": proc.pid, "Name": "unknown source", "Timestamp": "2018-06-21T05:00:00+00:00"}]))
    result.timeline = build_timeline(result)
    assert not any(e.category.lower().startswith("vadyarascan") for e in result.timeline)
    assert any("unknown source" in e.description for e in result.timeline)               # a plugin MemoryGraph does not know still gets its time column used


def test_timeline_window_leaves_file_times_off_until_asked(tmp_path):
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    from app.windows.dashboard_window import DashboardWindow
    result = load_fixture_result()
    result.plugins.append(plugin("windows.shimcachemem", [{"File Path": "C:\\Users\\Public\\old.exe", "Last Modified": "2009-07-12T01:55:00+00:00",
                                                          "Last Update": "2018-06-21T01:00:00+00:00"}]))
    from app.engines.windows.analysis.timeline_builder import build_timeline
    result.timeline = build_timeline(result)
    window = DashboardWindow(result, settings={})
    window.show()
    view = window.select_view(window.IDX["Timeline"])
    assert "File time" in view.category_boxes and not view.category_boxes["File time"].isChecked() and view.category_boxes["Process"].isChecked()
    shown = lambda: {view.proxy.index(r, 2).data() for r in range(view.proxy.rowCount())}
    assert "File time" not in shown() and "Process" in shown()                           # the 2009 date is not in the list (or the chart range)
    view.category_boxes["File time"].setChecked(True)
    assert "File time" in shown()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_a_failed_requirement_check_blames_the_plugin_when_windows_info_already_worked():
    from app.analysis.volatility_runner import explain_failure
    stderr = "Unable to validate the plugin requirements: ['plugins.ScheduledTasks.kernel.layer_name']"
    with_os = explain_failure(stderr, 1, "windows.registry.scheduled_tasks", os_info="Windows XP (NT 5.1, build 2600), 32-bit")
    assert "windows.info read this image (Windows XP" in with_os and "does not support this Windows version" in with_os and "could not build the Windows symbol table" not in with_os
    without_os = explain_failure(stderr, 1, "windows.registry.scheduled_tasks")
    assert "symbol table" in without_os and "windows.info read this image" not in without_os          # nothing known about the image: the old explanation stays


def test_yara_match_bytes_are_shown_as_text_when_they_are_text():
    from app.engines.windows.indicators.rules.ioc import readable_match
    assert readable_match("77 69 6e 64 6f 77 73").startswith("'windows' (ASCII) [77 69")
    assert readable_match("6d 00 69 00 63 00 72 00 6f 00").startswith("'micro' (UTF-16)")
    assert readable_match("00 01 02 03") == "00 01 02 03" and readable_match("not hex") == "not hex" and readable_match(None) == ""
