"""Offline plumbing, file index / file report, the Files view (filescan explorer + dumping), and comparing two investigations."""
import copy
import hashlib
import json
import os
import struct
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, FIXTURE, env, load_fixture_result, make_dump, settings
from test_case_and_ioc import run_with
from test_roadmap_features import plugin

V = r"\Device\HarddiskVolume2"
NAMES = [V + r"\Windows\System32\ntdll.dll", V + r"\Windows\System32\drivers\ntfs.sys", V + r"\Users\bob\Downloads\setup.exe",
         V + r"\Users\Public\Libraries\update.exe", V + r"\Users\bob\Documents\invoice.pdf.exe", V + r"\Users\bob\Documents\notes.txt",
         V + r"\Windows\Temp\x.dll", r"\Device\Mup\server\share\a.docx", r"\Windows\NoDevice\b.txt"]


def filescan_rows():
    return [{"Offset": 0x1000 * (i + 1), "Name": name} for i, name in enumerate(NAMES)]


# ============================================================================= always local: no offline setting, --offline is always passed
def test_volatility_is_always_started_offline_and_symbol_folders_are_added():
    from app.analysis.volatility_runner import global_args
    from app.settings import DEFAULT_SETTINGS, sanitize
    assert global_args({}) == ["--offline"] and global_args(None) == ["--offline"]
    assert global_args({"symbol_dirs": ["D:\\sym", " E:\\more ", ""]}) == ["--offline", "-s", "D:\\sym;E:\\more"]
    assert "offline_mode" not in DEFAULT_SETTINGS                                      # no such setting any more
    assert sanitize({"symbol_dirs": "not a list"})["symbol_dirs"] == []
    assert "vol2_path" in DEFAULT_SETTINGS and DEFAULT_SETTINGS["vol2_deep_scan"] is False


def test_offline_option_reaches_every_volatility_command(tmp_path):
    result, _ = run_with(tmp_path, {}, symbol_dirs=[str(tmp_path / "syms")])
    commands = [p.command for p in result.plugins if p.command]
    assert commands and all("--offline" in c and c[c.index("-s") + 1] == str(tmp_path / "syms") for c in commands)
    assert all(c.index("--offline") < c.index("-f") for c in commands)               # global options come before the memory image
    plain, _ = run_with(tmp_path, {})
    assert all("--offline" in p.command and "-s" not in p.command for p in plain.plugins if p.command)


def test_settings_window_saves_symbol_folders_volatility_2_and_bundles(tmp_path, monkeypatch):
    QtWidgets = pytest.importorskip("PySide6.QtWidgets")
    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    import app.windows.settings_window as sw
    monkeypatch.setattr(sw, "save_settings", lambda values: True)
    dialog = sw.SettingsWindow()
    assert not hasattr(dialog, "offline") and [dialog.nav.item(i).text() for i in range(dialog.nav.count())] == ["Appearance", "Volatility", "Plugins", "Indicators", "Performance"]
    dialog.symbol_dirs.setText("D:\\sym; E:\\more")
    dialog.vol2_path.setText("D:\\tools\\volatility_2.6_win64_standalone.exe")
    dialog.python2_path.setText("C:\\Python27\\python.exe")
    dialog.vol2_deep.setChecked(True)
    dialog.bundle_boxes["persistence"].setChecked(True)
    dialog.bundle_boxes["network"].setChecked(False)
    dialog.apply_and_close()
    saved = dialog.settings
    assert saved["symbol_dirs"] == ["D:\\sym", "E:\\more"] and saved["vol2_path"].endswith("standalone.exe") and saved["python2_path"].endswith("python.exe")
    assert saved["vol2_deep_scan"] is True and {"run_keys", "autostart_keys", "windows.svcscan"} <= set(saved["optional_plugins"])
    assert "windows.netscan" not in saved["enabled_plugins"] and "windows.pslist" in saved["enabled_plugins"]
    dialog.close()
    dialog.deleteLater()


# ============================================================================= file index
def test_file_index_splits_devices_builds_the_tree_and_flags_like_file_001():
    from app.engines.windows.analysis.fileindex import FileIndex, entries_from_rows, flags_for, split_name
    assert split_name(NAMES[0]) == ("HarddiskVolume2", r"\Windows\System32\ntdll.dll") and split_name(NAMES[8]) == ("", NAMES[8])
    index = FileIndex(entries_from_rows(filescan_rows() + [{"Offset": 0, "Name": ""}, {"Name": "x"}, "garbage"]))
    assert len(index.entries) == 9 and sorted(index.devices) == ["", "harddiskvolume2", "mup"]
    volume = index.devices["harddiskvolume2"]
    assert index.drive_hint(volume) == "C:" and index.drive_hint(index.devices["mup"]) == ""
    system32 = volume.children["windows"].children["system32"]
    assert system32.path == r"\Windows\System32" and [e.name for e in system32.files] == ["ntdll.dll"] and system32.total() == 2
    assert volume.total() == 7 and index.root.total() == 9
    entry = index.entries[0]
    assert (entry.folder, entry.extension, entry.name, entry.full_name) == (r"\Windows\System32", ".dll", "ntdll.dll", NAMES[0])
    assert index.folder_for(entry) is system32
    assert flags_for(index.entries[0]) == [] and "Temp / Downloads" in flags_for(index.entries[2])[0]
    assert "Public" in flags_for(index.entries[3])[0] and "document name" in flags_for(index.entries[4])[0] and "Windows\\Temp" in flags_for(index.entries[6])[0]
    assert flags_for(index.entries[5]) == []
    assert [e.name for e in index.search("bob invoice")] == ["invoice.pdf.exe"] and len(index.search("", volume)) == 7
    assert [e.name for e in index.search("setup", index.devices["harddiskvolume2"])] == ["setup.exe"]


def test_dump_files_are_found_by_the_object_address(tmp_path):
    from app.engines.windows.analysis.fileindex import dump_files_for
    for name in ("file.0x2000.0xffffa800.DataSectionObject.a.dll.dat", "file.0x2000.0xffffa900.ImageSectionObject.a.dll.img",
                 "file.0x20000.0xffffa800.DataSectionObject.b.dll.dat", "other.txt"):
        (tmp_path / name).write_bytes(b"x")
    found = dump_files_for(str(tmp_path), 0x2000)
    assert [kind for kind, _p in found] == ["DataSectionObject", "ImageSectionObject"]          # 0x2000 is not a prefix match for 0x20000
    assert dump_files_for(str(tmp_path), 0x9999) == [] and dump_files_for(str(tmp_path / "missing"), 0x2000) == [] and dump_files_for("", 1) == []


# ============================================================================= file report
def make_pe(path, packed=True):
    """A small but valid PE32+ DLL: .text (RWX, high entropy) and .idata importing VirtualAlloc from kernel32.dll."""
    e_lfanew, text_raw, idata_raw = 0x80, 0x200, 0xA00
    dos = (b"MZ" + bytes(0x3A) + struct.pack("<I", e_lfanew)).ljust(e_lfanew, b"\0")
    header = b"PE\0\0" + struct.pack("<HHIIIHH", 0x8664, 2, 0x5B2B0A80, 0, 0, 0xF0, 0x2022)
    optional = bytearray(0xF0)
    struct.pack_into("<H", optional, 0, 0x20B)
    struct.pack_into("<I", optional, 16, 0x1000)
    struct.pack_into("<Q", optional, 24, 0x180000000)
    struct.pack_into("<H", optional, 68, 2)
    struct.pack_into("<I", optional, 108, 16)
    struct.pack_into("<II", optional, 112 + 8, 0x2000, 40)                      # import directory
    sections = (b".text\0\0\0" + struct.pack("<IIIIIIHHI", 0x800, 0x1000, 0x800, text_raw, 0, 0, 0, 0, 0xE0000020)
                + b".idata\0\0" + struct.pack("<IIIIIIHHI", 0x200, 0x2000, 0x200, idata_raw, 0, 0, 0, 0, 0xC0000040))
    data = bytearray(dos + header + bytes(optional) + sections).ljust(text_raw, b"\0")
    data += bytes((i * 167 + 13 + (i >> 3)) % 256 for i in range(0x800)) if packed else bytes(0x800)
    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0, 0x2040, 0, 0, 0x2060, 0x2040)
    struct.pack_into("<Q", idata, 0x40, 0x2080)
    idata[0x60:0x60 + 13] = b"kernel32.dll\0"
    idata[0x80:0x80 + 14] = struct.pack("<H", 0) + b"VirtualAlloc\0"
    data += idata + b"http://evil.test/p.bin\0C:\\Users\\Public\\x.exe\0HKEY_CURRENT_USER\\Software\\Evil\0\0\0" + "10.20.30.40".encode("utf-16-le")
    path.write_bytes(bytes(data))
    return path


def test_report_reads_pe_structure_hashes_and_strings(tmp_path):
    from app.engines.windows.analysis import file_report
    path = make_pe(tmp_path / "dropped.dll")
    report = file_report.build_report(str(path))
    raw = path.read_bytes()
    assert report.sha256 == hashlib.sha256(raw).hexdigest() and report.md5 == hashlib.md5(raw).hexdigest() and report.size == len(raw)
    assert report.kind == "Windows executable (PE)" and not report.truncated
    pe = report.pe
    assert (pe.machine, pe.kind, pe.subsystem, pe.entry_section) == ("x64", "DLL", "Windows GUI", ".text")
    assert pe.timestamp == "2018-06-21 02:16:32 UTC" and pe.entry_point == 0x1000 and pe.image_base == 0x180000000
    assert [s.name for s in pe.sections] == [".text", ".idata"] and pe.sections[0].flags == "XRW"
    assert any("writable and executable" in n for n in pe.sections[0].notes) and any("high entropy" in n for n in pe.sections[0].notes)
    assert pe.imports == {"kernel32.dll": 1} and pe.suspicious_imports == ["VirtualAlloc"] and not pe.signed
    assert report.urls == ["http://evil.test/p.bin"] and r"C:\Users\Public\x.exe" in report.paths[0]
    assert report.registry == ["HKEY_CURRENT_USER\\Software\\Evil"] and "10.20.30.40" in report.ips


def test_report_copes_with_other_files_truncated_pes_and_zero_pages(tmp_path):
    from app.engines.windows.analysis import file_report
    text = tmp_path / "a.txt"
    text.write_text("hello world, this is plain text", encoding="utf-8")
    assert file_report.build_report(str(text)).kind == "text / script" and file_report.build_report(str(text)).pe is None
    zeros = tmp_path / "z.bin"
    zeros.write_bytes(bytes(5000))
    report = file_report.build_report(str(zeros))
    assert report.kind.startswith("zeros") and report.zero_fraction == 1.0 and any("not in memory" in n for n in report.notes)
    pe = make_pe(tmp_path / "p.dll").read_bytes()
    for cut in (0x30, 0x90, 0x120, 0x1A0, 0x300, 0xA10):                          # cut off in the headers, section table, imports
        cut_file = tmp_path / f"cut{cut}.dll"
        cut_file.write_bytes(pe[:cut])
        file_report.build_report(str(cut_file))                                    # must not raise
    assert file_report.parse_pe(b"MZ" + bytes(100)) is None and file_report.parse_pe(b"") is None
    assert file_report.detect_type(b"%PDF-1.7") == "PDF document" and file_report.detect_type(b"PK\x03\x04") .startswith("ZIP")
    assert file_report.shannon_entropy(bytes(range(256)) * 4) == pytest.approx(8.0) and file_report.shannon_entropy(b"") == 0.0


# ============================================================================= dumping with the fake Volatility
def test_dumper_dumps_several_file_objects_in_one_run(tmp_path):
    from app.engines.windows.analysis.dumper import VolatilityDumper
    out = tmp_path / "out"
    with env(FAKE_VOL_DUMPFILES="0x2000,0x3000"):
        completed, command = VolatilityDumper(make_dump(tmp_path), str(FAKE_VOL), ["--offline"]).dump_file_objects([0x2000, 0x3000, 0x4000], str(out))
    assert command.count("windows.dumpfiles") == 1 and command[command.index("--virtaddr") + 1:] == ["0x2000", "0x3000", "0x4000"]
    assert "--pid" not in command and "--offline" in command
    assert sorted(a.name.split(".")[1] for a in completed.artifacts) == ["0x2000", "0x3000"]            # 0x4000 had nothing in memory
    assert all(len(a.sha256) == 64 for a in completed.artifacts) and (out / "memorygraph_hashes.csv").is_file()
    from app.errors import MemoryGraphError
    with pytest.raises(MemoryGraphError):
        VolatilityDumper(make_dump(tmp_path), str(FAKE_VOL)).dump_file_objects([], str(out))


def test_controller_can_run_one_more_plugin_on_an_open_investigation(tmp_path):
    """The Files view's 'Run windows.filescan now' merges the new plugin into the existing result and keeps the case."""
    from app.analysis import case_state
    from app.engines.windows.analysis.real_provider import RealProvider
    first, _ = run_with(tmp_path, {})
    assert not any(p.name == "windows.filescan" for p in first.plugins)
    case_state.add_note(first, "process", "process|x", "x", "kept")
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    data["windows.filescan"] = filescan_rows()
    fixture = tmp_path / "with_filescan.json"
    fixture.write_text(json.dumps(data), encoding="utf-8")
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(fixture)):
        merged = RealProvider(settings(tmp_path)).rerun(first, ["windows.filescan"])
    scan = next(p for p in merged.plugins if p.name == "windows.filescan")
    assert scan.status == "Completed" and len(scan.rows) == len(NAMES) and len(merged.plugins) == len(first.plugins) + 1
    assert merged.case["notes"][0]["text"] == "kept" and any(f.rule_id == "FILE-001" for f in merged.indications)


# ============================================================================= GUI
QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(scope="module")
def app():
    return QtWidgets.QApplication.instance() or QtWidgets.QApplication([])


def dispose(app, *windows):
    """Close AND delete windows: an app-wide stylesheet change re-polishes every widget that is still alive, so leftovers slow later tests."""
    import gc
    from PySide6.QtCore import QCoreApplication, QEvent
    for window in windows:
        window.close()
        window.deleteLater()
    app.processEvents()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gc.collect()


def wait_for(app, condition, seconds=20):
    end = time.time() + seconds
    while time.time() < end:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


@pytest.fixture()
def files_dashboard(app, tmp_path):
    from app.analysis.pipeline import reanalyze
    from app.windows.dashboard_window import DashboardWindow
    result = load_fixture_result()
    result.plugins.append(plugin("windows.filescan", filescan_rows()))
    result = reanalyze(result)
    result.dump_path = make_dump(tmp_path)
    ioc_list = tmp_path / "intel.txt"
    (tmp_path / "dumps").mkdir()
    window = DashboardWindow(result, settings={"files_dump_dir": str(tmp_path / "dumps"), "volatility_path": str(FAKE_VOL),
                                               "ioc_files": [str(ioc_list)], "offline_mode": True})
    window.resize(1400, 800)
    window.show()
    app.processEvents()
    yield window, ioc_list
    dispose(app, *getattr(window.view("Files"), "_hex_views", []), window)


def patch_messages(monkeypatch):
    import app.windows.files_window as fw
    messages = []
    monkeypatch.setattr(fw, "show_info", lambda parent, title, text: messages.append((title, text)))
    monkeypatch.setattr(fw, "show_error", lambda parent, title, text, details="": messages.append((title, text)))
    return messages


def test_files_view_without_filescan_explains_and_offers_to_run_it(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.show()
    view = window.select_view(window.IDX["Files"])
    assert view.stack.currentIndex() == 0 and "not been run" in view.empty_text.text() and not view.run_button.isEnabled()      # no home window: cannot run
    calls = []
    window.run_plugins = lambda names, view_name="": calls.append((names, view_name))
    view.run_filescan()
    assert calls == [(["windows.filescan"], "Files")]
    dispose(app, window)


def listing(view):
    """``[(name, kind)]`` of what the open folder shows, in the order shown."""
    from app.engines.windows.analysis.fileindex import Folder
    return [(view.proxy.index(r, 1).data(), "folder" if isinstance(view.proxy.payload_at(view.proxy.index(r, 0)), Folder) else "file") for r in range(view.proxy.rowCount())]


def test_files_view_is_an_explorer_folders_first_double_click_to_enter_address_bar_back_forward_up(app, files_dashboard):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    assert view.stack.currentIndex() == 1 and len(view.index.files) == len(NAMES) and view.tree.topLevelItem(0).text(0) == "This image (9 files)"
    assert view.address.text() == "This image" and not view.up_button.isEnabled() and not view.back_button.isEnabled()
    assert sorted(n for n, k in listing(view)) == ["(volume not named)", "HarddiskVolume2 (C:)".split(" (")[0], "Mup"] and all(k == "folder" for _n, k in listing(view))
    # the C: volume is only recognised by \Windows\System32; its label says so
    volume = next(p for p in view.model.payloads if p.name == "HarddiskVolume2")
    assert view.index.label(volume) == "HarddiskVolume2 (C:)"
    view.open_item(volume)                                                                    # double-click a folder: it opens
    assert listing(view) == [("Users", "folder"), ("Windows", "folder")] and view.address.text() == "This image  ›  HarddiskVolume2 (C:)"
    assert view.up_button.isEnabled() and view.back_button.isEnabled() and not view.forward_button.isEnabled()
    view.address.setText("C:\\Windows\\System32")                                              # the address bar understands drive letters
    view.address_entered()
    assert listing(view) == [("drivers", "folder"), ("ntdll.dll", "file")] and view.address.text().endswith("Windows  ›  System32")
    assert view.model.rows[0][2] == "File folder" and view.model.rows[0][3] == "1 file(s)" and view.model.rows[1][2] == "DLL file"
    view.go_up()
    assert [n for n, _k in listing(view)] == ["System32", "Temp"]                              # (Windows holds System32 and Temp)
    view.go_back()
    assert view.address.text().endswith("System32") and view.forward_button.isEnabled()
    view.go_forward()
    assert view.address.text().endswith("Windows") and not view.forward_button.isEnabled()
    view.go_back()
    view.go_back()
    assert view.address.text().endswith("(C:)") or view.address.text() == "This image  ›  HarddiskVolume2 (C:)"
    for unknown in ("C:\\Nothing\\Here", "Z:\\Windows", "HarddiskVolume9"):
        before = view.address.text()
        view.address.setText(unknown)
        view.address_entered()
        assert "was not found" in view.status.text()
    assert view.index.resolve("\\Users\\Public\\Libraries").name == "Libraries" and view.index.resolve("this image") is view.index.root
    view.tree.setCurrentItem(view._tree_items[id(view.index.resolve("HarddiskVolume2\\Windows\\System32\\drivers"))])      # the tree opens folders too
    assert listing(view) == [("ntfs.sys", "file")] and view.address.text().endswith("drivers")


def test_search_and_filters_list_matching_files_of_the_whole_subtree_with_their_location(app, files_dashboard):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    assert view.view.isColumnHidden(7)                                                       # no Location column while browsing
    view.search.setText("bob documents")
    view.populate()
    assert listing(view) == [("invoice.pdf.exe", "file"), ("notes.txt", "file")] and not view.view.isColumnHidden(7)
    assert [view.model.rows[i][7] for i in range(2)] == ["\\Users\\bob\\Documents"] * 2
    assert "2 matching file(s)" in view.status.text()
    view.search.setText("bob docs")
    view.populate()
    assert listing(view) == []
    view.search.setText("")
    view.only_flagged.setChecked(True)
    assert {n for n, _k in listing(view)} == {"setup.exe", "update.exe", "invoice.pdf.exe", "x.dll"}
    view.only_flagged.setChecked(False)
    view.only_programs.setChecked(True)
    assert all(n.rsplit(".", 1)[-1] in ("exe", "dll", "sys") for n, _k in listing(view)) and "notes.txt" not in dict(listing(view))
    view.only_programs.setChecked(False)
    view.navigate(view.index.resolve("HarddiskVolume2\\Users"))                              # a search stays inside the open folder
    view.search.setText("exe")
    view.populate()
    assert {n for n, _k in listing(view)} == {"setup.exe", "update.exe", "invoice.pdf.exe"}


def test_selecting_a_file_shows_only_what_is_known_about_it_not_its_content(app, files_dashboard):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    entry = next(e for e in view.index.files if e.name == "setup.exe")
    assert view.select_target(entry.target) and view.address.text().endswith("bob  ›  Downloads")
    text = view.details.toPlainText()
    assert "Full path" in text and "FILE_OBJECT address" in text and "0x3000" in text and "Not dumped yet" in text and "its content is not shown" in text
    assert "Strings" not in text and "Entropy" not in text and "SHA-256" not in text and view.tabs.tabText(1) == "Content (after dump)"
    assert "content" in view.report.toPlainText().lower() and "dump the file" in view.report.toPlainText().lower() and not view.hex_button.isEnabled()
    folder = view.index.resolve("HarddiskVolume2\\Users")
    view.navigate(folder.parent)
    view.view.selectRow(next(r for r in range(view.proxy.rowCount()) if view.proxy.payload_at(view.proxy.index(r, 0)) is folder))
    props = view.details.toPlainText()
    assert "Path" in props and "file(s) including subfolders" in props and "Flagged files" in props and "Double-click a folder" in props
    assert not view.dump_one_button.isEnabled() and view.dump_all_button.isEnabled() is False                 # a folder row is not a file; no file is listed


def test_right_click_menu_depends_on_what_is_under_the_mouse(app, files_dashboard):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    folder = view.index.resolve("HarddiskVolume2\\Windows")
    assert [label for label, _h in view.actions_for(folder)] == ["Open", "Dump all files in this folder…"]
    entry = next(e for e in view.index.files if e.name == "ntdll.dll")
    labels = [label for label, _h in view.actions_for(entry)]
    assert labels == ["Dump…", "Bookmark / remove bookmark", "Add note…", "Copy full path"]
    view.dumps[entry.offset] = [("DataSectionObject", "x.dat")]
    assert "Open hex view of the dump" in [label for label, _h in view.actions_for(entry)] and view.actions_for(None) == []
    dict(view.actions_for(entry))["Copy full path"]()
    assert QtWidgets.QApplication.clipboard().text() == entry.full_name
    messages = []
    import app.windows.files_window as fw
    fw_confirm = fw.confirm
    fw.confirm = lambda *a, **k: messages.append("asked") or False
    try:
        dict(view.actions_for(view.index.resolve("HarddiskVolume2")))["Dump all files in this folder…"]()
    finally:
        fw.confirm = fw_confirm
    assert messages == ["asked"] and not (view._task and view._task.running)
    view.open_item(view.index.resolve("HarddiskVolume2"))
    view.address.setText("This image")
    view.address_entered()
    assert view.location is view.index.root and view.back_button.isEnabled()


def select_name(view, name):
    entry = next(e for e in view.index.entries if e.name == name)
    assert view.select_target(entry.target)
    return entry


def test_details_show_flags_references_and_notes(app, files_dashboard, monkeypatch):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    proc = window.result.processes[3]
    proc.handles.append({"type": "File", "name": r"\Device\HarddiskVolume2\Users\Public\Libraries\update.exe", "value": "0x4", "access": 3})
    view._refs = None
    entry = select_name(view, "update.exe")
    text = view.details.toPlainText()
    assert "Public" in text and "Why it is flagged" in text and f"open handle in {proc.name} (PID {proc.pid})" in text and "0x4000" in text
    monkeypatch.setattr(QtWidgets.QInputDialog, "getMultiLineText", staticmethod(lambda *a, **k: ("dropper candidate", True)))
    view.add_note_current()
    view.toggle_bookmark_current()
    from app.analysis import case_state
    assert case_state.is_bookmarked(window.result, entry.target) and "dropper candidate" in view.details.toPlainText()
    row = next(r for r in view.model.rows if r[1] == "update.exe")
    assert row[0] == "★✎"
    case_view = window.select_view(window.IDX["Case Notes"])
    assert case_view.tabs.tabText(0) == "Bookmarks (1)"
    window.select_view(window.IDX["Process Tree"])
    case_view._open(("bookmark", entry.target, {"pid": 0}))                                  # jumps to the file in the explorer
    assert window.stack.currentIndex() == window.IDX["Files"] and view._current() is entry


def test_dump_flow_hashes_checks_iocs_reports_and_opens_the_hex_view(app, files_dashboard, monkeypatch, tmp_path):
    window, ioc_list = files_dashboard
    view = window.select_view(window.IDX["Files"])
    messages = patch_messages(monkeypatch)
    content = b"MZ" + bytes(range(256)) * 4 + b"http://evil.test/payload.bin\x00" + b"C:\\Users\\Public\\x.exe"
    ioc_list.write_text(hashlib.sha256(content).hexdigest() + "   # known dropper\n", encoding="utf-8")
    window.home = None
    view._iocs = None
    first, second = select_name(view, "setup.exe"), next(e for e in view.index.entries if e.name == "update.exe")
    with env(FAKE_VOL_DUMPFILES=f"{first.offset:#x}"):
        view._dump([first, second])
        assert wait_for(app, lambda: view._task is not None and not view._task.running and messages)
    title, text = messages[-1]
    assert title == "Dump finished" and "1 of 2 file(s) had contents" in text and "IOC HASH MATCH" in text and "known dropper" in text
    assert "produced nothing" in text and view.dumps[first.offset] and second.offset in view.empty_dumps
    assert (tmp_path / "dumps" / "memorygraph_hashes.csv").is_file()
    assert view._dump_state(first) == "1 file(s)" and view._dump_state(second) == "not cached"
    select_name(view, "setup.exe")
    assert view.hex_button.isEnabled() and view.dumped_model.rows[0][0] == "DataSectionObject"
    assert wait_for(app, lambda: view.reports), "the report is built in the background when a dumped file is selected"
    report_text = view.report.toPlainText()
    assert hashlib.sha256(content).hexdigest() in report_text and "IOC HASH MATCH" in report_text and "http://evil.test/payload.bin" in report_text
    select_name(view, "update.exe")
    assert "none of its contents were cached" in view.details.toPlainText() and not view.hex_button.isEnabled()
    select_name(view, "setup.exe")
    view.open_hex()
    hex_view = view._hex_views[-1]
    assert hex_view.data == content and hex_view.base == 0 and "setup.exe" in hex_view.windowTitle() and not hex_view.reset_button.isVisible()
    assert hex_view.hex_text.toPlainText().splitlines()[0].startswith("00000000  4d 5a 00 01")
    from app.analysis import case_state
    monkeypatch.setattr(QtWidgets.QInputDialog, "getMultiLineText", staticmethod(lambda *a, **k: ("looks packed", True)))
    hex_view.add_region_note()
    assert case_state.notes_for(window.result, first.target)[0]["kind"] == "file"                 # the note belongs to the file, not to a memory region
    # a fresh view finds the earlier dump again from the folder alone
    view.reload()
    assert view.dumps[first.offset] and "1 dumped file(s)" in view.dump_label.text()


def test_dump_failure_is_reported_not_raised(app, files_dashboard, monkeypatch):
    window, _ = files_dashboard
    view = window.select_view(window.IDX["Files"])
    messages = patch_messages(monkeypatch)
    window.result.dump_path = "Z:\\missing.raw"
    view._dump([view.index.entries[0]])
    assert messages and messages[-1][0] == "Dump" and "not available" in messages[-1][1]


# ============================================================================= compare
def mutated_pair():
    reference = load_fixture_result()
    current = copy.deepcopy(reference)
    gone = current.processes.pop()
    kept = next(p for p in current.processes if p.dlls and p.pid > 4)
    new_proc = copy.deepcopy(kept)
    new_proc.pid, new_proc.name, new_proc.create_time = 9990, "dropper.exe", "2018-06-21T09:00:00+00:00"
    new_proc.path, new_proc.command_line, new_proc.network, new_proc.memory_regions = r"C:\Users\Public\dropper.exe", "dropper.exe -x", [], []
    current.processes.append(new_proc)
    extra = copy.deepcopy(kept.dlls[0])
    extra.name, extra.path = "evil.dll", r"C:\Users\Public\evil.dll"
    kept.dlls.append(extra)
    return reference, current, gone, kept, new_proc


def test_compare_same_boot_finds_new_gone_and_changed():
    from app.engines.windows.analysis import compare
    reference, current, gone, kept, new_proc = mutated_pair()
    comparison = compare.compare(current, reference)
    assert comparison.mode == compare.SAME_BOOT and comparison.match_fraction > 0.9
    processes = comparison.rows["Processes"]
    assert [(r.change, r.item) for r in processes] == [("new", "dropper.exe (PID 9990)"), ("gone", f"{gone.name} (PID {gone.pid})")]
    assert processes[0].pid == 9990 and "Public" in processes[0].detail
    modules = comparison.rows["Modules"]
    assert [(r.change, r.item, r.pid) for r in modules] == [("new", "evil.dll", kept.pid)] and not modules[0].trusted
    counts = comparison.counts()
    assert counts["Processes"] == {"new": 1, "gone": 1, "changed": 0} and "same boot" in " ".join(comparison.notes)


def test_compare_notices_new_connections_findings_regions_and_plugin_rows():
    from app.engines.windows.analysis import compare
    from app.models import NetworkConnection
    reference, current, gone, kept, new_proc = mutated_pair()
    conn = NetworkConnection(kept.pid, kept.name, "10.0.0.5", "50000", "203.0.113.9", "443", "ESTABLISHED", "TCPv4")
    current.connections = list(current.connections) + [conn]
    kept.network.append(conn)
    victim = next(p for p in current.processes if p.memory_regions)
    removed_region = victim.memory_regions.pop()
    finding = copy.deepcopy(current.indications[0])
    finding.title = "A brand new finding"
    finding.severity = "High"
    current.indications.append(finding)
    changed = copy.deepcopy(reference.indications[1])
    ref_sev = changed.severity
    current.indications[1].severity = "High" if ref_sev != "High" else "Medium"
    reference.plugins.append(plugin("windows.svcscan", [{"Name": "OldSvc", "Binary": "C:\\a.exe"}, {"Name": "Same", "Binary": "C:\\s.exe"}]))
    current.plugins.append(plugin("windows.svcscan", [{"Name": "NewSvc", "Binary": "C:\\n.exe"}, {"Name": "Same", "Binary": "C:\\s.exe"}]))
    current.plugins.append(plugin("windows.filescan", [{"Offset": 1, "Name": V + r"\Windows\x.dll"}]))
    reference.plugins.append(plugin("windows.filescan", [{"Offset": 99, "Name": r"\Device\HarddiskVolume3\Windows\x.dll"}]))     # same file, other volume number
    comparison = compare.compare(current, reference)
    assert [r.item for r in comparison.rows["Network"] if r.change == "new"] == [f"{kept.name} TCPv4 10.0.0.5:50000 → 203.0.113.9:443 ESTABLISHED"]
    findings = {(r.change, r.item) for r in comparison.rows["Findings"]}
    assert any(change == "new" and "A brand new finding" in item for change, item in findings) and any(c == "changed" for c, _i in findings)
    assert any(r.change == "gone" and removed_region.start in r.item for r in comparison.rows["Memory"])
    rows = {(r.change, r.item) for r in comparison.rows["Plugin rows"]}
    assert ("new", "NewSvc | C:\\n.exe") in rows and ("gone", "OldSvc | C:\\a.exe") in rows and not any("Same" in item or "x.dll" in item for _c, item in rows)
    reference.plugins.append(plugin("windows.modules", [{"Name": "a.sys", "Path": "C:\\a.sys"}]))
    assert any("windows.modules" in n and "reference" in n for n in compare.compare(current, reference).notes)
    current.plugins.append(plugin("windows.callbacks", [{"Type": "t", "Symbol": "s", "Module": "m"}]))
    assert any("windows.callbacks" in n and "current" in n for n in compare.compare(current, reference).notes)


def test_compare_different_systems_matches_by_image_and_path_and_ignores_addresses():
    from app.engines.windows.analysis import compare
    reference, current, gone, kept, new_proc = mutated_pair()
    for number, proc in enumerate(current.processes):
        proc.pid += 1000                                            # other boot: new PIDs ...
        proc.create_time = f"2018-07-01T10:{number % 60:02d}:00+00:00"          # ... and other start times
    comparison = compare.compare(current, reference)
    assert comparison.mode == compare.DIFFERENT and comparison.match_fraction < 0.3
    titles = {(r.change, r.item.split("  ")[0]) for r in comparison.rows["Processes"]}
    assert ("new", "dropper.exe") in titles and ("gone", gone.name) in titles and len(titles) == 2          # nothing else differs once PIDs/times are ignored
    assert [r.item for r in comparison.rows["Modules"]] == ["evil.dll"] and comparison.rows["Memory"] == []
    forced = compare.compare(current, reference, compare.SAME_BOOT)
    assert forced.mode == compare.SAME_BOOT and len(forced.rows["Processes"]) > 5          # a wrong choice is visible, not hidden


def test_compare_exports_csv_and_handles_empty_input(tmp_path):
    from app.engines.windows.analysis import compare
    from app.models import AnalysisResult
    reference, current, *_ = mutated_pair()
    path = tmp_path / "diff.csv"
    comparison = compare.compare(current, reference)
    count = compare.export_csv(comparison, str(path))
    lines = path.read_text(encoding="utf-8").splitlines()
    assert count == len(lines) - 1 == len(comparison.all_rows()) and lines[0] == "Section,Change,Item,Detail,PID"
    empty = compare.compare(AnalysisResult("a.raw", [], [], []), AnalysisResult("b.raw", [], [], []))
    assert any("no process list" in n for n in empty.notes) and empty.all_rows() == []
    assert compare.compare(current, current).all_rows() == []                                  # an investigation equals itself


def test_compare_view_loads_a_saved_investigation_and_filters(app, tmp_path, monkeypatch):
    from app.models import save_analysis_result
    from app.windows.dashboard_window import DashboardWindow
    import app.windows.compare_window as cw
    reference, current, gone, kept, new_proc = mutated_pair()
    path = tmp_path / "reference.json"
    save_analysis_result(reference, str(path))
    window = DashboardWindow(current, settings={})
    window.resize(1300, 800)
    window.show()
    view = window.select_view(window.IDX["Compare"])
    assert "No reference" in view.summary.text() and not view.export_button.isEnabled()
    view.load_reference(str(path))
    assert wait_for(app, lambda: view.comparison is not None)
    assert view.tabs.tabText(0) == "Processes (2)" and view.tabs.tabText(1) == "Modules (1)" and view.export_button.isEnabled()
    assert "same boot" in view.summary.text() and "Processes: 1 new, 1 gone" in view.summary.text()
    model, table, proxy, _note = view._views["Processes"]
    assert proxy.rowCount() == 2
    view.search.setText("dropper")
    assert view._views["Processes"][2].rowCount() == 1
    view.search.setText("")
    view.mode.setCurrentIndex(view.mode.findData(cw.compare_module.DIFFERENT))
    assert view.comparison.mode == cw.compare_module.DIFFERENT and view.tabs.tabText(0).startswith("Processes (")
    opened = []
    window.show_process = lambda pid: opened.append(pid)
    view._open(view.comparison.rows["Processes"][0])
    assert opened == [new_proc.pid]
    monkeypatch.setattr(QtWidgets.QFileDialog, "getSaveFileName", staticmethod(lambda *a, **k: (str(tmp_path / "out.csv"), "")))
    monkeypatch.setattr(cw, "show_info", lambda *a, **k: None)
    view.export_csv()
    assert (tmp_path / "out.csv").read_text(encoding="utf-8").startswith("Section,Change")
    messages = []
    monkeypatch.setattr(cw, "show_error", lambda parent, title, text, details="": messages.append(title))
    view.load_reference(str(tmp_path / "not-there.json"))
    assert wait_for(app, lambda: messages) and messages == ["Reference investigation"]
    dispose(app, window)


# ============================================================================= lessons from a real image (WinDump.mem)
def test_real_filescan_shapes_folder_objects_servicing_leftovers_and_shortcuts():
    """windows.filescan 2.28 prints names without a device, lists opened folders as objects, and the offsets are kernel virtual addresses."""
    from app.engines.windows.analysis.fileindex import FileIndex, entries_from_rows, flags_for
    rows = [{"Offset": 0xD98DF369CB00, "Name": r"\Windows\Temp\2964312081\reach.exe"},
            {"Offset": 0xD98DF36B59F0, "Name": r"\Windows\WinSxS\Temp\PendingDeletes\4bb1.mssrch.dll"},
            {"Offset": 0xD98DF7D69EF0, "Name": r"\Users\Public\Desktop\Google Chrome.lnk"},
            {"Offset": 0xD98DF3AB26A0, "Name": r"\Windows\System32\kernel32.dll"},
            {"Offset": 0xD98DF1000000, "Name": r"\Windows\System32"},                        # a folder that was opened
            {"Offset": 0xD98DF1000100, "Name": r"\Windows"},
            {"Offset": 0xD98DF1000200, "Name": r"\Windows\Temp"}]
    index = FileIndex(entries_from_rows(rows))
    assert [e.path for e in index.entries if e.is_directory] == [r"\Windows\System32", r"\Windows", r"\Windows\Temp"]
    assert sorted(e.name for e in index.files) == ["4bb1.mssrch.dll", "Google Chrome.lnk", "kernel32.dll", "reach.exe"]
    flagged = {e.name: flags_for(e) for e in index.files if flags_for(e)}
    assert list(flagged) == ["reach.exe"] and "Windows\\Temp" in flagged["reach.exe"][0]          # servicing leftovers and a .lnk are not flagged
    assert index.root.total() == 4 and index.drive_hint(index.devices[""]) == "C:" and index.devices[""].name == "(volume not named)"
    from test_case_and_ioc import by_rule, with_plugins
    assert [f.severity for f in by_rule(with_plugins(plugin("windows.filescan", rows)), "FILE-001")] == ["Medium"]        # the rule agrees: one finding


def test_dump_command_uses_virtual_addresses():
    """filescan's Offset is a kernel virtual address (0xd98d...); --physaddr would read the wrong object."""
    from app.engines.windows.analysis.dumper import VolatilityDumper
    import inspect
    source = inspect.getsource(VolatilityDumper.dump_file_objects)
    assert "--virtaddr" in source and "--physaddr" not in source


def test_report_explains_empty_tables_and_made_up_compile_times(tmp_path):
    """Real dumps of Windows files: compile time 2074 (a hash, not a date) and import/export tables on pages that were not in memory."""
    from app.engines.windows.analysis import file_report
    data = bytearray(make_pe(tmp_path / "a.dll").read_bytes())
    struct.pack_into("<I", data, 0x80 + 8, 0xF0000000)                                  # TimeDateStamp far in the future
    data[0xA00:0xA00 + 0x200] = bytes(0x200)                                            # the import pages are zeros in this dump
    path = tmp_path / "b.dll"
    path.write_bytes(bytes(data))
    pe = file_report.build_report(str(path)).pe
    warnings = " ".join(pe.warnings)
    assert "not a real date" in warnings and "import table, but it is empty" in warnings and pe.imports == {}
    assert file_report.build_report(str(make_pe(tmp_path / "ok.dll"))).pe.warnings == []                 # an intact sample raises none of them


def test_names_that_filescan_read_from_damaged_pool_memory_are_listed_together_not_as_folders():
    from app.engines.windows.analysis import fileindex
    B = chr(92)
    rows = [{"Offset": 0x1000, "Name": B.join(["", "Device", "HarddiskVolume2", "Windows", "System32", "ntdll.dll"])},
            {"Offset": 0x2000, "Name": B.join(["", "Device", "HarddiskVolume2", "Windows", "System32", "kernel32.dll"])},
            # real names of a Windows 10 image: a piece of a Windows Update XML manifest, control characters, a path whose first characters were overwritten
            {"Offset": 0x3000, "Name": 'rchitecture="amd64" versionScope="nonSxS" publicKeyToken="31bf3856ad364e35"/><update name="4'},
            {"Offset": 0x4000, "Name": chr(8) + chr(0x1AA) + chr(0x1000) + chr(0xC0) + chr(0x1F9)},
            {"Offset": 0x5000, "Name": chr(0x1180) + chr(0xFFFD) + "dows" + B + "Microsoft.NET" + B + "ngennicupdatelock.dat"}]
    index = fileindex.FileIndex(fileindex.entries_from_rows(rows))
    assert [f.name for f in index.root.subfolders()] == ["HarddiskVolume2", "(damaged names)"]                  # the damaged names are listed last
    damaged = index.devices[fileindex.DAMAGED_DEVICE.lower()]
    assert damaged.total() == 3 and not damaged.children                                       # one flat folder, not a folder per fragment
    assert {e.raw for e in damaged.files} == {r["Name"] for r in rows[2:]} and all(e.offset for e in damaged.files)      # still dumpable by address
    assert damaged.files[0].full_name == damaged.files[0].raw
    assert index.devices["harddiskvolume2"].total() == 2
