"""Hex view helpers, the hex view dialog, and notes/bookmarks on DLLs, plugin rows and memory regions."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import load_fixture_result

QtWidgets = pytest.importorskip("PySide6.QtWidgets")

PROLOGUE = bytes.fromhex("55 48 89 e5 90 c3")
_OPENED = []


# ============================================================================= pure helpers
def test_parse_hexdump_reads_the_json_layout_and_volatility_text_layout_and_offsets():
    from app.analysis.hexview import parse_hexdump
    data = bytes(range(70, 90)) + b"\xfe\xed"
    assert parse_hexdump(" ".join(f"{b:02x}" for b in data)) == data                       # -r json: one line, no ASCII column (64 bytes in real runs)
    assert parse_hexdump(f"0x1000: {data[:16].hex(' ')}\n0x1010: {data[16:].hex(' ')}") == data    # offset column
    assert parse_hexdump("") == b"" and parse_hexdump(None) == b"" and parse_hexdump("not hex at all") == b""
    try:
        from volatility3.cli.text_renderer import hex_bytes_as_text
        text = hex_bytes_as_text(data)
    except ImportError:                                  # same algorithm, written out
        text = "\n46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 FGHIJKLMNOPQRSTU\n56 57 58 59 5a 5b fe ed" + " " * 30 + "VWXYZ[..          "
    assert parse_hexdump(text) == data                                                      # text renderer: ASCII column ignored, short last line


def test_ascii_column_letters_do_not_become_bytes_in_the_malfind_rule():
    """The old rule helper stripped every non-hex character, so the letters a-f of an ASCII column became extra 'bytes'."""
    from app.engines.windows.indicators.rules.memory import _hex_bytes
    from app.models import MemoryRegion
    line = "61 62 63 64 65 66 61 62 63 64 65 66 61 62 63 64 abcdefabcdefabcd"
    assert len(_hex_bytes(MemoryRegion(1, "x", details={"Hexdump": "\n" + line}))) == 32


def test_layout_maps_text_positions_to_offsets_and_back():
    from app.analysis.hexview import Layout, format_dump
    data = bytes(range(40))
    text = format_dump(data, 0x7FF600000000)
    lines = text.splitlines()
    layout = Layout(0x7FF600000000, len(data))
    assert layout.address_digits == 16 and lines[0].startswith("00007ff600000000  00 01 02") and len(lines) == 3
    assert lines[2].startswith("00007ff600000020  20 21 22 23 24 25 26 27") and lines[2].endswith("  !\"#$%&'")
    for offset in (0, 7, 15, 16, 39):
        line, column = layout.line_of(offset), layout.hex_column(offset)
        assert lines[line][column:column + 2] == f"{data[offset]:02x}" and layout.offset_at(line, column) == offset
        assert layout.offset_at(line, column + 1) == offset                               # the space after the byte is still that byte
        assert lines[line][layout.ascii_column(offset)] == (chr(data[offset]) if 32 <= data[offset] < 127 else ".")
        assert layout.offset_at(line, layout.ascii_column(offset)) == offset
    assert layout.offset_at(0, 3) is None and layout.offset_at(2, layout.hex_column(8)) is None        # address column; past the data
    assert Layout(0x1000, 40).address_digits == 8


def test_search_hex_wildcards_text_utf16_and_wrap_around():
    from app.analysis import hexview
    data = b"\x00MZ\x90\x00\x03\x00kernel32.dll\x00" + "Evil".encode("utf-16-le") + b"\x00MZ\x91\x00"
    assert hexview.find_next(data, hexview.compile_pattern("4d 5a ?? 00")) == (1, 4)
    assert hexview.find_next(data, hexview.compile_pattern("0x4d,0x5a 91"), 0) == (len(data) - 4, 3)
    assert hexview.find_next(data, hexview.compile_pattern("4d5a"), 2) == (len(data) - 4, 2)
    assert hexview.find_next(data, hexview.compile_pattern("4d5a"), len(data) - 3) == (1, 2)            # wraps
    assert hexview.find_next(data, hexview.compile_pattern("4d5a"), len(data) - 3, wrap=False) is None
    assert hexview.find_next(data, hexview.compile_pattern("KERNEL32", "ascii")) is None
    assert hexview.find_next(data, hexview.compile_pattern("KERNEL32", "ascii", ignore_case=True)) == (7, 8)
    assert hexview.find_next(data, hexview.compile_pattern("evil", "utf16", ignore_case=True)) == (20, 8)
    pattern = hexview.compile_pattern("4d 5a")
    assert hexview.find_previous(data, pattern, len(data)) == (len(data) - 4, 2)
    assert hexview.find_previous(data, pattern, len(data) - 4) == (1, 2)
    assert hexview.find_previous(data, pattern, 1) == (len(data) - 4, 2)                                  # wraps to the last
    assert hexview.find_previous(data, pattern, 1, wrap=False) is None
    assert hexview.count_matches(data, pattern) == 2
    for bad in ("", "4d 5", "zz", "0x"):
        with pytest.raises(ValueError):
            hexview.compile_pattern(bad)


def test_disassembly_covers_more_than_the_stored_bytes_and_resynchronises():
    pytest.importorskip("capstone")
    from app.analysis import hexview
    code = PROLOGUE + b"\x06" + PROLOGUE                       # 0x06 (push es) does not exist in 64-bit mode
    instructions, error = hexview.disassemble(code, 0x1000, 64)
    assert not error
    assert [i.text for i in instructions] == ["push rbp", "mov rbp, rsp", "nop", "ret", "db 0x06", "push rbp", "mov rbp, rsp", "nop", "ret"]
    assert instructions[0].address == 0x1000 and instructions[4].valid is False and instructions[5].offset == 7
    assert [i.text for i in hexview.disassemble(code, 0, 32)[0]][:3] == ["push ebp", "dec eax", "mov ebp, esp"]            # same bytes, 32-bit mode
    assert "db 0x06" not in [i.text for i in hexview.disassemble(code, 0, 32)[0]]
    assert [i.text for i in hexview.disassemble(code, 0, 64, start=2, limit=2)[0]] == ["mov ebp, esp", "nop"]       # starts mid-instruction
    assert len(hexview.disassemble(code, 0, 64, limit=3)[0]) == 3


def test_disassembly_without_capstone_explains_itself(monkeypatch):
    import builtins
    from app.analysis import hexview
    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "capstone":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", blocked)
    instructions, error = hexview.disassemble(PROLOGUE)
    assert instructions == [] and "capstone is not installed" in error and not hexview.capstone_available()


def test_dump_file_lookup_by_malfind_naming(tmp_path):
    from app.analysis import hexview
    exact = tmp_path / "pid.2688.vad.0x1f0000-0x1fffff.dmp"
    exact.write_bytes(b"\x90" * 100)
    (tmp_path / "pid.2688.vad.0x300000-0x3fffff.dmp").write_bytes(b"x")
    assert hexview.find_dump_file(str(tmp_path), 2688, 0x1F0000, 0x1FFFFF) == str(exact)
    assert hexview.find_dump_file(str(tmp_path), 2688, 0x1F0000, 0x1F8000) == str(exact)                 # same start, other end
    assert hexview.find_dump_file(str(tmp_path), 2688, 0x400000, 0x4FFFFF) is None
    assert hexview.find_dump_file(str(tmp_path / "missing"), 1, 0, 1) is None and hexview.find_dump_file("", 1, 0, 1) is None
    data, size = hexview.read_file(str(exact), limit=10)
    assert data == b"\x90" * 10 and size == 100


# ============================================================================= GUI
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


@pytest.fixture()
def dashboard(app):
    from app.windows.dashboard_window import DashboardWindow
    window = DashboardWindow(load_fixture_result(), settings={})
    window.resize(1400, 800)
    window.show()
    app.processEvents()
    yield window
    extra = []
    for opened in _OPENED:                          # other tests count visible process windows
        extra += list(getattr(opened, "_hex_views", [])) + [opened]
    _OPENED.clear()
    dispose(app, *extra, window)


def select_payload(view, proxy, wanted, key=lambda payload: payload):
    """Select the row whose payload is ``wanted`` (the tables sort themselves, so row numbers say nothing about the data)."""
    for row in range(proxy.rowCount()):
        if key(proxy.payload_at(proxy.index(row, 0))) is wanted:
            view.selectRow(row)
            return
    raise AssertionError("payload not in the table")


def answer_note(monkeypatch, text="my note"):
    monkeypatch.setattr(QtWidgets.QInputDialog, "getMultiLineText", staticmethod(lambda *a, **k: (text, True)))


def process_window(dashboard, app, pid=2688):
    from app.windows.process_window import ProcessWindow
    proc = next(p for p in dashboard.result.processes if p.pid == pid)
    tree = dashboard.select_view(dashboard.IDX["Process Tree"])
    window = ProcessWindow(proc, tree, dump_path="x.raw")
    window.show()
    _OPENED.append(window)
    app.processEvents()
    return window, proc


def test_hex_view_shows_offsets_finds_bytes_and_disassembles(app, dashboard, monkeypatch, tmp_path):
    pytest.importorskip("capstone")
    from app.windows.hex_view import HexViewDialog
    from app.analysis import hexview
    window, proc = process_window(dashboard, app)
    region = next(r for r in proc.memory_regions if bytes.fromhex("4883ec") in hexview.region_bytes(r))
    data = hexview.region_bytes(region)
    select_payload(window.region_view, window.region_proxy, region)
    app.processEvents()
    assert window.hex_button.isEnabled()
    window.open_hex_view()
    view = window._hex_views[-1]
    assert isinstance(view, HexViewDialog) and view.isVisible() and view.data == data and len(data) == 64
    assert "2688" in view.windowTitle()
    first = view.hex_text.toPlainText().splitlines()[0]
    assert first.startswith(f"{int(region.start, 16):016x}  " + data[:8].hex(" "))
    assert "malfind keeps only the first 64 bytes" in view.info.text()
    assert view.dis_model.rows[0][2] == hexview.disassemble(data, int(region.start, 16), 64)[0][0].text and "instruction(s)" in view.dis_status.text()

    hit = data.find(bytes.fromhex("4883ec"))
    view.search_text.setText("48 83 ec ??")
    view.find_next()
    assert view._current == (hit, 4) and "Match at" in view.search_status.text() and view.hex_text.extraSelections()
    view.find_next()                                                          # the next match of a single-match pattern is itself
    assert view._current == (hit, 4)
    view.search_text.setText("zz")
    view.find_next()
    assert "not a hex byte" in view.search_status.text()
    view.goto_text.setText(hex(int(region.start, 16) + 0x10))
    view.go_to()
    assert view._cursor_offset == 0x10 and "u32" in view.inspector.text()
    view.goto_text.setText("0x10000000000000")
    view.go_to()
    assert "outside the loaded bytes" in view.search_status.text()

    view.dis_view.selectRow(2)                                                # selecting an instruction highlights its bytes in the dump
    app.processEvents()
    assert view._instruction == (view.dis_model.payloads[2].offset, len(view.dis_model.payloads[2].raw))
    assert view._cursor_offset == view.dis_model.payloads[2].offset                      # ... and moves the cursor there
    view.goto_text.setText(hex(int(region.start, 16) + 0x10))
    view.go_to()
    view.disassemble_from_cursor()
    assert view.dis_model.rows[0][0] == f"{int(region.start, 16) + 0x10:#x}"

    big = tmp_path / f"pid.2688.vad.{region.start}-{region.end}.dmp"
    big.write_bytes(bytes.fromhex("56 57 53 55 41 54 41 55") + b"\x90" * 3000 + b"MZ\x90\x00")
    assert view.load_path(str(big)) and len(view.data) == 3012
    view.search_text.setText("4d 5a 90 00")
    view.find_next()
    assert view._current == (3008, 4)
    assert "3,012 byte(s)" in view.info.text() and len(view.dis_model.rows) == 200                       # 200 instructions by default
    view.count.setValue(5000)
    view.disassemble_from_start()
    assert len(view.dis_model.rows) > 3000
    view.use_malfind_bytes()
    assert len(view.data) == 64
    view.close()


def test_hex_view_region_bookmark_and_note_are_listed_in_case_notes(app, dashboard, monkeypatch):
    from app.analysis import case_state
    window, proc = process_window(dashboard, app)
    region = proc.memory_regions[-1]
    select_payload(window.region_view, window.region_proxy, region)
    window.open_hex_view()
    view = window._hex_views[-1]
    answer_note(monkeypatch, "RWX stub, check the import table")
    view.add_region_note()
    view.toggle_region_bookmark()
    target = case_state.region_target(proc, region)
    assert case_state.is_bookmarked(dashboard.result, target) and case_state.notes_for(dashboard.result, target)
    assert "★" in view.bookmark_button.text() and "RWX stub" in view.note_info.text()
    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(0) == "Bookmarks (1)" and case_view.tabs.tabText(1) == "Notes (1)"
    view.close()


def test_dll_bookmark_and_note_show_marks_and_survive_save_load(app, dashboard, monkeypatch, tmp_path):
    from app.analysis import case_state
    from app.models import load_analysis_result, save_analysis_result
    window, proc = process_window(dashboard, app, pid=3828 if any(p.pid == 3828 and p.dlls for p in dashboard.result.processes) else 2688)
    assert proc.dlls
    dll = proc.dlls[1]
    row_number = proc.dlls.index(dll)
    select_payload(window.modules_view, window.modules_proxy, dll, key=lambda payload: payload[0])
    app.processEvents()
    assert window.dll_bookmark_button.isEnabled() and window.dll_note_button.isEnabled()
    answer_note(monkeypatch, "unsigned module")
    window.add_dll_note()
    window.toggle_dll_bookmark()
    target = case_state.dll_target(proc, dll)
    assert case_state.is_bookmarked(dashboard.result, target) and case_state.notes_for(dashboard.result, target)[0]["kind"] == "dll"
    assert window.modules_model.rows[row_number][5] == "★✎" and "unsigned module" in window.dll_note_info.text()
    assert window.modules_proxy.rowCount() == len(proc.dlls)
    window.only_unusual.setChecked(True)                                         # the filter still works with the tuple payload
    assert window.modules_proxy.rowCount() < len(proc.dlls)                      # system modules are filtered out
    window.only_unusual.setChecked(False)
    select_payload(window.modules_view, window.modules_proxy, dll, key=lambda payload: payload[0])
    window.toggle_dll_bookmark()
    assert not case_state.is_bookmarked(dashboard.result, target) and window.modules_model.rows[row_number][5] == "✎"

    path = tmp_path / "inv.json"
    save_analysis_result(dashboard.result, str(path))
    again = load_analysis_result(str(path))
    assert case_state.notes_for(again, target)[0]["text"] == "unsigned module"
    reopened, _ = process_window(dashboard, app, pid=proc.pid)
    assert reopened.modules_model.rows[row_number][5] == "✎"


def test_process_window_without_an_investigation_disables_module_marks(app):
    from app.windows.process_window import ProcessWindow
    proc = load_fixture_result().processes[0]
    window = ProcessWindow(proc, None, dump_path="x.raw")
    if proc.dlls:
        window.modules_view.selectRow(0)
    assert not window.dll_bookmark_button.isEnabled() and not window.dll_note_button.isEnabled()
    assert "opened from an investigation" in window.dll_note_info.text()


def test_plugin_row_bookmark_note_marks_and_jump_from_case_notes(app, dashboard, monkeypatch):
    from app.analysis import case_state
    view = dashboard.select_view(dashboard.IDX["Plugin Output"])
    names = [p.name for p in dashboard.result.plugins]
    assert view.show_plugin_by_name("windows.malfind") and view.table_model.columns[0] == "Marks"
    wanted = view.table_model.payloads[1]
    select_payload(view.table_view, view.table_proxy, wanted)
    app.processEvents()
    assert view.bookmark_button.isEnabled()
    name, row = view.table_proxy.payload_at(view.table_view.currentIndex())
    assert (name, row) == wanted
    assert name == "windows.malfind" and row["PID"]
    answer_note(monkeypatch, "second region looks like a stub")
    view.add_note_current()
    view.toggle_bookmark_current()
    target = case_state.plugin_row_target(name, row)
    assert case_state.is_bookmarked(dashboard.result, target) and view.table_model.rows[1][0] == "★✎"
    assert "second region" in view.note_info.text() and sum(1 for r in view.table_model.rows if r[0]) == 1

    other = next(n for n in names if n != "windows.malfind")                    # marks follow the row when the plugin is shown again
    view.show_plugin_by_name(other)
    view.show_plugin_by_name("windows.malfind")
    assert sum(1 for r in view.table_model.rows if r[0]) == 1

    case_view = dashboard.select_view(dashboard.IDX["Case Notes"])
    assert case_view.tabs.tabText(0) == "Bookmarks (1)"
    view.show_plugin_by_name(other)
    dashboard.select_view(dashboard.IDX["Case Notes"])
    case_view._open(("note", "x", {"target": target, "pid": 0}))                 # a note about a plugin row opens that row
    app.processEvents()
    assert dashboard.stack.currentIndex() == dashboard.IDX["Plugin Output"]
    assert view.plugins.currentRow() == names.index("windows.malfind")
    selected = view.table_proxy.payload_at(view.table_view.currentIndex())
    assert selected is not None and case_state.plugin_row_target(*selected) == target
    text_mode = view.text_mode
    text_mode.setChecked(True)
    assert view.marks_bar.isHidden()
    text_mode.setChecked(False)
    assert not view.marks_bar.isHidden()
