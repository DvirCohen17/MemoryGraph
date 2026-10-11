"""The engines (app/engines): the interface, the Windows engine through it, the Linux skeleton, the settings that follow the choice, the switch, the windows that adapt."""
import inspect
import json
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, env, load_fixture_result, make_dump
from test_round5 import app, dispose, wait_for  # noqa: F401  (the app fixture)

QtWidgets = pytest.importorskip("PySide6.QtWidgets")


@pytest.fixture(autouse=True)
def instant_switch():
    """The switch animates by default; every test but the animation test wants an instant change."""
    from app.windows import os_switch
    old = os_switch.ANIMATED
    os_switch.ANIMATED = False
    yield
    os_switch.ANIMATED = old


def linux_result():
    result = load_fixture_result()
    result.target_os = "linux"
    return result


# ============================================================================= finding an engine
def test_engines_are_found_by_id_by_result_and_by_settings_and_unknown_means_windows():
    from app.engines import DEFAULT_OS, OS_IDS, engine_for, engine_for_settings, get_engine
    assert OS_IDS == ("windows", "linux") and DEFAULT_OS == "windows"
    assert get_engine("windows").id == "windows" and get_engine("linux").id == "linux" and get_engine("LINUX").id == "linux"
    assert get_engine("beos").id == "windows" and get_engine(None).id == "windows" and get_engine("") .id == "windows"
    assert get_engine("linux") is get_engine("linux")                                               # one instance each
    assert engine_for(load_fixture_result()).id == "windows" and engine_for(linux_result()).id == "linux"
    assert engine_for_settings({"target_os": "linux"}).id == "linux" and engine_for_settings({}).id == "windows" and engine_for(None).id == "windows"


def test_both_engines_implement_the_whole_interface_and_only_linux_is_a_skeleton():
    from app.engines.base import Engine
    from app.engines.linux import LinuxEngine
    from app.engines.windows import WindowsEngine
    interface = [name for name, value in vars(Engine).items() if callable(value) and not name.startswith("_")]
    assert len(interface) >= 15
    for engine_class in (WindowsEngine, LinuxEngine):
        missing = [name for name in interface if name not in vars(engine_class) and name not in ("is_risky_path", "is_trusted_path")]
        assert missing == [], (engine_class.__name__, missing)                                         # no method is left to the base class's "not implemented"
    assert WindowsEngine.implemented and not LinuxEngine.implemented and "skeleton" in LinuxEngine.status_note
    for engine_class in (WindowsEngine, LinuxEngine):
        engine = engine_class()
        assert engine.terms.title and engine.terms.image_filter and engine.terms.symbols_hint and engine.terms.modules_tab
        assert [v.id for v in engine.view_specs()][0] == "Overview" and "Case Notes" in [v.id for v in engine.view_specs()]


def test_the_windows_engine_does_what_the_pipeline_asks_of_it():
    from app.analysis.pipeline import analyze_plugins
    from app.engines import get_engine
    engine = get_engine("windows")
    result = load_fixture_result()
    assert result.target_os == "windows" and engine.describe_os(result).startswith("Windows 10") and engine.rule_name("PT-003")
    assert engine.attack_for("MAL-001") and engine.rule_catalog()["PT-003"].name and engine.is_trusted_path("C:\\Windows\\System32\\x.dll") and engine.is_risky_path("C:\\Users\\a\\Downloads\\x.exe")
    rebuilt = analyze_plugins("x.raw", result.plugins, engine="windows")
    assert rebuilt.target_os == "windows" and [p.pid for p in rebuilt.processes] == [p.pid for p in result.processes]
    assert engine.plugin_registry().REGISTRY and engine.make_provider({}).CORE_PLUGINS and engine.make_dumper("x.raw").dump_path == "x.raw"
    assert engine.capabilities.registry and engine.capabilities.legacy_network_engine and "Registry" in [v.id for v in engine.view_specs()]


# ============================================================================= the Linux skeleton
def test_every_linux_function_exists_and_says_what_is_missing():
    from app.engines.base import EngineNotImplemented
    from app.engines.linux import LinuxEngine
    from app.engines.linux.analysis import compare, dumper, files, normalizer, os_profile, provider, quality, timeline
    from app.engines.linux.indicators import engine as rules
    from app.models import AnalysisResult
    empty = AnalysisResult("x.raw", [], [], [])
    calls = [
        lambda: normalizer.normalize("x.raw", []), lambda: timeline.build_timeline(empty), lambda: timeline.apply_severity(empty), lambda: quality.data_quality_warnings(empty),
        lambda: os_profile.parse_banner("Linux version 5.15"), lambda: os_profile.from_rows([]), lambda: os_profile.from_result(empty), lambda: os_profile.describe_os(empty),
        lambda: files.entries_from_rows([]), lambda: compare.compare(empty, empty),
        lambda: provider.LinuxProvider({}).run("x.raw"), lambda: provider.LinuxProvider({}).rerun(empty),
        lambda: dumper.LinuxDumper("x.raw").dump_process(1, "."), lambda: dumper.LinuxDumper("x.raw").dump_dlls(1, "."), lambda: dumper.LinuxDumper("x.raw").dump_handles(1, "."),
        lambda: dumper.LinuxDumper("x.raw").dump_malfind_pages(1, "."), lambda: dumper.LinuxDumper("x.raw").dump_all_process_images("."),
        lambda: rules.IndicatorEngine().evaluate(empty), lambda: LinuxEngine().refresh_image_hash_findings(empty), lambda: os_profile.LinuxProfile(kernel="5.15").version,
    ]
    for call in calls:
        with pytest.raises(EngineNotImplemented) as caught:
            call()
        assert "Linux engine does not implement" in caught.value.message and caught.value.function, caught.value.message
    assert rules.DEFAULT_RULES == [] and rules.rule_name("LNX-001") == "LNX-001" and LinuxEngine().attack_for("LNX-001") == []
    assert not LinuxEngine().is_risky_path("/tmp/x") and not LinuxEngine().is_trusted_path("/usr/bin/x")          # neutral until the baseline tables are filled


def test_the_linux_plugin_list_is_consistent_and_works_with_the_same_settings_keys():
    from app.engines import get_engine
    registry = get_engine("linux").plugin_registry()
    names = {spec.name for spec in registry.REGISTRY}
    assert len(names) == len(registry.REGISTRY) and all(n.startswith(("linux.", "banners.")) for n in names)
    for bundle in registry.BUNDLES:
        assert bundle.members and set(bundle.members) <= names, bundle.id
    assert set(registry.required_names()) <= names and registry.bundle_of("linux.pslist.PsList").locked
    settings = registry.apply_bundles({}, {"network": "on", "kernel": "on", "pagecache": "off"})
    assert settings["run_extended_plugins"] is True and "linux.pagecache.Files" not in settings["optional_plugins"]
    assert registry.bundle_state(registry.bundle_of("linux.sockstat.Sockstat"), settings) == "on"
    assert not any(n.startswith("windows.") for n in names) and all("registry" not in n.lower() for n in names)          # Linux has no registry


def test_a_linux_analysis_fails_with_a_message_not_a_crash(app, tmp_path):
    from app.windows.home_window import HomeWindow
    window = HomeWindow()
    try:
        window.os_switch.set_os("linux")
        window.path.setText(make_dump(tmp_path))
        window.run_analysis()
        assert wait_for(app, lambda: window.progress_window._failed, 15)
        assert window.progress_window.status.text() == "Analysis failed"
        message = window.progress_window.message.text()
        assert "Linux engine does not implement" in message and "LinuxProvider.run" in message and "app/engines/linux" in message
        assert window.progress_window.retry.isVisibleTo(window.progress_window) and window.progress_window.back.isVisibleTo(window.progress_window)       # a way out
        assert window.dashboard_window is None
    finally:
        dispose(app, window)


def test_the_pipeline_given_the_linux_engine_stops_with_the_missing_function(tmp_path):
    from app.analysis.pipeline import analyze_plugins
    from app.engines.base import EngineNotImplemented
    with pytest.raises(EngineNotImplemented) as caught:
        analyze_plugins("x.raw", [], engine="linux")
    assert caught.value.function == "normalize"


# ============================================================================= the settings follow the choice
def test_switching_the_operating_system_swaps_only_the_settings_that_belong_to_one():
    from app.settings import sanitize, switch_target_os
    settings = sanitize({"theme": "Light", "volatility_path": "C:/vol.exe", "optional_plugins": ["run_keys"], "run_extended_plugins": True, "symbol_dirs": ["D:/win-symbols"],
                         "yara_rules_file": "win.yar", "parallel_plugins": 5})
    assert settings["target_os"] == "windows" and settings["os_profiles"] == {}
    switch_target_os(settings, "linux")
    assert settings["target_os"] == "linux"
    assert settings["optional_plugins"] == [] and settings["run_extended_plugins"] is False and settings["symbol_dirs"] == [] and settings["yara_rules_file"] == ""      # Linux starts clean
    assert settings["theme"] == "Dark" and settings["volatility_path"] == "C:/vol.exe" and settings["parallel_plugins"] == 5                                         # the rest is shared
    settings["symbol_dirs"] = ["/opt/linux-isf"]
    settings["optional_plugins"] = ["linux.pagecache.Files"]
    switch_target_os(settings, "windows")                                                           # back: everything the Windows profile had is back
    assert settings["optional_plugins"] == ["run_keys"] and settings["run_extended_plugins"] is True and settings["symbol_dirs"] == ["D:/win-symbols"] and settings["yara_rules_file"] == "win.yar"
    assert settings["os_profiles"]["linux"]["symbol_dirs"] == ["/opt/linux-isf"]
    switch_target_os(settings, "linux")
    assert settings["symbol_dirs"] == ["/opt/linux-isf"] and settings["optional_plugins"] == ["linux.pagecache.Files"]
    switch_target_os(settings, "linux")                                                             # the same choice again changes nothing
    assert settings["symbol_dirs"] == ["/opt/linux-isf"]
    switch_target_os(settings, "beos")                                                              # an unknown one means Windows
    assert settings["target_os"] == "windows"
    assert sanitize({"target_os": "beos", "os_profiles": "x"})["target_os"] == "windows" and sanitize({"os_profiles": 5})["os_profiles"] == {}
    json.dumps(settings)                                                                            # it must stay saveable


def test_the_operating_system_is_saved_with_the_investigation_and_old_files_mean_windows(tmp_path):
    from app.models import analysis_result_to_dict, analysis_result_from_dict, load_analysis_result, save_analysis_result
    result = linux_result()
    target = str(tmp_path / "linux.json.gz")
    save_analysis_result(result, target)
    assert load_analysis_result(target).target_os == "linux"
    data = analysis_result_to_dict(load_fixture_result())
    data.pop("target_os", None)                                                                     # a file saved before engines existed
    assert analysis_result_from_dict(data).target_os == "windows"
    data["target_os"] = "LINUX"
    assert analysis_result_from_dict(data).target_os == "linux"


# ============================================================================= the switch
def test_the_switch_changes_by_click_key_and_code_and_says_so_once(app):
    from PySide6.QtCore import QEvent, QPointF, Qt
    from PySide6.QtGui import QKeyEvent, QMouseEvent
    from app.windows.os_switch import OsSwitch
    switch = OsSwitch(current="windows")
    switch.resize(420, 84)
    seen = []
    switch.changed.connect(seen.append)
    assert switch.os_id == "windows" and switch.position == 0.0
    switch.set_os("windows")                                                                        # nothing changes: nothing is said
    assert seen == []
    switch.set_os("linux")
    assert seen == ["linux"] and switch.os_id == "linux" and switch.position == 1.0
    left = QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(40, 40), QPointF(40, 40), Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
    switch.mousePressEvent(left)                                                                    # a click on the left half
    assert seen == ["linux", "windows"]
    switch.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Right, Qt.KeyboardModifier.NoModifier))
    switch.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Right, Qt.KeyboardModifier.NoModifier))   # already there: silent
    assert seen == ["linux", "windows", "linux"]
    switch.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Space, Qt.KeyboardModifier.NoModifier))
    assert switch.os_id == "windows"
    switch.set_os("beos")                                                                           # unknown: ignored
    quiet = []
    switch.changed.connect(quiet.append)
    switch.set_os("linux", emit=False)
    assert quiet == [] and switch.os_id == "linux"
    assert switch.grab().width() > 100 and not switch.grab().isNull()                               # it paints
    switch.deleteLater()


def test_the_switch_really_animates_when_animation_is_on(app):
    from app.windows import os_switch
    os_switch.ANIMATED = True
    switch = os_switch.OsSwitch(current="windows")
    switch.resize(420, 84)
    positions = []
    switch.set_os("linux")
    assert switch._slide.state() == switch._slide.State.Running
    end = time.time() + 3
    while time.time() < end and switch._slide.state() == switch._slide.State.Running:
        app.processEvents()
        positions.append(round(switch.position, 3))
        time.sleep(0.01)
    assert len(set(positions)) > 5 and abs(switch.position - 1.0) < 1e-3 and switch.os_id == "linux"       # it moved through many positions and arrived
    assert any(0.1 < p < 0.9 for p in positions)                                                    # (it was seen between the two sides, not only at the ends)
    switch.deleteLater()


# ============================================================================= the start window
def test_the_start_window_follows_the_switch_in_words_filter_settings_and_file(app, tmp_path):
    from app.settings import load_settings
    from app.windows.home_window import HomeWindow
    window = HomeWindow()
    try:
        assert window.settings["target_os"] == "windows" and window.title_label.text() == "Windows Memory Analysis" and not window.os_note.isVisibleTo(window)
        assert "Windows" in window.path.placeholderText() and window.engine.id == "windows"
        window.settings["optional_plugins"] = ["run_keys"]
        window.os_switch.set_os("linux")
        assert window.settings["target_os"] == "linux" and window.engine.id == "linux" and window.settings["optional_plugins"] == []
        assert window.title_label.text() == "Linux Memory Analysis" and "Linux" in window.path.placeholderText() and ".lime" in window.engine.terms.image_filter
        assert window.os_note.isVisibleTo(window) and "skeleton" in window.os_note.text()
        assert load_settings()["target_os"] == "linux"                                              # the choice is remembered
        window.os_switch.set_os("windows")
        assert window.settings["optional_plugins"] == ["run_keys"] and window.title_label.text() == "Windows Memory Analysis" and not window.os_note.isVisibleTo(window)
    finally:
        dispose(app, window)


def test_a_saved_investigation_of_the_other_operating_system_moves_the_switch(app):
    from app.windows.home_window import HomeWindow
    window = HomeWindow()
    try:
        assert window.os_switch.os_id == "windows"
        window.progress_window.begin("Loading", "x.json")
        window.on_finished(linux_result())
        assert window.os_switch.os_id == "linux" and window.settings["target_os"] == "linux" and window.dashboard_window.engine.id == "linux"
    finally:
        dispose(app, window.dashboard_window, window)


# ============================================================================= the dashboard and the other windows
def test_the_dashboard_of_a_linux_investigation_has_no_registry_and_placeholders_where_the_engine_is_missing(app):
    from app.windows.dashboard_window import DashboardWindow
    from app.windows.placeholder_view import PlaceholderView
    windows = DashboardWindow(load_fixture_result(), settings={})
    linux = DashboardWindow(linux_result(), settings={})
    try:
        assert "Registry" in windows.IDX and "Registry" not in linux.IDX
        assert set(windows.IDX) - set(linux.IDX) == {"Registry"} and list(linux.IDX)[:3] == ["Overview", "Search", "Process Tree"]
        for name in ("Injection", "Files", "Compare"):
            view = linux.select_view(linux.IDX[name])
            assert isinstance(view, PlaceholderView) and "Not available yet for Linux" in view.findChild(QtWidgets.QLabel, "Warning").text() and view.reason.text()
        for name in ("Overview", "Process Tree", "Indications", "Plugin Output", "Network", "Timeline", "Lifetimes", "Case Notes", "Computer Info", "Search"):
            view = linux.select_view(linux.IDX[name])
            assert not isinstance(view, PlaceholderView) and "could not be built" not in view.findChildren(QtWidgets.QLabel)[0].text(), name
        tree = linux.view("Process Tree")
        assert not tree.hash_button.isVisibleTo(tree) and not tree.export_hashes_button.isVisibleTo(tree)          # no process images to hash on Linux
        case = linux.view("Case Notes")
        assert not [b for b in case.findChildren(QtWidgets.QPushButton) if "known-good" in b.text()]
        assert any("known-good" in b.text() for b in windows.view("Case Notes").findChildren(QtWidgets.QPushButton))
        assert windows.view("Process Tree").hash_button.isVisibleTo(windows.view("Process Tree"))
    finally:
        dispose(app, windows, linux)


def test_the_process_window_uses_the_words_of_the_operating_system(app):
    from app.windows.dashboard_window import DashboardWindow
    from app.windows.process_window import ProcessWindow
    windows, linux = DashboardWindow(load_fixture_result(), settings={}), DashboardWindow(linux_result(), settings={})
    try:
        proc = next(p for p in windows.result.processes if p.dlls)
        for dashboard, tab, dump in ((windows, "Modules (", "Dump DLLs"), (linux, "Libraries (", "Dump libraries")):
            dialog = ProcessWindow(proc, dashboard, dump_path="x.raw", findings=[])
            tabs = dialog.findChild(QtWidgets.QTabWidget)
            assert any(tabs.tabText(i).startswith(tab) for i in range(tabs.count())) and any(b.text() == dump for b in dialog.buttons)
            assert dialog.engine.id == dashboard.engine.id
            dialog.deleteLater()
    finally:
        dispose(app, windows, linux)


def test_settings_show_the_plugin_groups_and_pages_of_the_chosen_operating_system(app, monkeypatch):
    from app.settings import save_settings, sanitize, switch_target_os
    from app.windows.settings_window import SettingsWindow
    class Parent(QtWidgets.QWidget):
        settings = sanitize({})
    parent = Parent()
    windows_dialog = SettingsWindow(parent)
    switch_target_os(parent.settings, "linux")
    linux_dialog = SettingsWindow(parent)
    try:
        assert windows_dialog.engine.id == "windows" and linux_dialog.engine.id == "linux" and "Linux" in linux_dialog.windowTitle()
        assert set(windows_dialog.bundle_boxes) != set(linux_dialog.bundle_boxes) and "kernel" in linux_dialog.bundle_boxes and "libraries" in linux_dialog.bundle_boxes
        assert hasattr(windows_dialog, "vol2_path") and not hasattr(linux_dialog, "vol2_path")                  # Volatility 2 is for Windows XP / 2003 only
        linux_dialog.preset_quick()
        assert {i for i, box in linux_dialog.bundle_boxes.items() if box.isChecked()} == {"processes", "network", "memory"}
        monkeypatch.setattr("app.windows.settings_window.save_settings", lambda s: None)
        linux_dialog.apply_and_close()
        assert parent.settings["target_os"] == "linux" and parent.settings["os_profiles"]["windows"]["optional_plugins"] is not None
        assert "vol2_path" in parent.settings                                                                   # untouched
    finally:
        dispose(app, windows_dialog, linux_dialog, parent)


def test_one_settings_object_never_changes_the_defaults_of_the_next():
    from app.settings import DEFAULT_SETTINGS, sanitize, switch_target_os
    first = sanitize({})
    switch_target_os(first, "linux")
    first["layout"]["home"] = {"w": 1}
    first["recent_dumps"].append("x")
    second = sanitize({})
    assert second["os_profiles"] == {} and second["layout"] == {} and second["recent_dumps"] == [] and DEFAULT_SETTINGS["os_profiles"] == {} and DEFAULT_SETTINGS["layout"] == {}
