"""Windows version profiles, plugins that do not exist for an OS (skipped, not failed), Settings bundles, and Volatility 2 as the network engine for XP / 2003."""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from test_pipeline_and_runner import FAKE_VOL, env, load_fixture_result
from test_case_and_ioc import run_with

FAKE_VOL2 = Path(__file__).with_name("fake_vol2.py")


@pytest.fixture(autouse=True)
def no_bundled_vol2(monkeypatch, tmp_path_factory):
    """The project's tools/volatility2 folder holds the real Volatility 2 exe: these tests must not depend on what is in it."""
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    monkeypatch.setattr(vol2_runner, "BUNDLED_DIR", str(tmp_path_factory.mktemp("no_volatility2")))


def test_the_volatility_2_dropped_into_tools_volatility2_is_found_without_any_setting(monkeypatch, tmp_path):
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    assert vol2_runner.bundled_location() == "" and vol2_runner.find_vol2("") is None
    folder = tmp_path / "volatility2"
    folder.mkdir()
    (folder / "README.txt").write_text("x")
    (folder / "volatility_2.6_win64_standalone.exe").write_bytes(b"MZ")
    monkeypatch.setattr(vol2_runner, "BUNDLED_DIR", str(folder))
    tool = vol2_runner.find_vol2("")
    assert tool is not None and tool.kind == "exe" and tool.argv == [str(folder / "volatility_2.6_win64_standalone.exe")]


def info_rows(major, minor, lab, is64=False, build=0):
    rows = [("NtMajorVersion", str(major)), ("NtMinorVersion", str(minor)), ("Is64Bit", str(is64)), ("NTBuildLab", lab),
            ("Major/Minor", f"15.{build}" if build else "15.2600"), ("DTB", "0x31c000"), ("KdDebuggerDataBlock", "0x80545ae0"),
            ("SystemTime", "2026-09-24 15:44:20+00:00"), ("Kernel Base", "0x804d7000")]
    return [{"Variable": k, "Value": v} for k, v in rows]


XP = info_rows(5, 1, "2600.xpsp.080413-2111")
WIN7 = info_rows(6, 1, "7601.17514.x86fre.win7sp1_rtm.101119-1850", build=7601)
WIN10 = info_rows(10, 0, "19041.1.amd64fre.vb_release.191206-1406", True, 19041)


def vol2_fixture(tmp_path, pid):
    data = {
        "connections": {"columns": ["Offset(V)", "LocalAddress", "RemoteAddress", "PID"],
                        "rows": [[0x81000000, "192.168.0.5:1034", "93.184.216.34:80", pid]]},
        "connscan": {"columns": ["Offset(P)", "LocalAddress", "RemoteAddress", "PID"],
                     "rows": [[0x1000, "192.168.0.5:1034", "93.184.216.34:80", pid], [0x2000, "192.168.0.5:1040", "203.0.113.9:443", pid]]},
        "sockets": {"columns": ["Offset(V)", "PID", "Port", "Proto", "Protocol", "Address", "Create Time"],
                    "rows": [[0x82000000, pid, 135, 6, "TCP", "0.0.0.0", "2026-09-24 15:33:00 UTC+0000"]]},
        "sockscan": {"columns": ["Offset(P)", "PID", "Port", "Proto", "Protocol", "Address", "Create Time"],
                     "rows": [[0x3000, pid, 135, 6, "TCP", "0.0.0.0", "2026-09-24 15:33:00 UTC+0000"]]},
        "netscan": {"columns": ["Offset(P)", "Proto", "LocalAddr", "ForeignAddr", "State", "PID", "Owner", "Created"],
                    "rows": [[0x4000, "TCPv4", "10.0.0.7:49200", "198.51.100.20:443", "ESTABLISHED", pid, "svchost.exe", "2026-09-24 15:40:00 UTC+0000"]]},
    }
    path = tmp_path / "vol2.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture()
def vol2_setup(tmp_path, monkeypatch):
    """Settings that make a ``vol.py``-style Volatility 2 available (the stand-in runs under the current Python in place of Python 2)."""
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    monkeypatch.setattr(vol2_runner, "find_python2", lambda configured="": [sys.executable])
    pid = load_fixture_result().processes[3].pid
    record = tmp_path / "vol2_calls.jsonl"
    environment = {"FAKE_VOL2_FIXTURE": str(vol2_fixture(tmp_path, pid)), "FAKE_VOL2_RECORD": str(record)}
    return {"vol2_path": str(FAKE_VOL2)}, environment, pid, record


def calls(record):
    return [json.loads(line) for line in Path(record).read_text(encoding="utf-8").splitlines()] if Path(record).exists() else []


# ============================================================================= Windows version profile
def test_os_profile_names_the_windows_version_service_pack_and_volatility_2_profile():
    from app.engines.windows.analysis.os_profile import OsProfile, debug_addresses, from_rows, parse_imageinfo
    xp = from_rows(XP)
    assert (xp.family, xp.service_pack, xp.legacy, xp.vol2_profile) == ("xp", 3, True, "WinXPSP3x86") and xp.name.startswith("Windows XP SP3 (x86, NT 5.1")
    assert from_rows(info_rows(5, 1, "2600.xpsp_sp2_gdr.050301-1519")).vol2_profile == "WinXPSP2x86"
    assert from_rows(info_rows(5, 2, "3790.srv03_sp2_rtm.070216-1710", True)).vol2_profile == "Win2003SP2x64"
    assert from_rows(info_rows(6, 0, "6002.18005.x86fre", build=6002)).vol2_profile == "VistaSP2x86"
    assert from_rows(WIN7).vol2_profile == "Win7SP1x86" and from_rows(info_rows(6, 1, "7600.16385.amd64fre", True, 7600)).vol2_profile == "Win7SP0x64"
    win10 = from_rows(WIN10)
    assert win10.family == "10" and not win10.legacy and win10.vol2_profile == "" and from_rows(info_rows(10, 0, "22621.1", True, 22621)).family == "11"
    assert not from_rows([]).known and from_rows([{"Variable": "NtMajorVersion", "Value": "x"}]) == OsProfile() and OsProfile().name == "unknown Windows"
    assert debug_addresses(XP) == {"dtb": "0x31c000", "kdbg": "0x80545ae0"} and debug_addresses([]) == {}
    assert parse_imageinfo("          Suggested Profile(s) : Win7SP1x64, Win7SP0x64 (Instantiated with Win7SP0x64)\n") == ["Win7SP1x64", "Win7SP0x64"]
    assert parse_imageinfo("Suggested Profile(s) : No suggestion (Instantiated with no profile)") == [] and parse_imageinfo("") == []


def test_plugins_state_which_windows_versions_they_exist_for():
    from app.engines.windows.analysis import plugin_registry as registry
    from app.engines.windows.analysis.os_profile import from_rows
    xp, win7, win10 = from_rows(XP), from_rows(WIN7), from_rows(WIN10)
    skipped_on_xp = {s.name for s in registry.REGISTRY if s.inapplicable(xp)}
    assert skipped_on_xp == {"windows.netscan", "windows.netstat", "windows.registry.scheduled_tasks", "windows.registry.amcache", "windows.malware.svcdiff"}
    assert "needs Windows Vista or newer; this image is Windows XP SP3" in registry.get("windows.netscan").inapplicable(xp)
    assert {s.name for s in registry.REGISTRY if s.inapplicable(win7)} == {"windows.malware.svcdiff"} and not [s for s in registry.REGISTRY if s.inapplicable(win10)]
    assert registry.get("windows.netscan").inapplicable(from_rows([])) == ""                  # unknown Windows: nothing is skipped


# ============================================================================= bundles
def test_every_plugin_belongs_to_exactly_one_bundle_and_defaults_match_the_old_behaviour():
    from app.engines.windows.analysis import plugin_registry as registry
    members = [name for bundle in registry.BUNDLES for name in bundle.members]
    assert sorted(members) == sorted(spec.name for spec in registry.REGISTRY) and len(members) == len(set(members))
    assert [b.id for b in registry.BUNDLES if registry.bundle_state(b, {}) == "on"] == ["processes", "network", "memory", "handles"]
    assert registry.bundle_state(registry.BUNDLES[0], {}) == "on" and len(registry.BUNDLES) <= 12


def test_bundle_choices_are_written_back_to_the_existing_settings_keys():
    from app.engines.windows.analysis import plugin_registry as registry
    settings = {}
    registry.apply_bundles(settings, {"network": "off", "kernel": "on", "persistence": "on", "hunting": "on", "processes": "off"})
    assert settings["run_extended_plugins"] is True
    assert "windows.netscan" not in settings["enabled_plugins"] and "windows.pslist" in settings["enabled_plugins"] and "windows.info" in settings["enabled_plugins"]
    assert {"run_keys", "autostart_keys", "service_keys", "windows.svcscan", "windows.driverscan", "windows.driverirp",
            "windows.malware.hollowprocesses"} <= set(settings["optional_plugins"])
    assert registry.bundle_state(registry.bundle_of("windows.netscan"), settings) == "off" and registry.bundle_state(registry.bundle_of("windows.ssdt"), settings) == "on"
    registry.apply_bundles(settings, {"network": "on", "kernel": "off", "persistence": "off", "hunting": "off"})
    assert settings["enabled_plugins"] == [] and settings["run_extended_plugins"] is False and settings["optional_plugins"] == []
    partial = {"optional_plugins": ["run_keys"]}
    assert registry.bundle_state(registry.bundle_of("windows.svcscan"), partial) == "partial"
    registry.apply_bundles(partial, {"persistence": "keep"})
    assert partial["optional_plugins"] == ["run_keys"]                                       # "keep" leaves a mixed bundle exactly as it was


# ============================================================================= Volatility 2: finding it and running it
def test_find_vol2_accepts_an_exe_or_vol_py_and_explains_what_is_missing(tmp_path, monkeypatch):
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    assert vol2_runner.find_vol2("") is None
    with pytest.raises(vol2_runner.Vol2Unusable, match="does not exist"):
        vol2_runner.find_vol2(str(tmp_path / "nope.exe"))
    monkeypatch.setattr(vol2_runner, "find_python2", lambda configured="": None)
    with pytest.raises(vol2_runner.Vol2Unusable, match="needs Python 2.7"):
        vol2_runner.find_vol2(str(FAKE_VOL2))
    monkeypatch.setattr(vol2_runner, "find_python2", lambda configured="": [sys.executable])
    py = vol2_runner.find_vol2(str(FAKE_VOL2))
    assert py.kind == "py" and py.argv == [sys.executable, str(FAKE_VOL2)]
    exe = tmp_path / "volatility_2.6_win64_standalone.exe"
    exe.write_bytes(b"MZ")
    assert vol2_runner.find_vol2(str(exe)).kind == "exe" and vol2_runner.find_vol2(str(tmp_path)).argv == [str(exe)]       # a folder works too
    assert vol2_runner.check_vol2(py).version == "2.6.1"
    with env(FAKE_VOL2_NOT="1"):
        with pytest.raises(vol2_runner.Vol2Unusable, match="That is Volatility 3"):
            vol2_runner.check_vol2(py)


@pytest.mark.skipif(os.name != "nt", reason="a .bat stands in for the standalone .exe")
def test_a_standalone_executable_is_run_directly(tmp_path):
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    launcher = tmp_path / "volatility_2.6_win64_standalone.exe.bat"
    launcher.write_text(f'@"{sys.executable}" "{FAKE_VOL2}" %*\r\n', encoding="utf-8")
    tool = vol2_runner.check_vol2(vol2_runner.find_vol2(str(launcher)))
    assert tool.kind == "exe" and tool.version == "2.6.1"
    pid = 7
    with env(FAKE_VOL2_FIXTURE=str(vol2_fixture(tmp_path, pid))):
        result = vol2_runner.run_vol2(tool, "x.raw", "vol2.connections", "WinXPSP3x86")
    assert result.status == "Completed" and result.rows[0]["RemoteAddress"] == "93.184.216.34:80"


def test_run_vol2_passes_the_profile_and_debugger_addresses_and_survives_wrong_ones(tmp_path, vol2_setup):
    import app.engines.windows.analysis.vol2_runner as vol2_runner
    settings, environment, pid, record = vol2_setup
    tool = vol2_runner.check_vol2(vol2_runner.find_vol2(settings["vol2_path"]))
    with env(**environment):
        ok = vol2_runner.run_vol2(tool, "x.raw", "vol2.connections", "WinXPSP3x86", kdbg="0x80545ae0", dtb="0x31c000")
    assert ok.status == "Completed" and ok.rows[0]["PID"] == pid
    last = calls(record)[-1]
    assert "--profile=WinXPSP3x86" in last and "--kdbg=0x80545ae0" in last and "--dtb=0x31c000" in last and "--output=json" in last and last[-1] == "connections"
    with env(FAKE_VOL2_NOKDBG="1", **environment):                                              # a wrong KDBG: tried again without the hints
        retried = vol2_runner.run_vol2(tool, "x.raw", "vol2.connections", "WinXPSP3x86", kdbg="0xdead", dtb="0x1")
    assert retried.status == "Completed" and "--kdbg=0xdead" not in retried.command
    with env(FAKE_VOL2_PROFILES="WinXPSP2x86", FAKE_VOL2_SUGGEST="WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)", **environment):
        fallback = vol2_runner.run_vol2(tool, "x.raw", "vol2.connections", "WinXPSP3x86")           # derived profile refused: imageinfo suggests another
    assert fallback.status == "Completed" and "--profile=WinXPSP2x86" in fallback.command
    with env(FAKE_VOL2_PROFILES="Win7SP1x64", FAKE_VOL2_SUGGEST="No suggestion", **environment):
        refused = vol2_runner.run_vol2(tool, "x.raw", "vol2.connections", "WinXPSP3x86")
    assert refused.status == "Failed" and "profile was refused" in refused.error and "WinXPSP3x86" in refused.error


# ============================================================================= the whole analysis of an XP image
def test_xp_image_skips_vol3_network_plugins_and_gets_one_merged_connection_list_from_vol2(tmp_path, vol2_setup):
    settings, environment, pid, record = vol2_setup
    result, events = run_with(tmp_path, {"windows.info": XP}, **settings, env=environment)
    by_name = {p.name: p for p in result.plugins}
    for name in ("windows.netscan", "windows.netstat", "windows.registry.scheduled_tasks"):
        assert name not in by_name or by_name[name].status == "Skipped"
    assert by_name["windows.netscan"].skipped and "needs Windows Vista" in by_name["windows.netscan"].error and "Volatility 2 instead" in by_name["windows.netscan"].error
    assert not any(p.failed for p in result.plugins)                                           # nothing is red: "not for this Windows" is not a failure
    assert by_name["vol2.connections"].status == "Completed" and by_name["vol2.sockets"].status == "Completed" and "vol2.connscan" not in by_name
    command = by_name["vol2.connections"].command
    assert "--profile=WinXPSP3x86" in command and "--kdbg=0x80545ae0" in command and "--dtb=0x31c000" in command
    shown = {(c.local, c.remote, c.protocol): c for c in result.connections}
    assert ("192.168.0.5:1034", "93.184.216.34:80", "TCPv4") in shown and any(c.state == "LISTENING" and c.local_port == "135" for c in result.connections)
    assert shown[("192.168.0.5:1034", "93.184.216.34:80", "TCPv4")].pid == pid and shown[("192.168.0.5:1034", "93.184.216.34:80", "TCPv4")].source_plugins == ["vol2.connections"]
    assert any("Not run because they do not exist for this Windows version" in w and "windows.netscan" in w for w in result.warnings)
    assert [s for n, s in events if n == "windows.netscan"][-1] == "skipped"


def test_deep_scan_adds_connscan_and_the_same_connection_is_shown_once_with_both_sources(tmp_path, vol2_setup):
    settings, environment, pid, record = vol2_setup
    result, _ = run_with(tmp_path, {"windows.info": XP}, **settings, vol2_deep_scan=True, env=environment)
    names = [p.name for p in result.plugins]
    assert {"vol2.connections", "vol2.sockets", "vol2.connscan", "vol2.sockscan"} <= set(names)
    both = [c for c in result.connections if c.local == "192.168.0.5:1034"]
    assert len(both) == 1 and both[0].source_plugins == ["vol2.connections", "vol2.connscan"]          # compared, not listed twice
    assert [c.remote for c in result.connections if c.local == "192.168.0.5:1040"] == ["203.0.113.9:443"]     # only the scan saw this one
    assert len([c for c in result.connections if c.local_port == "135"]) == 1


def test_xp_without_volatility_2_says_so_instead_of_failing(tmp_path):
    result, _ = run_with(tmp_path, {"windows.info": XP})
    netscan = next(p for p in result.plugins if p.name == "windows.netscan")
    assert netscan.skipped and "Volatility 2 is not set up" in netscan.error and not any(p.failed for p in result.plugins)
    assert not any(p.name.startswith("vol2.") for p in result.plugins) and result.connections == []


def test_a_broken_volatility_2_setting_is_reported_not_raised(tmp_path):
    result, _ = run_with(tmp_path, {"windows.info": XP}, vol2_path=str(tmp_path / "missing.exe"))
    netscan = next(p for p in result.plugins if p.name == "windows.netscan")
    assert netscan.skipped and "does not exist" in netscan.error and result.processes


def test_windows_7_uses_volatility_3_and_only_falls_back_to_volatility_2_when_it_cannot_read_the_network(tmp_path, vol2_setup):
    settings, environment, pid, record = vol2_setup
    ok, _ = run_with(tmp_path, {"windows.info": WIN7}, **settings, env=environment)
    assert not any(p.name.startswith("vol2.") for p in ok.plugins) and not any(p.skipped for p in ok.plugins)       # Volatility 3 handles Windows 7
    assert calls(record) == [] or not [c for c in calls(record) if c[-1] != "-h"]
    broken, _ = run_with(tmp_path, {"windows.info": WIN7}, **settings, env=dict(environment, FAKE_VOL_FAIL="windows.netscan,windows.netstat"))
    fallback = next(p for p in broken.plugins if p.name == "vol2.netscan")
    assert fallback.status == "Completed" and "--profile=Win7SP1x86" in fallback.command
    assert any(c.remote == "198.51.100.20:443" and c.state == "ESTABLISHED" and c.process == "svchost.exe" for c in broken.connections)


def test_windows_10_is_untouched_by_all_of_this(tmp_path, vol2_setup):
    settings, environment, *_ = vol2_setup
    result, _ = run_with(tmp_path, {"windows.info": WIN10}, **settings, env=environment)
    assert not any(p.skipped or p.name.startswith("vol2.") for p in result.plugins)


def test_a_failed_vol2_job_can_be_rerun_and_is_cached(tmp_path, vol2_setup):
    from app.engines.windows.analysis.real_provider import RealProvider
    from test_pipeline_and_runner import make_dump, settings as base_settings
    settings, environment, pid, record = vol2_setup
    first, _ = run_with(tmp_path, {"windows.info": XP}, **settings, env=dict(environment, FAKE_VOL2_PROFILES="Win7SP1x64", FAKE_VOL2_SUGGEST="No suggestion"))
    failed = [p.name for p in first.plugins if p.failed]
    assert failed == ["vol2.connections", "vol2.sockets"] and next(p for p in first.plugins if p.name == "vol2.connections").error.startswith("vol2.connections failed")
    data = json.loads((tmp_path / "fixture.json").read_text(encoding="utf-8"))
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(tmp_path / "fixture.json"), **environment):
        again = RealProvider(base_settings(tmp_path, **settings)).rerun(first)
    assert not any(p.failed for p in again.plugins) and any(c.remote == "93.184.216.34:80" for c in again.connections)


def test_adapter_reads_the_real_volatility_2_column_names_and_endpoint_formats():
    """Column and endpoint formats taken from the Volatility 2 source (connections / connscan / sockets / sockscan / netscan)."""
    from app.engines.windows.analysis.vol2_adapter import network_rows
    walk = network_rows("vol2.connections", [{"Offset(V)": 1, "LocalAddress": "192.168.0.5:1034", "RemoteAddress": "93.184.216.34:80", "PID": 1556}])
    assert walk[0]["LocalAddr"] == "192.168.0.5" and walk[0]["LocalPort"] == "1034" and walk[0]["ForeignAddr"] == "93.184.216.34" and walk[0]["PID"] == 1556
    spaced = network_rows("vol2.connscan", [{"Local Address": "10.0.0.1:5", "Remote Address": "10.0.0.2:6", "Pid": 9}])          # older / other spellings still work
    assert spaced[0]["ForeignPort"] == "6" and spaced[0]["PID"] == 9
    net = network_rows("vol2.netscan", [{"Proto": "TCPv4", "LocalAddr": "0.0.0.0:135", "ForeignAddr": "*:0", "State": "LISTENING", "PID": 4, "Owner": "svchost.exe", "Created": "x"},
                                        {"Proto": "UDPv4", "LocalAddr": "10.0.0.7:123", "ForeignAddr": "*:*", "State": "", "PID": 5, "Owner": "svchost.exe", "Created": ""},
                                        {"Proto": "TCPv6", "LocalAddr": ":::445", "ForeignAddr": ":::0", "State": "LISTENING", "PID": 4, "Owner": "System", "Created": ""},
                                        {"Proto": "TCPv4", "LocalAddr": "10.0.0.7:49200", "ForeignAddr": "198.51.100.20:443", "State": "ESTABLISHED", "PID": 6, "Owner": "x", "Created": ""}])
    assert [(r["ForeignAddr"], r["ForeignPort"]) for r in net] == [("", ""), ("", ""), ("", ""), ("198.51.100.20", "443")]      # "any" endpoints become empty
    assert net[2]["LocalAddr"] == "::" and net[2]["LocalPort"] == "445"
    assert network_rows("vol2.sockets", [{"PID": "x", "Port": 80, "Proto": 6, "Protocol": "TCP", "Address": "1.2.3.4", "Create Time": "t"}])[0]["PID"] == -1
    assert network_rows("vol2.pslist", [{"PID": 1}]) == [] and network_rows("vol2.connections", [{"LocalAddress": "", "RemoteAddress": ""}]) == []


# ============================================================================= malware-hunting rules and OS-specific rule profiles
def with_os(result, major, minor=0):
    for row in result.system_info:
        if str(row.get("Variable", "")).lower() == "ntmajorversion":
            row["Value"] = str(major)
        if str(row.get("Variable", "")).lower() == "ntminorversion":
            row["Value"] = str(minor)
    return result


def plugin_result(name, rows):
    from app.models import PluginResult
    return PluginResult(name, "Completed", rows)


def rule_findings(result, rule_id):
    from app.engines.windows.indicators.engine import IndicatorEngine
    return [f for f in IndicatorEngine().evaluate(result) if f.rule_id == rule_id]


def with_rows(name, rows):
    result = load_fixture_result()
    result.plugins.append(plugin_result(name, rows))
    return result


def test_hollowed_ghosted_and_etw_patched_processes_are_reported_per_process():
    # (each of these rests on ONE plugin, so it is Medium until a second plugin agrees: see tests/test_round9.py and app/analysis/indicators/corroboration.py)
    pid = next(p.pid for p in load_fixture_result().processes if p.pid > 4)
    hollow = rule_findings(with_rows("windows.malware.hollowprocesses", [{"PID": pid, "Process": "svchost.exe", "Notes": "Process memory is different from the file on disk"}]), "MAL-001")
    assert len(hollow) == 1 and hollow[0].severity == "Medium" and hollow[0].process_pid == pid and "different from the file" in hollow[0].evidence[0]
    ghost = rule_findings(with_rows("windows.malware.processghosting", [{"PID": pid, "Process": "x.exe", "Base": 0x400000, "FILE_OBJECT": 1, "DeletePending": 1, "DeleteOnClose": 0, "Path": "\\Temp\\a.exe"}]), "MAL-004")
    assert len(ghost) == 1 and "DeletePending=1" in ghost[0].evidence[0] and ghost[0].severity == "Medium"
    etw = rule_findings(with_rows("windows.etwpatch", [{"PID": pid, "Process": "x.exe", "DLL": "ntdll.dll", "Function": "EtwEventWrite", "Offset": 0x7FF00000, "Opcode": "ret"}]), "MAL-007")
    assert len(etw) == 1 and "EtwEventWrite" in etw[0].evidence[0]
    for rule, plugin_name in (("MAL-001", "windows.malware.hollowprocesses"), ("MAL-004", "windows.malware.processghosting"), ("MAL-007", "windows.etwpatch")):
        assert rule_findings(with_rows(plugin_name, []), rule) == []


def test_suspicious_threads_ignore_the_xp_artefacts_of_the_plugin():
    pid = next(p.pid for p in load_fixture_result().processes if p.name.lower() not in ("smss.exe", "csrss.exe", "system"))
    rows = [{"Process": "smss.exe", "PID": 384, "TID": 388, "Context": "Win32Start", "Address": 0, "VAD Path": "<Non-File Backed Region>", "Note": "x"},         # address 0
            {"Process": "csrss.exe", "PID": 612, "TID": 624, "Context": "Win32Start", "Address": 0x7F6F1234, "VAD Path": "<Non-File Backed Region>", "Note": "x"},
            {"Process": "evil.exe", "PID": pid, "TID": 9, "Context": "Win32Start", "Address": 0x2D0000, "VAD Path": "<Non-File Backed Region>", "Note": "thread in a private region"},
            {"Process": "evil.exe", "PID": pid, "TID": 10, "Context": "StartAddress", "Address": 0x2D1000, "VAD Path": "C:\\Windows\\x.dll", "Note": "y"}]
    modern = rule_findings(with_os(with_rows("windows.malware.suspicious_threads", rows), 10), "MAL-002")
    assert {f.process_pid for f in modern if f.process_pid} >= {pid} and any("csrss" in f.title for f in modern) and not any("smss" in f.title for f in modern)
    legacy = rule_findings(with_os(with_rows("windows.malware.suspicious_threads", rows), 5, 1), "MAL-002")
    assert len(legacy) == 1 and legacy[0].process_pid == pid and legacy[0].severity == "Medium" and "2 thread(s)" in legacy[0].title


def test_peb_masquerade_ignores_smss_and_reports_other_changes():
    pid = next(p.pid for p in load_fixture_result().processes if p.pid > 4)
    row = lambda p, name, path, spoof_path, spoof_cmd: {"PID": p, "EPROCESS_ImageFileName": name, "EPROCESS_SeAudit_ImageFileName": "\\Device\\HarddiskVolume1\\WINDOWS\\system32\\" + name,
                                                        "PEB_ImageFilePath": path, "PEB_ImageFilePath_Spoofed": spoof_path, "PEB_CommandLine_Spoofed": spoof_cmd}
    rows = [row(384, "smss.exe", "\\SystemRoot\\System32\\smss.exe", True, True), row(4, "System", "None", False, False),
            row(pid, "svchost.exe", "C:\\Users\\Public\\svchost.exe", True, False), row(pid + 1000, "calc.exe", "C:\\Windows\\calc.exe", False, True),
            row(pid + 2000, "ok.exe", "C:\\ok.exe", False, False)]
    found = {f.process_pid or f.title: f for f in rule_findings(with_rows("windows.malware.pebmasquerade", rows), "MAL-003")}
    assert len(found) == 2 and found[pid].severity == "Medium" and "image path" in found[pid].evidence[0]
    assert {f.severity for f in found.values()} == {"Medium"}
    # the same file written two ways (drive letter vs device path) is not a difference, whatever the plugin says (real XP image: wmiprvse.exe)
    same = [{"PID": pid, "EPROCESS_ImageFileName": "wmiprvse.exe", "EPROCESS_SeAudit_ImageFileName": "\\Device\\HarddiskVolume1\\WINDOWS\\system32\\wbem\\wmiprvse.exe",
             "PEB_ImageFilePath": "C:\\WINDOWS\\system32\\wbem\\wmiprvse.exe", "PEB_ImageFilePath_Spoofed": True, "PEB_CommandLine_Spoofed": False}]
    assert rule_findings(with_rows("windows.malware.pebmasquerade", same), "MAL-003") == []


def test_irp_handlers_outside_every_module_are_hooks_and_normal_forwarding_is_not():
    rows = [{"Driver Name": "CmBatt", "IRP": "IRP_MJ_CREATE", "Module": "CmBatt", "Address": 0xF8000000},
            {"Driver Name": "CmBatt", "IRP": "IRP_MJ_READ", "Module": "ntoskrnl", "Address": 0x80500000, "Symbol": "IopInvalidDeviceRequest"},
            {"Driver Name": "Evil", "IRP": "IRP_MJ_WRITE", "Module": None, "Address": 0xF4000000},
            {"Driver Name": "Evil", "IRP": "IRP_MJ_READ", "Module": "", "Address": 0xF4000010}]
    found = rule_findings(with_rows("windows.driverirp", rows), "MAL-006")
    assert len(found) == 1 and found[0].severity == "Medium" and "Evil: 2 IRP handler(s)" in found[0].title and "IRP_MJ_WRITE @ 0xf4000000" in found[0].evidence[0]


def test_services_hidden_from_the_list_are_reported_and_the_plugin_is_windows_10_only():
    from app.engines.windows.analysis import plugin_registry as registry
    from app.engines.windows.analysis.os_profile import from_rows
    found = rule_findings(with_rows("windows.malware.svcdiff", [{"Name": "Hider", "Display": "x", "Binary": "C:\\Users\\Public\\h.exe"}]), "MAL-005")
    assert len(found) == 1 and "Hider" in found[0].evidence[0] and found[0].title.startswith("1 service(s) hidden")
    assert registry.get("windows.malware.svcdiff").inapplicable(from_rows(WIN7)) and not registry.get("windows.malware.svcdiff").inapplicable(from_rows(WIN10))


def test_system_processes_that_do_not_exist_on_the_image_windows_are_reported():
    import copy
    result = load_fixture_result()
    donor = next(p for p in result.processes if p.pid > 4)
    for pid, name in ((9101, "wininit.exe"), (9102, "dwm.exe"), (9103, "conhost.exe")):
        fake = copy.deepcopy(donor)
        fake.pid, fake.name, fake.exited = pid, name, False
        result.processes.append(fake)
    on_xp = {f.process_name for f in rule_findings(with_os(result, 5, 1), "PT-005")}
    assert {"wininit.exe", "dwm.exe", "conhost.exe"} <= on_xp
    on_vista = {f.process_name for f in rule_findings(with_os(result, 6, 0), "PT-005")}
    assert "conhost.exe" in on_vista and not {"wininit.exe", "dwm.exe"} & on_vista         # Vista has wininit and dwm, but no conhost (Windows 7 added it)
    assert rule_findings(with_os(result, 10, 0), "PT-005") == []
    unknown = load_fixture_result()
    unknown.system_info = []
    assert rule_findings(unknown, "PT-005") == []


def test_every_rule_has_a_catalog_entry_and_an_attack_entry():
    from app.engines.windows.indicators.attack import ATTACK_BY_RULE
    from app.engines.windows.indicators.engine import DEFAULT_RULES, RULE_CATALOG
    for rule in DEFAULT_RULES:
        assert rule.rule_id in RULE_CATALOG and rule.rule_id in ATTACK_BY_RULE and rule.name and rule.description, rule.rule_id
    assert len(DEFAULT_RULES) == 43
