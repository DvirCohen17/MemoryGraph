"""Volatility version / plugin availability handling and the failure messages of the network plugins."""
from test_pipeline_and_runner import FIXTURE, load_fixture_result, run_provider

ALL_PLUGINS = ("windows.info,windows.pslist,windows.psscan,windows.pstree,windows.cmdline,windows.getsids,"
               "windows.netscan,windows.netstat,windows.malfind,windows.dlllist,windows.handles")
WITHOUT_NETSCAN = ALL_PLUGINS.replace("windows.netscan,", "")

# Excerpt in the format of a real `vol -h` (Volatility 3 2.28.2).
REAL_HELP = """\
  plugin
    banners.Banners     Attempts to identify potential Linux banners in an
    windows.info.Info   Show OS & kernel details of the memory sample being
    windows.netscan.NetScan
                        Scans for network objects present in a particular
    windows.netstat.NetStat
                        Traverses network tracking structures present in a
    windows.pslist.PsList
                        Lists the processes present in a particular windows
    windows.registry.hivelist.HiveList
                        Lists the registry hives present in a particular
"""


def failed(result, name):
    return next(p for p in result.plugins if p.name == name)


def test_plugin_list_is_parsed_from_real_help_format():
    from app.analysis.volatility_runner import parse_plugin_list
    names = parse_plugin_list(REAL_HELP)
    assert {"windows.netscan", "windows.netstat", "windows.info", "windows.registry.hivelist"} <= names
    assert parse_plugin_list("usage: vol [-h]\n") is None            # unreadable -> unknown, not "nothing available"


def test_version_comparison_and_note():
    from app.analysis.volatility_runner import RECOMMENDED_VERSION, VolatilityTool, version_key, version_note
    assert version_key("2.11.0") < version_key("2.28.2") < version_key("2.100.0")
    assert "2.11.0" in version_note(VolatilityTool(["x"], version="2.11.0")) and RECOMMENDED_VERSION in version_note(VolatilityTool(["x"], version="2.11.0"))
    assert version_note(VolatilityTool(["x"], version=RECOMMENDED_VERSION)) == ""
    assert version_note(VolatilityTool(["x"], version="9.0.0")) == ""


def test_describe_os_from_info_rows():
    from app.analysis.volatility_runner import describe_os
    from app.models import PluginResult
    rows = [{"Variable": "NtMajorVersion", "Value": 6}, {"Variable": "NtMinorVersion", "Value": 1},
            {"Variable": "Major/Minor", "Value": "15.7601"}, {"Variable": "Is64Bit", "Value": True}]
    assert describe_os(PluginResult("windows.info", "Completed", rows)) == "Windows 7 / Server 2008 R2 (NT 6.1, build 7601), 64-bit"
    assert "did not complete" in describe_os(PluginResult("windows.info", "Failed", []))
    assert describe_os(None) == ""


def test_missing_plugin_is_reported_without_stopping_the_investigation(tmp_path):
    result, events = run_provider(tmp_path, {"FAKE_VOL_PLUGINS": WITHOUT_NETSCAN, "FAKE_VOL_VERSION": "2.11.0"})
    netscan = failed(result, "windows.netscan")
    assert netscan.status == "Failed"
    assert "not available in this Volatility" in netscan.error and "2.11.0" in netscan.error
    assert netscan.duration == 0.0                                    # no process was started for it
    assert all(p.status == "Completed" for p in result.plugins if p.name != "windows.netscan")
    assert result.processes and any("windows.netscan" in w for w in result.warnings)
    assert ("windows.netscan", "failed") in {(n, s) for n, s, _d in events}


def test_unsupported_windows_build_is_distinguished_from_a_version_problem(tmp_path):
    text = "Traceback (most recent call last):\\nNotImplementedError: This version of Windows is not supported: 5.1 15.2600!"
    result, _ = run_provider(tmp_path, {"FAKE_VOL_ERRTEXT": f"windows.netscan::{text}", "FAKE_VOL_VERSION": "2.28.2"})
    netscan = failed(result, "windows.netscan")
    assert netscan.status == "Failed"
    assert "does not support this image's Windows build" in netscan.error
    assert "Volatility version: 2.28.2" in netscan.error
    assert "Image operating system:" in netscan.error                 # taken from windows.info of the same run
    assert netscan.error.splitlines()[-1].startswith("NotImplementedError")   # Volatility's own words are kept, last
    assert failed(result, "windows.netstat").status == "Completed"


def test_netstat_that_logs_an_error_and_returns_nothing_is_not_reported_as_empty_success(tmp_path):
    result, _ = run_provider(tmp_path, {"FAKE_VOL_ERRLOG": "windows.netstat"})
    netstat = failed(result, "windows.netstat")
    assert netstat.status == "Failed"
    assert "tcpip" in netstat.error and "produced no rows" in netstat.error
    assert failed(result, "windows.netscan").status == "Completed"
    assert result.connections                                         # netscan still fills the network view


def test_internal_plugin_crash_and_missing_dependency(tmp_path):
    crash = "Traceback (most recent call last):\\nUnboundLocalError: local variable 'tcpip_symbol_table' referenced before assignment"
    result, _ = run_provider(tmp_path, {"FAKE_VOL_ERRTEXT": f"windows.netstat::{crash}"})
    netstat = failed(result, "windows.netstat")
    assert "internal Python error" in netstat.error and netstat.error.splitlines()[-1].startswith("UnboundLocalError")
    result, _ = run_provider(tmp_path, {"FAKE_VOL_ERRTEXT": "windows.netscan::ModuleNotFoundError: No module named 'pefile'"})
    assert "dependency of Volatility is missing: pefile" in failed(result, "windows.netscan").error


def test_old_version_is_named_in_the_failure_and_unknown_plugin_list_still_runs(tmp_path):
    # the default fake lists no plugins -> availability unknown -> plugins are simply attempted
    result, _ = run_provider(tmp_path, {"FAKE_VOL_ERRTEXT": "windows.netstat::RuntimeError: boom", "FAKE_VOL_VERSION": "2.11.0"})
    netstat = failed(result, "windows.netstat")
    assert netstat.status == "Failed" and "2.11.0" in netstat.error
    assert "tested with Volatility 3 2.28.2" in netstat.error
    assert all(p.status == "Completed" for p in result.plugins if p.name != "windows.netstat")


def test_compatibility_report_lists_missing_plugins(tmp_path):
    from app.analysis.volatility_runner import VolatilityTool, compatibility_report, parse_plugin_list
    tool = VolatilityTool(["x"], version="2.11.0", description="fake", plugins=parse_plugin_list(REAL_HELP))
    report = compatibility_report(tool, ["windows.netscan", "windows.malfind"])
    assert "Not available in this Volatility: windows.malfind" in report and "2.11.0" in report
    assert FIXTURE.exists() and load_fixture_result().processes
