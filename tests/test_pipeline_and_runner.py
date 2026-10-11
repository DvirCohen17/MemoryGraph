"""Regression tests for the collection pipeline using a fake `vol` command and real Volatility-shaped data."""
import json
import os
import sys
import threading
import time
from pathlib import Path


HERE = Path(__file__).parent
FIXTURE = HERE / "fixtures" / "mini_plugins.json"
FAKE_VOL = HERE / "fake_vol.py"
FAKE_ENV = ("FAKE_VOL_FAIL", "FAKE_VOL_HANG", "FAKE_VOL_SLOW", "FAKE_VOL_BADJSON", "FAKE_VOL_NOSYMBOLS",
            "FAKE_VOL_VERSION", "FAKE_VOL_PLUGINS", "FAKE_VOL_ERRTEXT", "FAKE_VOL_ERRLOG")


class env:
    """Context manager: set environment variables, restore afterwards."""

    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self.saved = {k: os.environ.get(k) for k in set(self.values) | set(FAKE_ENV)}
        for k in FAKE_ENV:
            os.environ.pop(k, None)
        for k, v in self.values.items():
            os.environ[k] = v

    def __exit__(self, *exc):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def make_dump(tmp_path):
    path = tmp_path / "fake.mem"
    if not path.exists():                      # keep one file so size/mtime (the cache key) stay stable
        path.write_bytes(os.urandom(1_500_000))
    return str(path)


def settings(tmp_path, **extra):
    base = {"volatility_path": str(FAKE_VOL), "parallel_plugins": 3, "idle_timeout_seconds": 30, "use_cache": False}
    base.update(extra)
    return base


def run_provider(tmp_path, extra_env=None, cancel=None, **settings_extra):
    from app.engines.windows.analysis.real_provider import RealProvider
    events = []
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE), **(extra_env or {})):
        result = RealProvider(settings(tmp_path, **settings_extra)).run(
            make_dump(tmp_path), None, lambda n, s, d: events.append((n, s, d)), cancel)
    return result, events


# ----------------------------------------------------------------------------- normalization
def load_fixture_result(established=False):
    """The real Windows 10 fixture. Two of its processes (3828, 6120) were created AFTER the acquisition started (the capture time is the start of the
    acquisition), so PT-003 correctly rates them Low. ``established=True`` moves the capture time to the day after, which gives the older tests the
    unlinked-while-alive Medium finding they use as a sample finding."""
    from app.analysis.pipeline import analyze_plugins
    from app.models import PluginResult
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if established:
        for row in data.get("windows.info", []):
            if str(row.get("Variable", "")).lower() == "systemtime":
                row["Value"] = "2018-06-22 00:00:00+00:00"
    return analyze_plugins("fixture.raw", [PluginResult(n, "Completed", rows) for n, rows in data.items()])


def test_command_line_path_user_and_unicode_are_parsed():
    result = load_fixture_result()
    explorer = [p for p in result.processes if p.name == "explorer.exe"][0]
    assert "Zoë" in explorer.command_line and "übung" in explorer.command_line     # "Args" column, utf-8
    assert explorer.path.lower().endswith("explorer.exe")                            # from pstree Path
    assert explorer.user == "passmark"                                              # first getsids row
    system = [p for p in result.processes if p.pid == 4][0]
    assert system.user == "NT AUTHORITY\\SYSTEM"


def test_path_is_not_just_the_process_name():
    result = load_fixture_result()
    with_path = [p for p in result.processes if "\\" in p.path]
    assert len(with_path) >= len(result.processes) - 3


def test_malfind_ranges_and_privacy_flags_are_filled():
    result = load_fixture_result()
    regions = result.memory_regions
    assert regions
    assert all(r.start.startswith("0x") and r.end.startswith("0x") and r.size for r in regions)
    assert all(r.private for r in regions)


def test_hidden_process_detected_and_capture_time_known():
    result = load_fixture_result()
    assert {p.pid for p in result.processes if p.hidden} == {3828, 6120}
    assert result.capture_time.startswith("2018-06-21")
    assert any(e.event_type == "Memory captured" for e in result.timeline)


def test_clean_system_produces_few_findings_and_no_high():
    result = load_fixture_result()
    assert len(result.indications) <= 12
    assert not [i for i in result.indications if i.severity == "High"]


def test_timeline_is_sorted_deduplicated_and_free_of_garbage_times():
    from app.util import parse_time
    result = load_fixture_result()
    stamps = [parse_time(e.timestamp) for e in result.timeline]
    assert stamps == sorted(stamps)
    capture = parse_time(result.capture_time)
    assert all(s.year >= 1995 and s.timestamp() <= capture.timestamp() + 86400 for s in stamps)
    starts = [(e.pid, e.timestamp) for e in result.timeline if e.event_type == "Process started"]
    assert len(starts) == len(set(starts))


def test_nested_pstree_rows_are_flattened():
    from app.engines.windows.analysis.normalizer import flatten_rows
    rows = [{"PID": 1, "__children": [{"PID": 2, "__children": [{"PID": 3, "__children": []}]}]}, {"PID": 4}]
    assert [r["PID"] for r in flatten_rows(rows)] == [1, 2, 3, 4]
    assert all("__children" not in r for r in flatten_rows(rows))


# ----------------------------------------------------------------------------- saved files
def test_legacy_investigation_file_still_loads(tmp_path):
    from app.models import load_analysis_result
    legacy = {"dump_path": "old.raw", "processes": [{"pid": 4, "ppid": 0, "name": "System", "path": "System", "image_base": "",
                                                     "user": "", "session": 0, "create_time": "", "command_line": "",
                                                     "handles": ["\\Device\\x"], "network": [{"pid": 4, "process": "System", "local": "1.2.3.4:5",
                                                                                             "remote": "6.7.8.9:10", "state": "ESTABLISHED"}],
                                                     "unknown_future_field": 1}],
              "indications": [{"title": "t", "severity": "Low", "future": True}], "plugins": [], "timeline": []}
    path = tmp_path / "old.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    result = load_analysis_result(str(path))
    assert result.processes[0].network[0].remote == "6.7.8.9:10"
    assert result.processes[0].handles[0]["name"] == "\\Device\\x"


def test_corrupt_and_wrong_files_give_friendly_errors(tmp_path):
    from app.models import load_analysis_result
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}', encoding="utf-8")
    for path, fragment in ((bad, "not valid JSON"), (other, "does not look like")):
        try:
            load_analysis_result(str(path))
        except ValueError as exc:
            assert fragment in str(exc)
        else:
            raise AssertionError("expected ValueError")
    try:
        load_analysis_result(str(tmp_path / "missing.json"))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_save_is_atomic_and_gzip_round_trips(tmp_path):
    from app.models import load_analysis_result, save_analysis_result
    result = load_fixture_result()
    for name in ("a.json", "a.json.gz"):
        path = tmp_path / name
        save_analysis_result(result, str(path))
        loaded = load_analysis_result(str(path))
        assert len(loaded.processes) == len(result.processes)
        assert len(loaded.indications) == len(result.indications)
        assert not (tmp_path / (name + ".tmp")).exists()


def test_reanalysis_rebuilds_from_stored_plugin_rows(tmp_path):
    from app.analysis.pipeline import reanalyze
    from app.models import load_analysis_result, save_analysis_result
    result = load_fixture_result()
    for p in result.processes:                 # simulate an old file where paths/commands were never parsed
        p.path, p.command_line = p.name, ""
    result.indications = []
    path = tmp_path / "old.json"
    save_analysis_result(result, str(path))
    rebuilt = reanalyze(load_analysis_result(str(path)))
    assert any(p.command_line for p in rebuilt.processes)
    assert any("\\" in p.path for p in rebuilt.processes)


# ----------------------------------------------------------------------------- volatility runner
def test_full_run_with_fake_volatility(tmp_path):
    result, events = run_provider(tmp_path)
    assert len(result.processes) >= 20
    assert all(p.status == "Completed" for p in result.plugins)
    states = {s for _n, s, _d in events}
    assert {"queued", "running", "done"} <= states


def test_one_failing_plugin_becomes_a_warning_not_an_abort(tmp_path):
    result, _events = run_provider(tmp_path, {"FAKE_VOL_FAIL": "windows.netscan"})
    failed = [p for p in result.plugins if p.status != "Completed"]
    assert [p.name for p in failed] == ["windows.netscan"]
    assert any("windows.netscan" in w for w in result.warnings)
    assert result.processes


def test_no_process_list_gives_clear_error(tmp_path):
    from app.errors import VolatilityUnusable
    try:
        run_provider(tmp_path, {"FAKE_VOL_NOSYMBOLS": "1"})
    except VolatilityUnusable as exc:
        assert "symbol" in (exc.message + exc.details).lower()
    else:
        raise AssertionError("expected VolatilityUnusable")


def test_hung_plugin_is_stopped_by_idle_timeout(tmp_path):
    started = time.time()
    result, _events = run_provider(tmp_path, {"FAKE_VOL_HANG": "windows.malfind"}, idle_timeout_seconds=30)
    # idle_timeout is clamped to >= 30 by settings; the runner itself honours small values, tested below
    assert time.time() - started < 120
    assert result is not None


def test_runner_idle_timeout_and_progress_keepalive(tmp_path):
    from app.analysis.volatility_runner import VolatilityTool, run_plugin
    tool = VolatilityTool([sys.executable, str(FAKE_VOL)])
    dump = make_dump(tmp_path)
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE), FAKE_VOL_HANG="windows.pslist"):
        res = run_plugin(tool, dump, "windows.pslist", idle_timeout=2)
    assert res.status == "Failed" and "no output or progress" in res.error
    progress = []
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE), FAKE_VOL_SLOW="windows.pslist"):
        res = run_plugin(tool, dump, "windows.pslist", idle_timeout=2, on_progress=lambda p, m: progress.append(p))
    # ~3s of runtime with a 2s idle limit: survives only because progress lines keep arriving (read1 fix)
    assert res.status == "Completed", res.error
    assert len(progress) >= 4


def test_runner_reports_bad_json_and_crash(tmp_path):
    from app.analysis.volatility_runner import VolatilityTool, run_plugin
    tool = VolatilityTool([sys.executable, str(FAKE_VOL)])
    dump = make_dump(tmp_path)
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE), FAKE_VOL_BADJSON="windows.pslist"):
        bad = run_plugin(tool, dump, "windows.pslist")
    assert bad.status == "Failed" and "not valid JSON" in bad.error
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE), FAKE_VOL_FAIL="windows.pslist"):
        crash = run_plugin(tool, dump, "windows.pslist")
    assert crash.status == "Failed" and "simulated plugin crash" in crash.error


def test_cancel_stops_the_analysis(tmp_path):
    from app.errors import AnalysisCancelled
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    try:
        run_provider(tmp_path, {"FAKE_VOL_SLOW": "windows.dlllist"}, cancel=cancel)
    except AnalysisCancelled:
        pass
    else:
        raise AssertionError("expected AnalysisCancelled")


def test_cache_serves_second_run_and_rerun_fixes_failed_plugin(tmp_path):
    from app.engines.windows.analysis.real_provider import RealProvider
    first, _ = run_provider(tmp_path, use_cache=True)
    second, events = run_provider(tmp_path, use_cache=True)
    assert {s for _n, s, _d in events if s in ("cached", "done")} == {"cached"}
    assert len(second.processes) == len(first.processes)
    broken, _ = run_provider(tmp_path, {"FAKE_VOL_FAIL": "windows.netscan"})
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home"), FAKE_VOL_FIXTURE=str(FIXTURE)):
        fixed = RealProvider(settings(tmp_path)).rerun(broken)
    assert all(p.status == "Completed" for p in fixed.plugins)
    assert not any("netscan" in w for w in fixed.warnings)


def test_dump_validation_messages(tmp_path):
    from app.engines.windows.analysis.real_provider import validate_dump
    from app.errors import DumpFileError
    tiny = tmp_path / "tiny.mem"
    tiny.write_bytes(b"x" * 100)
    for bad in ("", str(tmp_path), str(tmp_path / "missing.mem"), str(tiny)):
        try:
            validate_dump(bad)
        except DumpFileError:
            continue
        raise AssertionError(f"expected DumpFileError for {bad!r}")


def test_missing_volatility_is_explained(tmp_path):
    from app.engines.windows.analysis.real_provider import RealProvider
    from app.errors import VolatilityNotFound
    with env(MEMORYGRAPH_HOME=str(tmp_path / "home")):
        try:
            RealProvider({"volatility_path": str(tmp_path / "nope.exe")}).run(make_dump(tmp_path))
        except VolatilityNotFound as exc:
            assert "nope.exe" in exc.message
        else:
            raise AssertionError("expected VolatilityNotFound")


def test_settings_are_sanitised(tmp_path):
    from app.settings import sanitize
    values = sanitize({"parallel_plugins": "banana", "idle_timeout_seconds": 1, "recent_dumps": "oops"})
    assert values["parallel_plugins"] == 3
    assert values["idle_timeout_seconds"] >= 30
    assert values["recent_dumps"] == []


def test_works_with_python38_style_executor_without_cancel_futures(tmp_path):
    """ThreadPoolExecutor.shutdown(cancel_futures=...) only exists on Python 3.9+; the provider must not use it."""
    import concurrent.futures as cf
    import app.engines.windows.analysis.real_provider as rp

    class Py38Executor(cf.ThreadPoolExecutor):
        def shutdown(self, wait=True):          # no cancel_futures parameter, like Python 3.8
            return super().shutdown(wait=wait)

    original = rp.cf.ThreadPoolExecutor
    rp.cf.ThreadPoolExecutor = Py38Executor
    try:
        result, _events = run_provider(tmp_path)
    finally:
        rp.cf.ThreadPoolExecutor = original
    assert all(p.status == "Completed" for p in result.plugins)
