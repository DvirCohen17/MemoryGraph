"""The real-world test harness itself (tools/realworld): its comparison logic must catch what it claims to catch.

These tests use the small fixture only to prove the CHECKS work (a damaged copy of a result must fail the check that should notice it). The real answer about
MemoryGraph comes from ``tools/realworld/run_realworld.py`` on real memory images, never from the fixture.
"""
import copy
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools" / "realworld"))

import checks  # noqa: E402
from test_pipeline_and_runner import load_fixture_result  # noqa: E402


def by_name(items, fragment):
    return next(c for c in items if fragment in c.name)


def test_an_undamaged_result_passes_every_integrity_check():
    result = load_fixture_result()
    results = checks.all_checks(result)
    assert not [c for c in results if c.status == checks.FAIL], [(c.name, c.items) for c in results if c.status == checks.FAIL]


def test_a_dropped_process_a_wrong_parent_a_lost_dll_and_a_lost_connection_are_each_noticed():
    result = load_fixture_result()
    damaged = copy.deepcopy(result)
    victim = next(p for p in damaged.processes if p.dlls)
    damaged.processes.remove(damaged.processes[5])
    assert by_name(checks.check_processes(damaged), "same processes").status == checks.FAIL
    damaged = copy.deepcopy(result)
    damaged.processes[3].ppid += 1
    assert by_name(checks.check_processes(damaged), "parent PIDs").status == checks.FAIL
    damaged = copy.deepcopy(result)
    next(p for p in damaged.processes if p.dlls).dlls.pop()
    assert checks.check_dlls(damaged)[0].status == checks.FAIL
    damaged = copy.deepcopy(result)
    damaged.connections = damaged.connections[1:]
    assert by_name(checks.check_network(damaged), "every connection of Volatility").status == checks.FAIL
    damaged = copy.deepcopy(result)
    damaged.memory_regions = damaged.memory_regions[1:]
    assert checks.check_memory(damaged)[0].status == checks.FAIL
    assert victim is not None


def test_a_plugin_that_did_not_complete_makes_the_check_inconclusive_not_failed():
    result = load_fixture_result()
    for p in result.plugins:
        if p.name in ("windows.netscan", "windows.netstat"):
            p.status, p.error = "Failed", "NotImplementedError: This version of Windows is not supported: 5.1 15.2600!"
    network = checks.check_network(result)
    assert network and all(c.status == checks.INCONCLUSIVE for c in network)


def test_failures_are_classified_only_from_volatilitys_own_words():
    from app.models import PluginResult
    cases = {
        "NotImplementedError: This version of Windows is not supported: 5.1": "unsupported operating system",
        "ModuleNotFoundError: No module named 'yara'": "Missing dependency",
        "vol.py: error: argument plugin: invalid choice: 'windows.x'": "version incompatibility",
        "Unsatisfied requirement plugins.PsList.kernel.symbol_table_name": "Symbols unavailable",
        "Traceback (most recent call last):\nValueError: boom": "plugin crash",
        "something nobody has seen before": "Unclassified",
    }
    for text, expected in cases.items():
        category, evidence = checks.classify_plugin(PluginResult("windows.x", "Failed", [], text))
        assert expected.lower() in category.lower(), (text, category)
        assert evidence == text.splitlines()[-1]
    assert checks.classify_plugin(PluginResult("p", "Skipped", [], "needs Vista"))[0].startswith("Skipped")
    assert "0 rows" in checks.classify_plugin(PluginResult("p", "Completed", []))[0]


def test_expected_facts_and_finding_review_never_guess():
    result = load_fixture_result()
    pid = result.processes[3].pid
    name = result.processes[3].name
    facts = [{"id": "a", "type": "process", "name": name, "pid": pid, "description": "x"}, {"id": "b", "type": "process", "name": "nothing.exe", "description": "y"},
             {"id": "c", "type": "finding", "rule_id": "NOPE-999", "description": "z"}, {"id": "d", "type": "plugin", "name": "windows.pslist", "status": "Completed", "description": "p"}]
    states = {f["id"]: f["status"] for f in checks.evaluate_facts(result, facts)}
    assert states == {"a": checks.PASS, "b": checks.FAIL, "c": checks.FAIL, "d": checks.PASS}
    result.plugins = [p for p in result.plugins if p.name != "windows.pslist"]
    assert checks.evaluate_facts(result, [{"id": "e", "type": "process", "name": name, "description": "q"}])[0]["status"] == checks.INCONCLUSIVE
    rows = checks.review_findings(load_fixture_result(), {"true_positive": [], "false_positive": []})
    assert rows and {r["verdict"] for r in rows} == {"Unreviewed"}
