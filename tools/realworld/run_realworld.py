"""Run MemoryGraph on real memory images and write a report of how its result compares with what Volatility printed.

    python tools/realworld/run_realworld.py [--ids local-xp-sp3,local-win10] [--dumps-dir testdumps] [--out realworld_out] [--plugins standard|all]

Every image goes through the real program: the real Volatility 3 (from Settings / the environment, never a stand-in), the real ``RealProvider`` (the same code the
Run-analysis button uses), the real rule engine and then the real dashboard windows. Nothing from ``tests/`` is used (no fixtures, no fake_vol).
Images that are not on this computer are listed as NOT TESTED with the reason; nothing is downloaded (MemoryGraph has no internet access by design).
For each tested image ``<out>/<id>/`` gets ``result.json.gz`` (the investigation), ``report.json`` and ``report.md``; ``<out>/SUMMARY.md`` has the test matrix.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import checks  # noqa: E402
import ui_checks  # noqa: E402
from app.engines import OS_IDS, get_engine  # noqa: E402
from app.analysis.volatility_runner import check_tool, describe_tool, find_volatility  # noqa: E402
from app.models import save_analysis_result  # noqa: E402


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def locate(entry, dumps_dir):
    candidates = ([entry["local_path"]] if entry.get("local_path") else []) + [os.path.join(dumps_dir, f) for f in entry.get("files", [])]
    return next((c for c in candidates if os.path.isfile(c)), "")


def environment(settings) -> dict:
    tool = check_tool(find_volatility(settings.get("volatility_path", "")))
    import PySide6
    return {"os": platform.platform(), "python": sys.version.split()[0], "volatility": describe_tool(tool), "volatility_plugins_listed": len(tool.plugins or ()),
            "pyside6": PySide6.__version__, "memorygraph": f"source tree {ROOT} (no version number; schema {__import__('app.models', fromlist=['x']).SCHEMA_VERSION})",
            "dependencies": {name: _version(name) for name in ("capstone", "yara", "pefile")}}


def _version(module):
    try:
        import importlib.metadata as md
        return md.version({"yara": "yara-python"}.get(module, module))
    except Exception:  # noqa: BLE001
        return "not installed"


def make_settings(profile: str, os_id: str = "windows") -> dict:
    engine = get_engine(os_id)
    settings = {"use_cache": False, "parallel_plugins": 2, "idle_timeout_seconds": 1800, "max_plugin_seconds": 7200, "target_os": engine.id}
    if profile == "all":
        settings["run_extended_plugins"] = True
        settings["optional_plugins"] = [c[0] for c in engine.plugin_registry().optional_choices()]
    return settings


def run_one(entry, path, settings, out_dir, expected, with_ui: bool = True):
    engine = get_engine(settings.get("target_os"))
    started = time.time()
    log = []

    def on_plugin(name, state, detail):
        if state in ("done", "failed", "cached", "skipped"):
            line = f"[{round(time.time() - started):5d}s] {name}: {state} {detail[:90]}"
            log.append(line)
            print("   " + line, flush=True)

    result = engine.make_provider(settings).run(path, lambda *a: None, on_plugin)
    seconds = round(time.time() - started)
    os.makedirs(out_dir, exist_ok=True)
    save_analysis_result(result, os.path.join(out_dir, "result.json.gz"))
    report = {"entry": entry, "seconds": seconds, "dump": path, "size_bytes": os.path.getsize(path), "warnings": result.warnings,
              "counts": {"processes": len(result.processes), "connections": len(result.connections), "memory_regions": len(result.memory_regions),
                         "findings": sum(1 for i in result.indications if i.triage not in ("false_positive", "baseline"))},
              "plugins": checks.plugin_table(result), "checks": [c.as_dict() for c in checks.all_checks(result)],
              "facts": checks.evaluate_facts(result, expected.get("facts", [])), "findings": checks.review_findings(result, expected.get("findings_review", {})),
              "ui": ui_checks.run(result) if with_ui else [], "os_profile": _profile(result), "engine": engine.id, "tool_info": dict(getattr(result, "tool_info", {}) or {}),
              "timeline_events": len(result.timeline), "analysis_warnings": list(result.warnings)}
    sev = {}
    rules = {}
    for f in report["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        rules[f["rule_id"]] = rules.get(f["rule_id"], 0) + 1
    report["severity_distribution"], report["rule_distribution"] = sev, rules
    return report


def _profile(result):
    """What the engine says about the image's operating system (Windows adds the structured profile)."""
    engine = get_engine(getattr(result, "target_os", "windows"))
    try:
        info = {"engine": engine.id, "name": engine.describe_os(result)}
    except Exception as exc:  # noqa: BLE001 - a skeleton engine has no description yet
        return {"engine": engine.id, "name": f"({type(exc).__name__}: {exc})"[:200]}
    if engine.id == "windows":
        from app.engines.windows.analysis.os_profile import from_result
        profile = from_result(result)
        info.update({"family": profile.family, "nt": f"{profile.nt_major}.{profile.nt_minor}", "build": profile.build, "service_pack": profile.service_pack,
                     "is64": profile.is64, "volatility2_profile": profile.vol2_profile})
    return info


def write_report(out_dir, report):
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=1, ensure_ascii=False)
    e = report["entry"]
    lines = [f"# {e['name']}", "", f"* image: `{report['dump']}` ({report['size_bytes'] / 2**20:,.0f} MiB), analysed in {report['seconds']} s",
             f"* OS (windows.info): {report['os_profile']}", f"* counts: {report['counts']}", ""]
    lines += ["## Plugins", "", "| Plugin | Status | Rows | s | Category | Volatility's own words |", "|---|---|---|---|---|---|"]
    lines += [f"| {p['plugin']} | {p['status']} | {p['rows']} | {p['seconds']} | {p['category']} | {p['evidence'].replace('|', '/')} |" for p in report["plugins"]]
    lines += ["", "## MemoryGraph versus the raw Volatility output", "", "| Area | Check | Result | Detail |", "|---|---|---|---|"]
    for c in report["checks"] + report["ui"]:
        lines.append(f"| {c['area']} | {c['name']} | **{c['status']}** | {c['detail']} {'; '.join(c['items'][:5])} |".replace("\n", " "))
    if report["facts"]:
        lines += ["", "## Expected facts", "", "| Id | Fact | Verified | Result | Detail |", "|---|---|---|---|---|"]
        lines += [f"| {f['id']} | {f['description']} | {'yes' if f['verified'] else 'NO'} | **{f['status']}** | {f['detail']} |" for f in report["facts"]]
    lines += ["", f"## Findings ({len(report['findings'])})", "", f"Severity: {report['severity_distribution']}  ·  Rules: {report['rule_distribution']}", "",
              "| Rule | Sev | Process | Title | Evidence | Verdict |", "|---|---|---|---|---|---|"]
    lines += [f"| {f['rule_id']} | {f['severity']} | {f['process']} | {f['title'][:80]} | {f['evidence'][:120].replace('|', '/')} | {f['verdict']}{' - ' + f['why'] if f['why'] else ''} |" for f in report["findings"]]
    if report["warnings"]:
        lines += ["", "## Warnings of the analysis", ""] + [f"* {w[:300]}" for w in report["warnings"]]
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ids", default="", help="comma separated ids from manifest.json (default: all)")
    parser.add_argument("--dumps-dir", default=os.path.join(ROOT, "testdumps"))
    parser.add_argument("--out", default=os.path.join(ROOT, "realworld_out"))
    parser.add_argument("--plugins", choices=("standard", "all"), default="all", help="'all' also runs the extended and opt-in plugins")
    parser.add_argument("--volatility", default="", help="path of Volatility 3 (default: found like the application does)")
    parser.add_argument("--os", choices=OS_IDS, default="windows", help="the engine to analyse with (default: windows)")
    parser.add_argument("--no-ui", action="store_true", help="skip the checks of the dashboard windows (they need PySide6)")
    args = parser.parse_args(argv)
    manifest = load_json(os.path.join(HERE, "manifest.json"))["dumps"]
    wanted = {i for i in args.ids.split(",") if i}
    settings = make_settings(args.plugins, args.os)
    if args.volatility:
        settings["volatility_path"] = args.volatility
    env_info = environment(settings)
    print("environment:", json.dumps(env_info, indent=1), flush=True)
    os.makedirs(args.out, exist_ok=True)
    matrix = []
    for entry in manifest:
        if wanted and entry["id"] not in wanted:
            continue
        path = locate(entry, args.dumps_dir)
        if not path:
            matrix.append({"entry": entry, "tested": False, "reason": entry["status"]})
            print(f"NOT TESTED {entry['id']}: {entry['status']}", flush=True)
            continue
        expected_path = os.path.join(HERE, "expected", entry["id"] + ".json")
        expected = load_json(expected_path) if os.path.isfile(expected_path) else {}
        print(f"=== {entry['id']}: {path}", flush=True)
        try:
            report = run_one(entry, path, settings, os.path.join(args.out, entry["id"]), expected, with_ui=not args.no_ui)
            write_report(os.path.join(args.out, entry["id"]), report)
            matrix.append({"entry": entry, "tested": True, "report": report})
        except Exception as exc:  # noqa: BLE001 - one dump failing must not stop the others
            traceback.print_exc()
            matrix.append({"entry": entry, "tested": False, "reason": f"the run itself failed: {type(exc).__name__}: {exc}"})
    with open(os.path.join(args.out, "matrix.json"), "w", encoding="utf-8") as handle:
        json.dump({"environment": env_info, "matrix": matrix}, handle, indent=1, ensure_ascii=False, default=str)
    print("done:", sum(1 for m in matrix if m["tested"]), "tested,", sum(1 for m in matrix if not m["tested"]), "not tested", flush=True)


if __name__ == "__main__":
    main()
