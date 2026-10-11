"""Analyse memory images with MemoryGraph and write the testing report. Works on a computer with no internet: nothing here opens a network connection, and the report is
plain files (Markdown, a self-contained HTML page, JSON).

    python tools/realworld/run_report.py --check                                  is this computer ready? (Python, PySide6, Volatility, symbols, disk)
    python tools/realworld/run_report.py --dump D:/images/case1.raw               analyse one image and write the report
    python tools/realworld/run_report.py --dump a.raw --dump b.mem --os windows   several images
    python tools/realworld/run_report.py --dump x.lime --os linux                 a Linux image (the Linux engine is a skeleton: the report says so)
    python tools/realworld/run_report.py --from-manifest --dumps-dir testdumps    every image of manifest.json that is in testdumps/ (the others are listed as NOT TESTED)
    python tools/realworld/run_report.py --simulate                               no image: run the synthetic malware scenarios through the rules
    python tools/realworld/run_report.py --dump a.raw --expected a.expected.json  also check what is IN the image (see tools/realworld/README.md for the file)

Options: --out DIR (default realworld_report_<time>), --plugins standard|all (default all), --volatility PATH, --no-ui (skip the dashboard checks), --hash (SHA-256 of each image),
--title TEXT. The report is DIR/REPORT.md, DIR/REPORT.html and DIR/REPORT.json; each image also gets DIR/<image>/result.json.gz (open it in MemoryGraph with "Load existing").
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import report_builder  # noqa: E402
import run_realworld  # noqa: E402
from app.engines import OS_IDS, get_engine  # noqa: E402


def slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:60] or "image"


def sha256_of(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# ------------------------------------------------------------------------------------------------------------- is this computer ready?
def preflight(volatility: str, out_dir: str, dumps) -> list:
    """``[(OK / WARN / PROBLEM, text)]``: everything the run needs, checked without any network."""
    lines = [("OK", f"Python {sys.version.split()[0]} on {platform.platform()}")]
    try:
        import PySide6
        lines.append(("OK", f"PySide6 {PySide6.__version__} (the dashboard checks need it; --no-ui runs without)"))
    except ImportError:
        lines.append(("WARN", "PySide6 is not installed: use --no-ui (the analysis and the report do not need it)"))
    try:
        from app.analysis.volatility_runner import check_tool, describe_tool, find_volatility
        tool = check_tool(find_volatility(volatility))
        lines.append(("OK", f"Volatility 3 found: {describe_tool(tool)}; {len(tool.plugins or ())} plugins listed"))
    except Exception as exc:  # noqa: BLE001
        lines.append(("PROBLEM", f"Volatility 3 was not found or does not start: {str(exc).splitlines()[0] if str(exc) else type(exc).__name__}. Install it, or pass --volatility PATH."))
    from app.settings import load_settings
    settings = load_settings()
    for folder in settings.get("symbol_dirs") or []:
        lines.append(("OK" if os.path.isdir(folder) else "PROBLEM", f"symbol folder {folder}" + ("" if os.path.isdir(folder) else " does not exist")))
    if not settings.get("symbol_dirs"):
        lines.append(("WARN", "no extra symbol folder is set (Settings → Volatility → Extra symbol folders): Volatility can only use the symbols it already has. No internet is used to fetch them."))
    try:
        from app.engines.windows.analysis import vol2_runner
        tool2 = vol2_runner.find_vol2(settings.get("vol2_path", ""), settings.get("python2_path", ""))
        lines.append(("OK" if tool2 else "WARN", f"Volatility 2 (Windows XP / 2003 network): {tool2.description if tool2 else 'not set up; XP images get no network connections'}"))
    except Exception as exc:  # noqa: BLE001
        lines.append(("WARN", f"Volatility 2: {str(exc).splitlines()[0]}"))
    free = shutil.disk_usage(os.path.dirname(os.path.abspath(out_dir)) or ".").free / 2**30
    lines.append(("OK" if free > 2 else "PROBLEM", f"{free:.1f} GB free where the report goes"))
    for path in dumps:
        if not os.path.isfile(path):
            lines.append(("PROBLEM", f"image not found: {path}"))
        else:
            lines.append(("OK", f"image {path}: {os.path.getsize(path) / 2**20:,.0f} MiB"))
    lines.append(("OK", "MemoryGraph itself never opens a network connection; Volatility runs with --offline"))
    return lines


# ------------------------------------------------------------------------------------------------------------- one image
def expected_for(path: str, entry_id: str, explicit: str) -> dict:
    candidates = [explicit] if explicit else []
    candidates += [path + ".expected.json", os.path.splitext(path)[0] + ".expected.json", os.path.join(HERE, "expected", entry_id + ".json")]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return run_realworld.load_json(candidate)
    return {}


def analyse(entry: dict, path: str, settings: dict, out_dir: str, explicit_expected: str, with_ui: bool) -> dict:
    expected = expected_for(path, entry["id"], explicit_expected)
    print(f"=== {entry['name']}: {path}", flush=True)
    try:
        report = run_realworld.run_one(entry, path, settings, os.path.join(out_dir, entry["id"]), expected, with_ui=with_ui)
        run_realworld.write_report(os.path.join(out_dir, entry["id"]), report)
        report["expected_file"] = bool(expected)
        return {"entry": entry, "tested": True, "report": report}
    except Exception as exc:  # noqa: BLE001 - one image failing must not lose the others
        message = getattr(exc, "message", None) or str(exc) or type(exc).__name__
        print(f"   NOT TESTED: {message.splitlines()[0]}", flush=True)
        return {"entry": entry, "tested": False, "reason": f"the run stopped: {message.splitlines()[0]}"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dump", action="append", default=[], help="a memory image (repeat for several)")
    parser.add_argument("--os", choices=OS_IDS, default="windows", help="the engine to analyse with")
    parser.add_argument("--out", default="", help="folder for the report (default realworld_report_<time>)")
    parser.add_argument("--expected", default="", help="expected-results JSON for the image")
    parser.add_argument("--plugins", choices=("standard", "all"), default="all")
    parser.add_argument("--volatility", default="", help="path of Volatility 3 (default: found like the application does)")
    parser.add_argument("--no-ui", action="store_true", help="skip the dashboard checks")
    parser.add_argument("--hash", action="store_true", help="SHA-256 of each image (slow on big images)")
    parser.add_argument("--simulate", action="store_true", help="run the synthetic malware scenarios (no image needed)")
    parser.add_argument("--from-manifest", action="store_true", help="every image of manifest.json found in --dumps-dir; the others are listed as NOT TESTED")
    parser.add_argument("--dumps-dir", default=os.path.join(ROOT, "testdumps"))
    parser.add_argument("--check", action="store_true", help="only check that this computer is ready")
    parser.add_argument("--title", default="MemoryGraph testing report")
    args = parser.parse_args(argv)

    out_dir = args.out or os.path.join(ROOT, "realworld_report_" + time.strftime("%Y%m%d_%H%M%S"))
    if args.check or not (args.dump or args.simulate or args.from_manifest):
        problems = 0
        for status, text in preflight(args.volatility, out_dir, args.dump):
            print(f"[{status:7s}] {text}")
            problems += status == "PROBLEM"
        if not (args.dump or args.simulate or args.from_manifest):
            print("\nNothing to analyse: pass --dump FILE, --from-manifest or --simulate (see --help).")
        return 1 if problems else 0

    os.makedirs(out_dir, exist_ok=True)
    settings = run_realworld.make_settings(args.plugins, args.os)
    if args.volatility:
        settings["volatility_path"] = args.volatility
    env = {}
    if args.dump or args.from_manifest:
        try:
            env = run_realworld.environment(settings)
            env["engine"] = get_engine(args.os).label
        except Exception as exc:  # noqa: BLE001
            env = {"error": f"Volatility could not be started: {str(exc).splitlines()[0]}", "os": platform.platform(), "python": sys.version.split()[0]}
    else:
        env = {"os": platform.platform(), "python": sys.version.split()[0], "memorygraph": f"source tree {ROOT}", "mode": "synthetic scenarios only (no memory image)"}

    entries = []
    jobs = []
    if args.from_manifest:
        for entry in run_realworld.load_json(os.path.join(HERE, "manifest.json"))["dumps"]:
            entry.setdefault("os_id", "windows")
            path = run_realworld.locate(entry, args.dumps_dir)
            if path:
                jobs.append((entry, path))
            else:
                entries.append({"entry": entry, "tested": False, "reason": entry.get("status", "image not found")})
    for path in args.dump:
        entry = {"id": slug(os.path.splitext(os.path.basename(path))[0]), "name": os.path.basename(path), "source": "local file", "os_id": args.os, "os": get_engine(args.os).label}
        if args.hash and os.path.isfile(path):
            entry["source"] += f"; SHA-256 {sha256_of(path)}"
        jobs.append((entry, path))
    for entry, path in jobs:
        if not os.path.isfile(path):
            entries.append({"entry": entry, "tested": False, "reason": f"file not found: {path}"})
            continue
        entry_settings = dict(settings, target_os=entry.get("os_id", args.os))
        entries.append(analyse(entry, path, entry_settings, out_dir, args.expected if len(jobs) == 1 else "", not args.no_ui))

    scenario_results = None
    if args.simulate:
        import scenarios
        scenario_results = scenarios.run_all()
        for s in scenario_results:
            print(f"scenario {s['id']}: " + ", ".join(o["status"] for o in s["outcomes"]), flush=True)

    note = "Mode: " + ("synthetic scenarios only." if not entries and scenario_results else "real images" + (" and synthetic scenarios." if scenario_results else "."))
    markdown = report_builder.build_markdown(entries, env, scenario_results, args.title, note)
    with open(os.path.join(out_dir, "REPORT.md"), "w", encoding="utf-8") as handle:
        handle.write(markdown)
    with open(os.path.join(out_dir, "REPORT.html"), "w", encoding="utf-8") as handle:
        handle.write(report_builder.markdown_to_html(markdown, args.title))
    with open(os.path.join(out_dir, "REPORT.json"), "w", encoding="utf-8") as handle:
        json.dump({"environment": env, "entries": entries, "scenarios": scenario_results}, handle, indent=1, ensure_ascii=False, default=str)
    totals = report_builder.collect(entries, scenario_results)
    print(f"\nReport: {os.path.join(out_dir, 'REPORT.html')}  (also REPORT.md, REPORT.json)")
    print(f"images tested: {len(totals['tested'])} of {len(entries)}; integrity checks failed: {totals['check_status'].get('FAIL', 0)}; "
          f"verified facts missed: {sum(1 for f in totals['facts'] if f['status'] == 'FAIL' and f['verified'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
