"""Builds the testing report from the results of a run: Markdown for reading and diffing, HTML to open on a computer with nothing installed (no network, no external files).

Everything in the report is computed from the data of the run. Nothing is estimated and nothing is invented: when a number cannot be measured (no expected-results file, no reviewed
findings, no network plugin on that Windows) the report says "not measured" and why. The scores at the end are indicators computed by the formulas printed next to them; they are not
an expert's judgement, and they are only as good as the expected-results files behind them.
"""
from __future__ import annotations

import html
import re
import time
from collections import Counter
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = {"High": 3, "Medium": 2, "Low": 1}
UNEXPLAINED = ("Unclassified", "plugin crash")


def _pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def _rate_score(passed: int, failed: int) -> Optional[float]:
    return round(10 * passed / (passed + failed), 1) if passed + failed else None


def _score_text(score: Optional[float]) -> str:
    return "not measured" if score is None else f"{score:.1f}"


def _cell(value) -> str:
    return str(value).replace("|", "/").replace("\n", " ").strip()


def collect(entries: List[dict], scenarios: Optional[List[dict]]) -> dict:
    """Totals over every tested dump (and the synthetic scenarios)."""
    plugins, checks, ui, facts, findings = [], [], [], [], []
    tested = [e for e in entries if e.get("tested")]
    for e in tested:
        r = e["report"]
        plugins += [dict(p, dump=e["entry"]["name"]) for p in r["plugins"]]
        checks += [dict(c, dump=e["entry"]["name"]) for c in r["checks"]]
        ui += [dict(c, dump=e["entry"]["name"]) for c in r.get("ui", [])]
        facts += [dict(f, dump=e["entry"]["name"]) for f in r["facts"]]
        findings += [dict(f, dump=e["entry"]["name"]) for f in r["findings"]]
    scen = [o for s in (scenarios or []) for o in s["outcomes"]]
    return {"tested": tested, "plugins": plugins, "checks": checks, "ui": ui, "facts": facts, "findings": findings, "scenario_outcomes": scen,
            "plugin_status": Counter(p["status"] for p in plugins), "plugin_category": Counter(p["category"] for p in plugins if p["status"] in ("Failed",)),
            "check_status": Counter(c["status"] for c in checks), "ui_status": Counter(c["status"] for c in ui), "fact_status": Counter(f["status"] for f in facts),
            "verdicts": Counter(f["verdict"] for f in findings), "severity": Counter(f["severity"] for f in findings)}


def scores(t: dict) -> List[Tuple[str, Optional[float], str]]:
    """``(category, score or None, how it was computed and from how much data)`` for the categories. None = not measured."""
    plugin_runs = t["plugins"]
    ran = [p for p in plugin_runs if p["status"] != "Skipped"]
    failed = [p for p in plugin_runs if p["status"] == "Failed"]
    unexplained = [p for p in failed if any(u in p["category"] for u in UNEXPLAINED)]
    reliability = round(10 * (len(ran) - len(unexplained) - 0.5 * (len(failed) - len(unexplained))) / len(ran), 1) if ran else None
    by_area = lambda *areas: [c for c in t["checks"] if c["area"] in areas]
    counts = lambda cs: (sum(c["status"] == "PASS" for c in cs), sum(c["status"] == "FAIL" for c in cs))
    sample = lambda cs: "n = %d (%d passed, %d failed, %d inconclusive)" % (len(cs), *counts(cs), sum(c["status"] == "INCONCLUSIVE" for c in cs))
    rate = lambda cs: _rate_score(*counts(cs))
    verified = [f for f in t["facts"] if f["verified"]]
    verdict = t["verdicts"]
    reviewed = verdict.get("True Positive", 0) + verdict.get("False Positive", 0) + verdict.get("Inconclusive", 0)
    total_findings = sum(verdict.values())
    covered = total_findings > 0 and reviewed >= 0.5 * total_findings
    fp_control = round(10 * (1 - verdict.get("False Positive", 0) / reviewed), 1) if covered else None
    unclassified = [p for p in failed if "Unclassified" in p["category"]]
    compat = round(10 * (1 - len(unclassified) / len(ran)), 1) if ran else None
    scen = t["scenario_outcomes"]
    rows = [
        ("Plugin reliability", reliability, f"10 × (runs that were not skipped − unexplained failures − ½ × explained failures) ÷ runs that were not skipped; unexplained = unclassified or a crash; n = {len(ran)} runs, {len(failed)} failed ({len(unexplained)} unexplained)"),
        ("Process analysis", rate(by_area("Processes", "Handles")), "10 × passed ÷ (passed + failed) of the checks on processes, parents, command lines, hidden processes and handle counts; " + sample(by_area("Processes", "Handles"))),
        ("Memory analysis", rate(by_area("Memory", "Modules")), "10 × passed ÷ (passed + failed) of the checks on malfind regions and module lists; " + sample(by_area("Memory", "Modules"))),
        ("Network analysis", rate(by_area("Network")), "10 × passed ÷ (passed + failed) of the network checks (not measured when no network plugin completed); " + sample(by_area("Network"))),
        ("Detection rules", _rate_score(sum(f["status"] == "PASS" for f in verified), sum(f["status"] == "FAIL" for f in verified)),
         f"10 × passed ÷ (passed + failed) of the VERIFIED expected facts; unverified expectations are listed but not scored; n = {len(verified)} verified of {len(t['facts'])} expected facts"),
        ("False-positive control", fp_control, f"10 × (1 − false positives ÷ reviewed findings), only when at least half of the findings have a verdict; {reviewed} of {total_findings} findings have one"
                                               + ("" if covered else " (too few: not measured)")),
        ("Evidence integrity", rate(t["checks"]), "10 × passed ÷ (passed + failed) of all integrity checks (what Volatility printed against what MemoryGraph holds); " + sample(t["checks"])),
        ("UI / data presentation", rate(t["ui"]), "10 × passed ÷ (passed + failed) of the dashboard checks; " + sample(t["ui"])),
        ("Volatility compatibility", compat, f"10 × (1 − unclassified failures ÷ runs that were not skipped); a failure Volatility itself explains (unsupported Windows, missing symbols, missing dependency) is classified; n = {len(ran)} runs, {len(unclassified)} unclassified failures"),
    ]
    if scen:
        rows.append(("Detection on synthetic scenarios", _rate_score(sum(o["status"] == "PASS" for o in scen), sum(o["status"] == "FAIL" for o in scen)),
                     f"10 × passed ÷ (passed + failed) of the scenario expectations (rules on constructed malware-shaped rows; not real images); n = {len(scen)}"))
    measured = [s for _n, s, _h in rows if s is not None]
    rows.append(("Overall (mean of the measured ones)", round(sum(measured) / len(measured), 1) if measured else None, f"the mean of the {len(measured)} scores above that could be measured"))
    return rows


def recommendations(t: dict, scenarios: Optional[List[dict]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {"Critical": [], "High": [], "Medium": [], "Low": []}
    for c in t["checks"]:
        if c["status"] == "FAIL":
            out["Critical"].append(f"{c['dump']}: integrity check failed — {c['area']}: {c['name']} ({c['detail']}). The investigator would see something other than what Volatility printed. {('; '.join(c['items'][:3]))}")
    for f in t["facts"]:
        if f["status"] == "FAIL" and f["verified"]:
            out["Critical"].append(f"{f['dump']}: a verified expected fact is missing — {f['description']} ({f['detail']}).")
    for s in scenarios or []:
        for o in s["outcomes"]:
            if o["status"] == "FAIL":
                out["High"].append(f"Scenario {s['id']} ({s['title']}): {o['description']} was not detected ({o['detail']}).")
    for p in t["plugins"]:
        if p["status"] == "Failed" and any(u in p["category"] for u in UNEXPLAINED):
            out["High"].append(f"{p['dump']}: {p['plugin']} failed and the cause is not explained ({p['category']}): {p['evidence'][:160]}. Reproduce it with another Volatility version before blaming MemoryGraph.")
    for f in t["facts"]:
        if f["status"] == "FAIL" and not f["verified"]:
            out["Medium"].append(f"{f['dump']}: an unverified expectation was not met — {f['description']} ({f['detail']}). Decide whether the expectation or the rules are wrong.")
    unreviewed_high = [f for f in t["findings"] if f["verdict"] == "Unreviewed" and f["severity"] == "High"]
    if unreviewed_high:
        out["Medium"].append(f"{len(unreviewed_high)} High finding(s) have no verdict in the expected-results file ({', '.join(sorted({f['rule_id'] for f in unreviewed_high}))}): review each against the raw plugin rows and record it as true positive, false positive or inconclusive.")
    for f in t["findings"]:
        if f["verdict"] == "False Positive":
            out["High" if f["severity"] in ("High", "Medium") else "Medium"].append(f"{f['dump']}: false positive {f['rule_id']} {f['severity']} on {f['process']} — {f['why']}.")
    zero = [p for p in t["plugins"] if p["status"] == "Completed" and p["rows"] == 0]
    if zero:
        out["Low"].append(f"{len(zero)} plugin run(s) completed with 0 rows ({', '.join(sorted({p['plugin'] for p in zero})[:6])}): 'nothing found' and 'could not read' look the same.")
    for c in t["ui"]:
        if c["status"] == "FAIL":
            out["Low"].append(f"{c['dump']}: dashboard check failed — {c['name']} ({c['detail']}).")
    for e in t["tested"]:
        for w in e["report"].get("analysis_warnings", [])[:3]:
            out["Low"].append(f"{e['entry']['name']}: analysis warning — {w[:200]}")
    return out


def build_markdown(entries: List[dict], env: dict, scenarios: Optional[List[dict]] = None, title: str = "MemoryGraph testing report", note: str = "") -> str:
    t = collect(entries, scenarios)
    tested, skipped = t["tested"], [e for e in entries if not e.get("tested")]
    L: List[str] = [f"# {title}", "", f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')} by `tools/realworld/run_report.py`. {note}".strip(), ""]
    L += ["## 1. Executive summary", ""]
    ps = t["plugin_status"]
    unexplained = sum(1 for p in t["plugins"] if p["status"] == "Failed" and any(u in p["category"] for u in UNEXPLAINED))
    L += [f"* **Dumps tested:** {len(tested)}" + (f"; not tested: {len(skipped)} (see section 3)" if skipped else ""),
          f"* **Plugin runs:** {sum(ps.values())} — completed {ps.get('Completed', 0)}, skipped by design {ps.get('Skipped', 0)}, failed {ps.get('Failed', 0)} (unexplained: {unexplained})",
          f"* **MemoryGraph versus the raw Volatility output:** {t['check_status'].get('PASS', 0)} checks passed, {t['check_status'].get('FAIL', 0)} failed, {t['check_status'].get('INCONCLUSIVE', 0)} inconclusive",
          f"* **Dashboard:** {t['ui_status'].get('PASS', 0)} checks passed, {t['ui_status'].get('FAIL', 0)} failed",
          f"* **Expected facts:** {t['fact_status'].get('PASS', 0)} met, {t['fact_status'].get('FAIL', 0)} not met, {t['fact_status'].get('INCONCLUSIVE', 0)} inconclusive "
          f"({sum(1 for f in t['facts'] if f['verified'])} of {len(t['facts'])} were verified against raw output)",
          f"* **Findings:** {sum(t['severity'].values())} visible (High {t['severity'].get('High', 0)}, Medium {t['severity'].get('Medium', 0)}, Low {t['severity'].get('Low', 0)}); "
          f"verdicts: true positive {t['verdicts'].get('True Positive', 0)}, false positive {t['verdicts'].get('False Positive', 0)}, inconclusive {t['verdicts'].get('Inconclusive', 0)}, "
          f"unreviewed {t['verdicts'].get('Unreviewed', 0)}"]
    if scenarios:
        sc = Counter(o["status"] for o in t["scenario_outcomes"])
        L.append(f"* **Synthetic malware scenarios:** {len(scenarios)} scenarios, {sc.get('PASS', 0)} of {sum(sc.values())} expectations detected (constructed rows, not real images)")
    fails = t["check_status"].get("FAIL", 0) + sum(1 for f in t["facts"] if f["status"] == "FAIL" and f["verified"])
    if tested:
        assessment = ("no integrity check failed and no verified expectation was missed on the images tested" if not fails else
                      f"{fails} problem(s) that could make an investigator trust wrong evidence or miss evidence (section 10)")
    elif scenarios:
        failed_scenarios = sum(1 for o in t["scenario_outcomes"] if o["status"] == "FAIL")
        assessment = ("no real image was analysed; on the synthetic scenarios " + ("every expectation was detected" if not failed_scenarios else f"{failed_scenarios} expectation(s) were not detected (section 10)"))
    else:
        assessment = "no real image was analysed in this run"
    L += ["", "**Assessment from this run:** " + assessment + ". Recall on real malware is not measured unless the images come with an expected-results file that names what is in them.", ""]

    L += ["## 2. Test environment", "", "| | |", "|---|---|"] + [f"| {k} | {_cell(v)} |" for k, v in env.items()] + [""]

    L += ["## 3. Test dataset", ""]
    if not entries:
        L += ["No memory image was given: only the synthetic scenarios ran.", ""]
    else:
        L += ["| Dump | Engine | Operating system | Size | Analysed in | Source | Result |", "|---|---|---|---|---|---|---|"]
    for e in entries:
        en = e["entry"]
        if e.get("tested"):
            r = e["report"]
            L.append(f"| {_cell(en['name'])} | {r.get('engine', '')} | {_cell(r['os_profile'].get('name', ''))} | {r['size_bytes'] / 2**20:,.0f} MiB | {r['seconds']} s | {_cell(en.get('source', ''))} | tested |")
        else:
            L.append(f"| {_cell(en['name'])} | {en.get('os_id', '')} | {_cell(en.get('os', ''))} | – | – | {_cell(en.get('source', ''))} | **NOT TESTED**: {_cell(e.get('reason', ''))} |")
    L.append("")

    L += ["## 4. Plugin compatibility", ""]
    if not t["plugins"]:
        L += ["No real image was analysed in this run, so no plugin ran.", ""]
    else:
        L += ["| Dump | Plugin | Status | Rows | Seconds | Category | Volatility's own words |", "|---|---|---|---|---|---|---|"]
    for p in t["plugins"]:
        L.append(f"| {_cell(p['dump'])} | {p['plugin']} | {p['status']} | {p['rows']} | {p['seconds']} | {_cell(p['category'])} | {_cell(p['evidence'][:140])} |")
    L += ["", "Categories use only Volatility's own words: *unsupported operating system*, *missing dependency*, *version incompatibility*, *symbols unavailable* and *plugin crash* are limits of Volatility or of the "
          "environment, not of MemoryGraph; *unclassified* means nobody has found the cause yet. A failure is never called a MemoryGraph bug without evidence.", ""]

    L += ["## 5. MemoryGraph against the raw Volatility output", ""]
    if not (t["checks"] or t["ui"]):
        L += ["Nothing to compare: no real image was analysed in this run.", ""]
    else:
        L += ["| Dump | Area | Check | Result | Detail |", "|---|---|---|---|---|"]
    for c in t["checks"] + t["ui"]:
        L.append(f"| {_cell(c['dump'])} | {c['area']} | {_cell(c['name'])} | **{c['status']}** | {_cell(c['detail'])} {_cell('; '.join(c['items'][:4]))} |")
    L.append("")

    L += ["## 6. Detection results (expected facts)", ""]
    if not t["facts"] and not tested:
        L.append("No real image was analysed, so there is nothing to check against expected facts.")
    elif t["facts"]:
        L += ["| Dump | Id | Expected finding | Verified | Result | Detail |", "|---|---|---|---|---|---|"]
        L += [f"| {_cell(f['dump'])} | {f['id']} | {_cell(f['description'])} | {'yes' if f['verified'] else 'no'} | **{f['status']}** | {_cell(f['detail'])} |" for f in t["facts"]]
    else:
        L.append("No expected-results file was given, so nothing could be checked against what is *in* the images. Write one (copy `tools/realworld/expected/local-xp-sp3.json`) and run again with `--expected`.")
    L.append("")
    if scenarios:
        L += ["### Synthetic malware scenarios", "", "Constructed Volatility-shaped rows run through the real Windows engine. A PASS shows the *rules* recognise the pattern; it does not show that Volatility would print such rows for a real sample.", "",
              "| Scenario | Expectation | Rule | Result | Detail |", "|---|---|---|---|---|"]
        for s in scenarios:
            for o in s["outcomes"]:
                L.append(f"| {s['id']} {_cell(s['title'])} | {_cell(o['description'])} | {o['rule_id']} | **{o['status']}** | {_cell(o['detail'][:140])} |")
        L.append("")

    L += ["## 7. Findings, with verdicts", ""]
    if not t["findings"]:
        L += ["No finding to list." + ("" if tested else " (No real image was analysed in this run.)"), ""]
    else:
        L += ["| Dump | Rule | Severity | Process | Title | Evidence | Verdict |", "|---|---|---|---|---|---|---|"]
    for f in sorted(t["findings"], key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), f["rule_id"])):
        L.append(f"| {_cell(f['dump'])} | {f['rule_id']} | {f['severity']} | {_cell(f['process'])} | {_cell(f['title'][:80])} | {_cell(f['evidence'][:110])} | {f['verdict']}{(' — ' + _cell(f['why'])) if f['why'] else ''} |")
    L += ["", "Verdicts come from the expected-results file only (True Positive / False Positive / Inconclusive); everything else is **Unreviewed**: it is shown, never guessed.", ""]

    L += ["## 8. Missed detections and false positives", ""]
    missed = [f for f in t["facts"] if f["status"] == "FAIL"]
    false_pos = [f for f in t["findings"] if f["verdict"] == "False Positive"]
    L += ([f"* missed: **{f['dump']}** — {f['description']} ({f['detail']}){'' if f['verified'] else ' [unverified expectation]'}" for f in missed] or ["* No expected fact was missed."])
    L += ([f"* false positive: **{f['dump']}** — {f['rule_id']} {f['severity']} on {f['process']}: {f['why']}" for f in false_pos] or ["* No finding was marked as a false positive."]) + [""]

    L += ["## 9. Compatibility problems, by cause", ""]
    if t["plugin_category"]:
        L += ["| Cause | Runs |", "|---|---|"] + [f"| {_cell(k)} | {v} |" for k, v in t["plugin_category"].most_common()]
    else:
        L.append("No plugin failed.")
    L += [""]

    L += ["## 10. Recommendations", ""]
    recs = recommendations(t, scenarios)
    for level in ("Critical", "High", "Medium", "Low"):
        L += [f"### {level}", ""] + ([f"* {r}" for r in recs[level]] or ["* nothing in this run"]) + [""]

    L += ["## 11. Scores (computed indicators, 0–10)", "", "| Category | Score | How it is computed |", "|---|---|---|"]
    L += [f"| {name} | {_score_text(score)} | {how} |" for name, score, how in scores(t)]
    L += ["", "These are indicators computed by the formulas shown, not an expert's judgement: arithmetic on the data of this run. They say nothing about categories the run could not measure, and a perfect score on two images is not evidence about all images.", ""]

    L += ["## 12. Next development priorities", ""]
    priorities = [r for level in ("Critical", "High") for r in recs[level]][:8]
    L += ([f"{i}. {p}" for i, p in enumerate(priorities, 1)] or ["1. Run more, different images (the more kinds of malware and Windows / Linux versions, the more this report can say)."])
    L.append("")
    return "\n".join(L)


# ------------------------------------------------------------------------------------------------------ Markdown -> self-contained HTML
_STYLE = ("body{font:14px/1.5 Segoe UI,Arial,sans-serif;max-width:1200px;margin:24px auto;padding:0 18px;color:#1b2430;background:#fff}h1{font-size:26px}h2{margin-top:30px;border-bottom:1px solid #d5dbe3;padding-bottom:4px}"
          "h3{margin-top:18px}table{border-collapse:collapse;margin:10px 0;display:block;overflow-x:auto}th,td{border:1px solid #d5dbe3;padding:4px 8px;text-align:left;vertical-align:top;font-size:13px}"
          "th{background:#eef2f7}code{background:#eef2f7;padding:1px 4px;border-radius:3px}tr:nth-child(even) td{background:#fafbfd}")


def _inline(text: str) -> str:
    text = html.escape(text, quote=False)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", text)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", text)


def markdown_to_html(md: str, title: str = "MemoryGraph testing report") -> str:
    """The small Markdown subset the report uses (headings, tables, lists, bold, code), as one HTML file with its own style and no external resource."""
    out, lines, i = [], md.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            out.append(f"<h{level}>{_inline(line[level:].strip())}</h{level}>")
        elif line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            i -= 1
            head, body = rows[0], [r for r in rows[2:]] if len(rows) > 1 and set("".join(rows[1])) <= set("-: ") else rows[1:]
            out.append("<table><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr>" + "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in body) + "</table>")
        elif re.match(r"^(\*|-) ", line):
            items = []
            while i < len(lines) and re.match(r"^(\*|-) ", lines[i]):
                items.append(lines[i][2:])
                i += 1
            i -= 1
            out.append("<ul>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ul>")
        elif re.match(r"^\d+\. ", line):
            items = []
            while i < len(lines) and re.match(r"^\d+\. ", lines[i]):
                items.append(re.sub(r"^\d+\. ", "", lines[i]))
                i += 1
            i -= 1
            out.append("<ol>" + "".join(f"<li>{_inline(x)}</li>" for x in items) + "</ol>")
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
        i += 1
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title><style>{_STYLE}</style></head><body>{''.join(out)}</body></html>"
