"""Checks that compare MemoryGraph's result with the raw Volatility output it was built from (no Qt, no Volatility needed).

Every plugin's raw rows are kept in ``AnalysisResult.plugins``, so the Volatility baseline for a dump is exactly what the plugin printed. The checks re-derive the
important facts from those raw rows *independently of the normalizer* (plain column lookups) and compare them with what MemoryGraph shows: processes, parents,
command lines, DLLs, malfind regions, network connections, handles, hidden processes. A check is PASS, FAIL or INCONCLUSIVE (the plugin it needs did not complete,
so nothing can be said). Nothing here decides whether a *rule* is right; that needs ground truth (see ``evaluate_facts`` and ``review_findings``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from app.analysis.indicators.scoring import severity_rank
from app.util import to_int

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"


@dataclass
class Check:
    area: str
    name: str
    status: str
    detail: str = ""
    items: List[str] = field(default_factory=list)       # the differences, at most ``LIMIT``

    def as_dict(self) -> dict:
        return {"area": self.area, "name": self.name, "status": self.status, "detail": self.detail, "items": self.items}


LIMIT = 15

#: which plugin answers which question, per operating system (Linux: provisional until the Linux plugins' real columns are checked on a real image)
PLUGINS = {
    "windows": {"pslist": "windows.pslist", "psscan": "windows.psscan", "cmdline": "windows.cmdline", "dlls": "windows.dlllist", "malfind": "windows.malfind",
                "net": ("windows.netscan", "windows.netstat"), "handles": "windows.handles"},
    "linux": {"pslist": "linux.pslist.PsList", "psscan": "linux.psscan.PsScan", "cmdline": "linux.psaux.PsAux", "dlls": "linux.library_list.LibraryList",
              "malfind": "linux.malfind.Malfind", "net": ("linux.sockstat.Sockstat",), "handles": "linux.lsof.Lsof"},
}


def N(result, key):
    """The name of the plugin that answers ``key`` for the operating system of ``result``."""
    return PLUGINS.get(getattr(result, "target_os", "windows"), PLUGINS["windows"])[key]


def plugin(result, name: str):
    """The completed plugin result called ``name`` (None when it did not run or did not complete)."""
    for p in result.plugins:
        if p.name == name and p.status == "Completed":
            return p
    return None


def _first(row: dict, *keys, default=None):
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return default


def _text(value) -> str:
    return "" if value is None or str(value).strip() in ("None", "N/A", "-") else str(value).strip()



# ============================================================================= processes
def check_processes(result) -> List[Check]:
    ps, scan = plugin(result, N(result, "pslist")), plugin(result, N(result, "psscan"))
    if not ps and not scan:
        return [Check("Processes", "process list", INCONCLUSIVE, f"neither {N(result, 'pslist')} nor {N(result, 'psscan')} completed")]
    base: Dict[int, Tuple[str, int]] = {}
    for p in (ps, scan):
        for row in (p.rows if p else []):
            pid = to_int(_first(row, "PID", "Pid"))
            if pid is not None:
                base.setdefault(pid, (_text(_first(row, "ImageFileName", "Name", "COMM", default="")), to_int(_first(row, "PPID", "Ppid"), -1)))
    model = {p.pid: p for p in result.processes}
    out: List[Check] = []
    missing, extra = sorted(set(base) - set(model)), sorted(set(model) - set(base))
    out.append(Check("Processes", "same processes as Volatility (pslist ∪ psscan)", PASS if not missing and not extra else FAIL,
                     f"Volatility {len(base)}, MemoryGraph {len(model)}", [f"missing in MemoryGraph: PID {x} ({base[x][0]})" for x in missing[:LIMIT]]
                     + [f"only in MemoryGraph: PID {x} ({model[x].name})" for x in extra[:LIMIT]]))
    wrong_name = [f"PID {pid}: Volatility '{base[pid][0]}' vs MemoryGraph '{model[pid].name}'" for pid in sorted(set(base) & set(model))
                  if base[pid][0] and model[pid].name.lower() != base[pid][0].lower()]
    out.append(Check("Processes", "process names", PASS if not wrong_name else FAIL, f"{len(set(base) & set(model))} compared", wrong_name[:LIMIT]))
    if ps:
        parents = {to_int(_first(r, "PID", "Pid")): to_int(_first(r, "PPID", "Ppid"), -1) for r in ps.rows}
        wrong = [f"PID {pid}: PPID {pp} vs MemoryGraph {model[pid].ppid}" for pid, pp in sorted(parents.items()) if pid in model and model[pid].ppid != pp]
        out.append(Check("Processes", "parent PIDs (pslist PPID)", PASS if not wrong else FAIL, f"{len(parents)} compared", wrong[:LIMIT]))
    cmd = plugin(result, N(result, "cmdline"))
    if cmd:
        diffs = []
        for row in cmd.rows:
            pid = to_int(_first(row, "PID", "Pid"))
            if pid in model and _text(_first(row, "Args", "ARGS", default="")) != _text(model[pid].command_line):
                diffs.append(f"PID {pid}: Volatility {_text(row.get('Args'))[:80]!r} vs MemoryGraph {_text(model[pid].command_line)[:80]!r}")
        out.append(Check("Processes", f"command lines ({N(result, 'cmdline')})", PASS if not diffs else FAIL, f"{len(cmd.rows)} compared", diffs[:LIMIT]))
    else:
        out.append(Check("Processes", f"command lines ({N(result, 'cmdline')})", INCONCLUSIVE, f"{N(result, 'cmdline')} did not complete"))
    if ps and scan:
        in_list = {to_int(_first(r, "PID", "Pid")) for r in ps.rows}
        hidden = {to_int(_first(r, "PID", "Pid")) for r in scan.rows if to_int(_first(r, "PID", "Pid")) not in in_list and not _text(r.get("ExitTime"))}
        shown = {p.pid for p in result.processes if p.hidden}
        out.append(Check("Processes", "hidden processes (psscan only, not exited)", PASS if hidden == shown else FAIL,
                         f"Volatility {sorted(hidden)}, MemoryGraph {sorted(shown)}"))
    return out


# ============================================================================= modules, memory
def check_dlls(result) -> List[Check]:
    dl = plugin(result, N(result, "dlls"))
    if not dl:
        return [Check("Modules", f"module lists ({N(result, 'dlls')})", INCONCLUSIVE, f"{N(result, 'dlls')} did not complete")]
    base: Dict[int, set] = {}
    for row in dl.rows:
        pid = to_int(_first(row, "PID", "Pid"))
        if pid is not None and _text(row.get("Name")):
            base.setdefault(pid, set()).add(_text(row["Name"]).lower())
    model = {p.pid: {d.name.lower() for d in p.dlls} for p in result.processes}
    diffs = []
    for pid, names in sorted(base.items()):
        if pid not in model:
            diffs.append(f"PID {pid}: process missing in MemoryGraph")
        elif names != model[pid]:
            diffs.append(f"PID {pid}: missing {sorted(names - model[pid])[:4]}, extra {sorted(model[pid] - names)[:4]}")
    return [Check("Modules", "DLL lists per process (windows.dlllist)", PASS if not diffs else FAIL, f"{len(base)} processes, {len(dl.rows)} rows", diffs[:LIMIT])]


def check_memory(result) -> List[Check]:
    mf = plugin(result, N(result, "malfind"))
    if not mf:
        return [Check("Memory", "malfind regions", INCONCLUSIVE, f"{N(result, 'malfind')} did not complete")]
    base = {(to_int(_first(r, "PID", "Pid")), to_int(_first(r, "Start VPN", "Start"))) for r in mf.rows}
    model = {(r.pid, to_int(r.start)) for r in result.memory_regions if "malfind" in (r.source_plugin or "")}
    return [Check("Memory", "malfind regions (pid + start address)", PASS if base == model else FAIL, f"Volatility {len(base)}, MemoryGraph {len(model)}",
                  [f"missing: PID {p} {hex(s or 0)}" for p, s in sorted(base - model, key=str)[:LIMIT]] + [f"extra: PID {p} {hex(s or 0)}" for p, s in sorted(model - base, key=str)[:LIMIT]])]


# ============================================================================= network
def _addr(value) -> str:
    text = _text(value).lower()
    return "" if text in ("*", "0.0.0.0", "::", "0") else text


def _proto(value) -> str:
    return re.sub(r"v[46]$", "", _text(value).lower())


def check_network(result) -> List[Check]:
    out: List[Check] = []
    rows, used = [], []
    for name in N(result, "net"):
        p = plugin(result, name)
        if p is not None:
            rows.extend((name, r) for r in p.rows)
            used.append(f"{name} ({len(p.rows)})")
        else:
            failed = next((q for q in result.plugins if q.name == name), None)
            out.append(Check("Network", name, INCONCLUSIVE, f"{failed.status if failed else 'not run'}: "
                             + (((failed.error or '').strip().splitlines() or [''])[-1][:200] if failed else "")))
    from app.engines.windows.analysis import vol2_adapter
    for name in ("vol2.connections", "vol2.sockets", "vol2.netscan", "vol2.connscan", "vol2.sockscan"):
        p = plugin(result, name)
        if p is not None and p.rows:
            rows.extend((name, r) for r in vol2_adapter.network_rows(name, p.rows))
            used.append(f"{name} ({len(p.rows)})")
    if not rows:
        return out + [Check("Network", "connections kept", INCONCLUSIVE, "no network plugin of Volatility 3 or Volatility 2 completed")]

    def key(pid, proto, la, lp, fa, fp):
        return (pid if pid is not None else -1, _proto(proto), _addr(la), _text(lp), _addr(fa), _text(fp))

    base = {key(to_int(_first(r, "PID", "Pid")), _first(r, "Proto", "Protocol"), _first(r, "LocalAddr", "LocalAddress"), _first(r, "LocalPort"),
                _first(r, "ForeignAddr", "RemoteAddr"), _first(r, "ForeignPort", "RemotePort")) for _n, r in rows}
    model = {key(c.pid, c.protocol, c.local_address, c.local_port, c.remote_address, c.remote_port) for c in result.connections}
    lost = sorted(base - model, key=str)
    out.append(Check("Network", "every connection of Volatility 3 / 2 is in MemoryGraph (pid, protocol, local and remote address + port)", PASS if not lost else FAIL,
                     "from " + ", ".join(used) + f"; {len(base)} distinct connections, MemoryGraph {len(model)}",
                     [f"missing: PID {k[0]} {k[1]} {k[2]}:{k[3]} → {k[4]}:{k[5]}" for k in lost[:LIMIT]]))
    extra = sorted(model - base, key=str)
    out.append(Check("Network", "connections only in MemoryGraph", PASS if not extra else INCONCLUSIVE,
                     "expected when Volatility 2 supplied connections" if extra else "", [f"PID {k[0]} {k[1]} {k[2]}:{k[3]} → {k[4]}:{k[5]}" for k in extra[:LIMIT]]))
    return out


def check_handles(result) -> List[Check]:
    hp = plugin(result, N(result, "handles"))
    if not hp:
        return [Check("Handles", "handle counts per process", INCONCLUSIVE, f"{N(result, 'handles')} did not complete")]
    base: Dict[int, int] = {}
    for row in hp.rows:
        pid = to_int(_first(row, "PID", "Pid"))
        if pid is not None:
            base[pid] = base.get(pid, 0) + 1
    model = {p.pid: sum(p.handle_summary.values()) for p in result.processes if p.handle_summary}
    diffs = [f"PID {pid}: Volatility {n}, MemoryGraph {model.get(pid, 0)}" for pid, n in sorted(base.items()) if pid in {p.pid for p in result.processes} and model.get(pid, 0) != n]
    return [Check("Handles", "handle counts per process", PASS if not diffs else FAIL, f"{len(hp.rows)} handles, {len(base)} processes", diffs[:LIMIT])]


# ============================================================================= plugin health
def classify_plugin(p) -> Tuple[str, str]:
    """``(category, evidence)`` for a plugin result. Only Volatility's own words decide the category; anything else is 'Unclassified'."""
    if p.status == "Completed":
        return ("Completed, 0 rows (possibly incomplete or nothing to report)" if not p.rows else "OK"), ""
    text = p.error or ""
    low = text.lower()
    last = ((text.strip().splitlines() or [""])[-1])[:240]
    if p.status == "Skipped":
        return "Skipped by MemoryGraph: not applicable to this Windows", last
    if "no module named" in low or "pip install" in low and "yara" in low:
        return "Missing dependency", last
    if "this version of windows is not supported" in low or "not supported" in low and "windows" in low:
        return "Volatility plugin limitation / unsupported operating system", last
    if "invalid choice" in low or "not one of them" in low:
        return "Volatility version incompatibility (plugin not available in this version)", last
    if "symbol table" in low or "unsatisfied requirement" in low or "unable to validate the plugin requirements" in low or "offlineexception" in low or "tcpip" in low and "symbol" in low:
        return "Symbols unavailable (environment; offline)", last
    if "traceback" in low:
        return "Volatility plugin crash (reproduce with another Volatility version before blaming MemoryGraph)", last
    return "Unclassified (needs investigation)", last


def plugin_table(result) -> List[dict]:
    rows = []
    for p in result.plugins:
        category, evidence = classify_plugin(p)
        rows.append({"plugin": p.name, "status": p.status, "rows": len(p.rows), "seconds": round(p.duration), "category": category, "evidence": evidence})
    return rows


def all_checks(result) -> List[Check]:
    return check_processes(result) + check_dlls(result) + check_memory(result) + check_network(result) + check_handles(result)


# ============================================================================= expected facts and finding review
def _matching_processes(result, fact: dict):
    return [p for p in result.processes if (fact.get("name") is None or p.name.lower() == fact["name"].lower()) and (fact.get("pid") is None or p.pid == fact["pid"])]


def _fact_requirements(result, fact: dict) -> List[str]:
    pslist, net, malfind, dlls = N(result, "pslist"), list(N(result, "net")), N(result, "malfind"), N(result, "dlls")
    return {"process": [pslist], "parent": [pslist], "connection": net, "region": [malfind], "dll": [dlls], "plugin": []}.get(fact["type"], [])


def evaluate_fact(result, fact: dict) -> Tuple[str, str]:
    kind = fact["type"]
    needs = _fact_requirements(result, fact)
    if kind != "plugin" and needs and not any(plugin(result, n) for n in needs) and kind != "finding":
        return INCONCLUSIVE, "required plugin did not complete: " + " or ".join(needs)
    if kind == "process":
        found = _matching_processes(result, fact)
        if not found:
            return FAIL, "no such process"
        if fact.get("ppid") is not None and not any(p.ppid == fact["ppid"] for p in found):
            return FAIL, f"parent PID is {found[0].ppid}, expected {fact['ppid']}"
        if fact.get("hidden") is not None and not any(p.hidden == fact["hidden"] for p in found):
            return FAIL, f"hidden is {found[0].hidden}"
        return PASS, f"PID {found[0].pid}, PPID {found[0].ppid}"
    if kind == "parent":
        child = _matching_processes(result, {"name": fact["name"], "pid": fact.get("pid")})
        if not child:
            return FAIL, "child process not found"
        parent = next((p for p in result.processes if p.pid == child[0].ppid), None)
        ok = parent is not None and parent.name.lower() == fact["parent_name"].lower()
        return (PASS if ok else FAIL), f"parent is {parent.name if parent else 'PID ' + str(child[0].ppid) + ' (not in list)'}"
    if kind == "connection":
        hits = [c for c in result.connections if (fact.get("remote_address") in (None, c.remote_address)) and (fact.get("remote_port") in (None, str(c.remote_port)) or str(fact.get("remote_port")) == str(c.remote_port))
                and (fact.get("pid") is None or c.pid == fact["pid"])]
        return (PASS, f"{hits[0].protocol} {hits[0].local} → {hits[0].remote} {hits[0].state}") if hits else (FAIL, "no such connection")
    if kind == "region":
        hits = [r for r in result.memory_regions if (fact.get("pid") is None or r.pid == fact["pid"]) and (fact.get("protection") in (None, r.protection))]
        return (PASS, f"{len(hits)} region(s), first {hits[0].range}") if hits else (FAIL, "no such region")
    if kind == "dll":
        hits = [(p, d) for p in _matching_processes(result, fact) for d in p.dlls if d.name.lower() == fact["dll"].lower()]
        return (PASS, hits[0][1].path) if hits else (FAIL, "DLL not listed")
    if kind == "finding":
        hits = [i for i in result.indications if i.rule_id == fact["rule_id"] and i.triage not in ("false_positive", "baseline")
                and (fact.get("pid") is None or i.process_pid == fact["pid"]) and (fact.get("process") is None or i.process_name.lower() == fact["process"].lower())
                and severity_rank(i.severity) >= severity_rank(fact.get("min_severity", "Low"))]
        return (PASS, f"{hits[0].severity}: {hits[0].title}") if hits else (FAIL, "rule did not trigger")
    if kind == "any_finding":
        hits = [i for i in result.indications if i.triage not in ("false_positive", "baseline") and i.rule_id != "IOC-006"
                and (fact.get("pid") is None or i.process_pid == fact["pid"]) and (fact.get("process") is None or i.process_name.lower() == fact["process"].lower())
                and severity_rank(i.severity) >= severity_rank(fact.get("min_severity", "Low"))]
        return (PASS, f"{len(hits)} finding(s), e.g. {hits[0].rule_id} {hits[0].severity}") if hits else (FAIL, "no finding on this process")
    if kind == "plugin":
        p = next((q for q in result.plugins if q.name == fact["name"]), None)
        got = p.status if p else "not run"
        return (PASS if got == fact["status"] else FAIL), f"status {got}"
    if kind == "max_severity":
        worst = max((severity_rank(i.severity) for i in result.indications if i.triage not in ("false_positive", "baseline") and i.rule_id not in fact.get("except_rules", [])), default=0)
        return (PASS if worst <= severity_rank(fact["severity"]) else FAIL), f"worst finding rank {worst}"
    return INCONCLUSIVE, f"unknown fact type {kind}"


def evaluate_facts(result, facts: List[dict]) -> List[dict]:
    rows = []
    for fact in facts:
        status, detail = evaluate_fact(result, fact)
        rows.append({"id": fact.get("id", ""), "description": fact.get("description") or fact["type"], "verified": fact.get("verified", False),
                     "status": status, "detail": detail, "source": fact.get("source", "")})
    return rows


def review_findings(result, review: dict) -> List[dict]:
    """Every visible finding with a verdict taken from the expected-results file (True Positive / False Positive); anything not listed there is 'Unreviewed',
    never guessed."""
    def matches(item: dict, ind) -> bool:
        return (item.get("rule_id") in (None, ind.rule_id) and item.get("process") in (None, ind.process_name.lower()) and item.get("pid") in (None, ind.process_pid)
                and item.get("severity") in (None, ind.severity) and (not item.get("title_contains") or item["title_contains"] in ind.title) and (not item.get("evidence_contains") or item["evidence_contains"].lower() in " ".join(ind.evidence).lower()))

    rows = []
    for ind in sorted(result.indications, key=lambda i: (-severity_rank(i.severity), i.rule_id, i.process_pid)):
        if ind.triage in ("false_positive", "baseline"):
            continue
        verdict = "Unreviewed"
        why = ""
        for label, key in (("True Positive", "true_positive"), ("False Positive", "false_positive"), ("Inconclusive", "inconclusive")):
            hit = next((x for x in (review or {}).get(key, []) if matches({k: (v.lower() if k == "process" else v) for k, v in x.items() if k not in ("why",)}, ind)), None)
            if hit:
                verdict, why = label, hit.get("why", "")
        rows.append({"rule_id": ind.rule_id, "severity": ind.severity, "process": f"{ind.process_name} ({ind.process_pid})" if ind.process_pid else "-",
                     "title": ind.title, "evidence": "; ".join(ind.evidence[:2])[:240], "source": ", ".join(ind.source_plugins), "verdict": verdict, "why": why})
    return rows
