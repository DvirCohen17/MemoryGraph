"""Turns one detonation into a self-describing package: README.md, expected.json, metadata.json.

expected.json uses the format of MemoryGraph's real-world test harness (tools/realworld/README.md), so
    tools/realworld/run_report.py --dump memory.vmem --expected expected.json
checks MemoryGraph against what really ran in the VM.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional

# Processes that the lab itself or idle Windows start around the detonation. Used only for processes that
# are NOT descendants of the sample (those always count): a new powershell.exe with no link to the sample is
# most likely the lab's own collector, a new RegAsm.exe is most likely a hollowed host of the sample.
LAB_NOISE = {"powershell.exe", "conhost.exe", "wmiprvse.exe", "netstat.exe", "7z.exe", "vmtoolsd.exe",
             "searchprotocolhost.exe", "searchfilterhost.exe", "backgroundtaskhost.exe", "runtimebroker.exe",
             "smartscreen.exe", "taskhostw.exe", "audiodg.exe", "sppsvc.exe", "consent.exe",
             "explorer.exe"}  # explorer.exe <file> starts a short-lived second Explorer that hands the start over


def _parse_time(value) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _split_endpoint(text: str):
    """'1.2.3.4:443' / '[::1]:80' / '*:*' -> (address, port)."""
    text = (text or "").strip()
    if text.startswith("["):
        address, _, port = text[1:].partition("]:")
    else:
        address, _, port = text.rpartition(":")
    try:
        return address, int(port)
    except ValueError:
        return address, 0


def _is_remote(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback)


def sample_processes(truth: dict, detonation: dict) -> List[dict]:
    """The sample's processes: the ones it was started as, their descendants, and anything else
    that started after the launch and is not lab noise (hollowed hosts such as RegAsm.exe start this way)."""
    processes = truth.get("processes") or []
    by_pid = {p["pid"]: p for p in processes}
    collector = truth.get("collector_pid")
    collector_tree = set()
    if collector is not None:
        collector_tree.add(collector)
        changed = True
        while changed:
            changed = False
            for p in processes:
                if p["ppid"] in collector_tree and p["pid"] not in collector_tree:
                    collector_tree.add(p["pid"])
                    changed = True

    roots = {pid for pid in (detonation.get("pids") or []) if pid in by_pid}
    selected = set(roots)
    changed = True
    while changed:
        changed = False
        for p in processes:
            # Every descendant counts (malware often starts powershell.exe, cmd.exe, schtasks.exe ...).
            if p["ppid"] in selected and p["pid"] not in selected and p["pid"] not in collector_tree:
                selected.add(p["pid"])
                changed = True

    launched = _parse_time(detonation.get("launched_utc"))
    if launched is not None:
        for p in processes:
            created = _parse_time(p.get("created_utc"))
            if (created is not None and created >= launched and p["pid"] not in collector_tree
                    and p["name"].lower() not in LAB_NOISE):
                selected.add(p["pid"])
    return [by_pid[pid] for pid in sorted(selected)]


def sample_connections(truth: dict, pids: Iterable[int]) -> List[dict]:
    pids = set(pids)
    out, seen = [], set()
    for c in truth.get("connections") or []:
        if c.get("pid") not in pids:
            continue
        address, port = _split_endpoint(c.get("remote", ""))
        if not _is_remote(address) or not port:
            continue
        key = (address, port, c.get("pid"))
        if key in seen:
            continue
        seen.add(key)
        out.append({"proto": c.get("proto", ""), "remote_address": address, "remote_port": port,
                    "state": c.get("state", ""), "pid": c.get("pid")})
    return out


def build_expected(package_id: str, family, sample, truth: dict, detonation: dict, seconds_before_capture: float) -> dict:
    by_pid = {p["pid"]: p for p in truth.get("processes") or []}
    procs = sample_processes(truth, detonation)
    source = (f"lab ground truth: process list taken inside the VM {seconds_before_capture:.0f} s before the memory capture "
              f"(collect.ps1, Win32_Process)")
    facts = []
    for i, p in enumerate(procs, 1):
        parent = by_pid.get(p["ppid"])
        facts.append({"id": f"S-P{i}", "type": "process", "name": p["name"], "pid": p["pid"], "ppid": p["ppid"],
                      "description": f"{p['name']} (PID {p['pid']}) ran as part of the sample"
                                     + (f", started by {parent['name']} (PID {parent['pid']})" if parent else ""),
                      "verified": True, "source": source})
        if parent:
            facts.append({"id": f"S-R{i}", "type": "parent", "name": p["name"], "pid": p["pid"], "parent_name": parent["name"],
                          "description": f"{p['name']} is started by {parent['name']}", "verified": True, "source": source})
    for i, c in enumerate(sample_connections(truth, [p["pid"] for p in procs]), 1):
        facts.append({"id": f"S-N{i}", "type": "connection", "remote_address": c["remote_address"],
                      "remote_port": c["remote_port"], "pid": c["pid"],
                      "description": f"{by_pid.get(c['pid'], {}).get('name', '?')} (PID {c['pid']}) {c['proto']} "
                                     f"{c['state'] or ''} to {c['remote_address']}:{c['remote_port']} (fake internet)".replace("  ", " "),
                      "verified": True, "source": "lab ground truth: netstat -ano inside the VM before the capture"})
    for i, p in enumerate(procs, 1):
        facts.append({"id": f"S-F{i}", "type": "any_finding", "process": p["name"], "min_severity": "Low",
                      "description": f"MemoryGraph should flag {p['name']} (PID {p['pid']}) at least once",
                      "verified": False, "source": "expectation: the process is malware"})
    basis = ("No sample process was running at capture time (it exited, failed or hides itself): look in psscan for an exit time. "
             if not procs else "")
    basis += (f"Package {package_id}: {family.name} sample {sample.sha256} run in a clean lab VM. "
             "Facts with verified:true come from inside the VM seconds before the capture (not from the dump), "
             "so they are independent of Volatility. 'any_finding' facts are expectations. "
             "Edit findings_review after you have checked MemoryGraph's findings.")
    return {"id": package_id, "basis": basis, "facts": facts,
            "findings_review": {"true_positive": [], "false_positive": [], "inconclusive": []}}


def build_baseline_expected(package_id: str, truth: dict) -> dict:
    return {"id": package_id,
            "basis": f"Package {package_id}: the clean lab VM with no sample. Use it as the reference in MemoryGraph's Compare view "
                     "and to see which findings a clean machine already produces.",
            "facts": [{"id": "B-C1", "type": "max_severity", "severity": "Medium",
                       "description": "A clean lab VM should have nothing above Medium", "verified": False,
                       "source": "expectation"}],
            "findings_review": {"true_positive": [], "false_positive": [], "inconclusive": []}}


def _table(rows: List[List[str]], header: List[str]) -> str:
    def cell(v):
        return str(v).replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines += ["| " + " | ".join(cell(v) for v in row) + " |" for row in rows]
    return "\n".join(lines)


def build_readme(meta: dict, expected: dict, truth: dict, family=None) -> str:
    pid = meta["id"]
    sample = meta.get("sample")
    run = meta["run"]
    os_info = (truth.get("os") or {}) if truth else {}
    os_text = " ".join(x for x in (os_info.get("product"), os_info.get("display_version") or os_info.get("release_id"),
                                   f"build {os_info.get('build')}.{os_info.get('ubr')}" if os_info.get("build") else "") if x)
    parts = [f"# {pid}", ""]
    if sample:
        parts += ["> **Live malware inside.** The archive holds a memory image of a machine infected with a real "
                  f"{family.name if family else sample['family']} sample. Analyse it only in an isolated lab. Archive password: `infected`.", ""]
        parts += [f"## What the malware is: {family.name if family else sample['family']}", "",
                  (family.description if family and family.description else "(no description)"), ""]
        parts += ["## Sample", "", _table([
            ["SHA-256", f"`{sample['sha256']}`"], ["MD5", f"`{sample.get('md5', '')}`"],
            ["File name", sample.get("file_name", "")], ["Type / size", f"{sample.get('file_type', '')} / {sample.get('file_size', 0):,} bytes"],
            ["First seen", sample.get("first_seen", "")], ["Tags", ", ".join(sample.get("tags") or [])],
            ["MalwareBazaar", sample.get("page", "")]], ["", ""]), ""]
    else:
        parts += ["Clean lab VM, no malware: the reference image for this guest.", ""]
    parts += ["## The capture", "", _table([
        ["Guest", f"{run['guest']} ({os_text or 'unknown build'})"],
        ["Started", run.get("launch", "-")],
        ["Ran for", f"{run['seconds']} s before the capture"],
        ["Captured (UTC)", run["captured_utc"]],
        ["Method", "VMware Workstation suspend: the whole RAM written from outside the VM (no capture tool in the image)"],
        ["Memory file", f"`memory.vmem` ({meta['memory']['size']:,} bytes, SHA-256 `{meta['memory'].get('sha256', '')}`) + `memory.vmss`"],
        ["Network", "isolated lab network; DNS/HTTP/SMTP... answered by INetSim (fake internet)"],
    ], ["", ""]), ""]
    facts = expected.get("facts", [])
    procs = [f for f in facts if f["type"] == "process"]
    conns = [f for f in facts if f["type"] == "connection"]
    parts += ["## What MemoryGraph should find", ""]
    if sample:
        if procs:
            parts += ["Processes of the sample (seen inside the VM just before the capture):", "",
                      _table([[f["name"], f["pid"], f["ppid"], f["description"]] for f in procs], ["Process", "PID", "Parent PID", ""]), ""]
        else:
            parts += ["No sample process was running at capture time: it exited, failed, or hides. Look in psscan for an exit time.", ""]
        if conns:
            parts += ["Network activity of the sample:", "",
                      _table([[f"{f['remote_address']}:{f['remote_port']}", f["pid"], f["description"]] for f in conns], ["Remote", "PID", ""]), ""]
        if family and family.look_for:
            parts += ["Typical for this family (may or may not show in this run):", ""] + [f"- {x}" for x in family.look_for] + [""]
    else:
        parts += ["Nothing malicious. Findings MemoryGraph shows here are its false-positive baseline for this guest.", ""]
    parts += ["`expected.json` is the machine-readable answer key (format: `tools/realworld/README.md` in MemoryGraph).", ""]
    parts += ["## How to use it", "", "```",
              f"gh release download {pid} --repo {meta.get('repo') or '<owner>/<repo>'} --dir {pid}",
              f"7z x {pid}\\{pid}.7z.001 -pinfected -o{pid}",
              "```", "",
              f"Then in MemoryGraph: *Run analysis* on `{pid}\\memory.vmem` (keep `memory.vmss` next to it). To score MemoryGraph:",
              "", "```", f"tools\\realworld\\run_report.bat --dump {pid}\\memory.vmem --expected {pid}\\expected.json", "```", "",
              "## Analyst notes", "", "_What you found, false positives, things MemoryGraph missed._", ""]
    return "\n".join(parts)


def write_json(path: Path, data) -> None:
    Path(path).write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
