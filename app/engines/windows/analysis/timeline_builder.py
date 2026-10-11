"""Build the investigation timeline from normalized evidence.

Compared with a plain "every plugin row with a timestamp" approach this:
  * emits ONE event per fact (a process creation appears once, not once per plugin),
  * adds process exits, network connection creation, third-party module loads, and the
    memory capture time as an anchor,
  * sorts by parsed time (not by string), and
  * tags every event with the severity of the findings on the same process.
"""
from __future__ import annotations

from typing import Dict, List

from app.engines.windows.analysis import plugin_registry, timeline_sources
from app.engines.windows.indicators.helpers import full_name, is_trusted_dir
from app.analysis.indicators.scoring import risk_by_pid
from app.models import AnalysisResult, TimelineEvent
from app.util import parse_time, time_key

MAX_MODULE_EVENTS = 3000
_HANDLED_PLUGINS = {"windows.pslist", "windows.psscan", "windows.pstree", "windows.netscan", "windows.netstat",
                    "windows.dlllist", "windows.info", "windows.cmdline", "windows.handles", "windows.getsids",
                    "windows.malfind"}
_TIME_KEYS = ("CreateTime", "Create Time", "Time", "Timestamp", "Created", "StartTime", "LoadTime", "TimeDateStamp",
              "Last Updated", "Last Write Time")      # userassist / registry keys


def build_timeline(result: AnalysisResult) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    seen = set()
    capture = parse_time(result.capture_time)
    latest = capture.timestamp() + 86400 if capture else None   # nothing can happen after the capture
    earliest = parse_time("1995-01-01T00:00:00+00:00").timestamp()

    def add(ts, category, etype, description, pid=0, plugin="", details=None, provenance=None, process=""):
        parsed = parse_time(ts) if ts else None
        if parsed is None:
            return
        stamp = parsed.timestamp()
        # Some modules carry garbage load times (e.g. year 2328); they would stretch the whole timeline.
        if stamp < earliest or (latest is not None and stamp > latest) or parsed.year > 2100:
            return
        key = (str(ts), etype, pid, description)
        if key in seen:
            return
        seen.add(key)
        events.append(TimelineEvent(str(ts), etype, description, pid, plugin, details or {}, provenance or {},
                                    "", category, process))

    if result.capture_time:
        add(result.capture_time, "System", "Memory captured", "Memory image was captured (windows.info SystemTime)", 0,
            "windows.info", {"SystemTime": result.capture_time})

    for p in result.processes:
        prov = p.provenance.get("create_time", {})
        plugin = prov.get("plugin", "windows.pslist")
        label = f"{p.name} (PID {p.pid}), parent {p.ppid}"
        if p.hidden:
            label += " — not in pslist (possibly hidden)"
        details = {"PID": p.pid, "PPID": p.ppid, "Path": p.path, "User": p.user, "Command line": p.command_line}
        add(p.create_time, "Process", "Process started", label, p.pid, plugin, details, {"timestamp": prov}, p.name)
        if p.exit_time:
            add(p.exit_time, "Process", "Process exited", f"{p.name} (PID {p.pid}) exited", p.pid,
                p.provenance.get("exit_time", {}).get("plugin", plugin), details,
                {"timestamp": p.provenance.get("exit_time", {})}, p.name)

    for conn in result.connections or [c for p in result.processes for c in p.network]:
        if not conn.created:
            continue
        remote = conn.remote if conn.remote_address not in ("", "*", "::", "0.0.0.0") else "(listening / unconnected)"
        add(conn.created, "Network", "Network", f"{conn.process or 'PID ' + str(conn.pid)} {conn.protocol} {conn.local} → {remote} {conn.state}".strip(),
            conn.pid, ", ".join(conn.source_plugins),
            {"Local": conn.local, "Remote": conn.remote, "State": conn.state, "Protocol": conn.protocol},
            {"timestamp": conn.provenance.get("row", {})}, conn.process)

    module_events = 0
    for p in result.processes:
        for d in p.dlls[1:]:
            if module_events >= MAX_MODULE_EVENTS:
                break
            if not d.load_time or is_trusted_dir(d.path) or not d.path:
                continue
            add(d.load_time, "Module", "Module loaded", f"{p.name} (PID {p.pid}) loaded {d.name}", p.pid, "windows.dlllist",
                {"Path": d.path, "Base": d.base, "Size": d.size}, {"timestamp": d.provenance.get("row", {})}, p.name)
            module_events += 1

    by_pid = {p.pid: p for p in result.processes}
    for plugin in result.plugins:
        if plugin.name in _HANDLED_PLUGINS or plugin.status != "Completed":
            continue
        if timeline_sources.covers(plugin.name):                 # registry keys, scheduled tasks, UserAssist, Amcache, shimcache
            before = len(events)
            timeline_sources.add_events(plugin, add)
            produced = len(events) - before
            if produced > timeline_sources.MAX_EVENTS_PER_PLUGIN:
                del events[before + timeline_sources.MAX_EVENTS_PER_PLUGIN:]
                note = (f"Timeline: only the first {timeline_sources.MAX_EVENTS_PER_PLUGIN} of {produced} events from {plugin.name} are "
                        "shown. The full rows are in Plugin Output.")
                if note not in result.warnings:
                    result.warnings.append(note)
            continue
        if plugin_registry.find(plugin.name) is not None:
            continue          # a plugin MemoryGraph knows and has no event source for: its time columns describe other things (vadyarascan repeats the process start)
        for index, row in enumerate(plugin.rows):
            if not isinstance(row, dict):
                continue
            ts = next((row[k] for k in _TIME_KEYS if row.get(k)), None)
            if not ts:
                continue
            try:
                pid = int(row.get("PID") or 0)
            except (TypeError, ValueError):
                pid = 0
            name = by_pid[pid].name if pid in by_pid else ""
            label = plugin.name.replace("windows.", "")
            summary = next((str(row[k]) for k in ("Name", "Path", "Process", "Module", "Description") if row.get(k)), "")
            add(ts, label.title(), label.title(), f"{label}: {summary or name or 'event'}", pid, plugin.name, dict(row),
                {"timestamp": {"plugin": plugin.name, "row_index": index}}, name)

    events.sort(key=lambda e: (time_key(e.timestamp), e.category, e.pid))
    return events


def apply_severity(result: AnalysisResult) -> None:
    """Tag timeline events with the process risk severity (Medium and above only)."""
    risks = risk_by_pid(result.indications)
    for event in result.timeline:
        risk = risks.get(event.pid)
        event.severity = risk.severity if risk and risk.severity in ("Medium", "High") else ""
