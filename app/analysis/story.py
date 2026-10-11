"""The story of one process: everything the investigation knows about it, on one clock (no Qt).

A finding says what looks wrong; the story says what happened around it: who started the process, when, what was written to the registry or run before and after,
which connections it opened, what it started itself. It only arranges what the plugins already reported (the Timeline events, the process list, the network table,
the findings): it adds no evidence and decides nothing.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import List, Optional

from app.analysis.indicators.scoring import severity_rank
from app.util import format_time, parse_time, path_file

# an event about the program's file (a Run key, UserAssist, Amcache, shimcache) belongs to the story at any time; other events only near the process start
NEAR = timedelta(minutes=10)


@dataclass
class StoryItem:
    time: str                 # as stored ('' = no time known)
    seconds: Optional[float]  # relative to the process start (negative = before), None when not comparable
    kind: str                 # parent / start / network / module / registry / execution / child / exit / finding
    text: str
    severity: str = ""
    source: str = ""


def _relative(moment, start) -> Optional[float]:
    return (moment - start).total_seconds() if moment is not None and start is not None else None


def build(result, pid: int) -> List[StoryItem]:
    """The ordered story of process ``pid`` (empty when the process is not in the result)."""
    proc = next((p for p in result.processes if p.pid == pid), None)
    if proc is None:
        return []
    start = parse_time(proc.create_time)
    items: List[StoryItem] = []

    def add(time, kind, text, severity="", source=""):
        moment = parse_time(time)
        items.append(StoryItem(str(time or ""), _relative(moment, start), kind, text, severity, source))

    by_pid = {p.pid: p for p in result.processes}
    parent = by_pid.get(proc.ppid)
    if parent is not None:
        add(parent.create_time, "parent", f"parent {parent.name} (PID {parent.pid}) started", source="windows.pslist")
    add(proc.create_time, "start", f"{proc.name} (PID {pid}) started" + (f" by {parent.name} (PID {parent.pid})" if parent else f" by PID {proc.ppid}")
        + (f"; command line: {proc.command_line}" if proc.command_line else ""), source="windows.pslist")
    if proc.exit_time:
        add(proc.exit_time, "exit", f"{proc.name} exited", source="windows.pslist")
    for conn in proc.network:
        add(conn.created, "network", f"{conn.protocol} {conn.local} → {conn.remote} {conn.state}".strip(), source=", ".join(conn.source_plugins))
    for child in result.processes:
        if child.ppid == pid and child.pid != pid:
            add(child.create_time, "child", f"started {child.name} (PID {child.pid})", source="windows.pslist")
    captured = parse_time(result.capture_time)
    for dll in proc.dlls:
        if dll.load_time and start is not None:
            moment = parse_time(dll.load_time)
            # (a load time after the capture, or from before the process existed, is a damaged value: dlllist prints such times on Windows 10 images)
            if moment is not None and NEAR < moment - start and (captured is None or moment <= captured + timedelta(hours=1)):
                add(dll.load_time, "module", f"loaded {dll.name} long after the start ({dll.path})", source="windows.dlllist")

    image = path_file(proc.path or "").lower() or proc.name.lower()
    seen = set()
    for event in result.timeline:
        text = f"{event.description} {event.details}".lower()
        about_file = bool(image) and image in text and event.category not in ("Process",)
        near = False
        moment = parse_time(event.timestamp)
        if moment is not None and start is not None and abs(moment - start) <= NEAR and event.category in ("Registry", "Execution", "Module", "File time"):
            near = True
        if event.pid != pid and not about_file and not (near and (proc.name.lower() in text or image in text)):
            continue
        if event.category == "Process" and event.pid != pid:
            continue                                            # another process' start is not about this one (children are added above)
        key = (event.timestamp, event.event_type, event.description)
        if key in seen or event.category in ("Process", "Network") and event.pid == pid:
            continue                                            # the start, the exit and the connections are already there
        seen.add(key)
        add(event.timestamp, event.category.lower() if event.category else "event", f"{event.event_type}: {event.description}", event.severity, event.source_plugin)

    for finding in result.indications:
        if finding.process_pid == pid and finding.triage not in ("false_positive", "baseline"):
            items.append(StoryItem("", None, "finding", f"{finding.rule_id} {finding.title}", finding.severity, ", ".join(finding.source_plugins)))
    # chronological; items without a time (findings) come first, so the reader sees what to look for before the sequence
    items.sort(key=lambda i: (i.time != "" or i.kind != "finding", -severity_rank(i.severity) if i.kind == "finding" else 0,
                              parse_time(i.time).timestamp() if parse_time(i.time) else 0.0))
    return items


def describe_offset(seconds: Optional[float]) -> str:
    """``+12 s`` / ``-3 min`` / ``+2.4 h`` relative to the process start."""
    if seconds is None:
        return ""
    sign, value = ("+" if seconds >= 0 else "-"), abs(seconds)
    if value < 90:
        return f"{sign}{value:.0f} s"
    if value < 5400:
        return f"{sign}{value / 60:.0f} min"
    if value < 172800:
        return f"{sign}{value / 3600:.1f} h"
    return f"{sign}{value / 86400:.0f} d"


def display_time(item: StoryItem) -> str:
    return format_time(item.time) if item.time else ""
