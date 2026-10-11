"""Turn raw Volatility 3 plugin rows into the normalized evidence models.

This module knows the *shape* of Volatility output (column names differ between plugins and
versions) and nothing else: no detection logic lives here. It is used both by the live
provider and when an old saved investigation is re-analysed from its stored plugin rows.

Every plugin is normalized inside its own try/except, so a malformed or unexpected plugin
output degrades to a warning instead of aborting the whole analysis.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.analysis.rows import flatten_rows  # noqa: F401  (shared by every engine; re-exported here for older callers)
from app.engines.windows.analysis import vol2_adapter
from app.logging_setup import get_logger
from app.models import (
    AnalysisResult, DLL, MemoryRegion, NetworkConnection, PluginResult, Process,
)
from app.util import human_size, norm_path, path_file, to_hex, to_int

log = get_logger("normalizer")

PLUGIN_INFO = "windows.info"
PLUGIN_PSLIST = "windows.pslist"
PLUGIN_PSSCAN = "windows.psscan"
PLUGIN_PSTREE = "windows.pstree"
PLUGIN_CMDLINE = "windows.cmdline"
PLUGIN_DLLLIST = "windows.dlllist"
PLUGIN_HANDLES = "windows.handles"
PLUGIN_GETSIDS = "windows.getsids"
PLUGIN_NETSTAT = "windows.netstat"
PLUGIN_NETSCAN = "windows.netscan"
PLUGIN_MALFIND = "windows.malfind"

# Handle types that are almost always unnamed noise; we keep only a per-type count for them.
_HANDLE_KEEP_ALWAYS = {"process", "thread", "file", "key", "mutant", "section", "token", "directory", "desktop", "windowstation", "job"}

_WELL_KNOWN_SIDS = {
    "S-1-5-18": "NT AUTHORITY\\SYSTEM",
    "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
    "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
}


# ----------------------------------------------------------------------------- row helpers
def _key(name: Any) -> str:
    return str(name).strip().lower().replace(" ", "").replace("_", "")


class Row:
    """Case/space/underscore-insensitive access to one plugin row."""

    __slots__ = ("raw", "_norm")

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self._norm = {_key(k): (k, v) for k, v in raw.items()}

    def get(self, names: Sequence[str], default: Any = "") -> Tuple[Any, str]:
        """Return ``(value, original_key)`` for the first name present with a non-None value."""
        for name in names:
            hit = self._norm.get(_key(name))
            if hit is not None and hit[1] is not None:
                return hit[1], str(hit[0])
        return default, ""

    def value(self, names: Sequence[str], default: Any = "") -> Any:
        return self.get(names, default)[0]

    def text(self, names: Sequence[str], default: str = "") -> str:
        value = self.value(names, None)
        return default if value is None else str(value)

    def integer(self, names: Sequence[str], default: Optional[int] = None) -> Optional[int]:
        return to_int(self.value(names, None), default)


def _prov(plugin: str, row_index: int, field: str, raw_key: str, value: Any) -> Dict[str, Any]:
    return {"plugin": plugin, "row_index": row_index, "field": field, "raw_key": raw_key,
            "value": "" if value is None else str(value)}


def _iter_rows(plugins: Sequence[PluginResult], name: str):
    """Yield ``(row_index, Row)`` for every dict row of a successfully completed plugin."""
    for plugin in plugins:
        if plugin.name != name or plugin.status != "Completed":
            continue
        for index, raw in enumerate(flatten_rows(plugin.rows)):
            if isinstance(raw, dict):
                yield index, Row(raw)


def _plugin_ok(plugins: Sequence[PluginResult], name: str) -> bool:
    return any(p.name == name and p.status == "Completed" for p in plugins)


PID_KEYS = ["PID", "Pid", "ProcessId", "UniqueProcessId"]


# ----------------------------------------------------------------------------- processes
def _build_processes(plugins: Sequence[PluginResult], warnings: List[str]) -> Dict[int, Process]:
    processes: Dict[int, Process] = {}

    def add(plugin_name: str, index: int, row: Row, source: str) -> None:
        pid = row.integer(PID_KEYS)
        if pid is None or pid in processes:
            return
        provenance: Dict[str, Dict[str, Any]] = {}

        def pick(field: str, names: Sequence[str], default: Any = "") -> Any:
            value, raw_key = row.get(names, default)
            provenance[field] = _prov(plugin_name, index, field, raw_key, value)
            return value

        name = str(pick("name", ["ImageFileName", "Name", "Process", "ImageName", "ProcessName"], "Unknown") or "Unknown")
        ppid = to_int(pick("ppid", ["PPID", "Ppid", "InheritedFromUniqueProcessId"], 0), 0) or 0
        create_time = str(pick("create_time", ["CreateTime", "Created", "Create Time"], "") or "")
        exit_time = str(pick("exit_time", ["ExitTime", "Exit Time"], "") or "")
        session = to_int(pick("session", ["SessionId", "Session"], None), None)
        threads = to_int(pick("threads", ["Threads", "Thread Count"], 0), 0) or 0
        wow64 = bool(pick("wow64", ["Wow64"], False))
        offset = to_hex(pick("offset", ["Offset(V)", "Offset(P)", "Offset"], ""))
        path = str(pick("path", ["Path", "ImagePath", "FullPath", "ExeName"], "") or "")
        base = str(pick("image_base", ["ImageBase", "Base", "ImageBaseAddress"], "") or "")
        processes[pid] = Process(
            pid=pid, ppid=ppid, name=name, path=path, image_base=base, user="",
            session=session if session is not None else -1, create_time=create_time, command_line="",
            provenance=provenance, exit_time=exit_time, threads=threads, wow64=wow64, offset=offset,
            source=source, exited=bool(exit_time),
            hidden=(source == "psscan" and not exit_time),
        )

    for plugin_name, source in ((PLUGIN_PSLIST, "pslist"), (PLUGIN_PSSCAN, "psscan"), (PLUGIN_PSTREE, "pstree")):
        try:
            for index, row in _iter_rows(plugins, plugin_name):
                add(plugin_name, index, row, source)
        except Exception as exc:  # noqa: BLE001
            log.exception("Normalizing %s failed", plugin_name)
            warnings.append(f"{plugin_name}: could not be normalized ({exc})")

    # A process found only by psscan while pslist exists is "hidden" only if pslist really ran.
    if not _plugin_ok(plugins, PLUGIN_PSLIST):
        for proc in processes.values():
            proc.hidden = False
    return processes


def _enrich_from_pstree(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> None:
    for index, row in _iter_rows(plugins, PLUGIN_PSTREE):
        pid = row.integer(PID_KEYS)
        proc = processes.get(pid) if pid is not None else None
        if not proc:
            continue
        path, raw_key = row.get(["Path"], "")
        if path and not proc.path:
            proc.path = str(path)
            proc.provenance["path"] = _prov(PLUGIN_PSTREE, index, "path", raw_key, path)
        elif not proc.path:
            audit, raw_key = row.get(["Audit"], "")
            if audit:
                proc.path = str(audit)
                proc.provenance["path"] = _prov(PLUGIN_PSTREE, index, "path", raw_key, audit)
        cmd, raw_key = row.get(["Cmd", "CommandLine"], "")
        if cmd and not proc.command_line:
            proc.command_line = str(cmd)
            proc.provenance["command_line"] = _prov(PLUGIN_PSTREE, index, "command_line", raw_key, cmd)


def _apply_cmdline(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> None:
    for index, row in _iter_rows(plugins, PLUGIN_CMDLINE):
        pid = row.integer(PID_KEYS)
        proc = processes.get(pid) if pid is not None else None
        if not proc:
            continue
        # Volatility 3 names this column "Args"; older/other builds use CommandLine/CmdLine.
        value, raw_key = row.get(["Args", "CommandLine", "CmdLine", "Command"], "")
        text = str(value or "").strip()
        if not text or text.lower().startswith(("required memory at", "unable to read", "process is not")):
            continue
        proc.command_line = text
        proc.provenance["command_line"] = _prov(PLUGIN_CMDLINE, index, "command_line", raw_key, text)


def _apply_dlls(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> None:
    first_module: Dict[int, DLL] = {}
    for index, row in _iter_rows(plugins, PLUGIN_DLLLIST):
        pid = row.integer(PID_KEYS)
        proc = processes.get(pid) if pid is not None else None
        if not proc:
            continue
        path = row.text(["Path", "FullPath", "DllPath"])
        name = row.text(["Name", "DLL", "DllName"]) or path_file(path.replace("/", "\\"))
        if not name and not path:
            continue
        base = to_hex(row.value(["Base", "DllBase", "ImageBase"], ""))
        size = str(row.value(["Size", "Length"], "") or "")
        load_time = row.text(["LoadTime", "Load Time"])
        dll = DLL(name or "unknown.dll", path, base, size, False,
                  {"row": _prov(PLUGIN_DLLLIST, index, "module", "Name", name)}, load_time)
        proc.dlls.append(dll)
        first_module.setdefault(proc.pid, dll)

    # The first module of a process is its executable: use it when no better path/base exists.
    for pid, dll in first_module.items():
        proc = processes[pid]
        if not proc.path and dll.path:
            proc.path = dll.path
            proc.provenance["path"] = dict(dll.provenance.get("row", {}), field="path")
        if not proc.image_base and dll.base:
            proc.image_base = dll.base
            proc.provenance["image_base"] = dict(dll.provenance.get("row", {}), field="image_base")


def _apply_sids(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> List[dict]:
    first_for_pid: Dict[int, Tuple[str, str]] = {}
    accounts: Dict[str, dict] = {}
    for index, row in _iter_rows(plugins, PLUGIN_GETSIDS):
        pid = row.integer(PID_KEYS)
        proc = processes.get(pid) if pid is not None else None
        sid = row.text(["SID"])
        name = row.text(["Name"])
        if not sid:
            continue
        label = f"{name} ({sid})" if name else sid
        if proc:
            proc.groups.append(label)
        if pid is not None and pid not in first_for_pid:
            first_for_pid[pid] = (sid, name)  # Volatility lists the process owner (user SID) first
    for pid, (sid, name) in first_for_pid.items():
        proc = processes.get(pid)
        display = _WELL_KNOWN_SIDS.get(sid) or name or sid
        if proc:
            proc.user = display
        entry = accounts.setdefault(sid, {"sid": sid, "name": display, "processes": 0})
        entry["processes"] += 1
    return sorted(accounts.values(), key=lambda a: (-a["processes"], a["name"].lower()))


def _network_rows(plugins: Sequence[PluginResult]):
    """``(plugin name, row index, Row)`` of every network source: Volatility 3's netstat / netscan and, for the images it cannot read
    (Windows XP / 2003) or when its symbols are missing, Volatility 2's plugins converted to the same columns."""
    for plugin_name in (PLUGIN_NETSTAT, PLUGIN_NETSCAN):
        for index, row in _iter_rows(plugins, plugin_name):
            yield plugin_name, index, row
    for plugin in plugins:
        if plugin.name in vol2_adapter.NETWORK_RESULTS and plugin.status == "Completed":
            for index, raw in enumerate(vol2_adapter.network_rows(plugin.name, [r for r in flatten_rows(plugin.rows) if isinstance(r, dict)])):
                yield plugin.name, index, Row(raw)


def _apply_network(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> List[NetworkConnection]:
    merged: Dict[Tuple, NetworkConnection] = {}
    for plugin_name, index, row in _network_rows(plugins):
        pid = row.integer(PID_KEYS, -1)
        pid = -1 if pid is None else pid
        owner = row.text(["Owner", "Process", "ProcessName", "ImageFileName", "Name"])
        local_address = row.text(["LocalAddr", "LocalAddress", "Local", "Source", "SourceAddress"])
        remote_address = row.text(["ForeignAddr", "RemoteAddress", "Remote", "Destination", "ForeignAddress", "DestinationAddress"])
        local_port = row.text(["LocalPort", "SourcePort"])
        remote_port = row.text(["ForeignPort", "RemotePort", "DestinationPort"])
        state = row.text(["State", "ConnectionState", "TCPState", "Status"])
        proto = row.text(["Proto", "Protocol"])
        created = row.text(["Created", "CreateTime"])
        if not (local_address or remote_address):
            continue
        key = (pid, local_address, local_port, remote_address, remote_port, state, proto)
        existing = merged.get(key)
        if existing:
            if plugin_name not in existing.source_plugins:
                existing.source_plugins.append(plugin_name)
            if not existing.created and created:
                existing.created = created
            continue
        name = owner or (processes[pid].name if pid in processes else "")
        provenance = {
            "row": _prov(plugin_name, index, "connection", "", f"{local_address}:{local_port} -> {remote_address}:{remote_port}")
        }
        merged[key] = NetworkConnection(pid, name, local_address, local_port, remote_address, remote_port,
                                        state, proto, [plugin_name], provenance, created)
    connections = list(merged.values())
    for conn in connections:
        proc = processes.get(conn.pid)
        if proc:
            proc.network.append(conn)
    return connections


def _apply_malfind(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> List[MemoryRegion]:
    regions: List[MemoryRegion] = []
    for index, row in _iter_rows(plugins, PLUGIN_MALFIND):
        pid = row.integer(PID_KEYS)
        if pid is None:
            continue
        proc = processes.get(pid)
        start = to_int(row.value(["Start VPN", "Start", "VadStart", "Address"], None))
        end = to_int(row.value(["End VPN", "End", "VadEnd"], None))
        protection = row.text(["Protection", "Protect", "MemoryProtection"])
        prot = protection.upper()
        size = ""
        if start is not None and end is not None and end >= start:
            size = human_size(end - start + 1)
        private_raw = row.value(["PrivateMemory", "Private"], None)
        private = bool(to_int(private_raw, 0)) if private_raw is not None else True
        details = dict(row.raw)
        region = MemoryRegion(
            pid, row.text(["Process", "ProcessName", "Name"]) or (proc.name if proc else ""),
            to_hex(start) if start is not None else "", to_hex(end) if end is not None else "", size, protection,
            private, "EXECUTE" in prot, "WRITE" in prot or "READWRITE" in prot, "READ" in prot or "EXECUTE" in prot,
            PLUGIN_MALFIND, details, {"row": _prov(PLUGIN_MALFIND, index, "region", "Start VPN", start)},
            row.text(["Tag"]),
        )
        regions.append(region)
        if proc:
            proc.memory_regions.append(region)
    return regions


def _apply_handles(processes: Dict[int, Process], plugins: Sequence[PluginResult]) -> None:
    for _index, row in _iter_rows(plugins, PLUGIN_HANDLES):
        pid = row.integer(PID_KEYS)
        proc = processes.get(pid) if pid is not None else None
        if not proc:
            continue
        htype = row.text(["Type", "HandleType"])
        name = row.text(["Name", "Object"])
        proc.handle_summary[htype or "?"] = proc.handle_summary.get(htype or "?", 0) + 1
        if not name and htype.lower() not in _HANDLE_KEEP_ALWAYS:
            continue  # unnamed noise (events, ETW registrations, ...) only counted
        proc.handles.append({
            "type": htype, "name": name, "value": to_hex(row.value(["HandleValue", "Handle"], "")),
            "access": to_int(row.value(["GrantedAccess", "Access"], 0), 0) or 0,
        })


def _system_context(plugins: Sequence[PluginResult]) -> Tuple[List[dict], str]:
    info: List[dict] = []
    capture_time = ""
    for plugin in plugins:
        if plugin.name == PLUGIN_INFO and plugin.status == "Completed":
            for row in flatten_rows(plugin.rows):
                if isinstance(row, dict):
                    info.append(row)
                    if str(row.get("Variable", "")).lower() == "systemtime":
                        capture_time = str(row.get("Value", "") or "")
    return info, capture_time


# ----------------------------------------------------------------------------- public API
def normalize(dump_path: str, plugins: Sequence[PluginResult]) -> AnalysisResult:
    """Build an :class:`AnalysisResult` (without indications/timeline) from plugin results."""
    warnings: List[str] = []
    skipped = [p.name for p in plugins if p.skipped]
    for plugin in plugins:
        if plugin.failed:
            detail = (plugin.error or "no details").strip().splitlines()
            warnings.append(f"{plugin.name} did not complete: {detail[-1][:240] if detail else 'no details'}")
    if skipped:
        warnings.append(f"Not run because they do not exist for this Windows version: {', '.join(skipped)} (see Plugin Output for the reason).")

    processes = _build_processes(plugins, warnings)

    steps = (
        ("pstree details", lambda: _enrich_from_pstree(processes, plugins)),
        ("command lines", lambda: _apply_cmdline(processes, plugins)),
        ("loaded modules", lambda: _apply_dlls(processes, plugins)),
        ("handles", lambda: _apply_handles(processes, plugins)),
    )
    for label, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001
            log.exception("Normalizing %s failed", label)
            warnings.append(f"Could not normalize {label}: {exc}")

    accounts: List[dict] = []
    connections: List[NetworkConnection] = []
    regions: List[MemoryRegion] = []
    try:
        accounts = _apply_sids(processes, plugins)
    except Exception as exc:  # noqa: BLE001
        log.exception("Normalizing getsids failed")
        warnings.append(f"Could not normalize user identities: {exc}")
    try:
        connections = _apply_network(processes, plugins)
    except Exception as exc:  # noqa: BLE001
        log.exception("Normalizing network failed")
        warnings.append(f"Could not normalize network connections: {exc}")
    try:
        regions = _apply_malfind(processes, plugins)
    except Exception as exc:  # noqa: BLE001
        log.exception("Normalizing malfind failed")
        warnings.append(f"Could not normalize memory regions: {exc}")

    for proc in processes.values():
        if not proc.path:
            proc.path = ""
    system_info, capture_time = _system_context(plugins)
    users = [f"{a['name']} — {a['sid']}" if a["name"] != a["sid"] else a["sid"] for a in accounts]

    return AnalysisResult(
        dump_path=dump_path,
        processes=sorted(processes.values(), key=lambda p: p.pid),
        indications=[],
        plugins=list(plugins),
        memory_regions=regions,
        timeline=[],
        system_info=system_info,
        users=users,
        connections=connections,
        warnings=warnings,
        accounts=accounts,
        capture_time=capture_time,
    )
