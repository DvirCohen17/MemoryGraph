"""Shared normalized evidence models used by providers, rules and the GUI.

Saved investigations are versioned (``schema_version``). Loading is tolerant: unknown
fields are ignored and missing fields fall back to defaults, so investigations saved by
older versions of MemoryGraph still open.
"""
from __future__ import annotations

import gzip
import json
import os
from dataclasses import asdict, dataclass, field, fields
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = 4        # 4: AnalysisResult.case, Indication.triage


@dataclass
class DLL:
    name: str
    path: str
    base: str
    size: str
    suspicious: bool = False
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    load_time: str = ""


@dataclass
class NetworkConnection:
    pid: int
    process: str
    local_address: str = ""
    local_port: str = ""
    remote_address: str = ""
    remote_port: str = ""
    state: str = ""
    protocol: str = ""
    source_plugins: List[str] = field(default_factory=list)
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    created: str = ""

    @property
    def local(self) -> str:
        return _join_endpoint(self.local_address, self.local_port)

    @property
    def remote(self) -> str:
        return _join_endpoint(self.remote_address, self.remote_port)

    @classmethod
    def from_legacy(cls, pid: int, process: str, local: str, remote: str, state: str = "", **kwargs):
        local_address, local_port = split_endpoint(local)
        remote_address, remote_port = split_endpoint(remote)
        return cls(pid, process, local_address, local_port, remote_address, remote_port, state, **kwargs)


@dataclass
class MemoryRegion:
    pid: int
    process: str
    start: str = ""
    end: str = ""
    size: str = ""
    protection: str = ""
    private: bool = False
    executable: bool = False
    writable: bool = False
    readable: bool = False
    source_plugin: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tag: str = ""

    @property
    def range(self) -> str:
        if self.start and self.end:
            return f"{self.start} - {self.end}"
        return self.start or self.end or "Unknown"


@dataclass
class TimelineEvent:
    timestamp: str
    event_type: str
    description: str
    pid: int = 0
    source_plugin: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    severity: str = ""       # highest severity of findings on the same process ("" = none)
    category: str = ""       # Process / Network / Module / System / <plugin>
    process: str = ""


@dataclass
class EvidenceItem:
    type: str
    field: str
    value: str
    description: str = ""
    source_plugin: str = ""
    row_index: int = -1


@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    path: str
    image_base: str
    user: str
    session: int
    create_time: str
    command_line: str
    dlls: List[DLL] = field(default_factory=list)
    network: List[NetworkConnection] = field(default_factory=list)
    handles: List[Any] = field(default_factory=list)  # list of {"type","name","value","access"} dicts
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    status: str = "Normal"
    provenance: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    exit_time: str = ""
    threads: int = 0
    wow64: bool = False
    offset: str = ""
    source: str = "pslist"          # pslist | psscan | pstree
    hidden: bool = False            # found by psscan only and not marked as exited
    exited: bool = False
    groups: List[str] = field(default_factory=list)          # "Name (SID)" entries from getsids
    handle_summary: Dict[str, int] = field(default_factory=dict)  # handle type -> count


@dataclass
class Indication:
    title: str
    severity: str
    process_pid: int = 0
    summary: str = ""
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    source_plugins: List[str] = field(default_factory=list)
    rule_id: str = ""
    description: str = ""
    process_name: str = ""
    related_processes: List[str] = field(default_factory=list)
    confidence: str = "Medium"
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    score: float = 0.0
    category: str = ""
    # Set from the investigation's case state after every (re-)analysis (see case_state.apply_case); never the source of truth.
    triage: str = ""            # "" open | "reviewed" | "false_positive" | "baseline"
    triage_note: str = ""


@dataclass
class PluginResult:
    name: str
    status: str
    rows: List[dict]
    error: str = ""
    raw_output: str = ""
    command: List[str] = field(default_factory=list)
    duration: float = 0.0
    cached: bool = False

    @property
    def skipped(self) -> bool:
        """Not run on purpose (the plugin does not exist for this Windows version): the reason is in ``error``. Not a failure."""
        return self.status == "Skipped"

    @property
    def failed(self) -> bool:
        return self.status not in ("Completed", "Skipped")


@dataclass
class AnalysisResult:
    dump_path: str
    processes: List[Process]
    indications: List[Indication]
    plugins: List[PluginResult]
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    timeline: List[TimelineEvent] = field(default_factory=list)
    system_info: List[dict] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    connections: List[NetworkConnection] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    accounts: List[dict] = field(default_factory=list)   # {"sid","name","processes"}
    capture_time: str = ""
    case: Dict[str, Any] = field(default_factory=dict)    # investigator's work: triage decisions, notes, bookmarks, baselines
    tool_info: Dict[str, str] = field(default_factory=dict)    # what produced the result: Volatility versions, the time of the analysis
    target_os: str = "windows"                              # the operating system of the image = the engine that made and judges this result (app/engines)
    schema_version: int = SCHEMA_VERSION


# ----------------------------------------------------------------------------- endpoints
def _join_endpoint(address: str, port: str) -> str:
    address = str(address or "")
    port = str(port or "")
    if not address:
        return ""
    if not port:
        return address
    if ":" in address and not address.startswith("["):
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def split_endpoint(value: str):
    value = str(value or "").strip()
    if not value:
        return "", ""
    if value.startswith("[") and "]" in value:
        close = value.find("]")
        address = value[1:close]
        port = value[close + 2:] if value[close + 1:close + 2] == ":" else ""
        return address, port
    if value.count(":") == 1:
        return tuple(value.rsplit(":", 1))
    return value, ""


# ----------------------------------------------------------------------------- loading
def _known(cls, data: Dict[str, Any]) -> Dict[str, Any]:
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in names}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _dll_from_dict(data: Dict[str, Any]) -> DLL:
    return DLL(
        str(data.get("name", "") or ""), str(data.get("path", "") or ""), str(data.get("base", "") or ""),
        str(data.get("size", "") or ""), bool(data.get("suspicious", False)),
        dict(data.get("provenance", {}) or {}), str(data.get("load_time", "") or ""),
    )


def _network_from_dict(data: Dict[str, Any]) -> NetworkConnection:
    common = dict(
        protocol=str(data.get("protocol", "") or ""), source_plugins=list(data.get("source_plugins", []) or []),
        provenance=dict(data.get("provenance", {}) or {}), created=str(data.get("created", "") or ""),
    )
    if "local_address" in data or "remote_address" in data:
        return NetworkConnection(
            pid=_int(data.get("pid")), process=str(data.get("process", "") or ""),
            local_address=str(data.get("local_address", "") or ""), local_port=str(data.get("local_port", "") or ""),
            remote_address=str(data.get("remote_address", "") or ""), remote_port=str(data.get("remote_port", "") or ""),
            state=str(data.get("state", "") or ""), **common,
        )
    return NetworkConnection.from_legacy(
        _int(data.get("pid")), str(data.get("process", "") or ""), str(data.get("local", "") or ""),
        str(data.get("remote", "") or ""), str(data.get("state", "") or ""), **common,
    )


def _memory_from_dict(data: Dict[str, Any]) -> MemoryRegion:
    return MemoryRegion(
        pid=_int(data.get("pid")), process=str(data.get("process", "") or ""), start=str(data.get("start", "") or ""),
        end=str(data.get("end", "") or ""), size=str(data.get("size", "") or ""), protection=str(data.get("protection", "") or ""),
        private=bool(data.get("private", False)), executable=bool(data.get("executable", False)),
        writable=bool(data.get("writable", False)), readable=bool(data.get("readable", False)),
        source_plugin=str(data.get("source_plugin", "") or ""), details=dict(data.get("details", {}) or {}),
        provenance=dict(data.get("provenance", {}) or {}), tag=str(data.get("tag", "") or ""),
    )


def _evidence_from_dict(data: Dict[str, Any]) -> EvidenceItem:
    return EvidenceItem(
        str(data.get("type", "")), str(data.get("field", "")), str(data.get("value", "")),
        str(data.get("description", "")), str(data.get("source_plugin", "")), _int(data.get("row_index"), -1),
    )


def _handle_from_any(value: Any) -> Any:
    if isinstance(value, dict):
        return value
    return {"type": "", "name": str(value), "value": "", "access": 0}  # legacy: list of strings


def _process_from_dict(item: Dict[str, Any]) -> Process:
    data = dict(item)
    data["dlls"] = [_dll_from_dict(d) for d in data.get("dlls", []) if isinstance(d, dict)]
    data["network"] = [_network_from_dict(n) for n in data.get("network", []) if isinstance(n, dict)]
    data["handles"] = [_handle_from_any(h) for h in data.get("handles", [])]
    data["memory_regions"] = [_memory_from_dict(m) for m in data.get("memory_regions", []) if isinstance(m, dict)]
    data["provenance"] = dict(data.get("provenance", {}) or {})
    data["pid"] = _int(data.get("pid"))
    data["ppid"] = _int(data.get("ppid"))
    data["session"] = _int(data.get("session"))
    for key in ("name", "path", "image_base", "user", "create_time", "command_line"):
        data[key] = str(data.get(key, "") or "")
    return Process(**_known(Process, data))


def _indication_from_dict(item: Dict[str, Any]) -> Indication:
    data = dict(item)
    data["evidence_items"] = [_evidence_from_dict(e) for e in data.get("evidence_items", []) if isinstance(e, dict)]
    data.setdefault("title", "Indication")
    data.setdefault("severity", "Low")
    return Indication(**_known(Indication, data))


def analysis_result_to_dict(result: AnalysisResult, compact_plugins: bool = False) -> Dict[str, Any]:
    data = asdict(result)
    data["schema_version"] = SCHEMA_VERSION
    if compact_plugins:
        # raw_output duplicates the parsed rows; keep it only when parsing produced nothing.
        for plugin in data.get("plugins", []):
            if plugin.get("rows") and plugin.get("status") == "Completed":
                plugin["raw_output"] = ""
    return data


def analysis_result_from_dict(data: Dict[str, Any]) -> AnalysisResult:
    if not isinstance(data, dict):
        raise ValueError("The file does not contain a MemoryGraph investigation (expected a JSON object).")
    if "processes" not in data and "plugins" not in data:
        raise ValueError("The file is JSON but does not look like a MemoryGraph investigation (no processes or plugins).")
    processes = [_process_from_dict(p) for p in data.get("processes", []) if isinstance(p, dict)]
    indications = [_indication_from_dict(i) for i in data.get("indications", []) if isinstance(i, dict)]
    plugins = []
    for p in data.get("plugins", []):
        if isinstance(p, dict):
            p = dict(p)
            p.setdefault("name", "unknown")
            p.setdefault("status", "Completed")
            p["rows"] = list(p.get("rows", []) or [])
            plugins.append(PluginResult(**_known(PluginResult, p)))
    timeline = []
    for t in data.get("timeline", []):
        if isinstance(t, dict):
            t = dict(t)
            t.setdefault("timestamp", "")
            t.setdefault("event_type", "")
            t.setdefault("description", "")
            timeline.append(TimelineEvent(**_known(TimelineEvent, t)))
    return AnalysisResult(
        dump_path=str(data.get("dump_path", "") or ""), processes=processes, indications=indications, plugins=plugins,
        memory_regions=[_memory_from_dict(m) for m in data.get("memory_regions", []) if isinstance(m, dict)],
        timeline=timeline,
        system_info=[r for r in data.get("system_info", []) if isinstance(r, dict)],
        users=[str(u) for u in data.get("users", [])],
        connections=[_network_from_dict(c) for c in data.get("connections", []) if isinstance(c, dict)],
        warnings=[str(w) for w in data.get("warnings", [])],
        accounts=[a for a in data.get("accounts", []) if isinstance(a, dict)],
        capture_time=str(data.get("capture_time", "") or ""),
        case=dict(data.get("case") or {}) if isinstance(data.get("case"), dict) else {},
        tool_info={str(k): str(v) for k, v in (data.get("tool_info") or {}).items()} if isinstance(data.get("tool_info"), dict) else {},
        target_os=str(data.get("target_os") or "windows").lower(),
        schema_version=_int(data.get("schema_version"), 1),
    )


def save_analysis_result(result: AnalysisResult, file_path: str) -> str:
    """Write the investigation atomically (temp file + rename). ``.gz`` paths are gzip-compressed."""
    data = analysis_result_to_dict(result, compact_plugins=True)
    tmp_path = f"{file_path}.tmp"
    try:
        if file_path.lower().endswith(".gz"):
            with gzip.open(tmp_path, "wt", encoding="utf-8", compresslevel=5) as handle:
                json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
        else:
            with open(tmp_path, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp_path, file_path)
    except BaseException:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def load_analysis_result(file_path: str) -> AnalysisResult:
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    try:
        if file_path.lower().endswith(".gz"):
            with gzip.open(file_path, "rt", encoding="utf-8") as handle:
                data = json.load(handle)
        else:
            with open(file_path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"The file is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}") from exc
    except UnicodeDecodeError as exc:
        raise ValueError("The file is not a UTF-8 text/JSON investigation file.") from exc
    result = analysis_result_from_dict(data)
    from app.analysis.case_state import apply_case      # late import: case_state uses the models
    apply_case(result)
    return result
