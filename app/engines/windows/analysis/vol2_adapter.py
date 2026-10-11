"""Volatility 2 network rows in the shape of Volatility 3's ``windows.netscan`` rows, so the normalizer merges both into one connection list.

Columns, as the Volatility 2 source defines them (``unified_output`` of each plugin):
  connections  Offset(V)  LocalAddress "1.2.3.4:1034"  RemoteAddress "5.6.7.8:80"  PID
  connscan     Offset(P)  LocalAddress  RemoteAddress  PID
  sockets      Offset(V)  PID  Port  Proto (number)  Protocol ("TCP")  Address  Create Time
  sockscan     Offset(P)  PID  Port  Proto  Protocol  Address  Create Time
  netscan      Offset(P)  Proto ("TCPv4")  LocalAddr "ip:port"  ForeignAddr "ip:port"  State  PID  Owner  Created
Column names are matched ignoring case, spaces and underscores, so ``LocalAddress`` and ``Local Address`` are the same.

A connection seen by both the list walk (connections) and the scan (connscan) has the same endpoints and PID, so it becomes one row in the Network view
with both plugins named as its source: the data is shown once, the sources are what is compared.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

NETWORK_RESULTS = ("vol2.connections", "vol2.connscan", "vol2.sockets", "vol2.sockscan", "vol2.netscan")


def _key(name: str) -> str:
    return re.sub(r"[\s_]+", "", str(name)).lower()


def _get(row: Dict[str, Any], *names: str) -> Any:
    lowered = {_key(k): v for k, v in row.items()}
    for name in names:
        value = lowered.get(_key(name))
        if value not in (None, ""):
            return value
    return ""


def _split(endpoint: str) -> Tuple[str, str]:
    """``address, port`` of ``1.2.3.4:80``, ``*:*``, ``:::0`` (IPv6 wildcard), ``[::1]:80``; the port is whatever follows the last colon."""
    text = str(endpoint or "").strip()
    if not text:
        return "", ""
    if text.startswith("[") and "]" in text:
        close = text.find("]")
        return text[1:close], text[close + 2:] if text[close + 1:close + 2] == ":" else ""
    if ":" in text:
        address, port = text.rsplit(":", 1)
        if port.isdigit() or port == "*":
            return address, port
    return text, ""


def _unset(address: str, port: str) -> bool:
    """A remote endpoint that only says "any": listening sockets and UDP."""
    return address in ("", "*", "0.0.0.0", "::", ":::") and port in ("", "0", "*")


def network_rows(result_name: str, rows: List[dict]) -> List[dict]:
    """Rows of one Volatility 2 network plugin as netscan-style dicts (``Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, Created``)."""
    out: List[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if result_name in ("vol2.connections", "vol2.connscan"):
            local, remote = str(_get(row, "LocalAddress", "LocalAddr")), str(_get(row, "RemoteAddress", "ForeignAddr"))
            proto, state, owner, created = "TCPv4", "", "", ""
            pid = _get(row, "PID")
        elif result_name in ("vol2.sockets", "vol2.sockscan"):
            protocol = str(_get(row, "Protocol")).strip() or str(_get(row, "Proto"))
            address, port = str(_get(row, "Address")), str(_get(row, "Port"))
            local, remote = (f"{address}:{port}" if address and port else address or port), ""
            proto = (protocol + "v4") if protocol.upper() in ("TCP", "UDP") else protocol
            state = "LISTENING" if protocol.upper() == "TCP" else ""
            pid, owner, created = _get(row, "PID"), "", str(_get(row, "CreateTime"))
        elif result_name == "vol2.netscan":
            local, remote = str(_get(row, "LocalAddr", "LocalAddress")), str(_get(row, "ForeignAddr", "RemoteAddress"))
            proto, state, owner, created = str(_get(row, "Proto")), str(_get(row, "State")), str(_get(row, "Owner")), str(_get(row, "Created"))
            pid = _get(row, "PID")
        else:
            continue
        local_address, local_port = _split(local)
        remote_address, remote_port = _split(remote)
        if _unset(remote_address, remote_port):
            remote_address = remote_port = ""
        if not (local_address or remote_address):
            continue
        try:
            pid_value: Any = int(pid)
        except (TypeError, ValueError):
            pid_value = -1
        out.append({"Proto": proto, "LocalAddr": local_address, "LocalPort": local_port, "ForeignAddr": remote_address, "ForeignPort": remote_port,
                    "State": state, "PID": pid_value, "Owner": owner, "Created": created})
    return out
