"""One registry tree from every ``windows.registry.printkey`` result in an investigation (no Qt, unit-tested without a GUI).

The Run keys, Winlogon / IFEO / AppInit, Active Setup, the whole ``Services`` key and any key the investigator fetched on demand were each read by a printkey run.
This module merges their rows into a browsable tree: hive -> keys -> values. Key paths are reduced to a hive and the path inside it
(``\\Device\\HarddiskVolume1\\WINDOWS\\system32\\config\\software\\Microsoft\\...`` -> hive ``SOFTWARE``, key ``Microsoft\\...``); a user hive is named after
the user (``NTUSER.DAT (Administrator)``). Reading is local: nothing is fetched here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from app.util import to_int

PRINTKEY_PREFIX = "windows.registry.printkey ["
CUSTOM_PREFIX = "windows.registry.printkey [custom: "
UNKNOWN_HIVE = "(hive not named)"
_CONFIG = re.compile(r"^(?:.*\\system32\\)?config\\([^\\]+)(?:\\(.*))?$", re.IGNORECASE)
_USER = re.compile(r"^(?:.*?\\)?([^\\]+)\\(ntuser\.dat|usrclass\.dat)(?:\\(.*))?$", re.IGNORECASE)
_REGISTRY = re.compile(r"^\\?registry\\(?:machine|user)\\([^\\]+)(?:\\(.*))?$", re.IGNORECASE)


@dataclass
class Value:
    name: str
    type: str
    data: str


@dataclass
class KeyNode:
    name: str
    hive: str
    path: str                       # inside the hive, e.g. "Microsoft\\Windows\\CurrentVersion\\Run"
    parent: Optional["KeyNode"] = None
    children: Dict[str, "KeyNode"] = field(default_factory=dict)
    values: List[Value] = field(default_factory=list)
    last_write: str = ""
    sources: List[str] = field(default_factory=list)       # printkey results that contributed

    @property
    def full_path(self) -> str:
        return f"{self.hive}\\{self.path}" if self.path else self.hive

    def subkeys(self) -> List["KeyNode"]:
        return sorted(self.children.values(), key=lambda n: n.name.lower())

    def count(self) -> int:
        return 1 + sum(child.count() for child in self.children.values())


def split_key(key: str) -> Tuple[str, str]:
    """``(hive label, path inside the hive)`` of a Key column value."""
    text = str(key or "").replace("/", "\\").strip("\\")
    match = _USER.match(text)
    if match:
        label = f"{match.group(2).upper() if match.group(2).lower() == 'ntuser.dat' else 'UsrClass.dat'} ({match.group(1)})"
        return label, (match.group(3) or "")
    match = _CONFIG.match(text)
    if match:
        return match.group(1).upper(), (match.group(2) or "")
    match = _REGISTRY.match(text)
    if match:
        return match.group(1).upper(), (match.group(2) or "")
    return UNKNOWN_HIVE, text


class RegistryTree:
    def __init__(self, plugins: Iterable):
        self.hives: Dict[str, KeyNode] = {}
        self.keys = 0
        self.values = 0
        for plugin in plugins:
            if plugin.name.startswith(PRINTKEY_PREFIX) and plugin.status == "Completed":
                self._add(plugin.name, plugin.rows)

    def _node(self, hive: str, path: str, source: str) -> KeyNode:
        root = self.hives.get(hive.lower())
        if root is None:
            root = self.hives[hive.lower()] = KeyNode(hive, hive, "")
        node = root
        built = []
        for part in [p for p in path.split("\\") if p]:
            built.append(part)
            child = node.children.get(part.lower())
            if child is None:
                child = node.children[part.lower()] = KeyNode(part, hive, "\\".join(built), node)
                self.keys += 1
            node = child
        if source and source not in node.sources:
            node.sources.append(source)
        return node

    def _add(self, source: str, rows) -> None:
        for row in rows:
            if not isinstance(row, dict) or not row.get("Key"):
                continue
            hive, path = split_key(row["Key"])
            kind = str(row.get("Type") or "")
            if kind.lower() == "key":                                   # a subkey of this key, with its own last-write time
                child = self._node(hive, f"{path}\\{row.get('Name') or ''}".strip("\\"), source)
                child.last_write = child.last_write or str(row.get("Last Write Time") or "")
                continue
            node = self._node(hive, path, source)
            node.last_write = node.last_write or str(row.get("Last Write Time") or "")
            value = Value(str(row.get("Name") or "(default)"), kind, "" if row.get("Data") is None else str(row.get("Data")))
            if not any(v.name == value.name and v.data == value.data for v in node.values):
                node.values.append(value)
                self.values += 1

    def roots(self) -> List[KeyNode]:
        return sorted(self.hives.values(), key=lambda n: n.name.lower())

    def find(self, text: str, limit: int = 500) -> List[Tuple[KeyNode, Optional[Value]]]:
        """Keys whose name or path contains every word of ``text``, and values whose key path, name or data does (value matches carry the value)."""
        words = [w for w in text.lower().split() if w]
        if not words:
            return []
        found: List[Tuple[KeyNode, Optional[Value]]] = []
        stack = list(self.roots())
        while stack and len(found) < limit:
            node = stack.pop()
            stack.extend(node.children.values())
            if all(w in node.full_path.lower() for w in words):
                found.append((node, None))
            for value in node.values:
                if all(w in f"{node.full_path} {value.name} {value.data}".lower() for w in words):
                    found.append((node, value))
        return sorted(found, key=lambda m: (m[0].full_path.lower(), m[1].name.lower() if m[1] else ""))

    def lookup(self, hive_and_path: str) -> Optional[KeyNode]:
        parts = [p for p in str(hive_and_path).replace("/", "\\").split("\\") if p]
        node = self.hives.get(parts[0].lower()) if parts else None
        for part in parts[1:]:
            node = node.children.get(part.lower()) if node is not None else None
        return node
