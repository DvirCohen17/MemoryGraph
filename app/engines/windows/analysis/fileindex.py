"""A folder tree over the file objects ``windows.filescan`` found in memory (no Qt in here, unit-tested without a GUI).

filescan prints ``\\Device\\HarddiskVolume2\\Windows\\System32\\ntdll.dll`` and the (kernel virtual) address of the FILE_OBJECT. This module
splits that into device + folders + file name, builds the tree an explorer needs, flags the same things rule FILE-001 flags, and
finds the dump files ``windows.dumpfiles`` wrote for an entry (``file.<offset>.<object>.<kind>.<name>.<ext>``).

A file object only proves that the file was opened while the system ran; whether its contents are still cached in memory
is only known after a dump.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from app.engines.windows.indicators.helpers import is_high_risk_dir
from app.util import norm_path, to_int

EXECUTABLE_EXTENSIONS = (".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".hta", ".wsf", ".cpl",
                         ".com", ".pif")
DOCUMENT_EXTENSIONS = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".jpeg", ".png", ".gif", ".rtf", ".zip",
                       ".mp3", ".mp4")
# Windows servicing leftovers (superseded component files waiting for deletion) are not "executables dropped in Temp".
BENIGN_TEMP_FRAGMENTS = ("\\windows\\winsxs\\temp\\", "\\windows\\servicing\\")
_STRICT = ("\\users\\public\\", "$recycle.bin\\", "\\recycler\\", "\\windows\\temp\\", "\\windows\\tasks\\", "\\windows\\debug\\")
_DEVICE = re.compile(r"^\\Device\\([^\\]+)(.*)$", re.IGNORECASE)
DAMAGED_DEVICE = "(damaged names)"
CACHE_KINDS = {"dat": "DataSectionObject", "img": "ImageSectionObject", "vacb": "SharedCacheMap"}


@dataclass
class FileEntry:
    offset: int                  # address of the FILE_OBJECT as filescan prints it (what windows.dumpfiles --virtaddr takes)
    device: str                  # "HarddiskVolume2", "Mup", "" when the name has no device
    path: str                    # "\Windows\System32\ntdll.dll" (device removed)
    row_index: int = -1          # row in the windows.filescan result (evidence provenance)
    raw: str = ""                # the name as filescan printed it (kept for names that were damaged)
    is_directory: bool = False   # filescan also lists folders that were opened; set by FileIndex when another entry lies below this one
    cached_flags: Optional[List[str]] = field(default=None, repr=False, compare=False)       # flags_for() result (depends on the path only)

    @property
    def name(self) -> str:
        return self.path.rsplit("\\", 1)[-1] or self.path

    @property
    def folder(self) -> str:
        return self.path.rsplit("\\", 1)[0] or "\\"

    @property
    def extension(self) -> str:
        base = self.name
        return base[base.rfind("."):].lower() if "." in base.strip(".") else ""

    @property
    def full_name(self) -> str:
        if self.device == DAMAGED_DEVICE:
            return self.raw
        return f"\\Device\\{self.device}{self.path}" if self.device else self.path

    @property
    def target(self) -> str:
        """Stable key for notes / bookmarks (device + lower-case path; the offset changes between dumps of the same system)."""
        return f"file|{self.device.lower()}|{self.path.lower()}"


def split_name(raw: str) -> Tuple[str, str]:
    """``(device, path)`` of a name as filescan prints it."""
    text = str(raw or "").strip().replace("/", "\\")
    match = _DEVICE.match(text)
    if match:
        return match.group(1), match.group(2) or "\\"
    return "", text


def is_damaged(device: str, path: str) -> bool:
    """A name that cannot be a path: it does not start with a backslash (no device and no root), or it holds control / replacement characters.
    filescan reads names out of pool memory; freed or half-overwritten objects leave fragments of other data there (on a real Windows 10 image: pieces of Windows
    Update XML manifests and garbled characters, 444 of 32,613 names). They are listed together instead of becoming a folder each."""
    if not device and not path.startswith("\\"):
        return True
    return any(ord(c) < 32 or c == "\ufffd" for c in path)


def entries_from_rows(rows: Iterable) -> List[FileEntry]:
    """File entries from windows.filescan rows (rows without a name or a usable offset are skipped). Damaged names go to one pseudo volume, each as a single
    flat name."""
    entries = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        name = str(row.get("Name") or "").strip()
        offset = to_int(row.get("Offset"))
        if not name or offset is None:
            continue
        device, path = split_name(name)
        if is_damaged(device, path):
            entries.append(FileEntry(offset, DAMAGED_DEVICE, "\\" + name.replace("\\", "/"), index, raw=name))
            continue
        entries.append(FileEntry(offset, device, path, index))
    return entries


# ----------------------------------------------------------------------------- flags
def flags_for(entry: FileEntry) -> List[str]:
    """Reasons this file deserves a look (the same ones rule FILE-001 reports), or []."""
    if entry.cached_flags is not None:
        return entry.cached_flags
    low = norm_path(entry.path)
    base = low.rsplit("\\", 1)[-1]
    flags = []
    if base.endswith(EXECUTABLE_EXTENSIONS):
        for ext in EXECUTABLE_EXTENSIONS:
            if base.endswith(ext) and any(base[:-len(ext)].endswith(doc) for doc in DOCUMENT_EXTENSIONS):
                flags.append("document name + executable extension")
                break
        if is_high_risk_dir(entry.path) and not any(f in low + "\\" for f in BENIGN_TEMP_FRAGMENTS):
            flags.append("executable in " + ("Public / Recycle Bin / Windows\\Temp" if any(s in low + "\\" for s in _STRICT) else "Temp / Downloads"))
    entry.cached_flags = flags
    return flags


# ----------------------------------------------------------------------------- tree
@dataclass
class Folder:
    name: str
    parent: Optional["Folder"] = None
    children: Dict[str, "Folder"] = field(default_factory=dict)
    files: List[FileEntry] = field(default_factory=list)
    _total: int = -1

    @property
    def path(self) -> str:
        parts, node = [], self
        while node.parent is not None and node.parent.parent is not None:      # the device level is not part of the path
            parts.append(node.name)
            node = node.parent
        return "\\" + "\\".join(reversed(parts))

    def total(self) -> int:
        if self._total < 0:
            self._total = len(self.files) + sum(child.total() for child in self.children.values())
        return self._total

    def subfolders(self) -> List["Folder"]:
        return sorted(self.children.values(), key=lambda f: (f.name == DAMAGED_DEVICE, f.name.lower()))      # the damaged names are listed last

    def all_files(self) -> List[FileEntry]:
        found = list(self.files)
        for child in self.children.values():
            found.extend(child.all_files())
        return found


class FileIndex:
    """All entries plus the tree: roots are devices (``HarddiskVolume2``), below them the folders."""

    def __init__(self, entries: Iterable[FileEntry]):
        self.entries: List[FileEntry] = list(entries)             # every file object filescan listed
        parents = set()
        for entry in self.entries:                                # a name that is the parent of another one is a folder that was opened
            parts = [p for p in entry.path.lower().split("\\") if p]
            for depth in range(1, len(parts)):
                parents.add((entry.device.lower(), "\\".join(parts[:depth])))
        for entry in self.entries:
            entry.is_directory = (entry.device.lower(), "\\".join(p for p in entry.path.lower().split("\\") if p)) in parents
        self.files: List[FileEntry] = [e for e in self.entries if not e.is_directory]
        self.root = Folder("")
        self.devices: Dict[str, Folder] = {}
        for entry in self.files:
            folder = self._device(entry.device)
            for part in [p for p in entry.path.split("\\")[:-1] if p]:
                folder = folder.children.setdefault(part.lower(), Folder(part, folder))
            folder.files.append(entry)

    def _device(self, device: str) -> Folder:
        key = device.lower()
        if key not in self.devices:
            self.devices[key] = Folder(device or "(volume not named)", self.root)
            self.root.children[key] = self.devices[key]
        return self.devices[key]

    def drive_hint(self, folder: Folder) -> str:
        """``C:`` for the device that holds \\Windows\\System32 (the system volume), '' for others."""
        node = folder
        while node.parent is not None and node.parent.parent is not None:
            node = node.parent
        windows = node.children.get("windows")
        return "C:" if windows is not None and "system32" in windows.children else ""

    def label(self, folder: Folder) -> str:
        """Name shown for a folder: the volume gets its drive letter when it can be told (``HarddiskVolume2 (C:)``)."""
        if folder.parent is self.root:
            hint = self.drive_hint(folder)
            if hint and folder.name == "(volume not named)":
                return f"{hint} (system volume)"
            return f"{folder.name} ({hint})" if hint else folder.name
        return folder.name or "This image"

    def breadcrumb(self, folder: Folder) -> List[str]:
        parts, node = [], folder
        while node is not None and node is not self.root:
            parts.append(self.label(node))
            node = node.parent
        return ["This image"] + list(reversed(parts))

    def resolve(self, text: str) -> Optional[Folder]:
        """The folder a typed address names: ``This image › HarddiskVolume2 (C:) › Windows``, ``HarddiskVolume2\\Windows``, ``C:\\Windows`` or
        just ``\\Windows\\System32`` (tried on every volume, the system volume first). None when no such folder exists in the image."""
        raw = str(text or "").strip().replace("/", "\\").replace("›", "\\")
        parts = [p.strip() for p in raw.split("\\") if p.strip()]
        if parts and parts[0].lower() == "this image":
            parts = parts[1:]
        if not parts:
            return self.root
        first = parts[0].split(" (")[0].lower()
        volumes = sorted(self.devices.values(), key=lambda f: (self.drive_hint(f) != "C:", -f.total()))
        start = None
        if first in self.devices:
            start, parts = self.devices[first], parts[1:]
        elif len(first) == 2 and first[1] == ":":
            start = next((v for v in volumes if self.drive_hint(v).lower() == first), None)
            if start is None:
                return None
            parts = parts[1:]
        for volume in ([start] if start is not None else volumes):
            node = volume
            for part in parts:
                node = node.children.get(part.lower()) if node is not None else None
            if node is not None:
                return node
        return None

    def folder_for(self, entry: FileEntry) -> Folder:
        folder = self._device(entry.device)
        for part in [p for p in entry.path.split("\\")[:-1] if p]:
            folder = folder.children[part.lower()]
        return folder

    def search(self, text: str, scope: Optional[Folder] = None) -> List[FileEntry]:
        """Entries in ``scope`` (default: everything) whose path contains every word of ``text`` (case-insensitive)."""
        words = [w for w in text.lower().split() if w]
        pool = scope.all_files() if scope is not None else self.files
        if not words:
            return pool
        return [e for e in pool if all(w in (e.device + e.path).lower() for w in words)]


# ----------------------------------------------------------------------------- dump files written by windows.dumpfiles
def index_dump_dir(directory: str) -> Dict[int, List[Tuple[str, str]]]:
    """``{FILE_OBJECT address: [(cache kind, path)]}`` for every ``file.<address>.…`` file in ``directory`` (one directory listing)."""
    found: Dict[int, List[Tuple[str, str]]] = {}
    if not directory or not os.path.isdir(directory):
        return found
    for name in sorted(os.listdir(directory)):
        parts = name.split(".")
        if len(parts) > 3 and parts[0].lower() == "file" and parts[1].lower().startswith("0x"):
            try:
                address = int(parts[1], 16)
            except ValueError:
                continue
            found.setdefault(address, []).append((CACHE_KINDS.get(parts[-1].lower(), parts[-1].lower()), os.path.join(directory, name)))
    return found


def dump_files_for(directory: str, offset: int) -> List[Tuple[str, str]]:
    """``[(cache kind, path)]`` of the files ``windows.dumpfiles`` wrote for the FILE_OBJECT at ``offset`` in ``directory``."""
    if not directory or not os.path.isdir(directory):
        return []
    prefix = f"file.{offset:#x}.".lower()
    found = []
    for name in sorted(os.listdir(directory)):
        if name.lower().startswith(prefix):
            ext = name.rsplit(".", 1)[-1].lower()
            found.append((CACHE_KINDS.get(ext, ext), os.path.join(directory, name)))
    return found
