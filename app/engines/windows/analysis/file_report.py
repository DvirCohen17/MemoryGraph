"""A read-only report about a file dumped from memory: type, hashes, entropy, PE structure, interesting strings.

Everything is computed from the bytes of the dumped file with the standard library only (no pefile, no network). Nothing here
executes or loads the file. Limits: only the first ``MAX_ANALYSE_BYTES`` are scanned for strings/entropy (hashes cover the whole file).
A memory dump of a file is not always the file as it was on disk (pages that were not in memory read as zeros), and PE header
fields such as the compile time are written by whoever built the file and can be forged.
"""
from __future__ import annotations

import datetime
import hashlib
import math
import os
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

MAX_ANALYSE_BYTES = 32 * 1024 * 1024
MAX_STRINGS = 300
SUSPICIOUS_APIS = (
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
    "QueueUserAPC", "SetThreadContext", "NtUnmapViewOfSection", "OpenProcess", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "URLDownloadToFile", "InternetOpen", "InternetReadFile", "WinExec", "ShellExecute", "CreateProcess", "RegSetValue", "CryptEncrypt",
    "SetWindowsHookEx", "GetAsyncKeyState", "IsDebuggerPresent", "AdjustTokenPrivileges", "CreateService", "StartService",
)
_SECTION_FLAGS = ((0x20000000, "X"), (0x40000000, "R"), (0x80000000, "W"))
_MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
_SUBSYSTEMS = {1: "native (driver)", 2: "Windows GUI", 3: "Windows console", 5: "OS/2 console", 9: "Windows CE", 10: "EFI application"}
_URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>\\]{4,}", re.IGNORECASE)
_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_WIN_PATH = re.compile(r"[A-Za-z]:\\[^\s\"'<>|*?]{3,}")
_REGISTRY = re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\s\"'<>]{3,}", re.IGNORECASE)
_ASCII_STRING = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


@dataclass
class Section:
    name: str
    virtual_size: int
    raw_size: int
    raw_offset: int
    flags: str
    entropy: Optional[float]
    notes: List[str] = field(default_factory=list)
    virtual_address: int = 0


@dataclass
class PEInfo:
    machine: str = ""
    kind: str = ""                              # "DLL" / "EXE" / "driver"
    timestamp: str = ""
    entry_point: int = 0
    entry_section: str = ""
    image_base: int = 0
    subsystem: str = ""
    sections: List[Section] = field(default_factory=list)
    imports: Dict[str, int] = field(default_factory=dict)       # DLL name -> number of imported functions
    suspicious_imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    export_count: int = 0
    signed: bool = False                        # a certificate table exists (NOT a validated signature)
    overlay_size: int = 0
    warnings: List[str] = field(default_factory=list)


@dataclass
class FileReport:
    path: str
    size: int
    sha256: str
    md5: str
    kind: str
    entropy: float
    zero_fraction: float
    analysed_bytes: int
    truncated: bool
    pe: Optional[PEInfo] = None
    strings: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    registry: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


# ----------------------------------------------------------------------------- basics
def shannon_entropy(data: bytes) -> float:
    """Bits per byte (0 = constant, 8 = random/compressed/encrypted)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts if c)


_MAGIC = ((b"MZ", "Windows executable (PE)"), (b"\x7fELF", "ELF executable"), (b"PK\x03\x04", "ZIP archive / Office / JAR"),
          (b"%PDF", "PDF document"), (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 container (old Office document, MSI)"),
          (b"Rar!", "RAR archive"), (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"), (b"MSCF", "Cabinet archive"), (b"\x1f\x8b", "gzip data"),
          (b"\x89PNG", "PNG image"), (b"\xff\xd8\xff", "JPEG image"), (b"GIF8", "GIF image"), (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (.lnk)"),
          (b"regf", "Registry hive"), (b"SQLite format 3", "SQLite database"), (b"\xfe\xed\xfa", "Mach-O executable"))


def detect_type(data: bytes) -> str:
    head = data[:512]
    if not head:
        return "empty"
    for magic, name in _MAGIC:
        if head.startswith(magic):
            return name
    if head.startswith(b"\xff\xfe") or head.startswith(b"\xfe\xff"):
        return "UTF-16 text"
    if head.startswith(b"\xef\xbb\xbf") or (sum(32 <= b < 127 or b in (9, 10, 13) for b in head) / len(head) > 0.95):
        return "text / script"
    if not any(head):
        return "zeros (the pages were not in memory)"
    return "binary data"


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> List[str]:
    """Printable ASCII and UTF-16LE strings of at least 6 characters, in file order, without duplicates."""
    found: Dict[int, str] = {}
    for match in _ASCII_STRING.finditer(data):
        found[match.start()] = match.group().decode("ascii")
        if len(found) >= limit * 20:
            break
    for match in _UTF16_STRING.finditer(data):
        found[match.start()] = match.group().decode("utf-16-le")
        if len(found) >= limit * 20:
            break
    seen, ordered = set(), []
    for _offset, text in sorted(found.items()):
        if text not in seen:
            seen.add(text)
            ordered.append(text)
    return ordered[:limit * 20]


def _first(pattern, strings, limit=40) -> List[str]:
    found: List[str] = []
    for text in strings:
        for hit in pattern.findall(text):
            if hit not in found:
                found.append(hit)
                if len(found) >= limit:
                    return found
    return found


# ----------------------------------------------------------------------------- PE
def parse_pe(data: bytes) -> Optional[PEInfo]:
    """Headers, sections, imports and exports of a PE file; None when ``data`` is not a PE. Tolerates truncated / zero-filled dumps."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return None
    machine, n_sections, stamp, _sym, _nsym, opt_size, characteristics = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
    info = PEInfo(machine=_MACHINES.get(machine, f"0x{machine:x}"))
    info.kind = "DLL" if characteristics & 0x2000 else "EXE"
    if stamp:
        try:
            info.timestamp = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OverflowError, OSError, ValueError):
            info.timestamp = f"invalid (0x{stamp:x})"
        else:
            built = datetime.datetime.fromtimestamp(stamp, datetime.timezone.utc)
            if built > datetime.datetime.now(datetime.timezone.utc) or built.year < 1995:
                info.warnings.append("The compile time is not a real date (Windows' own files, and reproducible builds, store a hash there).")
    opt = e_lfanew + 0x18
    if opt + 2 > len(data):
        info.warnings.append("The optional header is cut off.")
        return info
    magic = struct.unpack_from("<H", data, opt)[0]
    plus = magic == 0x20B
    try:
        info.entry_point = struct.unpack_from("<I", data, opt + 16)[0]
        info.image_base = struct.unpack_from("<Q" if plus else "<I", data, opt + (24 if plus else 28))[0]
        info.subsystem = _SUBSYSTEMS.get(struct.unpack_from("<H", data, opt + 68)[0], "")
        if info.subsystem.startswith("native"):
            info.kind = "driver" if not characteristics & 0x2000 else info.kind
        dir_base = opt + (112 if plus else 96)
        count = struct.unpack_from("<I", data, dir_base - 4)[0]
        directories = [struct.unpack_from("<II", data, dir_base + 8 * i) for i in range(min(count, 16)) if dir_base + 8 * i + 8 <= len(data)]
    except struct.error:
        info.warnings.append("The optional header is cut off.")
        return info
    table = opt + opt_size
    raw_end = 0
    for index in range(min(n_sections, 96)):
        entry = table + 40 * index
        if entry + 40 > len(data):
            info.warnings.append("The section table is cut off.")
            break
        name = data[entry:entry + 8].rstrip(b"\0").decode("latin-1", "replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, entry + 8)
        flags = struct.unpack_from("<I", data, entry + 36)[0]
        text = "".join(letter for bit, letter in _SECTION_FLAGS if flags & bit)
        chunk = data[roff:roff + rsize] if rsize and roff < len(data) else b""
        section = Section(name, vsize, rsize, roff, text, round(shannon_entropy(chunk), 2) if chunk else None, virtual_address=vaddr)
        if "W" in text and "X" in text:
            section.notes.append("writable and executable")
        if section.entropy is not None and section.entropy > 7.2 and len(chunk) > 1024:
            section.notes.append("high entropy (packed or encrypted?)")
        if rsize and chunk and not any(chunk[:4096]):
            section.notes.append("zeros in the dump (pages not in memory)")
        info.sections.append(section)
        raw_end = max(raw_end, roff + rsize)
        if vaddr <= info.entry_point < vaddr + max(vsize, rsize) and not info.entry_section:
            info.entry_section = name
    if info.entry_point and not info.entry_section and info.sections:
        info.warnings.append("The entry point is outside every section.")
    if raw_end and len(data) > raw_end + 512 and len(data) < MAX_ANALYSE_BYTES:
        info.overlay_size = len(data) - raw_end

    def to_offset(rva: int) -> Optional[int]:
        for section in info.sections:
            if section.virtual_address <= rva < section.virtual_address + max(section.raw_size, section.virtual_size):
                return section.raw_offset + (rva - section.virtual_address)
        return rva if rva < len(data) else None            # headers (rva == file offset)

    def read_cstring(offset: Optional[int], limit: int = 256) -> str:
        if offset is None or offset >= len(data):
            return ""
        end = data.find(b"\0", offset, offset + limit)
        return data[offset:end if end != -1 else offset + limit].decode("latin-1", "replace")

    try:
        if len(directories) > 4 and directories[4][0] and directories[4][1]:
            info.signed = True                                  # security directory present
        if len(directories) > 1 and directories[1][0]:
            _read_imports(data, info, to_offset, read_cstring, plus, directories[1][0])
        if directories and directories[0][0]:
            _read_exports(data, info, to_offset, read_cstring, directories[0][0])
        if len(directories) > 1 and directories[1][0] and not info.imports:
            info.warnings.append("The headers announce an import table, but it is empty or zero in this dump: those pages were not in memory.")
        if directories and directories[0][0] and not info.export_count:
            info.warnings.append("The headers announce an export table, but it is empty or zero in this dump: those pages were not in memory.")
    except (struct.error, IndexError, ValueError):
        info.warnings.append("The import or export table could not be read completely (damaged or partly zero-filled dump).")
    return info


def _read_imports(data, info, to_offset, read_cstring, plus, rva) -> None:
    offset = to_offset(rva)
    step = 8 if plus else 4
    descriptors = 0
    while offset is not None and offset + 20 <= len(data) and descriptors < 200:
        original, _stamp, _forwarder, name_rva, first = struct.unpack_from("<IIIII", data, offset)
        if not (original or first or name_rva):
            break
        dll = read_cstring(to_offset(name_rva)).lower()
        thunk = to_offset(original or first)
        count = 0
        while thunk is not None and thunk + step <= len(data) and count < 5000:
            value = struct.unpack_from("<Q" if plus else "<I", data, thunk)[0]
            if not value:
                break
            if not value >> (63 if plus else 31):                # imported by name (the high bit means by ordinal)
                name_offset = to_offset(value & 0x7FFFFFFF)
                api = read_cstring(name_offset + 2 if name_offset is not None else None, 80)
                if api.startswith(SUSPICIOUS_APIS) and api not in info.suspicious_imports and len(info.suspicious_imports) < 40:
                    info.suspicious_imports.append(api)
            count += 1
            thunk += step
        if dll:
            info.imports[dll] = info.imports.get(dll, 0) + count
        descriptors += 1
        offset += 20


def _read_exports(data, info, to_offset, read_cstring, rva) -> None:
    offset = to_offset(rva)
    if offset is None or offset + 40 > len(data):
        return
    info.export_count = struct.unpack_from("<I", data, offset + 20)[0]
    n_names = struct.unpack_from("<I", data, offset + 24)[0]
    names_rva = struct.unpack_from("<I", data, offset + 32)[0]
    names = to_offset(names_rva)
    for index in range(min(n_names, 60)):
        if names is None or names + 4 * index + 4 > len(data):
            break
        info.exports.append(read_cstring(to_offset(struct.unpack_from("<I", data, names + 4 * index)[0]), 120))


# ----------------------------------------------------------------------------- report
def build_report(path: str, max_bytes: int = MAX_ANALYSE_BYTES) -> FileReport:
    """Hash the whole file and analyse its first ``max_bytes``."""
    size = os.path.getsize(path)
    sha, md5 = hashlib.sha256(), hashlib.md5()           # md5 only because offline lookup lists still use it
    with open(path, "rb") as handle:
        head = handle.read(max_bytes)
        sha.update(head)
        md5.update(head)
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(block)
            md5.update(block)
    report = FileReport(path, size, sha.hexdigest(), md5.hexdigest(), detect_type(head), round(shannon_entropy(head), 3),
                        round(head.count(0) / len(head), 3) if head else 0.0, len(head), size > len(head))
    report.pe = parse_pe(head)
    texts = extract_strings(head)
    report.strings = texts[:MAX_STRINGS]
    report.urls, report.ips = _first(_URL, texts), [ip for ip in _first(_IP, texts) if not ip.startswith(("0.", "127."))]
    report.paths, report.registry = _first(_WIN_PATH, texts), _first(_REGISTRY, texts)
    if report.zero_fraction > 0.5:
        report.notes.append(f"{report.zero_fraction:.0%} of the bytes are zero: much of the file was not in memory when the image was taken.")
    if report.entropy > 7.2 and (report.pe is None or not report.pe.sections):
        report.notes.append("High entropy: the content looks compressed or encrypted.")
    if report.truncated:
        report.notes.append(f"Only the first {len(head) // (1024 * 1024)} MiB were analysed for strings and entropy; the hashes cover the whole file.")
    return report
