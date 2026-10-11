"""Helpers for the hex view of memory regions (no Qt in here, unit-tested without a GUI).

malfind stores, per region, the *first 64 bytes* as text (``Hexdump``) and Volatility's own disassembly of them. This module

* parses that text back into bytes (Volatility prints 16 bytes per line followed by an ASCII column; other layouts are accepted),
* lays bytes out as ``address  hex  ascii`` lines and maps text positions back to byte offsets,
* searches bytes (hex with ``??`` wildcards, ASCII, UTF-16) and
* disassembles any number of bytes with capstone (optional dependency), resynchronising after undecodable bytes.

A region can be made bigger than 64 bytes by loading the file ``windows.malfind --dump`` wrote for it (``pid.<pid>.vad.<start>-<end>.dmp``).
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

WIDTH = 16
MAX_LOAD_BYTES = 2 * 1024 * 1024         # what the view loads from a dump file (131 072 lines of 16 bytes)
MAX_INSTRUCTION_BYTES = 15               # longest x86 instruction
_VOLATILITY_LINE = re.compile(r"(?:[0-9a-fA-F]{2} |   ){16}")
_HEX_TOKEN = re.compile(r"[0-9a-fA-F]{2}")
_HEX_RUN = re.compile(r"[0-9a-fA-F]+")


# ----------------------------------------------------------------------------- parsing
def parse_hexdump(text) -> bytes:
    """Bytes of a hexdump. Two layouts occur:

    * ``-r json`` (what MemoryGraph stores): one line of space-separated bytes, ``56 57 53 ...``, no ASCII column;
    * Volatility's text renderer: 16 bytes per line followed by an ASCII column (the hex field is always the first 48 characters).

    Lines that start with an offset (``0x1000:`` / ``00001000``) are accepted too."""
    out = bytearray()
    for line in str(text or "").splitlines():
        if not line.strip():
            continue
        tokens = line.split()
        if tokens[0].endswith(":") or tokens[0].lower().startswith("0x") or (len(tokens[0]) > 2 and _HEX_RUN.fullmatch(tokens[0])):
            line = line[line.index(tokens[0]) + len(tokens[0]):]       # drop the offset column
            tokens = tokens[1:]
        if not all(_HEX_TOKEN.fullmatch(token) for token in tokens):
            if len(line) > 48 and _VOLATILITY_LINE.fullmatch(line[:48]):
                tokens = line[:48].split()                             # hex field + ASCII column
            else:
                good = []                                              # unknown layout: leading hex tokens only
                for token in tokens:
                    if not _HEX_TOKEN.fullmatch(token):
                        break
                    good.append(token)
                tokens = good
        out.extend(int(token, 16) for token in tokens)
    return bytes(out)


def region_bytes(region) -> bytes:
    details = getattr(region, "details", None) or {}
    return parse_hexdump(details.get("Hexdump") or details.get("hexdump") or "")


# ----------------------------------------------------------------------------- layout
@dataclass(frozen=True)
class Layout:
    """Column positions of the text produced by :func:`format_dump`: ``<address>  <hex bytes>  <ascii>`` per line."""
    base: int
    length: int
    width: int = WIDTH

    @property
    def address_digits(self) -> int:
        return 16 if self.base + max(self.length, 1) > 0xFFFFFFFF else 8

    @property
    def hex_start(self) -> int:
        return self.address_digits + 2

    @property
    def ascii_start(self) -> int:
        return self.hex_start + self.width * 3 + 1

    def hex_column(self, offset: int) -> int:
        return self.hex_start + (offset % self.width) * 3

    def ascii_column(self, offset: int) -> int:
        return self.ascii_start + offset % self.width

    def line_of(self, offset: int) -> int:
        return offset // self.width

    def offset_at(self, line: int, column: int) -> Optional[int]:
        """Byte offset behind a text position (in the hex or the ASCII column), None for the address column or outside the data."""
        if column >= self.ascii_start:
            index = column - self.ascii_start
        elif column >= self.hex_start:
            index = min((column - self.hex_start) // 3, self.width - 1)
        else:
            return None
        offset = line * self.width + index
        return offset if 0 <= index < self.width and 0 <= offset < self.length else None


def format_dump(data: bytes, base: int = 0, width: int = WIDTH) -> str:
    layout = Layout(base, len(data), width)
    lines = []
    for start in range(0, len(data), width):
        chunk = data[start:start + width]
        hexes = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + start:0{layout.address_digits}x}  {hexes}  {text}")
    return "\n".join(lines)


def inspect_at(data: bytes, offset: int) -> str:
    """One line describing the bytes at ``offset`` as integers (little endian) and text."""
    if not 0 <= offset < len(data):
        return ""
    parts = [f"offset 0x{offset:x}", f"u8 {data[offset]} (0x{data[offset]:02x})"]
    for size, label in ((2, "u16"), (4, "u32"), (8, "u64")):
        if offset + size <= len(data):
            value = int.from_bytes(data[offset:offset + size], "little")
            parts.append(f"{label} {value} (0x{value:x})")
    text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data[offset:offset + 16])
    parts.append(f"text '{text}'")
    return "   ".join(parts)


# ----------------------------------------------------------------------------- search
SEARCH_MODES = ("hex", "ascii", "utf16")


def compile_pattern(text: str, mode: str = "hex", ignore_case: bool = False):
    """Compiled bytes pattern. ``hex``: ``4d 5a`` / ``4d5a`` / ``0x4d 0x5a`` with ``??`` for any byte; ``ascii``; ``utf16`` (little endian)."""
    if not text:
        raise ValueError("Enter something to search for.")
    if mode == "hex":
        cleaned = re.sub(r"0x", " ", text, flags=re.IGNORECASE).replace(",", " ")
        tokens = []
        for word in cleaned.split():
            if len(word) % 2:
                raise ValueError(f"'{word}' has an odd number of hex digits.")
            tokens += [word[i:i + 2] for i in range(0, len(word), 2)]
        pattern = b""
        for token in tokens:
            if token == "??":
                pattern += b"."
            elif _HEX_TOKEN.fullmatch(token):
                pattern += re.escape(bytes([int(token, 16)]))
            else:
                raise ValueError(f"'{token}' is not a hex byte (use 00-ff or ?? for any byte).")
        if not pattern:
            raise ValueError("Enter something to search for.")
        return re.compile(pattern, re.DOTALL)
    if mode == "utf16":
        return re.compile(re.escape(text.encode("utf-16-le")), re.DOTALL | (re.IGNORECASE if ignore_case else 0))
    if mode == "ascii":
        return re.compile(re.escape(text.encode("latin-1", "replace")), re.DOTALL | (re.IGNORECASE if ignore_case else 0))
    raise ValueError(f"Unknown search mode: {mode}")


def find_next(data: bytes, pattern, start: int = 0, wrap: bool = True) -> Optional[Tuple[int, int]]:
    """``(offset, length)`` of the first match at or after ``start`` (wrapping to the beginning), or None."""
    found = pattern.search(data, max(0, start))
    if found is None and wrap and start > 0:
        found = pattern.search(data, 0)
    return (found.start(), found.end() - found.start()) if found else None


def find_previous(data: bytes, pattern, before: int, wrap: bool = True) -> Optional[Tuple[int, int]]:
    """``(offset, length)`` of the last match that starts before ``before`` (wrapping to the end), or None."""
    best = last = None
    for match in pattern.finditer(data):
        last = (match.start(), match.end() - match.start())
        if match.start() < before:
            best = last
    return best if best is not None else (last if wrap else None)


def count_matches(data: bytes, pattern, cap: int = 10000) -> int:
    total = 0
    for _ in pattern.finditer(data):
        total += 1
        if total >= cap:
            break
    return total


# ----------------------------------------------------------------------------- disassembly
@dataclass(frozen=True)
class Instruction:
    address: int
    offset: int
    raw: bytes
    text: str
    valid: bool = True


def capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
    except ImportError:
        return False
    return True


def disassemble(data: bytes, base: int = 0, bits: int = 64, start: int = 0, limit: int = 200) -> Tuple[List[Instruction], str]:
    """Up to ``limit`` x86 instructions from ``data[start:]``; bytes that do not decode become ``db 0x..`` and decoding goes on after them.

    Returns ``(instructions, error)``; ``error`` is non-empty when capstone is not installed."""
    try:
        import capstone
    except ImportError:
        return [], "capstone is not installed (pip install \"capstone>=5.0.3,<6\"); the hex view works without it."
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    out: List[Instruction] = []
    position = max(0, start)
    while position < len(data) and len(out) < limit:
        chunk = data[position:position + MAX_INSTRUCTION_BYTES]
        decoded = next(iter(md.disasm(chunk, base + position, 1)), None)
        if decoded is None:
            out.append(Instruction(base + position, position, data[position:position + 1], f"db 0x{data[position]:02x}", valid=False))
            position += 1
            continue
        out.append(Instruction(base + position, position, bytes(decoded.bytes), f"{decoded.mnemonic} {decoded.op_str}".strip()))
        position += decoded.size
    return out, ""


# ----------------------------------------------------------------------------- dump files written by windows.malfind --dump
def find_dump_file(directory: str, pid: int, start: int, end: int) -> Optional[str]:
    """The ``pid.<pid>.vad.<start>-<end>.dmp`` file of a region in ``directory`` (exact range first, then same start), or None."""
    if not directory or not os.path.isdir(directory):
        return None
    wanted = f"pid.{pid}.vad.{start:#x}-{end:#x}.dmp".lower()
    prefix = f"pid.{pid}.vad.{start:#x}-".lower()
    names = os.listdir(directory)
    for name in names:
        if name.lower() == wanted:
            return os.path.join(directory, name)
    for name in names:
        if name.lower().startswith(prefix) and name.lower().endswith(".dmp"):
            return os.path.join(directory, name)
    return None


def read_file(path: str, limit: int = MAX_LOAD_BYTES) -> Tuple[bytes, int]:
    """``(first `limit` bytes, total file size)``."""
    size = os.path.getsize(path)
    with open(path, "rb") as handle:
        return handle.read(limit), size
