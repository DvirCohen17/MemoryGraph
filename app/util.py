"""Small shared helpers: time parsing/formatting, safe conversions, path normalisation."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

_ISO_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
)


def parse_time(value: Any) -> Optional[datetime]:
    """Parse the timestamp formats Volatility emits into an aware UTC datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:                                   # epoch seconds (the chart passes these around)
            return datetime.fromtimestamp(float(value), timezone.utc) if value > 86400 else None
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text or text.lower() in {"n/a", "none", "null", "-", "0"} or text.startswith("1601-01-01"):
        return None
    text = text.replace("Z", "+00:00")
    # "+00:00" style offsets work with %z on every supported Python; also accept "+0000".
    for fmt in _ISO_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def time_key(value: Any) -> float:
    """Sortable epoch seconds; unparsable values sort last."""
    parsed = parse_time(value)
    return parsed.timestamp() if parsed else float("inf")


def format_time(value: Any, with_seconds: bool = True) -> str:
    parsed = parse_time(value)
    if not parsed:
        return str(value or "")
    return parsed.strftime("%Y-%m-%d %H:%M:%S" if with_seconds else "%Y-%m-%d %H:%M") + " UTC"


def format_delta(seconds: float) -> str:
    """Human readable signed delta, e.g. '-12m 05s' or '+2d 03h'."""
    sign = "-" if seconds < 0 else "+"
    seconds = abs(int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d {hours:02d}h"
    if hours:
        return f"{sign}{hours}h {minutes:02d}m"
    if minutes:
        return f"{sign}{minutes}m {secs:02d}s"
    return f"{sign}{secs}s"


def to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        text = str(value).strip()
        if not text:
            return default
        return int(text, 16) if text.lower().startswith("0x") else int(float(text))
    except (TypeError, ValueError):
        return default


def to_hex(value: Any) -> str:
    number = to_int(value)
    return hex(number) if number is not None else str(value or "")


def human_size(value: Any) -> str:
    number = to_int(value)
    if number is None:
        return str(value or "")
    size = float(number)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(number)


def clean_text(value: Any) -> str:
    return "" if value is None else str(value)


_NT_DEVICE = re.compile(r"^\\device\\harddiskvolume\d+", re.IGNORECASE)


def norm_path(path: Any) -> str:
    """Lower-case Windows path with NT-style prefixes translated to drive-letter form."""
    text = clean_text(path).strip().strip('"')
    if not text:
        return ""
    text = text.replace("/", "\\")
    low = text.lower()
    if low.startswith("\\??\\"):
        text = text[4:]
        low = text.lower()
    if low.startswith("\\systemroot"):
        text = "c:\\windows" + text[len("\\systemroot"):]
    elif low.startswith("%systemroot%"):
        text = "c:\\windows" + text[len("%systemroot%"):]
    elif low.startswith("%windir%"):
        text = "c:\\windows" + text[len("%windir%"):]
    elif _NT_DEVICE.match(text):
        text = "c:" + _NT_DEVICE.sub("", text)
    return text.lower()


def path_dir(path: str) -> str:
    return path.rsplit("\\", 1)[0] if "\\" in path else ""


def path_file(path: str) -> str:
    return path.rsplit("\\", 1)[-1] if path else ""


def first(iterable: Iterable, default=None):
    for item in iterable:
        return item
    return default
