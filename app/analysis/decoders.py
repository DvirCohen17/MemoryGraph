"""Decoders that turn something unreadable in the evidence into readable text *for display*.

A decoder never creates a finding and never replaces evidence: it returns what the original bytes say, together with
the exact text it came from, so the GUI can show both ("decoded from this command line of PID n").
If something cannot be decoded cleanly the result is ``None`` (nothing is guessed).
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Optional

# PowerShell accepts any prefix of -EncodedCommand from "-e" up; "-ExecutionPolicy" starts with -e too, but it is
# followed by a word, and the payload has to be base64 of a UTF-16LE script, which the checks below enforce.
_ENCODED_ARG = re.compile(r"(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|"
                          r"encodedcomman|encodedcommand)\s+(?:\"|')?([A-Za-z0-9+/=\s]{8,}?)(?:\"|')?(?=\s+[-/][A-Za-z]|\s*$)", re.IGNORECASE)
_MAX_CHARS = 8000


@dataclass
class DecodedCommand:
    text: str            # the decoded script (possibly truncated for display)
    encoded: str         # the base64 text it was decoded from
    truncated: bool = False
    note: str = "PowerShell -EncodedCommand: base64 of a UTF-16LE script"


def decode_encoded_command(command_line: str) -> Optional[DecodedCommand]:
    """Decode the payload of ``powershell -EncodedCommand <base64>``; None if absent or not a clean UTF-16LE script."""
    if not command_line:
        return None
    match = _ENCODED_ARG.search(command_line)
    if not match:
        return None
    payload = re.sub(r"\s+", "", match.group(1))
    if len(payload) < 8:
        return None
    try:
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw or len(raw) % 2:
        return None
    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    if not text.strip() or printable / len(text) < 0.9:
        return None                       # decoded to noise: not a UTF-16 script
    truncated = len(text) > _MAX_CHARS
    return DecodedCommand(text[:_MAX_CHARS], payload, truncated)
