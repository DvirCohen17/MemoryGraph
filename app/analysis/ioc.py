"""User-supplied indicators of compromise (IOCs): parsing and matching.

IOCs are *intelligence the investigator brings* (from a report, a ticket, a threat feed). They are deliberately a separate rule family
(``IOC-*``, see ``indicators/rules/ioc.py``): MemoryGraph's own behavioural rules never read them, IOC matches never feed the
behavioural correlation, and every IOC finding names the list and the exact entry that matched, so it is always clear whether
something was flagged by behaviour or by a list.

File format (plain text, one entry per line; ``#`` starts a comment)::

    203.0.113.7                      # bare values are recognised by their shape
    198.51.100.0/24
    evil.example.com
    hxxps://bad[.]example.net/path   # defanged URLs are fine
    44d88612fea8a8f36de82e1278abb02f
    mutex: Global\\XyzMutex
    file: C:\\Users\\Public\\payload.exe
    ip, 192.0.2.5, Cobalt Strike team server      # kind, value, note

A list can also be a STIX 2.x bundle (the patterns of its indicators) or a MISP JSON export (attributes with to_ids = true); the
format is detected from the file.
"""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from app.logging_setup import get_logger
from app.util import norm_path

log = get_logger("ioc")

KINDS = ("ip", "domain", "hash", "mutex", "file")
_FILE_EXTENSIONS = {"exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "scr", "tmp", "dat", "lnk", "hta", "msi",
                    "jar", "docm", "xlsm", "wsf", "cpl", "pif", "bin", "dmp", "log", "txt", "ini", "cfg"}   # not "com": it is a TLD
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{1,62}$")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_HOSTNAMES_IN_TEXT = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?(?:\.[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)+")


@dataclass
class Ioc:
    kind: str
    value: str               # normalised (domains/hashes lower-case, files lower-case path)
    list_name: str = ""
    note: str = ""
    original: str = ""       # as written in the file, shown in findings
    network: Optional[object] = field(default=None, repr=False)   # ip_network for kind == "ip"

    def describe(self) -> str:
        where = f"list '{self.list_name}'" if self.list_name else "IOC list"
        return f"{self.kind} IOC '{self.original or self.value}' from {where}" + (f" ({self.note})" if self.note else "")


class IocSet:
    def __init__(self, items: Iterable[Ioc] = ()):
        self.items: List[Ioc] = list(items)

    def __bool__(self) -> bool:
        return bool(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def of(self, kind: str) -> List[Ioc]:
        return [i for i in self.items if i.kind == kind]

    def counts(self) -> Dict[str, int]:
        return {k: len(self.of(k)) for k in KINDS}

    # -- matching: each returns the matching IOCs (empty list = no match) ---------------------
    def match_ip(self, host: str) -> List[Ioc]:
        try:
            address = ipaddress.ip_address(str(host or "").strip().strip("[]"))
        except ValueError:
            return []
        return [i for i in self.of("ip") if i.network is not None and i.network.version == address.version and address in i.network]

    def match_domains(self, text: str) -> List[Ioc]:
        """IOC domains that occur as a host name in ``text`` (exact host or a sub-domain of it)."""
        hosts = {h.lower().rstrip(".") for h in _HOSTNAMES_IN_TEXT.findall(text or "")}
        if not hosts:
            return []
        return [i for i in self.of("domain") if any(h == i.value or h.endswith("." + i.value) for h in hosts)]

    def match_hash(self, digest: str) -> List[Ioc]:
        digest = str(digest or "").strip().lower()
        return [i for i in self.of("hash") if i.value == digest] if digest else []

    def match_mutex(self, name: str) -> List[Ioc]:
        low = str(name or "").strip().lower()
        if not low:
            return []
        return [i for i in self.of("mutex") if low == i.value or low.endswith("\\" + i.value)]

    def match_file(self, path: str) -> List[Ioc]:
        full = norm_path(path)
        if not full:
            return []
        base = full.rsplit("\\", 1)[-1]
        found = []
        for i in self.of("file"):
            if "\\" in i.value:
                if i.value in full:          # a path (or path fragment) was given
                    found.append(i)
            elif i.value == base:
                found.append(i)
        return found


# ----------------------------------------------------------------------------- parsing
def _refang(text: str) -> str:
    text = text.strip()
    text = re.sub(r"(?i)^hxxp", "http", text)
    return text.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")


def _host_of(value: str) -> str:
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value, flags=re.IGNORECASE)
    value = re.split(r"[/?#]", value, maxsplit=1)[0]
    value = value.rsplit("@", 1)[-1]
    if value.count(":") == 1:                # host:port (not an IPv6 literal)
        value = value.split(":", 1)[0]
    return value.strip().lower().rstrip(".")


def _guess_kind(value: str) -> Optional[str]:
    if "\\" in value:
        return "file"
    try:
        ipaddress.ip_network(value.strip("[]"), strict=False)
        return "ip"
    except ValueError:
        pass
    if _HEX.match(value) and len(value) in (32, 40, 64):
        return "hash"
    host = _host_of(value)
    if "/" in value and "://" not in value:
        return "file"
    if host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS and "://" not in value:
        return "file"
    if _DOMAIN.match(host):
        return "domain"
    return None


def make_ioc(kind: str, raw: str, list_name: str = "", note: str = "") -> Ioc:
    """Build one normalised IOC; raises ValueError with a reason when ``raw`` is not valid for ``kind``."""
    original = raw.strip()
    value = _refang(original)
    if kind == "ip":
        try:
            network = ipaddress.ip_network(_host_of(value) if "/" not in value else value.strip("[]"), strict=False)
        except ValueError as exc:
            raise ValueError(f"not an IP address or CIDR range: {original}") from exc
        return Ioc("ip", str(network), list_name, note, original, network)
    if kind == "domain":
        host = _host_of(value).lstrip("*.")
        if host.startswith("www."):
            host = host[4:]
        if not _DOMAIN.match(host):
            raise ValueError(f"not a domain name: {original}")
        return Ioc("domain", host, list_name, note, original)
    if kind == "hash":
        digest = value.lower()
        if not (_HEX.match(digest) and len(digest) in (32, 40, 64)):
            raise ValueError(f"not an MD5/SHA-1/SHA-256 hash: {original}")
        return Ioc("hash", digest, list_name, note, original)
    if kind == "mutex":
        name = value.strip().lower().lstrip("\\")
        if not name:
            raise ValueError("empty mutex name")
        for prefix in ("basenamedobjects\\",):
            if name.startswith(prefix):
                name = name[len(prefix):]
        return Ioc("mutex", name, list_name, note, original)
    if kind == "file":
        name = norm_path(value) if ("\\" in value or "/" in value) else value.strip().lower()
        # windows.filescan / many plugins report device-relative paths without a drive letter, so compare without it
        name = re.sub(r"^[a-z]:(?=\\)", "", name)
        if not name:
            raise ValueError("empty file name")
        return Ioc("file", name, list_name, note, original)
    raise ValueError(f"unknown IOC type '{kind}'")


def parse_ioc_text(text: str, list_name: str = "") -> Tuple[List[Ioc], List[str]]:
    """Parse the text of an IOC list. Returns (iocs, warnings); bad lines are reported, never fatal."""
    items: List[Ioc] = []
    warnings: List[str] = []
    for number, line in enumerate((text or "").splitlines(), 1):
        body = line.strip()
        if not body or body.startswith("#"):
            continue
        note = ""
        if " #" in body:
            body, note = [part.strip() for part in body.split(" #", 1)]
        kind, value = "", body
        if "," in body and body.split(",", 1)[0].strip().lower() in KINDS:
            parts = [p.strip() for p in body.split(",", 2)]
            kind, value, note = parts[0].lower(), parts[1], (parts[2] if len(parts) > 2 else note)
        elif ":" in body and body.split(":", 1)[0].strip().lower() in KINDS:
            kind, value = [p.strip() for p in body.split(":", 1)]
            kind = kind.lower()
        try:
            if not kind:
                kind = _guess_kind(_refang(value)) or ""
                if not kind:
                    raise ValueError(f"cannot tell what this is (prefix it with ip:, domain:, hash:, mutex: or file:): {value}")
            items.append(make_ioc(kind, value, list_name, note))
        except ValueError as exc:
            warnings.append(f"{list_name or 'IOC list'} line {number}: {exc}")
    return items, warnings


# ----------------------------------------------------------------------------- STIX 2 and MISP
_STIX_TERM = re.compile(
    r"(?P<obj>ipv4-addr|ipv6-addr|domain-name|url|file:name|mutex|file:hashes\.(?:'[^']+'|\"[^\"]+\"|[A-Za-z0-9-]+))"
    r"(?::value|:name)?\s*(?:=|ISSUBSET|LIKE)\s*'(?P<value>(?:[^'\\]|\\.)*)'", re.IGNORECASE)


def _stix_kind(obj: str) -> str:
    obj = obj.lower()
    if obj in ("ipv4-addr", "ipv6-addr"):
        return "ip"
    if obj in ("domain-name", "url"):
        return "domain"
    if obj.startswith("file:hashes"):
        return "hash"
    if obj == "mutex":
        return "mutex"
    return "file"


def parse_stix(data, list_name: str = "") -> Tuple[List[Ioc], List[str]]:
    """IOCs from the patterns of STIX 2.x ``indicator`` objects (a bundle, a list of objects, or one object)."""
    objects = data.get("objects", [data]) if isinstance(data, dict) else data
    items: List[Ioc] = []
    warnings: List[str] = []
    for obj in objects if isinstance(objects, list) else []:
        if not isinstance(obj, dict) or obj.get("type") != "indicator" or not isinstance(obj.get("pattern"), str):
            continue
        note = str(obj.get("name") or obj.get("description") or "")[:80]
        found = False
        for match in _STIX_TERM.finditer(obj["pattern"]):
            found = True
            try:
                # STIX string literals escape a quote and a backslash with a backslash: 'C:\\Temp\\x.exe' means C:\Temp\x.exe
                items.append(make_ioc(_stix_kind(match.group("obj")), re.sub(r"\\(['\\])", r"\1", match.group("value")), list_name, note))
            except ValueError as exc:
                warnings.append(f"{list_name or 'STIX'} indicator '{note or obj.get('id', '?')}': {exc}")
        if not found:
            warnings.append(f"{list_name or 'STIX'} indicator '{note or obj.get('id', '?')}': pattern has no supported term (ip, domain, url, file hash/name, mutex)")
    return items, warnings


_MISP_SINGLE = {"ip-src": "ip", "ip-dst": "ip", "domain": "domain", "hostname": "domain", "url": "domain", "uri": "domain",
                "md5": "hash", "sha1": "hash", "sha256": "hash", "filename": "file", "mutex": "mutex"}
_MISP_COMPOSITE = {"ip-src|port": ("ip", None), "ip-dst|port": ("ip", None), "domain|ip": ("domain", "ip"),
                   "filename|md5": ("file", "hash"), "filename|sha1": ("file", "hash"), "filename|sha256": ("file", "hash")}


def parse_misp(data, list_name: str = "") -> Tuple[List[Ioc], List[str]]:
    """IOCs from MISP attributes anywhere in the JSON (event exports, search results). Attributes with ``to_ids`` false are skipped."""
    items: List[Ioc] = []
    warnings: List[str] = []

    def add(kind: str, value: str, note: str) -> None:
        try:
            items.append(make_ioc(kind, value, list_name, note))
        except ValueError as exc:
            warnings.append(f"{list_name or 'MISP'} attribute: {exc}")

    def walk(node) -> None:
        if isinstance(node, dict):
            kind, value = node.get("type"), node.get("value")
            if isinstance(kind, str) and isinstance(value, str) and node.get("to_ids", True) not in (False, 0, "0", "false"):
                note = str(node.get("comment") or "")[:80]
                if kind in _MISP_SINGLE:
                    add(_MISP_SINGLE[kind], value, note)
                elif kind in _MISP_COMPOSITE:
                    first, second = _MISP_COMPOSITE[kind]
                    left, _sep, right = value.partition("|")
                    add(first, left, note)
                    if second:
                        add(second, right, note)
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    walk(data)
    return items, warnings


def _dedupe(items: List[Ioc]) -> List[Ioc]:
    seen, out = set(), []
    for item in items:
        key = (item.kind, item.value)
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def parse_ioc_json(text: str, list_name: str = "") -> Optional[Tuple[List[Ioc], List[str]]]:
    """STIX 2 or MISP JSON -> (iocs, warnings); None when ``text`` is not JSON at all (the caller then treats it as a text list)."""
    import json
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, (dict, list)):
        return None
    stix_like = (isinstance(data, dict) and (data.get("type") in ("bundle", "indicator") or "objects" in data)) or \
                (isinstance(data, list) and any(isinstance(o, dict) and o.get("type") == "indicator" for o in data))
    items, warnings = parse_stix(data, list_name) if stix_like else parse_misp(data, list_name)
    if not items and not warnings:
        warnings.append(f"{list_name or 'IOC list'}: JSON file recognised as neither STIX 2 indicators nor MISP attributes (or it holds none that are actionable)")
    return _dedupe(items), warnings


def load_ioc_file(path: str) -> Tuple[List[Ioc], List[str]]:
    """Read one IOC list: plain text (see the module docstring), a STIX 2 bundle, or a MISP JSON export."""
    name = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        return [], [f"IOC list '{name}' could not be read: {exc}"]
    if text.lstrip()[:1] in ("{", "["):
        parsed = parse_ioc_json(text, name)
        if parsed is not None:
            return parsed
    items, warnings = parse_ioc_text(text, name)
    return _dedupe(items), warnings


def load_from_settings(settings: dict) -> Tuple[Optional[IocSet], List[str]]:
    """The IOC set configured in Settings (``ioc_files``) and the problems found while reading it. (None, []) when none is set."""
    paths = [p for p in (settings or {}).get("ioc_files", []) if p]
    if not paths:
        return None, []
    items: List[Ioc] = []
    warnings: List[str] = []
    for path in paths:
        found, problems = load_ioc_file(path)
        items.extend(found)
        warnings.extend(problems)
    log.info("Loaded %d IOC(s) from %d list(s)", len(items), len(paths))
    return (IocSet(items) if items else None), warnings


# ----------------------------------------------------------------------------- IOC list -> YARA rules (for windows.vadyarascan)
_YARA_KINDS = ("domain", "ip", "mutex")
MAX_YARA_STRINGS = 5000


def _yara_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def yara_rules_from_iocs(iocs: IocSet) -> Tuple[str, int]:
    """YARA source that finds your domains, IP addresses and mutex names in process memory, and the number of strings in it.

    This is how "domains in memory strings" are searched without carving every string out of the image first: ``windows.vadyarascan`` scans each
    process's memory with these rules and a hit becomes an IOC-006 finding (rule ``IOC_Domains`` / ``IOC_Ips`` / ``IOC_Mutexes``). Strings are
    matched as ASCII and UTF-16, ignoring case; network hits in memory are weaker evidence than a connection (a domain in a browser's cache
    was only looked at). Single IPs only (a CIDR range cannot be searched as text)."""
    sections = []
    total = 0
    for kind, rule_name, flags in (("domain", "IOC_Domains", "ascii wide nocase"), ("ip", "IOC_Ips", "ascii wide"), ("mutex", "IOC_Mutexes", "ascii wide nocase")):
        values = []
        for ioc in iocs.of(kind):
            text = ioc.value if kind != "ip" else (ioc.original or ioc.value)
            if kind == "ip" and "/" in text:
                continue
            if kind == "mutex":
                text = ioc.original or ioc.value
            if text and text not in values:
                values.append(text)
        values = values[:max(0, MAX_YARA_STRINGS - total)]
        if not values:
            continue
        total += len(values)
        strings = "\n".join(f'        $s{n} = "{_yara_text(v)}" {flags}' for n, v in enumerate(values))
        sections.append(f"rule {rule_name}\n{{\n    meta:\n        source = \"MemoryGraph: generated from your IOC list ({len(values)} {kind} entries)\"\n"
                        f"    strings:\n{strings}\n    condition:\n        any of them\n}}\n")
    header = "// Generated by MemoryGraph from the IOC lists in Settings. Regenerate it after changing the lists.\n"
    return header + "\n".join(sections), total
