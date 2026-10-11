"""IOC rule family: matches against indicators the investigator supplied (see ``app/analysis/ioc.py``).

These rules are separate from the behavioural rules on purpose:
* ids are ``IOC-*`` and the category is ``ioc`` (the engine keeps them out of behavioural correlation),
* the title starts with "IOC match:" and the reasons name the list and the exact entry that matched,
* they only exist when the user configured IOC lists or a YARA rule file.
"""
from typing import Iterable, List, Optional

from app.analysis.ioc import Ioc, IocSet
from app.analysis.indicators.base import (
    IndicatorRule, display, plugin_rows_indexed, process_for_pid, row_value,
)
from app.models import EvidenceItem
from app.util import to_int


class _IocRule(IndicatorRule):
    category = "ioc"
    iocs: IocSet

    def __init__(self, iocs: Optional[IocSet] = None):
        self.iocs = iocs or IocSet()

    def hit(self, *, ioc: Ioc, what: str, severity: str, process, evidence: str, sources: Iterable[str],
            items: Iterable[EvidenceItem] = ()):
        return self.make(
            title=f"IOC match: {ioc.original or ioc.value}" + (f" in {process.name}" if process else ""),
            severity=severity, confidence="High", process=process,
            summary=("This matches an indicator you supplied. It says nothing about behaviour: check the source of the list and whether "
                     "the match is meaningful for this system."),
            reasons=[f"Matches {ioc.describe()}", what], evidence=[evidence], source_plugins=list(sources), evidence_items=list(items))


class IpIocRule(_IocRule):
    rule_id = "IOC-001"
    name = "IOC: connection to a listed IP address"
    description = "The remote address of a network connection (windows.netscan / windows.netstat) is in your IOC list (single IPs or CIDR ranges)."

    def evaluate(self, result):
        connections = result.connections or [c for p in result.processes for c in p.network]
        findings, seen = [], set()
        for conn in connections:
            for ioc in self.iocs.match_ip(conn.remote_address):
                key = (conn.pid, ioc.value, conn.remote_address, conn.remote_port)
                if key in seen:
                    continue
                seen.add(key)
                proc = process_for_pid(result, conn.pid)
                prov = (conn.provenance or {}).get("row", {})
                findings.append(self.hit(
                    ioc=ioc, severity="High", process=proc, sources=conn.source_plugins,
                    what=f"Remote address {conn.remote_address} is {'in ' + ioc.value if '/' in ioc.value and not ioc.value.endswith('/32') else 'the IOC'}",
                    evidence=f"{conn.protocol} {conn.local} → {conn.remote} {conn.state} (owner {conn.process or 'unknown'}, PID {conn.pid})".strip(),
                    items=[EvidenceItem("network", "ForeignAddr", conn.remote_address, conn.remote, (conn.source_plugins or [""])[0],
                                        to_int(prov.get("row_index"), -1))]))
        return findings


class DomainIocRule(_IocRule):
    rule_id = "IOC-002"
    name = "IOC: listed domain on a command line"
    description = "A process command line (windows.cmdline) contains a host name that is, or is a sub-domain of, a domain in your IOC list."

    def evaluate(self, result):
        findings = []
        for p in result.processes:
            for ioc in self.iocs.match_domains(p.command_line):
                findings.append(self.hit(
                    ioc=ioc, severity="High", process=p, sources=["windows.cmdline"],
                    what=f"{display(p)} was started with a command line that names {ioc.value}",
                    evidence=f"Command line: {p.command_line[:600]}",
                    items=[EvidenceItem("process", "command_line", ioc.value, display(p), "windows.cmdline", -1)]))
        return findings


class MutexIocRule(_IocRule):
    rule_id = "IOC-004"
    name = "IOC: listed mutex"
    description = "A mutant (mutex) with a name from your IOC list exists in memory (windows.mutantscan) or is held by a process (windows.handles)."

    def evaluate(self, result):
        findings, seen = [], set()
        for index, row in plugin_rows_indexed(result, "windows.mutantscan"):
            name = str(row_value(row, "Name") or "")
            for ioc in self.iocs.match_mutex(name):
                if (None, ioc.value, name) in seen:
                    continue
                seen.add((None, ioc.value, name))
                findings.append(self.hit(
                    ioc=ioc, severity="High", process=None, sources=["windows.mutantscan"],
                    what="A mutant object with this name was found by pool scan (the scan has no owner process)",
                    evidence=f"Mutant: {name}", items=[EvidenceItem("mutant", "Name", name, "", "windows.mutantscan", index)]))
        for p in result.processes:
            for handle in p.handles:
                if not isinstance(handle, dict) or str(handle.get("type", "")).lower() != "mutant":
                    continue
                name = str(handle.get("name") or "")
                for ioc in self.iocs.match_mutex(name):
                    if (p.pid, ioc.value, name) in seen:
                        continue
                    seen.add((p.pid, ioc.value, name))
                    findings.append(self.hit(
                        ioc=ioc, severity="High", process=p, sources=["windows.handles"],
                        what=f"{display(p)} holds a handle to this mutant", evidence=f"Handle: Mutant {name}",
                        items=[EvidenceItem("handle", "Name", name, display(p), "windows.handles", -1)]))
        return findings


class FileIocRule(_IocRule):
    rule_id = "IOC-005"
    name = "IOC: listed file name or path"
    description = ("A process image, a loaded DLL, a file handle or a file object found by pool scan (windows.filescan) matches a file name "
                   "or path from your IOC list. A bare name matches the file name; an entry with a backslash matches as a path fragment.")

    def evaluate(self, result):
        findings, seen = [], set()

        def add(ioc, process, path, kind, sources, index=-1):
            key = (process.pid if process else 0, ioc.value, path.lower())
            if key in seen:
                return
            seen.add(key)
            findings.append(self.hit(
                ioc=ioc, severity="High" if "\\" in ioc.value else "Medium", process=process, sources=sources,
                what=f"{kind}: {path}", evidence=f"{kind}: {path}",
                items=[EvidenceItem("file", "path", path, kind, sources[0], index)]))

        for p in result.processes:
            for ioc in self.iocs.match_file(p.path or p.name):
                add(ioc, p, p.path or p.name, "Process image", ["windows.pslist", "windows.pstree"])
            for dll in p.dlls:
                for ioc in self.iocs.match_file(dll.path or dll.name):
                    add(ioc, p, dll.path or dll.name, "Loaded module", ["windows.dlllist"])
            for handle in p.handles:
                if isinstance(handle, dict) and str(handle.get("type", "")).lower() == "file":
                    for ioc in self.iocs.match_file(str(handle.get("name") or "")):
                        add(ioc, p, str(handle.get("name")), "Open file handle", ["windows.handles"])
        for index, row in plugin_rows_indexed(result, "windows.filescan"):
            name = str(row_value(row, "Name") or "")
            for ioc in self.iocs.match_file(name):
                add(ioc, None, name, "File object in memory", ["windows.filescan"], index)
        return findings


class ImageHashIocRule(_IocRule):
    rule_id = "IOC-007"
    name = "IOC: hash of a dumped process image"
    description = ("The SHA-256 / MD5 of a process image that \"Hash all process images\" dumped from this memory image is in your IOC list. "
                   "The hash is of the image reconstructed from memory: it equals the file's hash only when no page was missing or modified, so "
                   "a match is strong evidence and a non-match proves nothing. Needs the stored image hashes (Process Tree) and an IOC list with hashes.")

    def evaluate(self, result):
        from app.engines.windows.analysis import process_images
        findings, seen = [], set()
        for entry in process_images.stored(result):
            for digest in (entry["sha256"], entry.get("md5", "")):
                for ioc in self.iocs.match_hash(digest) if digest else []:
                    if (entry["pid"], ioc.value) in seen:
                        continue
                    seen.add((entry["pid"], ioc.value))
                    proc = process_for_pid(result, entry["pid"])
                    findings.append(self.hit(
                        ioc=ioc, severity="High", process=proc, sources=["windows.pslist"],
                        what=f"The dumped image of {entry.get('process', '?')} (PID {entry['pid']}) has this hash",
                        evidence=f"{entry.get('path') or entry.get('process')}  SHA-256 {entry['sha256']}",
                        items=[EvidenceItem("image_hash", "sha256", entry["sha256"], entry.get("process", ""), "windows.pslist", -1)]))
        return findings


def readable_match(value) -> str:
    """windows.vadyarascan prints the matched bytes as hex (``77 69 6e``). Show them as text when they are text (ASCII or UTF-16LE), with the hex kept."""
    text = str(value or "").strip()
    try:
        raw = bytes(int(part, 16) for part in text.split())
    except ValueError:
        return text
    if len(raw) < 4 or len(text.split()) != len(raw):
        return text
    for codec in ("ascii", "utf-16-le"):
        try:
            decoded = raw.decode(codec)
        except UnicodeDecodeError:
            continue
        if decoded and all(32 <= ord(ch) < 127 for ch in decoded):
            return f"'{decoded}' ({codec.upper().replace('-LE', '')}) [{text[:48]}{'…' if len(text) > 48 else ''}]"
    return text


class YaraHitRule(IndicatorRule):
    """Matches of the investigator's own YARA rules (windows.vadyarascan --yara-file). Needs the opt-in plugin and a rule file in Settings."""

    rule_id = "IOC-006"
    category = "ioc"
    name = "IOC: match of your YARA rules"
    description = ("windows.vadyarascan scanned the process memory with the YARA rule file configured in Settings and a rule matched. "
                   "One finding per process and rule; the matching strings are listed as evidence.")

    def evaluate(self, result):
        grouped = {}
        for index, row in plugin_rows_indexed(result, "windows.vadyarascan"):
            rule = str(row_value(row, "Rule") or "")
            pid = to_int(row_value(row, "PID", default=None))
            if not rule:
                continue
            grouped.setdefault((pid or 0, rule), []).append((index, row))
        findings = []
        for (pid, rule), hits in grouped.items():
            proc = process_for_pid(result, pid) if pid else None
            lines = []
            for _index, row in hits[:8]:
                component = row_value(row, "Component")
                value = row_value(row, "Value")
                lines.append(f"{row_value(row, 'Offset')} {component} {readable_match(value)}".strip())
            findings.append(self.make(
                title=f"IOC match: YARA rule {rule}" + (f" in {proc.name}" if proc else (f" in PID {pid}" if pid else "")),
                severity="High", confidence="High", process=proc,
                summary="A YARA rule you supplied matched this process's memory. The rule decides what that means: check its source.",
                reasons=[f"YARA rule '{rule}' matched {len(hits)} time(s) in the memory of PID {pid}"], evidence=lines,
                source_plugins=["windows.vadyarascan"],
                evidence_items=[EvidenceItem("yara", "Rule", rule, f"PID {pid}", "windows.vadyarascan", i) for i, _r in hits[:8]]))
        return findings


def ioc_rules(iocs: Optional[IocSet]) -> List[IndicatorRule]:
    """The IOC rules for this run. YARA hits need no IOC list (they are driven by the plugin), the others need one."""
    rules: List[IndicatorRule] = [YaraHitRule()]
    if iocs:
        rules[:0] = [IpIocRule(iocs), DomainIocRule(iocs), MutexIocRule(iocs), FileIocRule(iocs), ImageHashIocRule(iocs)]
    return rules
