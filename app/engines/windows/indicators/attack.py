"""MITRE ATT&CK technique tags for MemoryGraph's built-in rules.

A tag says "this behaviour is commonly associated with that technique". It is context for the investigator, not
evidence that the technique was used, and it never changes severity or score. The technique ids are the stable part
(names follow ATT&CK v15); the mapping is deliberately conservative: a rule with no defensible match has an explicit
empty entry with the reason, rather than a forced tag. Correlation findings (CORR-*) combine other findings and carry no tag of their own.

User-supplied IOC matches are a different rule family and are not tagged here.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class TechniqueInfo:
    """What MemoryGraph knows about a technique offline (``app/engines/windows/data/attack_techniques.json``)."""
    tactics: Tuple[str, ...] = ()
    summary: str = ""
    look_for: str = ""


@dataclass(frozen=True)
class Technique:
    id: str
    name: str

    @property
    def info(self) -> TechniqueInfo:
        """Tactics, a short description and what to look for, read from the local data file. Nothing is fetched from the internet;
        an id missing from the file simply has empty details."""
        entry = _local_details().get(self.id, {})
        return TechniqueInfo(tuple(entry.get("tactics", ())), str(entry.get("summary", "")), str(entry.get("look_for", "")))


@lru_cache(maxsize=1)
def _local_details() -> Dict[str, dict]:
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "attack_techniques.json")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return {str(k): v for k, v in (data.get("techniques") or {}).items() if isinstance(v, dict)}
    except (OSError, ValueError, AttributeError):
        return {}


T1003_001 = Technique("T1003.001", "OS Credential Dumping: LSASS Memory")
T1014 = Technique("T1014", "Rootkit")
T1027 = Technique("T1027", "Obfuscated Files or Information")
T1036 = Technique("T1036", "Masquerading")
T1036_005 = Technique("T1036.005", "Masquerading: Match Legitimate Name or Location")
T1055 = Technique("T1055", "Process Injection")
T1055_012 = Technique("T1055.012", "Process Injection: Process Hollowing")
T1055_013 = Technique("T1055.013", "Process Injection: Process Doppelgänging")
T1562_006 = Technique("T1562.006", "Impair Defenses: Indicator Blocking")
T1059 = Technique("T1059", "Command and Scripting Interpreter")
T1059_001 = Technique("T1059.001", "Command and Scripting Interpreter: PowerShell")
T1071 = Technique("T1071", "Application Layer Protocol")
T1105 = Technique("T1105", "Ingress Tool Transfer")
T1218 = Technique("T1218", "System Binary Proxy Execution")
T1546_010 = Technique("T1546.010", "Event Triggered Execution: AppInit DLLs")
T1546_012 = Technique("T1546.012", "Event Triggered Execution: Image File Execution Options Injection")
T1547_004 = Technique("T1547.004", "Boot or Logon Autostart Execution: Winlogon Helper DLL")
T1547_001 = Technique("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder")
T1547_014 = Technique("T1547.014", "Boot or Logon Autostart Execution: Active Setup")
T1053_005 = Technique("T1053.005", "Scheduled Task/Job: Scheduled Task")
T1543_003 = Technique("T1543.003", "Create or Modify System Process: Windows Service")
T1574 = Technique("T1574", "Hijack Execution Flow")
T1574_001 = Technique("T1574.001", "Hijack Execution Flow: DLL Search Order Hijacking")

# rule id -> techniques ([] = reviewed, no defensible mapping; see the comment)
ATTACK_BY_RULE: Dict[str, Tuple[Technique, ...]] = {
    "PT-001": (T1036,),
    "PT-002": (T1036,),
    "PT-003": (T1014,),                  # process unlinked from the active list but still in memory
    "PT-004": (T1059,),
    "PR-001": (T1036_005,),
    "PR-002": (T1036_005,),
    "PR-003": (),                        # running from Temp/Downloads is a location, not a specific technique
    "PR-004": (T1036,),
    "CL-001": (T1059_001, T1027),
    "CL-002": (T1218, T1105),
    "CL-003": (T1059,),
    "CL-004": (T1027,),
    "MEM-001": (T1055,),
    "DLL-001": (T1574,),
    "DLL-002": (T1574_001, T1036_005),
    "NET-001": (T1071,),
    "NET-002": (T1071,),
    "HND-001": (T1003_001,),
    "DRV-001": (T1014,),
    "DRV-002": (T1014,),
    "SSDT-001": (T1014,),                # system call table hooks are a rootkit technique
    "CBK-001": (T1014,),
    "SVC-001": (T1543_003,),
    "PER-001": (T1547_001, T1547_014),
    "PER-002": (T1547_004, T1546_010, T1546_012),
    "PER-003": (T1543_003,),
    "PER-004": (T1053_005,),
    "PT-005": (T1036_005,),
    "MAL-001": (T1055_012,),
    "MAL-002": (T1055,),
    "MAL-003": (T1036,),
    "MAL-004": (T1055_013,),
    "MAL-005": (T1014,),
    "MAL-006": (T1014,),
    "MAL-007": (T1562_006,),
    "PX-001": (T1014,),                  # hiding a process
    "BASE-001": (),                      # a difference from your baseline, not a behaviour
    "BEH-001": (),                       # a location and a way of starting, not a technique
    "UA-001": (),                        # execution history: a location, not a technique
    "FILE-001": (),                      # files that exist, not behaviour
    "ENV-001": (),                       # no clean single technique for a redirected COMSPEC/SystemRoot
    "VAD-001": (T1055,),
    "LDR-001": (T1055,),                 # manually mapped / unlinked images
    # IOC family: matches against the investigator's own lists; what they mean is decided by the list, not by MemoryGraph
    "IOC-001": (), "IOC-002": (), "IOC-004": (), "IOC-005": (), "IOC-006": (), "IOC-007": (),
    "CORR-001": (),                      # derived from other findings
    "CORR-002": (),
}


def attack_for(rule_id: str) -> List[Technique]:
    return list(ATTACK_BY_RULE.get(rule_id, ()))
