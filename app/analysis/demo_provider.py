"""Synthetic provider used for GUI/rule development without a memory dump.

The demo emits plugin rows in the same shape as Volatility 3 and sends them through the real
normalizer, timeline builder and rule engine, so it exercises exactly the production pipeline.
"""
from __future__ import annotations

import time
from typing import Callable, Optional

from app.analysis.pipeline import analyze_plugins
from app.models import PluginResult

Progress = Optional[Callable[[str, int], None]]

_BASE = [  # pid, ppid, name, path, user, created, cmdline
    (4, 0, "System", "", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:00+00:00", ""),
    (332, 4, "smss.exe", r"C:\Windows\System32\smss.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:01+00:00", r"\SystemRoot\System32\smss.exe"),
    (500, 424, "wininit.exe", r"C:\Windows\System32\wininit.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:03+00:00", "wininit.exe"),
    (872, 500, "services.exe", r"C:\Windows\System32\services.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:04+00:00", r"C:\Windows\System32\services.exe"),
    (884, 500, "lsass.exe", r"C:\Windows\System32\lsass.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:04+00:00", r"C:\Windows\System32\lsass.exe"),
    (1208, 872, "svchost.exe", r"C:\Windows\System32\svchost.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T00:00:05+00:00", r"C:\Windows\System32\svchost.exe -k netsvcs"),
    (1260, 872, "svchost.exe", r"C:\Windows\System32\svchost.exe", "NT AUTHORITY\\LOCAL SERVICE", "2026-01-01T00:00:05+00:00", r"C:\Windows\System32\svchost.exe -k LocalService"),
    (4321, 3900, "explorer.exe", r"C:\Windows\explorer.exe", "DESKTOP\\User", "2026-01-01T08:00:00+00:00", r"C:\Windows\explorer.exe"),
]
_ATTACK = [
    (4216, 4321, "powershell.exe", r"C:\Users\User\AppData\Local\Temp\powershell.exe", "DESKTOP\\User", "2026-01-01T08:01:00+00:00",
     r"powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
    (7824, 4216, "cmd.exe", r"C:\Windows\System32\cmd.exe", "DESKTOP\\User", "2026-01-01T08:01:02+00:00", r"cmd.exe /c C:\Users\User\AppData\Local\Temp\stage.exe"),
    (5150, 872, "svch0st.exe", r"C:\Users\Public\svch0st.exe", "NT AUTHORITY\\SYSTEM", "2026-01-01T08:02:00+00:00", r"C:\Users\Public\svch0st.exe"),
]


def _plugins(scenario: str):
    procs = list(_BASE) + (list(_ATTACK) if scenario == "correlated" else [])
    pslist = [{"PID": p, "PPID": pp, "ImageFileName": n[:14], "CreateTime": c, "ExitTime": None, "Threads": 4, "SessionId": 1 if p > 4000 else 0}
              for p, pp, n, _path, _u, c, _cmd in procs]
    pstree = [{"PID": p, "PPID": pp, "ImageFileName": n[:14], "Path": path or None, "Cmd": cmd or None, "CreateTime": c, "__children": []}
              for p, pp, n, path, _u, c, cmd in procs]
    cmdline = [{"PID": p, "Process": n[:14], "Args": cmd or None} for p, _pp, n, _path, _u, _c, cmd in procs]
    sids = [{"PID": p, "Process": n[:14], "SID": "S-1-5-18" if "SYSTEM" in u else ("S-1-5-19" if "LOCAL" in u else "S-1-5-21-1-2-3-1001"),
             "Name": u.split("\\")[-1]} for p, _pp, n, _path, u, _c, _cmd in procs]
    dlls = [{"PID": p, "Process": n[:14], "Name": n, "Path": path, "Base": 0x7FF600000000 + p, "Size": 65536, "LoadTime": c}
            for p, _pp, n, path, _u, c, _cmd in procs if path]
    rows = {
        "windows.info": [{"Variable": "Is64Bit", "Value": True}, {"Variable": "NtMajorVersion", "Value": 10},
                         {"Variable": "NtMinorVersion", "Value": 0}, {"Variable": "SystemTime", "Value": "2026-01-01T08:30:00+00:00"},
                         {"Variable": "KeNumberProcessors", "Value": 4}],
        "windows.pslist": pslist, "windows.psscan": pslist, "windows.pstree": pstree, "windows.cmdline": cmdline,
        "windows.getsids": sids, "windows.dlllist": dlls, "windows.netscan": [], "windows.malfind": [], "windows.handles": [],
    }
    rows["windows.netscan"] = [{"PID": 4321, "Owner": "explorer.exe", "Proto": "TCPv4", "LocalAddr": "192.168.1.10", "LocalPort": 51500,
                                "ForeignAddr": "8.8.8.8", "ForeignPort": 443, "State": "ESTABLISHED", "Created": "2026-01-01T08:10:00+00:00"}]
    if scenario == "correlated":
        rows["windows.netscan"].append({"PID": 4216, "Owner": "powershell.exe", "Proto": "TCPv4", "LocalAddr": "192.168.1.10", "LocalPort": 51501,
                                        "ForeignAddr": "185.220.101.42", "ForeignPort": 443, "State": "ESTABLISHED", "Created": "2026-01-01T08:01:05+00:00"})
        rows["windows.malfind"] = [{"PID": 4216, "Process": "powershell.exe", "Start VPN": 0x100000, "End VPN": 0x101FFF, "Protection": "PAGE_EXECUTE_READWRITE",
                                    "PrivateMemory": 1, "Tag": "VadS", "Hexdump": "4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00", "Disasm": "dec ebp; pop edx"}]
        rows["windows.dlllist"].append({"PID": 4216, "Process": "powershell.exe", "Name": "stage.dll", "Path": r"C:\Users\User\AppData\Local\Temp\stage.dll",
                                        "Base": 0x100000, "Size": 12288, "LoadTime": "2026-01-01T08:01:03+00:00"})
        rows["windows.handles"] = [{"PID": 5150, "Process": "svch0st.exe", "Type": "Process", "Name": "lsass.exe Pid 884", "GrantedAccess": 0x1410, "HandleValue": 0x44}]
    return rows


class DemoProvider:
    """Synthetic provider used for GUI/rule development without a memory dump."""

    def run(self, dump_path: str = "demo", progress: Progress = None, scenario: str = "correlated"):
        for text, value in [("Loading demo evidence", 10), ("Building normalized evidence", 45)]:
            if progress:
                progress(text, value)
                time.sleep(0.02)
        plugins = [PluginResult(name, "Completed", rows) for name, rows in _plugins(scenario).items()]
        return analyze_plugins(dump_path, plugins, progress)
