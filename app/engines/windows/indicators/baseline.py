"""Data tables describing what is *normal* on Windows.

Everything detection-related that is "knowledge" lives here so it can be reviewed and edited
without touching rule logic. These are generic baselines (the well known Windows process
hierarchy), not malware names or IOCs.
"""
from __future__ import annotations

# name -> expectations. ``parents``: allowed parent image names (lower case). ``parent_may_be_gone``:
# the parent legitimately exits (smss spawns csrss/wininit/winlogon and terminates).
CORE_PROCESSES = {
    "smss.exe":        {"dirs": [r"c:\windows\system32"], "parents": {"system", "smss.exe"}, "parent_may_be_gone": True, "single": False},
    "csrss.exe":       {"dirs": [r"c:\windows\system32"], "parents": {"smss.exe"}, "parent_may_be_gone": True, "single": False},
    "wininit.exe":     {"dirs": [r"c:\windows\system32"], "parents": {"smss.exe"}, "parent_may_be_gone": True, "single": True},
    "winlogon.exe":    {"dirs": [r"c:\windows\system32"], "parents": {"smss.exe"}, "parent_may_be_gone": True, "single": False},
    "services.exe":    {"dirs": [r"c:\windows\system32"], "parents": {"wininit.exe"}, "parent_may_be_gone": False, "single": True},
    "lsass.exe":       {"dirs": [r"c:\windows\system32"], "parents": {"wininit.exe"}, "parent_may_be_gone": False, "single": True},
    "lsm.exe":         {"dirs": [r"c:\windows\system32"], "parents": {"wininit.exe"}, "parent_may_be_gone": False, "single": True},
    "svchost.exe":     {"dirs": [r"c:\windows\system32", r"c:\windows\syswow64"], "parents": {"services.exe", "msmpeng.exe"}, "parent_may_be_gone": False, "single": False},
    "spoolsv.exe":     {"dirs": [r"c:\windows\system32"], "parents": {"services.exe"}, "parent_may_be_gone": False, "single": True},
    "taskhostw.exe":   {"dirs": [r"c:\windows\system32"], "parents": {"svchost.exe", "services.exe", "taskeng.exe"}, "parent_may_be_gone": True, "single": False},
    "sihost.exe":      {"dirs": [r"c:\windows\system32"], "parents": {"svchost.exe"}, "parent_may_be_gone": True, "single": False},
    "runtimebroker.exe": {"dirs": [r"c:\windows\system32"], "parents": {"svchost.exe"}, "parent_may_be_gone": True, "single": False},
    "dwm.exe":         {"dirs": [r"c:\windows\system32"], "parents": {"winlogon.exe"}, "parent_may_be_gone": True, "single": False},
    "explorer.exe":    {"dirs": [r"c:\windows"], "parents": {"userinit.exe", "winlogon.exe", "explorer.exe"}, "parent_may_be_gone": True, "single": False},
}

# Windows XP / Server 2003 (NT 5.x) have no wininit.exe: winlogon.exe starts services.exe and lsass.exe.
LEGACY_PARENTS = {"services.exe": {"winlogon.exe"}, "lsass.exe": {"winlogon.exe"}}

# Executable private regions that Windows itself creates, as (start address, size in bytes): reported one level lower by MEM-001.
# Seen in every GUI process of Windows XP / 2003 images (csrss.exe, explorer.exe, Process Explorer, ...).
KNOWN_BENIGN_REGIONS = {(0x7F6F0000, 0x100000): "the 1 MB section mapping every Windows XP / 2003 GUI process has at 0x7f6f0000"}

# First Windows (NT major, minor) that has this system process. Seeing it on an older Windows is a masquerading sign (rule PT-005).
MIN_WINDOWS_FOR_PROCESS = {"wininit.exe": (6, 0), "lsm.exe": (6, 0), "dwm.exe": (6, 0), "audiodg.exe": (6, 0), "taskeng.exe": (6, 0),
                           "conhost.exe": (6, 1), "taskhost.exe": (6, 1), "taskhostw.exe": (6, 2), "runtimebroker.exe": (6, 2),
                           "smartscreen.exe": (6, 2), "sihost.exe": (10, 0), "fontdrvhost.exe": (10, 0)}

# Names that look like core processes but are legitimate: never reported as look-alikes.
KNOWN_LEGIT_NAMES = set(CORE_PROCESSES) | {
    "taskhost.exe", "taskhostex.exe", "taskeng.exe", "dllhost.exe", "conhost.exe", "userinit.exe", "fontdrvhost.exe",
    "audiodg.exe", "wmiprvse.exe", "sppsvc.exe", "searchindexer.exe", "smartscreen.exe", "rundll32.exe", "dasHost.exe".lower(),
    "ctfmon.exe", "msiexec.exe", "lsaiso.exe", "dashost.exe", "wudfhost.exe", "winlogon.exe", "csrss.exe",
}

# Look-alike detection targets (names attackers commonly imitate).
LOOKALIKE_TARGETS = ["svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "explorer.exe", "winlogon.exe",
                     "smss.exe", "wininit.exe", "spoolsv.exe", "rundll32.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe"]

INTERPRETERS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "powershell_ise.exe"}

# Parents from which an interpreter is routine (interactive shells / terminals / dev tools).
NORMAL_INTERPRETER_PARENTS = {
    "explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "conhost.exe", "windowsterminal.exe", "wt.exe",
    "code.exe", "devenv.exe", "python.exe", "pythonw.exe", "java.exe", "node.exe", "taskeng.exe", "sihost.exe",
    "svchost.exe", "msiexec.exe", "setup.exe", "installer.exe", "winlogon.exe", "userinit.exe",
}

# Signed binaries that are routinely abused to download/execute (living off the land).
LOLBINS = {"certutil.exe", "bitsadmin.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "wmic.exe", "msiexec.exe",
           "installutil.exe", "cmstp.exe", "forfiles.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe", "odbcconf.exe",
           "wscript.exe", "cscript.exe", "powershell.exe", "pwsh.exe", "cmd.exe"}

# Processes that normally never talk to the public internet.
NO_NETWORK_EXPECTED = {"smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "notepad.exe", "calc.exe",
                       "mspaint.exe", "dwm.exe", "lsm.exe", "fontdrvhost.exe", "conhost.exe", "audiodg.exe"}

# System DLL names: loading one of these from outside the Windows directories is notable.
SYSTEM_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "advapi32.dll", "ws2_32.dll", "wininet.dll",
    "winhttp.dll", "crypt32.dll", "secur32.dll", "sspicli.dll", "rpcrt4.dll", "shell32.dll", "ole32.dll",
    "oleaut32.dll", "gdi32.dll", "msvcrt.dll", "combase.dll", "bcrypt.dll", "ncrypt.dll", "samlib.dll",
    "netapi32.dll", "wsock32.dll", "dnsapi.dll", "iphlpapi.dll", "mswsock.dll", "urlmon.dll", "shlwapi.dll",
}

# Directory fragments that are fine for DLLs/executables (side-by-side, .NET, app dirs).
TRUSTED_DIR_FRAGMENTS = (
    "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\microsoft.net\\",
    "\\windows\\assembly\\", "\\program files\\", "\\program files (x86)\\", "\\programdata\\microsoft\\windows defender\\",
    "\\windows\\systemapps\\", "\\windows\\immersivecontrolpanel\\", "\\windows\\servicing\\",
)

# Highly suspicious places to run code from.
HIGH_RISK_DIR_FRAGMENTS = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\temp\\", "\\users\\public\\", "\\downloads\\",
    "$recycle.bin\\", "\\recycler\\", "\\windows\\tasks\\", "\\windows\\debug\\",
)

# AppData sub-folders used by mainstream per-user installers (not reported at all).
APPDATA_VENDOR_FRAGMENTS = (
    "\\appdata\\local\\microsoft\\", "\\appdata\\local\\google\\", "\\appdata\\local\\programs\\",
    "\\appdata\\roaming\\microsoft\\", "\\appdata\\local\\mozilla\\", "\\appdata\\local\\slack\\",
    "\\appdata\\local\\discord\\", "\\appdata\\local\\zoom\\", "\\appdata\\roaming\\zoom\\", "\\appdata\\local\\teams\\",
    "\\appdata\\local\\temp\\microsoft\\", "\\appdata\\local\\packages\\", "\\appdata\\local\\spotify\\",
)

# Modules whose presence explains small RWX regions (JIT compilers, scripting runtimes, AV engines).
JIT_HOST_MODULES = {"clr.dll", "clrjit.dll", "coreclr.dll", "mscorwks.dll", "mscoreei.dll", "mscoree.dll",
                    "jscript9.dll", "jscript.dll", "chakra.dll", "mshtml.dll", "v8.dll", "libcef.dll",
                    "chrome_child.dll", "msedge.dll", "mozjs.dll", "libjvm.dll", "jvm.dll", "python3.dll"}
SECURITY_ENGINE_MODULES = {"mpengine.dll", "mpclient.dll"}

# Shellcode-looking byte prefixes (hex, no spaces).
SHELLCODE_PREFIXES = ("fce8", "fc4883e4f0", "fc4881e4f0", "e800000000", "60e8", "eb0e5b", "4831c9", "4831c0", "6a006a00", "90909090")

# Handle access bits.
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002

# Processes that legitimately hold read access handles to lsass.
LSASS_HANDLE_ALLOWED = {"system", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "winlogon.exe",
                        "msmpeng.exe", "nissrv.exe", "wmiprvse.exe", "taskmgr.exe", "smss.exe", "lsm.exe", "vmtoolsd.exe",
                        "securityhealthservice.exe", "csrss"}
