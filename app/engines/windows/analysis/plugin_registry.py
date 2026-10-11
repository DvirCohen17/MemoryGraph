"""Which Volatility plugins MemoryGraph knows about, and why.

One entry per plugin run. The provider, the Settings window and the documentation all read this list, so adding
a plugin is: one :class:`PluginSpec` here + (optionally) a rule that reads its rows. Nothing else hardcodes
plugin names for *running* them.

Groups
  core      always run (unless the user unticks them in Settings); ``required`` ones cannot be unticked
  extended  run together when "extended plugins" is ticked
  optional  run only when ticked in Settings (slower, narrower, larger or noisier plugins)

A spec's ``name`` is the key of its result (and what the GUI shows). It is also the Volatility plugin to run unless ``plugin`` says
otherwise, which lets one plugin run several times with different arguments (``printkey`` for several Run keys).
``alternatives`` lists other Volatility names of the same plugin (scheduled tasks and Amcache moved from ``windows.*`` to
``windows.registry.*``); the runner uses the first one the installed Volatility lists.
``setting_arg`` adds an argument from a user setting (``vadyarascan --yara-file <your rules>``); ``needs_setting`` makes the plugin
be skipped, with an explanation in the result's warnings, when that setting is empty.

Availability is not decided here: the runner asks the installed Volatility (``vol -h``) and reports a plugin that
does not exist in that version (or whose Python dependency, e.g. yara-python, is missing) as failed, with the version, instead of
crashing (see ``volatility_runner``). Raw plugin output stays untouched in ``PluginResult``; MemoryGraph rules read it through
``indicators.base.plugin_rows_indexed`` and keep the plugin name + row index as evidence provenance.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

from app.analysis.registry_core import CORE, EXTENDED, OPTIONAL, Bundle, PluginRegistry, PluginSpec, _NT_NAMES  # noqa: F401  (re-exported)

CORE, EXTENDED, OPTIONAL = "core", "extended", "optional"

_NT = "Microsoft\\Windows NT\\CurrentVersion"
_RUN = "Microsoft\\Windows\\CurrentVersion\\Run"
_RUN_USER = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
_CV = "Microsoft\\Windows\\CurrentVersion"
_MORE_RUN_LABEL = "more registry autostart keys: 32-bit Run keys, Policies\\Explorer\\Run, Active Setup"




REGISTRY: Tuple[PluginSpec, ...] = (
    # Order matters: the first entries are the ones every other view depends on.
    PluginSpec("windows.info", CORE, "OS and kernel details, capture time", required=True, used_by=("Computer Info", "Timeline")),
    PluginSpec("windows.pslist", CORE, "process list (active list)", required=True, used_by=("Process Tree", "PT-*", "PR-*")),
    PluginSpec("windows.psscan", CORE, "pool scan for processes, finds unlinked ones", used_by=("PT-003",)),
    PluginSpec("windows.pstree", CORE, "process hierarchy with image paths", used_by=("Process Tree", "PR-*")),
    PluginSpec("windows.cmdline", CORE, "process command lines", used_by=("CL-*", "IOC-002")),
    PluginSpec("windows.getsids", CORE, "owner and group SIDs per process", used_by=("Computer Info",)),
    PluginSpec("windows.netscan", CORE, "network objects found by pool scan", used_by=("NET-*", "IOC-001", "Network"), min_nt=(6, 0)),
    PluginSpec("windows.netstat", CORE, "network objects found by walking tcpip structures", used_by=("NET-*", "IOC-001", "Network"), min_nt=(6, 0)),
    PluginSpec("windows.malfind", CORE, "executable private memory regions", used_by=("MEM-001",)),
    PluginSpec("windows.dlllist", CORE, "loaded DLLs per process", used_by=("DLL-*", "VAD-001", "IOC-005")),
    PluginSpec("windows.handles", CORE, "open handles per process", used_by=("HND-001", "IOC-004", "IOC-005")),

    PluginSpec("windows.modules", EXTENDED, "kernel drivers from the loaded-module list", used_by=("DRV-001", "DRV-002")),
    PluginSpec("windows.modscan", EXTENDED, "kernel drivers found by pool scan (also unlinked/unloaded ones)", used_by=("DRV-001",)),
    PluginSpec("windows.ssdt", EXTENDED, "system service descriptor table", used_by=("SSDT-001",)),
    PluginSpec("windows.callbacks", EXTENDED, "kernel callbacks", used_by=("CBK-001",)),

    PluginSpec("windows.svcscan", OPTIONAL, "Windows services and their binaries (persistence)", used_by=("SVC-001",)),
    PluginSpec("windows.driverscan", OPTIONAL, "driver objects found by pool scan (needs windows.modules: tick extended plugins)",
               used_by=("DRV-002",)),
    PluginSpec("windows.registry.userassist", OPTIONAL, "UserAssist: programs the user started, with counts and times",
               used_by=("UA-001", "Timeline")),
    PluginSpec("windows.envars", OPTIONAL, "environment variables per process", used_by=("ENV-001",)),
    PluginSpec("windows.mutantscan", OPTIONAL, "mutants (mutexes) found by pool scan (for IOC lists)", used_by=("IOC-004",)),
    PluginSpec("windows.filescan", OPTIONAL, "file objects found by pool scan", used_by=("FILE-001", "IOC-005"),
               warning="slow; output can be very large (tens of thousands of rows)"),
    PluginSpec("windows.vadinfo", OPTIONAL, "memory map (VADs) of every process", used_by=("VAD-001",),
               warning="very slow; output is huge; needs windows.dlllist"),
    PluginSpec("windows.ldrmodules", OPTIONAL, "images mapped in each process vs. its three loader lists (unlinked / injected DLLs)",
               used_by=("LDR-001",), warning="slow on big images"),
    PluginSpec("windows.psxview", OPTIONAL, "process cross-view: pslist vs psscan vs thread scan vs csrss (hidden processes)",
               used_by=("PX-001",), warning="slow on big images"),
    PluginSpec("windows.vadyarascan", OPTIONAL, "scan process memory with your YARA rule file (set it below)", used_by=("IOC-006",),
               setting_arg=("yara_rules_file", "--yara-file"), needs_setting="yara_rules_file",
               warning="slow; needs the yara-python package"),
    # Persistence: the Run keys of the SOFTWARE hive (machine) and of each NTUSER.DAT (user): one choice, four printkey runs.
    PluginSpec("windows.registry.printkey [Run, machine]", OPTIONAL, "registry Run / RunOnce keys (persistence)", used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", _RUN), choice="run_keys"),
    PluginSpec("windows.registry.printkey [RunOnce, machine]", OPTIONAL, "registry Run / RunOnce keys (persistence)", used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", _RUN + "Once"), choice="run_keys"),
    PluginSpec("windows.registry.printkey [Run, user]", OPTIONAL, "registry Run / RunOnce keys (persistence)", used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", _RUN_USER), choice="run_keys"),
    PluginSpec("windows.registry.printkey [RunOnce, user]", OPTIONAL, "registry Run / RunOnce keys (persistence)", used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", _RUN_USER + "Once"), choice="run_keys"),
    # More persistence: Winlogon Shell/Userinit, AppInit_DLLs, Image File Execution Options debuggers (SOFTWARE hive, one choice, three runs).
    PluginSpec("windows.registry.printkey [Winlogon]", OPTIONAL, "registry autostart keys: Winlogon, AppInit_DLLs, Image File Execution Options",
               used_by=("PER-002",), plugin="windows.registry.printkey", args=("--key", _NT + "\\Winlogon"), choice="autostart_keys"),
    PluginSpec("windows.registry.printkey [AppInit]", OPTIONAL, "registry autostart keys: Winlogon, AppInit_DLLs, Image File Execution Options",
               used_by=("PER-002",), plugin="windows.registry.printkey", args=("--key", _NT + "\\Windows"), choice="autostart_keys"),
    PluginSpec("windows.registry.printkey [IFEO]", OPTIONAL, "registry autostart keys: Winlogon, AppInit_DLLs, Image File Execution Options",
               used_by=("PER-002",), plugin="windows.registry.printkey",
               args=("--key", _NT + "\\Image File Execution Options", "--recurse"), choice="autostart_keys"),
    # More persistence, part 2: Run keys of 32-bit programs, Policies\Explorer\Run and Active Setup (one choice, five runs).
    PluginSpec("windows.registry.printkey [Run, 32-bit]", OPTIONAL, _MORE_RUN_LABEL, used_by=("PER-001",), plugin="windows.registry.printkey",
               args=("--key", "Wow6432Node\\" + _CV + "\\Run"), choice="more_run_keys"),
    PluginSpec("windows.registry.printkey [RunOnce, 32-bit]", OPTIONAL, _MORE_RUN_LABEL, used_by=("PER-001",), plugin="windows.registry.printkey",
               args=("--key", "Wow6432Node\\" + _CV + "\\RunOnce"), choice="more_run_keys"),
    PluginSpec("windows.registry.printkey [Explorer Run, machine]", OPTIONAL, _MORE_RUN_LABEL, used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", _CV + "\\Policies\\Explorer\\Run"), choice="more_run_keys"),
    PluginSpec("windows.registry.printkey [Explorer Run, user]", OPTIONAL, _MORE_RUN_LABEL, used_by=("PER-001",),
               plugin="windows.registry.printkey", args=("--key", "Software\\" + _CV + "\\Policies\\Explorer\\Run"), choice="more_run_keys"),
    PluginSpec("windows.registry.printkey [Active Setup]", OPTIONAL, _MORE_RUN_LABEL, used_by=("PER-001",), plugin="windows.registry.printkey",
               args=("--key", "Microsoft\\Active Setup\\Installed Components", "--recurse"), choice="more_run_keys"),
    # Services as the registry has them (ImagePath, ServiceDll, Start, Type): finds what svcscan cannot (DLL services, services not in memory).
    PluginSpec("windows.registry.printkey [Services]", OPTIONAL, "registry services: ImagePath and ServiceDll of every service (persistence)",
               used_by=("PER-003", "Timeline"), plugin="windows.registry.printkey", args=("--key", "ControlSet001\\Services", "--recurse"),
               choice="service_keys", warning="slow; output is large (every service key and value)"),
    # Scheduled tasks (TaskCache), parsed by Volatility itself. The plugin moved in newer Volatility versions; both names are tried.
    PluginSpec("windows.registry.scheduled_tasks", OPTIONAL, "scheduled tasks: what they run, when they were created and last ran (persistence)",
               used_by=("PER-004", "Timeline"), alternatives=("windows.scheduled_tasks",), min_nt=(6, 0)),
    # Execution history that only feeds the Timeline (no rule): Amcache and the shimcache read from memory.
    PluginSpec("windows.registry.amcache", OPTIONAL, "Amcache: programs recorded as present/executed, with times and SHA-1 (Timeline)",
               used_by=("Timeline",), alternatives=("windows.amcache",), warning="slow on big images", min_nt=(6, 1)),
    # Malware hunting: checks Volatility 3 ships for process hollowing / injection / ghosting / masquerading, IRP hooks and ETW patching.
    PluginSpec("windows.malware.hollowprocesses", OPTIONAL, "hollowed processes: the image in memory differs from the file it was started from",
               used_by=("MAL-001",), alternatives=("windows.hollowprocesses",), warning="slow on big images"),
    PluginSpec("windows.malware.suspicious_threads", OPTIONAL, "threads that start in memory that is not backed by a file or module",
               used_by=("MAL-002", "Injection"), alternatives=("windows.suspicious_threads",), warning="slow on big images"),
    PluginSpec("windows.malware.pebmasquerade", OPTIONAL, "processes whose PEB image path / command line differs from the kernel's record (masquerading)",
               used_by=("MAL-003", "Injection")),
    PluginSpec("windows.malware.processghosting", OPTIONAL, "process ghosting: processes started from a file that is delete-pending or deleted",
               used_by=("MAL-004",), alternatives=("windows.processghosting",)),
    PluginSpec("windows.malware.svcdiff", OPTIONAL, "services found by scanning but hidden from the service list (Windows 10 build 15063+ only)",
               used_by=("MAL-005",), alternatives=("windows.svcdiff",), min_nt=(10, 0)),
    PluginSpec("windows.etwpatch", OPTIONAL, "ETW tracing functions patched in ntdll (a way to blind security tools)", used_by=("MAL-007",)),
    PluginSpec("windows.driverirp", OPTIONAL, "IRP handler of every driver: handlers that point outside the driver (IRP hooks)", used_by=("MAL-006",),
               warning="output is large (about 28 rows per driver)"),
    PluginSpec("windows.shimcachemem", OPTIONAL, "shimcache read from memory: executables Windows has seen, with file times (Timeline)",
               used_by=("Timeline",), warning="slow; supports only some Windows builds"),
)

RUN_KEY_PREFIX = "windows.registry.printkey ["      # kept for older callers; rules use plugin_names_used_by()
















# ----------------------------------------------------------------------------- bundles: what Settings shows


_RUN_KEY_MEMBERS = tuple(spec.name for spec in REGISTRY if spec.choice in ("run_keys", "autostart_keys", "more_run_keys", "service_keys"))
BUNDLES: Tuple[Bundle, ...] = (
    Bundle("processes", "Processes", "Process list, hidden-process scan, tree, command lines and owners (the base of every analysis).",
           ("windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline", "windows.getsids"), default=True, locked=True),
    Bundle("network", "Network connections",
           "Connections and listening ports. Volatility 3 reads Vista and newer; Windows XP / 2003 use Volatility 2 automatically when it is set up under Volatility.",
           ("windows.netscan", "windows.netstat"), default=True),
    Bundle("memory", "Injected code and modules", "Executable private memory (malfind) and the DLLs each process loaded.",
           ("windows.malfind", "windows.dlllist"), default=True),
    Bundle("handles", "Open handles", "Files, keys, mutexes and processes each process holds open.", ("windows.handles",), default=True,
           warning="slow on large images"),
    Bundle("hidden", "Deep check for hidden code", "Cross-checks processes (psxview), loader lists (ldrmodules) and the memory map (vadinfo).",
           ("windows.psxview", "windows.ldrmodules", "windows.vadinfo"), warning="slow; vadinfo output is huge"),
    Bundle("kernel", "Kernel integrity", "Drivers (loaded and found by scan), system-call table, kernel callbacks and driver IRP handlers.",
           ("windows.modules", "windows.modscan", "windows.driverscan", "windows.ssdt", "windows.callbacks", "windows.driverirp")),
    Bundle("persistence", "Persistence", "Services (scan and registry), Run keys, Winlogon / IFEO / AppInit, Active Setup and scheduled tasks.",
           ("windows.svcscan",) + _RUN_KEY_MEMBERS + ("windows.registry.scheduled_tasks",)),
    Bundle("history", "Execution history", "UserAssist, Amcache and the shimcache: programs that were started, with times (also feed the Timeline).",
           ("windows.registry.userassist", "windows.registry.amcache", "windows.shimcachemem")),
    Bundle("files", "Files and objects", "File objects (the Files view), mutexes and environment variables.",
           ("windows.filescan", "windows.mutantscan", "windows.envars"), warning="filescan output can be very large"),
    Bundle("hunting", "Malware hunting",
           "Process hollowing, ghosting, masquerading, suspicious thread starts, hidden services and ETW patching.",
           ("windows.malware.hollowprocesses", "windows.malware.suspicious_threads", "windows.malware.pebmasquerade",
            "windows.malware.processghosting", "windows.malware.svcdiff", "windows.etwpatch"), warning="slow on big images"),
    Bundle("yara", "YARA scan of process memory", "Scan every process with your YARA rule file (or rules made from your IOC list).",
           ("windows.vadyarascan",), warning="slow; needs the yara-python package and a rule file"),
)


# ----------------------------------------------------------------------------- the registry object and the module-level API (unchanged for existing callers)
_R = PluginRegistry(REGISTRY, BUNDLES)
plugin_names_used_by = _R.plugin_names_used_by
names = _R.names
get = _R.get
find = _R.find
known = _R.known
required_names = _R.required_names
optional_choices = _R.optional_choices
bundle_of = _R.bundle_of
bundle_state = _R.bundle_state
apply_bundles = _R.apply_bundles
REGISTRY_OBJECT = _R
