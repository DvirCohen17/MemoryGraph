"""Linux: the plugins MemoryGraph knows about and the groups Settings shows (PLACEHOLDER DATA: edit freely).

Same shape as ``app/engines/windows/analysis/plugin_registry.py`` (see ``app/analysis/registry_core.py``): one :class:`PluginSpec` per plugin run, one :class:`Bundle` per Settings
tick box. The names are the Volatility 3 ``linux.*`` plugins (the runner asks the installed Volatility which of them exist and reports the others as unavailable, so a name
that a version does not have is harmless). Nothing reads these rows yet: the Linux normalizer and rules are still to be written.
"""
from __future__ import annotations

from typing import Tuple

from app.analysis.registry_core import CORE, EXTENDED, OPTIONAL, Bundle, PluginRegistry, PluginSpec  # noqa: F401  (re-exported)

REGISTRY: Tuple[PluginSpec, ...] = (
    # --- core: the process list and what identifies the kernel
    PluginSpec("banners.Banners", CORE, "kernel banner: which kernel and distribution this is", required=True, used_by=("Computer Info",)),
    PluginSpec("linux.pslist.PsList", CORE, "process list (task list)", required=True, used_by=("Process Tree",)),
    PluginSpec("linux.psscan.PsScan", CORE, "scan for process structures: finds unlinked ones", used_by=()),
    PluginSpec("linux.pstree.PsTree", CORE, "process hierarchy", used_by=("Process Tree",)),
    PluginSpec("linux.psaux.PsAux", CORE, "process command lines", used_by=()),
    PluginSpec("linux.envars.Envars", CORE, "environment variables of each process", used_by=()),
    PluginSpec("linux.sockstat.Sockstat", CORE, "network sockets and their state", used_by=("Network",)),
    PluginSpec("linux.malfind.Malfind", CORE, "executable anonymous memory (injected code)", used_by=()),
    PluginSpec("linux.proc.Maps", CORE, "memory mappings of each process", used_by=()),
    PluginSpec("linux.lsof.Lsof", CORE, "open files of each process", used_by=()),
    # --- extended
    PluginSpec("linux.library_list.LibraryList", EXTENDED, "shared libraries loaded by each process", used_by=()),
    PluginSpec("linux.elfs.Elfs", EXTENDED, "ELF images mapped in each process", used_by=()),
    PluginSpec("linux.lsmod.Lsmod", EXTENDED, "loaded kernel modules", used_by=()),
    PluginSpec("linux.check_modules.Check_modules", EXTENDED, "kernel modules hidden from the module list", used_by=()),
    PluginSpec("linux.hidden_modules.Hidden_modules", EXTENDED, "kernel modules found by scanning memory", used_by=()),
    PluginSpec("linux.check_syscall.Check_syscall", EXTENDED, "system call table entries that were changed", used_by=()),
    PluginSpec("linux.check_idt.Check_idt", EXTENDED, "interrupt descriptor table entries that were changed", used_by=()),
    PluginSpec("linux.tty_check.tty_check", EXTENDED, "tty operation hooks", used_by=()),
    PluginSpec("linux.bash.Bash", EXTENDED, "bash command history recovered from memory", used_by=()),
    PluginSpec("linux.mountinfo.MountInfo", EXTENDED, "mounted file systems", used_by=()),
    # --- optional
    PluginSpec("linux.pagecache.Files", OPTIONAL, "files cached in memory (the Files view)", used_by=("Files",), warning="slow on big images"),
    PluginSpec("linux.check_creds.Check_creds", OPTIONAL, "processes that share credentials structures (privilege escalation)", used_by=()),
    PluginSpec("linux.check_afinfo.Check_afinfo", OPTIONAL, "network protocol handlers that were changed", used_by=()),
    PluginSpec("linux.keyboard_notifiers.Keyboard_notifiers", OPTIONAL, "keyboard notifier callbacks (keyloggers)", used_by=()),
    PluginSpec("linux.kmsg.Kmsg", OPTIONAL, "the kernel log buffer", used_by=("Timeline",)),
    PluginSpec("linux.ip.Addr", OPTIONAL, "network interfaces and addresses", used_by=("Network",)),
)

BUNDLES: Tuple[Bundle, ...] = (
    Bundle("processes", "Processes", "Process list, hidden-process scan, tree, command lines and environment (the base of every analysis).",
           ("banners.Banners", "linux.pslist.PsList", "linux.psscan.PsScan", "linux.pstree.PsTree", "linux.psaux.PsAux", "linux.envars.Envars"), default=True, locked=True),
    Bundle("network", "Network connections", "Sockets and their state.", ("linux.sockstat.Sockstat",), default=True),
    Bundle("memory", "Injected code and mappings", "Executable anonymous memory (malfind) and the memory maps of each process.", ("linux.malfind.Malfind", "linux.proc.Maps"), default=True),
    Bundle("files", "Open files", "The files each process has open.", ("linux.lsof.Lsof",), default=True),
    Bundle("libraries", "Libraries and ELF images", "Shared libraries and ELF images mapped in each process.", ("linux.library_list.LibraryList", "linux.elfs.Elfs")),
    Bundle("kernel", "Kernel integrity", "Kernel modules (listed and hidden), the system call table and the interrupt table.",
           ("linux.lsmod.Lsmod", "linux.check_modules.Check_modules", "linux.hidden_modules.Hidden_modules", "linux.check_syscall.Check_syscall", "linux.check_idt.Check_idt",
            "linux.tty_check.tty_check"), warning="slow on big images"),
    Bundle("history", "Shell history and mounts", "Bash history recovered from memory and the mounted file systems.", ("linux.bash.Bash", "linux.mountinfo.MountInfo")),
    Bundle("hooks", "Hooks and credentials", "Changed network handlers, keyboard notifiers and shared credentials.",
           ("linux.check_creds.Check_creds", "linux.check_afinfo.Check_afinfo", "linux.keyboard_notifiers.Keyboard_notifiers")),
    Bundle("pagecache", "File cache and logs", "Files cached in memory, the kernel log and the network interfaces.",
           ("linux.pagecache.Files", "linux.kmsg.Kmsg", "linux.ip.Addr"), warning="slow on big images"),
)

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
