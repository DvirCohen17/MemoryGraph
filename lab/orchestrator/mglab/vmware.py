"""VMware Workstation through vmrun, the VMX safety check and finding the memory files after a suspend."""
from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple


class VmrunError(Exception):
    pass


class SafetyError(Exception):
    pass


Runner = Callable[[Sequence[str], float], Tuple[int, str]]


def _default_runner(args: Sequence[str], timeout: float) -> Tuple[int, str]:
    proc = subprocess.run(list(args), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


@dataclass
class Vmrun:
    path: str
    guest_user: str
    guest_password: str
    runner: Runner = _default_runner
    sleep: Callable[[float], None] = time.sleep

    def _call(self, args: Sequence[str], guest: bool = False, timeout: float = 600, check: bool = True) -> str:
        cmd = [self.path, "-T", "ws"]
        if guest:
            cmd += ["-gu", self.guest_user, "-gp", self.guest_password]
        cmd += list(args)
        code, output = self.runner(cmd, timeout)
        if check and code != 0:
            raise VmrunError(f"vmrun {args[0]} failed: {output.strip()}")
        return output.strip()

    # --- power and snapshots
    def revert(self, vmx: str, snapshot: str) -> None:
        self._call(["revertToSnapshot", vmx, snapshot])

    def start(self, vmx: str) -> None:
        self._call(["start", vmx, "nogui"])

    def stop(self, vmx: str) -> None:
        self._call(["stop", vmx, "hard"], check=False)

    def suspend(self, vmx: str) -> None:
        self._call(["suspend", vmx, "hard"], timeout=1800)

    def snapshots(self, vmx: str) -> List[str]:
        out = self._call(["listSnapshots", vmx])
        return [line.strip() for line in out.splitlines()[1:] if line.strip()]

    def running(self) -> List[str]:
        out = self._call(["list"], check=False)
        return [line.strip() for line in out.splitlines()[1:] if line.strip()]

    # --- guest operations (through VMware Tools, not the network)
    def tools_running(self, vmx: str) -> bool:
        return "running" in self._call(["checkToolsState", vmx], check=False)

    def guest_processes(self, vmx: str) -> str:
        return self._call(["listProcessesInGuest", vmx], guest=True, check=False)

    def copy_to_guest(self, vmx: str, host_path: str, guest_path: str) -> None:
        self._call(["copyFileFromHostToGuest", vmx, host_path, guest_path], guest=True)

    def copy_from_guest(self, vmx: str, guest_path: str, host_path: str) -> None:
        self._call(["copyFileFromGuestToHost", vmx, guest_path, host_path], guest=True)

    def run_in_guest(self, vmx: str, program: str, arguments: str = "", interactive: bool = True,
                     wait: bool = True, timeout: float = 600, check: bool = True) -> str:
        args = ["runProgramInGuest", vmx]
        if not wait:
            args.append("-noWait")
        if interactive:
            args += ["-activeWindow", "-interactive"]
        args.append(program)
        if arguments:
            args.append(arguments)
        return self._call(args, guest=True, timeout=timeout, check=check)

    def make_guest_dir(self, vmx: str, guest_path: str) -> None:
        self._call(["createDirectoryInGuest", vmx, guest_path], guest=True, check=False)   # fails if it exists: fine

    def run_powershell(self, vmx: str, script: str, arguments: str = "", timeout: float = 600, check: bool = True) -> str:
        line = f"-NoProfile -ExecutionPolicy Bypass -File {script}"
        if arguments:
            line += " " + arguments
        return self.run_in_guest(vmx, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", line, timeout=timeout, check=check)

    def wait_until_ready(self, vmx: str, timeout: float) -> float:
        """Wait for VMware Tools and the desktop (explorer.exe). Returns the seconds waited."""
        start = time.monotonic()
        while True:
            if self.tools_running(vmx) and "explorer.exe" in self.guest_processes(vmx).lower():
                return time.monotonic() - start
            if time.monotonic() - start > timeout:
                raise VmrunError(f"The guest was not ready within {timeout:.0f} s (VMware Tools or the desktop missing)")
            self.sleep(5)


# --------------------------------------------------------------------------- VMX safety check
def read_vmx(path: Path) -> Dict[str, str]:
    values = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'\s*([^#=\s][^=]*?)\s*=\s*"(.*)"\s*$', line)
        if match:
            values[match.group(1).strip().lower()] = match.group(2)
    return values


def check_isolation(vmx_path: Path, lab_vnet: str) -> List[str]:
    """Everything that would let the infected guest reach your computer or the internet. Empty = safe."""
    vmx = read_vmx(vmx_path)
    problems = []
    adapters = sorted({key.split(".")[0] for key in vmx if re.match(r"ethernet\d+\.present$", key) and vmx[key].upper() == "TRUE"})
    for adapter in adapters:
        kind = vmx.get(f"{adapter}.connectiontype", "bridged").lower()
        if kind == "custom":
            vnet = vmx.get(f"{adapter}.vnet", "")
            if vnet.lower() != lab_vnet.lower():
                problems.append(f"{adapter} is on {vnet or '?'} instead of the lab network {lab_vnet}")
        else:
            problems.append(f"{adapter} uses '{kind}' networking (only the isolated lab network '{lab_vnet}' is allowed)")
    for key in ("isolation.tools.hgfs.disable", "isolation.tools.copy.disable", "isolation.tools.paste.disable",
                "isolation.tools.dnd.disable"):
        if vmx.get(key, "FALSE").upper() != "TRUE":
            problems.append(f'{key} is not "TRUE" (shared folders / clipboard / drag-and-drop must be off)')
    for key, value in vmx.items():
        if re.match(r"sharedfolder\d+\.present$", key) and value.upper() == "TRUE":
            problems.append(f"a shared folder is configured ({key})")
    if vmx.get("usb.present", "FALSE").upper() == "TRUE":
        problems.append("USB is enabled")
    return problems


def check_memory_settings(vmx_path: Path) -> List[str]:
    vmx = read_vmx(vmx_path)
    notes = []
    if vmx.get("mainmem.usenamedfile", "TRUE").upper() != "TRUE":
        notes.append('mainMem.useNamedFile is not "TRUE": a suspend may not write a .vmem file')
    if "encryption.keysafe" in vmx or "encryption.data" in vmx:
        notes.append("the VM is encrypted: its .vmem would be encrypted too and unreadable for Volatility")
    return notes


def find_memory_files(vm_dir: Path, since: float) -> Tuple[Path, Optional[Path]]:
    """After a suspend: the newest .vmss written since `since` and the .vmem with the same name."""
    vm_dir = Path(vm_dir)
    fresh = lambda p: p.stat().st_mtime >= since - 2
    states = sorted((p for p in vm_dir.glob("*.vmss") if fresh(p)), key=lambda p: p.stat().st_mtime, reverse=True)
    for state in states:
        memory = state.with_suffix(".vmem")
        if memory.is_file():
            return memory, state
    memories = sorted((p for p in vm_dir.glob("*.vmem") if fresh(p)), key=lambda p: p.stat().st_mtime, reverse=True)
    if memories:
        return memories[0], (states[0] if states else None)
    raise VmrunError(f"No .vmem written in {vm_dir} by the suspend (is mainMem.useNamedFile TRUE?)")
