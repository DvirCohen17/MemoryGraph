"""One detonation, start to finish: clean VM -> sample -> wait -> ground truth -> suspend -> package."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Optional

from . import __version__
from .package import build_baseline_expected, build_expected, build_readme, write_json
from .vmware import SafetyError, check_isolation, check_memory_settings, find_memory_files

GUEST_ARCHIVE = r"C:\lab\in\sample.zip"
GUEST_DETONATE = r"C:\lab\detonate.ps1"
GUEST_COLLECT = r"C:\lab\collect.ps1"
GUEST_DETONATION_JSON = r"C:\lab\out\detonation.json"
GUEST_TRUTH_JSON = r"C:\lab\out\groundtruth.json"
GUEST_LAB = r"C:\lab"
GUEST_SCRIPTS = ("lab-json.ps1", "detonate.ps1", "collect.ps1")
HOST_GUEST_DIR = Path(__file__).resolve().parents[2] / "guest"     # lab/guest: always the current version


class DetonationError(Exception):
    pass


def push_guest_scripts(vm, vmx: str, source: Path = HOST_GUEST_DIR) -> None:
    """Copy the current guest scripts into the VM after the revert, so fixes need no template rebuild."""
    for folder in (GUEST_LAB, GUEST_LAB + r"\in", GUEST_LAB + r"\out"):
        vm.make_guest_dir(vmx, folder)
    for name in GUEST_SCRIPTS:
        vm.copy_to_guest(vmx, str(Path(source) / name), GUEST_LAB + "\\" + name)


def run_guest_step(vm, vmx: str, script: str, arguments: str, result_guest: str, result_host: Path, what: str) -> dict:
    """Run a guest script and fetch its JSON. The JSON decides success, not the exit code. If there is no JSON,
    the script's console output (saved in the VM by cmd.exe) is fetched and shown."""
    name = Path(script.replace("\\", "/")).stem
    log_guest = rf"C:\lab\out\{name}.log"
    output = vm.run_powershell(vmx, script, arguments, timeout=300, check=False, log=log_guest) or ""
    try:
        vm.copy_from_guest(vmx, result_guest, str(result_host))
    except Exception as exc:  # noqa: BLE001
        detail = output.strip()[:300]
        log_host = Path(result_host).with_name(f"{name}.log")
        try:
            vm.copy_from_guest(vmx, log_guest, str(log_host))
            detail = log_host.read_text(encoding="utf-8", errors="replace").strip()[-2000:] or detail
        except Exception:  # noqa: BLE001
            pass
        raise DetonationError(f"{what} wrote no result in the VM. Its output:\n{detail}") from exc
    data = json.loads(Path(result_host).read_text(encoding="utf-8-sig"))
    if data.get("fatal"):
        raise DetonationError(f"{what} failed inside the VM: {data['fatal']}")
    return data


def utc_stamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%d-%H%M")


def utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def package_id(guest: str, family=None, sample=None, ts: Optional[float] = None) -> str:
    stamp = utc_stamp(ts if ts is not None else time.time())
    if sample is None:
        return f"{guest}-baseline-{stamp}"
    return f"{guest}-{family.slug}-{sample.sha256[:8]}-{stamp}"


def safe_file_name(name: str, sha256: str, file_type: str) -> str:
    """A plausible file name without spaces or quotes (it travels through vmrun's command line)."""
    stem = Path(name or "").stem
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")[:60]
    if not stem or stem.lower() == sha256[: len(stem)].lower():
        stem = "invoice_" + sha256[:6]          # MalwareBazaar often names files by their hash
    return f"{stem}.{file_type}"


def sha256_file(path: Path, chunk: int = 8 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


def run_capture(cfg, vm, guest, cache=None, family=None, sample=None, *, seconds: Optional[int] = None,
                log: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                clock: Callable[[], float] = time.time, allow_unsafe: bool = False) -> Path:
    """Returns the package folder (work_dir/<id>) with memory.vmem/.vmss and the text files."""
    vmx = guest.vmx
    seconds = cfg.run_seconds if seconds is None else seconds

    problems = check_isolation(Path(vmx), cfg.lab_vnet)
    if problems and not allow_unsafe:
        raise SafetyError(f"{vmx} is not isolated:\n  - " + "\n  - ".join(problems))
    notes = check_memory_settings(Path(vmx))
    if any("encrypted" in n for n in notes):
        raise SafetyError(notes[0])

    started = clock()
    pid = package_id(guest.name, family, sample, started)
    pkg = Path(cfg.work_dir) / pid
    if pkg.exists():
        shutil.rmtree(pkg)
    pkg.mkdir(parents=True)
    log(f"[{pid}] reverting {guest.name} to '{guest.snapshot}'")
    vm.stop(vmx)
    vm.revert(vmx, guest.snapshot)
    try:
        vm.start(vmx)
        waited = vm.wait_until_ready(vmx, cfg.boot_timeout)
        push_guest_scripts(vm, vmx)
        detonation = {}
        if sample is not None:
            archive = cache.archive_path(sample.sha256)
            if not Path(archive).is_file():
                raise DetonationError(f"{archive} is missing: run 'labctl.py fetch' first")
            log(f"[{pid}] copying the sample archive into the VM")
            vm.copy_to_guest(vmx, str(archive), GUEST_ARCHIVE)
            arguments = (f"-Archive {GUEST_ARCHIVE} -Sha256 {sample.sha256} -Password {cfg.archive_password} "
                         f"-FileType {sample.file_type} -FileName {safe_file_name(sample.file_name, sample.sha256, sample.file_type)}")
            if sample.file_type == "dll":
                arguments += f" -DllExport {family.dll_export}"
            if cfg.drop_dir:
                arguments += f" -DropDir {cfg.drop_dir}"
            log(f"[{pid}] starting {family.name} {sample.sha256[:12]}")
            detonation = run_guest_step(vm, vmx, GUEST_DETONATE, arguments, GUEST_DETONATION_JSON,
                                        pkg / "detonation.json", "detonate.ps1")
            if detonation.get("status") != "launched":
                raise DetonationError(f"the sample did not start: {detonation.get('error', detonation.get('status'))}")
            log(f"[{pid}] running {seconds} s (PIDs {detonation.get('pids') or 'not found'})")
        else:
            log(f"[{pid}] clean baseline: idling {seconds} s")
        sleep(seconds)

        log(f"[{pid}] recording processes and connections inside the VM")
        truth = run_guest_step(vm, vmx, GUEST_COLLECT, "", GUEST_TRUTH_JSON, pkg / "groundtruth.json", "collect.ps1")
        if truth.get("errors"):
            log(f"[{pid}] note: the collector reported {len(truth['errors'])} error(s), first: {truth['errors'][0][:200]}")
        collected = clock()
        sleep(3)

        log(f"[{pid}] capturing memory (suspend)")
        suspend_at = clock()
        vm.suspend(vmx)
        memory, state = find_memory_files(Path(vmx).parent, suspend_at)
        shutil.copyfile(memory, pkg / "memory.vmem")
        if state is not None:
            shutil.copyfile(state, pkg / "memory.vmss")
        captured = suspend_at
    finally:
        vm.stop(vmx)
        try:
            vm.revert(vmx, guest.snapshot)   # never leave an infected VM behind
        except Exception as exc:  # noqa: BLE001 - report, the package may still be fine
            log(f"[{pid}] WARNING: could not revert {guest.name}: {exc}")

    log(f"[{pid}] hashing the memory image")
    memory_info = {"size": (pkg / "memory.vmem").stat().st_size, "sha256": sha256_file(pkg / "memory.vmem"),
                   "vmss_size": (pkg / "memory.vmss").stat().st_size if (pkg / "memory.vmss").is_file() else 0,
                   "source_file": Path(memory).name}
    os_info = truth.get("os") or {}
    os_text = " ".join(x for x in (os_info.get("product"), os_info.get("display_version") or os_info.get("release_id"),
                                   f"build {os_info.get('build')}" if os_info.get("build") else "") if x)
    meta = {
        "id": pid,
        "title": (f"{family.name} on {guest.name} ({sample.sha256[:12]})" if sample else f"Clean {guest.name} baseline"),
        "lab_version": __version__,
        "repo": cfg.repo,
        "family": family.name if family else None,
        "sample": sample.to_dict() if sample else None,
        "os": os_info,
        "os_text": os_text,
        "run": {"guest": guest.name, "vmx": vmx, "snapshot": guest.snapshot, "seconds": seconds,
                "launch": detonation.get("launch", "-") if sample else "-", "launched_utc": detonation.get("launched_utc"),
                "pids": detonation.get("pids", []), "drop_path": detonation.get("path"),
                "started_utc": utc_iso(started), "ready_after_s": round(waited, 1),
                "groundtruth_utc": truth.get("taken_utc"), "captured_utc": utc_iso(captured),
                "seconds_groundtruth_to_capture": round(captured - collected, 1)},
        "memory": memory_info,
        "notes": notes,
    }
    if sample is not None:
        expected = build_expected(pid, family, sample, truth, detonation, captured - collected)
    else:
        expected = build_baseline_expected(pid, truth)
    write_json(pkg / "metadata.json", meta)
    write_json(pkg / "expected.json", expected)
    (pkg / "README.md").write_text(build_readme(meta, expected, truth, family), encoding="utf-8")
    if sample is not None and cache is not None:
        cache.mark_run(sample.sha256, guest.name, pid)
    log(f"[{pid}] package ready: {pkg}")
    return pkg
