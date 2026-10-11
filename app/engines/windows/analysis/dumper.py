"""Volatility dump actions (process image, DLLs, malfind pages, handle files).

Runs inside a ``BackgroundTask`` so the GUI never blocks. Uses the same Volatility discovery and
UTF-8 handling as the analysis runner, a generous inactivity-free timeout, and reports failures
as :class:`MemoryGraphError` (friendly message + technical details).
"""
from __future__ import annotations

import csv
import datetime
import hashlib
import os
import subprocess
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from app.analysis.volatility_runner import _creation_flags, _env, explain_failure, find_volatility
from app.errors import DumpFileError, MemoryGraphError
from app.logging_setup import get_logger

log = get_logger("dumper")

MANIFEST_NAME = "memorygraph_hashes.csv"
_MANIFEST_COLUMNS = ["utc_time", "file", "size_bytes", "sha256", "md5", "plugin", "pid", "source_image", "command"]


@dataclass
class DumpedFile:
    name: str
    size: int
    sha256: str
    md5: str
    error: str = ""          # set when the file was written but could not be read back to hash it (an antivirus often blocks dumped malware)

    @property
    def readable(self) -> bool:
        return not self.error and bool(self.sha256)


def snapshot_dir(directory: str) -> Dict[str, Tuple[int, int]]:
    """{file name: (size, mtime_ns)} of the files directly inside ``directory``."""
    state = {}
    with os.scandir(directory) as entries:
        for entry in entries:
            if entry.is_file() and entry.name != MANIFEST_NAME:
                info = entry.stat()
                state[entry.name] = (info.st_size, info.st_mtime_ns)
    return state


def hash_file(path: str) -> Tuple[str, str]:
    """(sha256, md5) of a file, read in blocks."""
    sha, md5 = hashlib.sha256(), hashlib.md5()      # md5: only because offline lookup lists still use it, not for integrity
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(block)
            md5.update(block)
    return sha.hexdigest(), md5.hexdigest()


def hash_new_files(directory: str, before: Dict[str, Tuple[int, int]]) -> List[DumpedFile]:
    """Hash the files that appeared (or were rewritten) since ``before`` was taken."""
    found = []
    for name, state in sorted(snapshot_dir(directory).items()):
        if before.get(name) == state:
            continue
        try:
            sha256, md5 = hash_file(os.path.join(directory, name))
        except OSError as exc:      # one blocked file must not cost the hashes of all the others
            log.warning("Could not read %s to hash it: %s", name, exc)
            found.append(DumpedFile(name, state[0], "", "", f"could not be read ({exc.strerror or exc})"))
            continue
        found.append(DumpedFile(name, state[0], sha256, md5))
    return found


def write_manifest(directory: str, files: List[DumpedFile], plugin: str, pid: int, source_image: str, command: List[str]) -> str:
    """Append one row per dumped file to ``memorygraph_hashes.csv`` (created with a header on first use)."""
    path = os.path.join(directory, MANIFEST_NAME)
    is_new = not os.path.isfile(path)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        if is_new:
            writer.writerow(_MANIFEST_COLUMNS)
        for item in files:
            writer.writerow([now, item.name, item.size, item.sha256, item.md5, plugin, pid, source_image, " ".join(command)])
    return path


class VolatilityDumper:
    def __init__(self, dump_path: str, volatility_path: str = "", global_args=()):
        self.dump_path = dump_path
        self.volatility_path = volatility_path or ""
        self.global_args = list(global_args)      # --offline / -s from Settings (volatility_runner.global_args)

    @staticmethod
    def find_executable(custom_path: str = "") -> str:
        """Kept for backward compatibility: path of the Volatility launcher."""
        return find_volatility(custom_path).argv[0]

    def _run(self, plugin: str, pid, output_dir: str, *extra: str, timeout: int = 3600) -> Tuple[subprocess.CompletedProcess, list]:
        if not self.dump_path or not os.path.isfile(self.dump_path):
            raise DumpFileError(f"The memory dump is no longer available:\n{self.dump_path}")
        try:
            os.makedirs(output_dir, exist_ok=True)
            probe = os.path.join(output_dir, ".mg_write_test")
            with open(probe, "w", encoding="utf-8") as handle:
                handle.write("ok")
            os.remove(probe)
        except OSError as exc:
            raise DumpFileError(f"Cannot write to the output folder:\n{output_dir}\n\n{exc}") from exc

        tool = find_volatility(self.volatility_path)
        command = tool.argv + self.global_args + ["-f", self.dump_path, "-o", output_dir, plugin, *(["--pid", str(pid)] if pid is not None else []), *extra]
        log.info("Running dump command: %s", " ".join(command))
        try:
            before = snapshot_dir(output_dir)
        except OSError:
            before = {}
        try:
            completed = subprocess.run(command, capture_output=True, timeout=timeout, check=False, stdin=subprocess.DEVNULL,
                                       creationflags=_creation_flags(), env=_env())
        except subprocess.TimeoutExpired as exc:
            raise MemoryGraphError(f"Volatility did not finish within {timeout // 60} minutes and was stopped.") from exc
        except OSError as exc:
            raise MemoryGraphError(f"Volatility could not be started: {exc}") from exc
        stdout = (completed.stdout or b"").decode("utf-8", "replace")
        stderr = (completed.stderr or b"").decode("utf-8", "replace")
        if completed.returncode != 0:
            raise MemoryGraphError("Volatility could not complete this dump.", explain_failure(stderr, completed.returncode))
        result = subprocess.CompletedProcess(command, 0, stdout, stderr)
        # Evidence integrity: hash what this run produced. A hashing problem must not turn a finished dump into a failure.
        result.artifacts, result.manifest = [], ""
        try:
            result.artifacts = hash_new_files(output_dir, before)
            if any(a.readable for a in result.artifacts):
                result.manifest = write_manifest(output_dir, [a for a in result.artifacts if a.readable], plugin, pid, self.dump_path, command)
        except OSError as exc:
            log.warning("Could not hash the dumped files in %s: %s", output_dir, exc)
        return result, command

    def dump_process(self, pid: int, output_dir: str):
        return self._run("windows.pslist", pid, output_dir, "--dump")

    def dump_all_process_images(self, output_dir: str):
        """Dump the executable of every process in one run (``windows.pslist --dump`` without a PID filter)."""
        return self._run("windows.pslist", None, output_dir, "--dump")

    def dump_dlls(self, pid: int, output_dir: str):
        return self._run("windows.dlllist", pid, output_dir, "--dump")

    def dump_handles(self, pid: int, output_dir: str):
        # windows.dumpfiles writes the file objects reachable through the process's handles.
        return self._run("windows.dumpfiles", pid, output_dir)

    def dump_malfind_pages(self, pid: int, output_dir: str):
        return self._run("windows.malfind", pid, output_dir, "--dump")

    def dump_file_objects(self, offsets, output_dir: str):
        """Dump the files found by filescan (``Offset`` = the FILE_OBJECT's address as filescan prints it, a kernel virtual address) with ONE windows.dumpfiles run.

        One run for many files matters: every Volatility start loads the symbols again. For each file Volatility writes up to three files
        (data section / image section / cache) named ``file.<object>.<section>.<cache>.<name>.<ext>``; a file whose contents are not in
        memory produces none."""
        addresses = [hex(int(o)) for o in offsets]
        if not addresses:
            raise MemoryGraphError("No file was selected.")
        return self._run("windows.dumpfiles", None, output_dir, "--virtaddr", *addresses)

    def dump_file_object(self, offset: int, output_dir: str):
        return self.dump_file_objects([offset], output_dir)
