"""Volatility 2 as a second engine for the plugins Volatility 3 cannot run: network connections of Windows XP / 2003.

Volatility 3's ``windows.netscan`` / ``windows.netstat`` start at Windows Vista. Volatility 2 reads XP and 2003 with ``connections`` and ``sockets``
(walking the kernel lists: seconds) and, on request, ``connscan`` / ``sockscan`` (a pool scan of the whole image: minutes, finds closed and hidden
ones). It also has ``netscan`` for Vista / 7, which needs no symbol download (Volatility 2 profiles are built in), so it is the fallback when
Volatility 3 cannot load the tcpip symbols offline.

It is used as a program, never imported: either the standalone ``volatility_2.6_win64_standalone.exe`` or ``vol.py`` (which needs Python 2.7;
``py -2``, ``python2`` or a path from Settings is found). The profile (``WinXPSP3x86`` ...) is derived from ``windows.info`` (see ``os_profile``), and the
kernel debugger block / DTB it reports are passed on (``--kdbg`` / ``--dtb``) so Volatility 2 does not have to search the image for them, which is
where it spends most of its time. If the derived profile is refused, ``imageinfo`` is asked once for suggestions.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from app.engines.windows.analysis import os_profile
from app.analysis.volatility_runner import _creation_flags
from app.errors import AnalysisCancelled, MemoryGraphError
from app.logging_setup import get_logger
from app.paths import project_root
from app.models import PluginResult

log = get_logger("vol2")

_BANNER = re.compile(r"Volatility Foundation Volatility Framework\s+([0-9][^\s]*)")
# result name -> Volatility 2 plugin
VOL2_PLUGINS: Dict[str, str] = {"vol2.connections": "connections", "vol2.sockets": "sockets", "vol2.connscan": "connscan",
                                "vol2.sockscan": "sockscan", "vol2.netscan": "netscan"}
FAST_NETWORK = ("vol2.connections", "vol2.sockets")          # list walks
DEEP_NETWORK = ("vol2.connscan", "vol2.sockscan")            # whole-image scans
PROFILE_REFUSED = ("invalid profile", "no suitable address space", "unable to find a profile", "profile")


class Vol2Unusable(MemoryGraphError):
    """Volatility 2 is configured but cannot be started."""


@dataclass
class Vol2Tool:
    argv: List[str]
    description: str = ""
    version: str = ""
    cwd: str = ""
    kind: str = "exe"                    # "exe" or "py"


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def find_python2(configured: str = "") -> Optional[List[str]]:
    """Command prefix of a Python 2 interpreter (a configured path, then ``py -2``, ``python2``, ``python2.7``, ``C:\\Python27``), or None."""
    candidates: List[List[str]] = []
    if configured.strip():
        candidates.append([configured.strip().strip('"')])
    else:
        if shutil.which("py"):
            candidates.append(["py", "-2"])
        for name in ("python2", "python2.7"):
            found = shutil.which(name)
            if found:
                candidates.append([found])
        for path in (r"C:\Python27\python.exe", r"C:\Python27-x64\python.exe"):
            if os.path.isfile(path):
                candidates.append([path])
    for argv in candidates:
        try:
            done = subprocess.run(argv + ["-V"], capture_output=True, timeout=20, check=False, creationflags=_creation_flags(), stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if b"Python 2." in (done.stdout or b"") + (done.stderr or b""):
            return argv
    return None


BUNDLED_DIR = os.path.join(str(project_root()), "tools", "volatility2")


def bundled_location() -> str:
    """The Volatility 2 dropped into the project's ``tools/volatility2`` folder (a standalone .exe or a vol.py), or '' when there is none."""
    if not os.path.isdir(BUNDLED_DIR):
        return ""
    for name in sorted(os.listdir(BUNDLED_DIR)):
        lower = name.lower()
        if lower.endswith(".exe") and "vol" in lower:
            return os.path.join(BUNDLED_DIR, name)
    for dirpath, _dirs, files in os.walk(BUNDLED_DIR):
        if "vol.py" in files and os.path.isdir(os.path.join(dirpath, "volatility")):
            return os.path.join(dirpath, "vol.py")
        if dirpath.count(os.sep) - BUNDLED_DIR.count(os.sep) >= 2:
            break
    return ""


def find_vol2(path: str = "", python2: str = "") -> Optional[Vol2Tool]:
    """The Volatility 2 described by Settings: an ``.exe`` (run directly), a ``vol.py`` (run with Python 2) or a folder containing either.
    Returns None when nothing is configured (Volatility 2 is optional); raises :class:`Vol2Unusable` when a configured path cannot be used."""
    path = (path or "").strip().strip('"')
    if not path:
        path = bundled_location()
    if not path:
        return None
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            lower = name.lower()
            if lower.endswith(".exe") and "vol" in lower and "volatility3" not in lower:
                path = os.path.join(path, name)
                break
        else:
            script = os.path.join(path, "vol.py")
            if not os.path.isfile(script):
                raise Vol2Unusable(f"No Volatility 2 executable or vol.py was found in:\n{path}")
            path = script
    if not os.path.isfile(path):
        raise Vol2Unusable(f"The Volatility 2 path in Settings does not exist:\n{path}")
    if path.lower().endswith(".py"):
        interpreter = find_python2(python2)
        if interpreter is None:
            raise Vol2Unusable("vol.py (Volatility 2) needs Python 2.7, which was not found. Install it, set its path under Settings → Volatility 2, "
                               "or use the standalone Volatility 2 .exe instead.")
        return Vol2Tool(interpreter + [path], f"{' '.join(interpreter)} {path}", cwd=os.path.dirname(path), kind="py")
    return Vol2Tool([path], path, cwd=os.path.dirname(path), kind="exe")


def check_vol2(tool: Vol2Tool, timeout: int = 120) -> Vol2Tool:
    """Start it once (``-h``) to prove it runs and read the version."""
    try:
        done = subprocess.run(tool.argv + ["-h"], capture_output=True, timeout=timeout, check=False, cwd=tool.cwd or None, env=_env(),
                              creationflags=_creation_flags(), stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as exc:
        raise Vol2Unusable(f"Volatility 2 did not start within {timeout} seconds.") from exc
    except OSError as exc:
        raise Vol2Unusable(f"Volatility 2 could not be started: {exc}") from exc
    text = (done.stdout or b"").decode("utf-8", "replace") + "\n" + (done.stderr or b"").decode("utf-8", "replace")
    match = _BANNER.search(text)
    if not match:
        if "volatility3" in text.lower() or "Volatility 3" in text:
            raise Vol2Unusable("That is Volatility 3. Choose Volatility 2 (2.6) here: its file is usually named volatility_2.6_win64_standalone.exe or vol.py.")
        raise Vol2Unusable("The program did not identify itself as Volatility 2.\n" + (text.strip().splitlines() or ["(no output)"])[-1][:300])
    tool.version = match.group(1)
    return tool


@dataclass
class _Outcome:
    code: Optional[int]
    stdout: str
    stderr: str
    seconds: float


def _run(tool: Vol2Tool, args: Sequence[str], timeout: int, cancel: Optional[threading.Event]) -> _Outcome:
    command = tool.argv + list(args)
    started = time.monotonic()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, cwd=tool.cwd or None, env=_env(),
                            creationflags=_creation_flags())
    while True:
        try:
            out, err = proc.communicate(timeout=1)
            break
        except subprocess.TimeoutExpired:
            if cancel is not None and cancel.is_set():
                proc.kill()
                proc.communicate()
                raise AnalysisCancelled("Analysis cancelled.")
            if time.monotonic() - started > timeout:
                proc.kill()
                proc.communicate()
                return _Outcome(None, "", f"Volatility 2 did not finish within {timeout // 60} minutes and was stopped.", time.monotonic() - started)
    return _Outcome(proc.returncode, (out or b"").decode("utf-8", "replace"), (err or b"").decode("utf-8", "replace"), time.monotonic() - started)


def parse_json_rows(text: str) -> List[dict]:
    """Rows of a Volatility 2 ``--output=json`` result (``{"columns": [...], "rows": [[...], ...]}``) as dicts."""
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON in the output")
    data = json.loads(text[start:])
    columns = [str(c) for c in data.get("columns", [])]
    return [dict(zip(columns, row)) for row in data.get("rows", []) if isinstance(row, (list, tuple))]


def imageinfo_profiles(tool: Vol2Tool, dump: str, timeout: int = 900, cancel: Optional[threading.Event] = None) -> List[str]:
    """Profiles Volatility 2's own ``imageinfo`` suggests (slow: it scans the image). Only used when the derived profile is refused."""
    outcome = _run(tool, ["-f", dump, "imageinfo"], timeout, cancel)
    return os_profile.parse_imageinfo(outcome.stdout + "\n" + outcome.stderr)


def run_vol2(tool: Vol2Tool, dump: str, result_name: str, profile: str, *, kdbg: str = "", dtb: str = "", timeout: int = 1200,
             cancel: Optional[threading.Event] = None) -> PluginResult:
    """Run one network plugin and return its rows (raw Volatility 2 columns) as a :class:`PluginResult` named ``result_name`` (``vol2.connections``).

    Never raises except for cancellation. The profile comes from windows.info; when it is refused ``imageinfo`` suggests one and the plugin runs again."""
    plugin = VOL2_PLUGINS[result_name]
    attempts: List[str] = []
    candidate = profile

    def command(prof: str, with_hints: bool) -> List[str]:
        args = ["-f", dump, f"--profile={prof}", "--output=json"]
        if with_hints and kdbg:
            args.append(f"--kdbg={kdbg}")
        if with_hints and dtb:
            args.append(f"--dtb={dtb}")
        return args + [plugin]

    started = time.monotonic()
    hints = bool(kdbg or dtb)                      # whether the command that produced the result carried --kdbg / --dtb
    outcome = _run(tool, command(candidate, True), timeout, cancel)
    attempts.append(f"{candidate}{' (with kdbg/dtb)' if kdbg or dtb else ''}")
    if outcome.code != 0 and (kdbg or dtb):
        # A wrong KDBG / DTB and a wrong profile give the same message ("No suitable address space mapping found"): drop the hints first and let
        # Volatility 2 search for them itself before blaming the profile.
        outcome = _run(tool, command(candidate, False), timeout, cancel)
        hints = False
        attempts.append(f"{candidate}")
    if outcome.code != 0 and any(w in outcome.stderr.lower() for w in PROFILE_REFUSED[:3]):
        for suggestion in imageinfo_profiles(tool, dump, timeout, cancel)[:2]:
            if suggestion == candidate:
                continue
            candidate = suggestion
            outcome = _run(tool, command(candidate, False), timeout, cancel)
            hints = False
            attempts.append(candidate)
            if outcome.code == 0:
                break
    full_command = tool.argv + command(candidate, hints)
    if outcome.code != 0:
        tail = "\n".join([l for l in outcome.stderr.splitlines() if l.strip()][-6:]) or f"exit code {outcome.code}"
        message = (f"{result_name} failed.\nVolatility 2 {tool.version or ''}; profile tried: {', '.join(attempts)}\n"
                   f"{'The profile was refused by Volatility 2: this build may need another profile (run imageinfo by hand).' if any(w in outcome.stderr.lower() for w in PROFILE_REFUSED[:3]) else ''}\n\nVolatility output:\n{tail}")
        return PluginResult(result_name, "Failed", [{"Status": "Failed", "Error": message}], message, outcome.stdout[:2000], full_command, outcome.seconds)
    try:
        rows = parse_json_rows(outcome.stdout)
    except (ValueError, json.JSONDecodeError) as exc:
        message = f"{result_name}: Volatility 2 ran but its output is not JSON ({exc}).\n{outcome.stdout[:400]}"
        return PluginResult(result_name, "Failed", [{"Status": "Failed", "Error": message}], message, outcome.stdout[:2000], full_command, outcome.seconds)
    result = PluginResult(result_name, "Completed", rows, "", outcome.stdout if len(outcome.stdout) < 2_000_000 else "", full_command, time.monotonic() - started)
    log.info("%s: %d rows with profile %s in %.0fs", result_name, len(rows), candidate, result.duration)
    return result
