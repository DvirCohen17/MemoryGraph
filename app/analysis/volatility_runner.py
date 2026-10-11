"""Locate and run Volatility 3 reliably.

Why this replaces the old ``subprocess.run(..., timeout=120)`` call:
  * output is decoded as UTF-8 (``text=True`` on Windows used the ANSI code page and crashed on
    non-ASCII process/file names),
  * stdout goes to a temp file (no pipe deadlock, no huge strings held twice),
  * Volatility's ``Progress:`` lines on stderr are parsed, giving live progress and
  * the time limit is an *inactivity* limit: a slow scan that keeps making progress (large image,
    first-time symbol download) is never killed, while a hung process is,
  * the process can be cancelled from the GUI,
  * failures are translated into messages a person can act on.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, FrozenSet, List, Optional, Sequence, Tuple

from app.analysis.rows import flatten_rows
from app.errors import AnalysisCancelled, VolatilityNotFound, VolatilityUnusable
from app.logging_setup import get_logger
from app.models import PluginResult
from app.paths import cache_dir

log = get_logger("volatility")

_PROGRESS_RE = re.compile(r"Progress:\s+([0-9]+(?:\.[0-9]+)?)\s*(.*)")
_ENTRY = "import sys; from volatility3.cli import main; sys.argv[0] = 'vol'; main()"
INSTALL_HINT = ("Install it in the same Python environment as MemoryGraph:\n    pip install volatility3\n"
                "or choose the vol/vol.exe file in Settings → Volatility path.")

ProgressFn = Callable[[float, str], None]

# The Volatility 3 release MemoryGraph is developed and tested against (keep in sync with requirements.txt).
# Other releases are used as they are; this is only used to explain a failure, never to refuse to run.
RECOMMENDED_VERSION = "2.28.2"

# Plugin lines in `vol -h` look like "    windows.netscan.NetScan   Scans for network objects ...".
_PLUGIN_LINE_RE = re.compile(r"^\s+((?:[a-z0-9_]+\.)+[A-Za-z_][A-Za-z0-9_]*)(?:\s|$)")
_LOG_ERROR_RE = re.compile(r"^(ERROR|CRITICAL)\b")


@dataclass
class VolatilityTool:
    argv: List[str]
    version: str = "unknown"
    description: str = ""
    # Plugins this Volatility lists in ``-h`` (e.g. "windows.netscan"); None = could not be determined.
    plugins: Optional[FrozenSet[str]] = None
    # Options placed before ``-f`` on every analysis/dump command (see :func:`global_args`): --offline, -s <symbol folders>.
    global_args: List[str] = field(default_factory=list)


def _creation_flags() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0


_EXE_NAMES = ("vol.exe", "vol", "volatility3.exe", "volatility3")
_SCRIPT_NAMES = ("vol.py", "volatility3.py")


def _env() -> dict:
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env["PYTHONUNBUFFERED"] = "1"   # make Progress lines arrive immediately when running vol.py
    return env


def _python_for_scripts() -> str:
    """A real Python interpreter to run vol.py with (sys.executable is the app itself when frozen)."""
    if not getattr(sys, "frozen", False):
        return sys.executable
    for name in ("python", "python3", "py"):
        found = shutil.which(name)
        if found:
            return found
    raise VolatilityNotFound(
        "vol.py needs a Python installation, but none was found on PATH.\n"
        "Install Python 3.8+ (and `pip install volatility3`'s dependencies), or choose vol.exe instead.")


def _script_tool(path: str) -> VolatilityTool:
    path = os.path.abspath(path)
    return VolatilityTool([_python_for_scripts(), path], description=path)


def find_volatility(custom_path: str = "") -> VolatilityTool:
    """Find Volatility 3. Order: settings path, the active environment, PATH, vol.py, python module."""
    custom_path = (custom_path or "").strip().strip('"')
    if custom_path:
        # A folder (e.g. a git clone of volatility3) -> use the vol.py inside it.
        if os.path.isdir(custom_path):
            for name in _SCRIPT_NAMES:
                script = os.path.join(custom_path, name)
                if os.path.isfile(script):
                    return _script_tool(script)
            raise VolatilityNotFound(f"No vol.py was found in the folder:\n{custom_path}")
        if not os.path.isfile(custom_path):
            raise VolatilityNotFound(f"The Volatility path in Settings does not exist:\n{custom_path}")
        if custom_path.lower().endswith(".py"):
            return _script_tool(custom_path)
        return VolatilityTool([custom_path], description=custom_path)

    env_dir = os.path.dirname(sys.executable)
    candidates = []
    for name in _EXE_NAMES:
        if env_dir:
            candidates.append(os.path.join(env_dir, name))
            candidates.append(os.path.join(env_dir, "Scripts", name))
    for name in _EXE_NAMES:
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return VolatilityTool([candidate], description=candidate)

    # vol.py: next to the app, in the working directory, in the volatility3 folder, or on PATH
    app_dir = os.path.dirname(os.path.abspath(sys.argv[0])) if sys.argv and sys.argv[0] else ""
    script_dirs = [d for d in (app_dir, os.getcwd(), os.path.join(app_dir, "volatility3"),
                               os.path.join(os.getcwd(), "volatility3")) if d]
    for directory in script_dirs:
        for name in _SCRIPT_NAMES:
            script = os.path.join(directory, name)
            if os.path.isfile(script):
                return _script_tool(script)
    for name in _SCRIPT_NAMES:
        found = shutil.which(name)
        if found:
            return _script_tool(found)

    if importlib.util.find_spec("volatility3") is not None:
        return VolatilityTool([sys.executable, "-c", _ENTRY], description=f"{sys.executable} (volatility3 module)")
    raise VolatilityNotFound("Volatility 3 was not found.\n" + INSTALL_HINT)

def global_args(settings) -> List[str]:
    """Options placed before ``-f`` on every Volatility 3 command. ``--offline`` is always there: MemoryGraph never connects to the internet, so a
    missing symbol file fails at once with Volatility's own message instead of waiting for network timeouts. ``-s`` adds the symbol folders
    from Settings (local ISF files; see docs/OFFLINE.md)."""
    settings = settings or {}
    args: List[str] = ["--offline"]
    folders = [str(d).strip() for d in (settings.get("symbol_dirs") or []) if str(d).strip()]
    if folders:
        args += ["-s", ";".join(folders)]
    return args


def check_tool(tool: VolatilityTool, timeout: int = 120) -> VolatilityTool:
    """Run ``vol -h`` once: proves Volatility starts, and reads its version."""
    try:
        completed = subprocess.run(
            tool.argv + ["-h"], capture_output=True, timeout=timeout, check=False,
            stdin=subprocess.DEVNULL, creationflags=_creation_flags(), env=_env(),
        )
    except subprocess.TimeoutExpired as exc:
        raise VolatilityUnusable(f"Volatility did not start within {timeout} seconds.", str(exc)) from exc
    except OSError as exc:
        raise VolatilityUnusable(f"Volatility could not be started: {exc}", f"Command: {' '.join(tool.argv)}") from exc
    text = (completed.stdout or b"").decode("utf-8", "replace") + "\n" + (completed.stderr or b"").decode("utf-8", "replace")
    match = re.search(r"Volatility 3 Framework\s+([0-9][^\s]*)", text)
    if match:
        tool.version = match.group(1)
    if completed.returncode != 0 or ("volatility" not in text.lower() and "usage" not in text.lower()):
        raise VolatilityUnusable(
            "Volatility started but did not respond correctly.\n" + _tail(text, 12) +
            "\n\nMake sure the volatility3 package and its dependencies are installed.", text)
    if tool.version == "unknown":
        try:
            from importlib.metadata import version
            tool.version = version("volatility3")
        except Exception:  # noqa: BLE001
            pass
    tool.plugins = parse_plugin_list(text)
    return tool


def parse_plugin_list(help_text: str) -> Optional[FrozenSet[str]]:
    """Plugin names (``windows.netscan``) listed in ``vol -h``; None when the list cannot be read."""
    names = set()
    for line in (help_text or "").splitlines():
        match = _PLUGIN_LINE_RE.match(line)
        if match:
            names.add(match.group(1).rsplit(".", 1)[0].lower())
    return frozenset(names) if len(names) >= 5 else None   # a handful of hits means we really parsed a plugin list


def plugin_available(tool: VolatilityTool, plugin: str) -> Optional[bool]:
    """True/False when the installed Volatility's plugin list is known, None when it is not."""
    if tool.plugins is None:
        return None
    return plugin.lower() in tool.plugins


def resolve_plugin_name(tool: VolatilityTool, preferred: str, alternatives: Sequence[str] = ()) -> str:
    """``preferred`` unless the installed Volatility does not list it but lists one of ``alternatives`` (renamed plugins)."""
    if plugin_available(tool, preferred) is False:
        for other in alternatives:
            if plugin_available(tool, other):
                return other
    return preferred


def version_key(text: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", (text or "").split("+")[0])[:3])


def version_note(tool: VolatilityTool) -> str:
    """A factual remark when the installed Volatility differs from the release MemoryGraph is tested with."""
    if tool.version == "unknown":
        return "The Volatility version could not be determined."
    if version_key(tool.version) < version_key(RECOMMENDED_VERSION):
        return (f"MemoryGraph is tested with Volatility 3 {RECOMMENDED_VERSION}; this is {tool.version}. "
                f"Upgrading (pip install -U volatility3=={RECOMMENDED_VERSION}) is the first thing to try.")
    return ""


def describe_tool(tool: VolatilityTool) -> str:
    return f"{tool.version} ({tool.description})" if tool.description else tool.version


def compatibility_report(tool: VolatilityTool, plugin_names: Sequence[str]) -> str:
    """Multi-line text for the Settings → Test button: version, version note and which requested plugins exist."""
    lines = [f"✔ Volatility {tool.version} found: {tool.description}"]
    note = version_note(tool)
    if note:
        lines.append("⚠ " + note)
    if tool.plugins is None:
        lines.append("Plugin availability could not be read from `vol -h`; plugins will simply be attempted.")
    else:
        # "a|b" = the same plugin under two names (renamed between versions): missing only when neither is listed
        missing = [n.split("|")[0] for n in plugin_names if not any(part.lower() in tool.plugins for part in n.split("|"))]
        lines.append(f"✖ Not available in this Volatility: {', '.join(missing)}" if missing
                     else f"✔ All {len(plugin_names)} plugins MemoryGraph uses are available.")
    return "\n".join(lines)


_NT_NAMES = {(5, 0): "Windows 2000", (5, 1): "Windows XP", (5, 2): "Windows XP x64 / Server 2003", (6, 0): "Windows Vista / Server 2008",
             (6, 1): "Windows 7 / Server 2008 R2", (6, 2): "Windows 8 / Server 2012", (6, 3): "Windows 8.1 / Server 2012 R2"}


def describe_os(info_plugin: Optional[PluginResult]) -> str:
    """One line about the image's Windows version, taken from ``windows.info`` ('' when unavailable)."""
    if info_plugin is None or info_plugin.status != "Completed":
        return "unknown (windows.info did not complete)" if info_plugin is not None else ""
    values = {str(r.get("Variable", "")).lower(): str(r.get("Value", "")) for r in info_plugin.rows if isinstance(r, dict)}
    try:
        major, minor = int(values.get("ntmajorversion", "")), int(values.get("ntminorversion", ""))
    except ValueError:
        return "unknown (windows.info has no NT version)"
    build = values.get("major/minor", "").split(".")[-1]
    if (major, minor) == (10, 0):
        name = "Windows 11 / Server 2022+" if build.isdigit() and int(build) >= 22000 else "Windows 10 / Server 2016-2019"
    else:
        name = _NT_NAMES.get((major, minor), "Windows")
    bits = {"true": "64-bit", "false": "32-bit"}.get(values.get("is64bit", "").lower(), "")
    return f"{name} (NT {major}.{minor}" + (f", build {build}" if build.isdigit() else "") + ")" + (f", {bits}" if bits else "")


def _tail(text: str, lines: int) -> str:
    parts = [l for l in (text or "").replace("\r", "\n").splitlines() if l.strip()]
    return "\n".join(parts[-lines:])


def classify_failure(stderr: str, plugin: str = "") -> str:
    """Reason for a failure, only when Volatility's own output says so ('' = no known pattern, show the output as it is)."""
    low = (stderr or "").lower()
    if "invalid choice" in low or "unable to find plugin" in low:
        return (f"{plugin or 'The plugin'} is not available in this Volatility installation (it is unknown, or its Python file "
                "failed to import). The Volatility version may be too old or too new for it.")
    if "this version of windows is not supported" in low:
        return ("The plugin does not support this image's Windows build (Volatility's own message below). That is a limit of the "
                "plugin for this operating system, not of MemoryGraph; a newer Volatility may add the build, but old systems "
                "such as Windows XP/2003 have no support in windows.netscan.")
    if "unable to locate symbols for the memory image's tcpip" in low or ("tcpip" in low and "symbol" in low and "pdb" in low):
        return ("Volatility could not load the symbols for tcpip.sys, which the network plugins need in addition to the kernel "
                "symbols. MemoryGraph never goes online (Volatility runs with --offline), so the tcpip.pdb of this Windows build must already be on this "
                "computer: add the folder that holds it under Settings → Extra symbol folders (docs/OFFLINE.md). It can also mean the tcpip.sys driver "
                "is not resident in the dump.")
    if "symbol table requirement was not fulfilled" in low or "unsatisfied requirement" in low or "unable to validate the plugin requirements" in low:
        return ("Volatility could not build the Windows symbol table for this image. MemoryGraph never goes online (Volatility runs with --offline), "
                "so the symbol file of this Windows build must already be on this computer: add the folder that holds it under Settings → "
                "Extra symbol folders (see docs/OFFLINE.md); each Volatility installation also has its own symbols folder. "
                "It can also mean the file is not a Windows memory image.")
    if "invalidaddressexception" in low:
        return "Volatility tried to read memory that is not present in the dump (paged out or not captured)."
    if "no such file" in low or "cannot find the file" in low:
        return "Volatility could not open the memory image (file missing or locked)."
    if "permission" in low and "denied" in low:
        return "Volatility was denied access to a file (memory image or symbol cache)."
    if "memoryerror" in low or "out of memory" in low:
        return "Volatility ran out of memory. Close other programs, or disable the heaviest plugins in Settings."
    missing = re.search(r"no module named ['\"]?([\w.]+)", low)
    if missing:
        return f"A Python dependency of Volatility is missing: {missing.group(1)} (pip install it in the same environment)."
    if "traceback (most recent call last)" in low:
        return ("The plugin crashed with an internal Python error (traceback below). It was raised inside Volatility's plugin code; "
                "the exact error line is the last line of the output.")
    return ""


def explain_failure(stderr: str, returncode: Optional[int], plugin: str = "", tool: Optional[VolatilityTool] = None,
                    os_info: str = "") -> str:
    """Readable failure text. The last line is always Volatility's own last output line (or the reason when there is none),
    because summaries elsewhere in the GUI show only the last line."""
    output = "\n".join(l if len(l) <= 400 else l[:400] + " …" for l in _tail(stderr, 8).splitlines()) \
        or f"Volatility exited with code {returncode}."
    reason = classify_failure(stderr, plugin)
    low = (stderr or "").lower()
    if os_info and not os_info.startswith("unknown") and "unable to validate the plugin requirements" in low and "tcpip" not in low:
        # windows.info already read this image with the same symbols, so a failed requirement check is about the plugin, not the symbols
        reason = (f"windows.info read this image ({os_info}) with the same kernel symbols, so the symbols are not the problem. Volatility's own "
                  f"requirement check for {plugin or 'this plugin'} failed: the plugin does not support this Windows version (for example scheduled "
                  "tasks and Amcache do not exist before Windows 7 / 8) or it needs a symbol file this image does not provide.")
    head = [f"{plugin} failed." if plugin else "Volatility failed."]
    if tool is not None:
        head.append(f"Volatility version: {describe_tool(tool)}")
    if os_info:
        head.append(f"Image operating system: {os_info}")
    if reason:
        head.append(f"Reason: {reason}")
    if tool is not None and (note := version_note(tool)):
        head.append(note)
    return "\n".join(head) + "\n\nVolatility output:\n" + output


def run_plugin(
    tool: VolatilityTool, dump_path: str, plugin: str, *, idle_timeout: int = 900, max_seconds: int = 7200,
    cancel: Optional[threading.Event] = None, on_progress: Optional[ProgressFn] = None, os_info: str = "",
    volatility_plugin: str = "", args: Sequence[str] = (), alternatives: Sequence[str] = (),
) -> PluginResult:
    """Run one plugin and return a :class:`PluginResult` (never raises except for cancellation).

    ``plugin`` is the name of the result; ``volatility_plugin`` (default: the same) is what is actually run, with ``args`` after it.
    ``alternatives`` are other names of the same plugin in other Volatility versions: the first one the installed Volatility lists is used.
    """
    real = resolve_plugin_name(tool, volatility_plugin or plugin, alternatives)
    command = tool.argv + tool.global_args + ["-f", dump_path, "-r", "json", real, *args]
    started = time.monotonic()
    if plugin_available(tool, real) is False:
        # Do not start a process that can only answer "invalid choice": say what is actually wrong.
        message = (f"{plugin} failed.\nVolatility version: {describe_tool(tool)}\n"
                   + (f"Image operating system: {os_info}\n" if os_info else "")
                   + f"Reason: {classify_failure('invalid choice', real)}\n"
                   + (version_note(tool) + "\n" if version_note(tool) else "")
                   + f"The installed Volatility lists {len(tool.plugins or ())} plugins and {real} is not one of them"
                   + (" (a plugin whose Python dependency is missing, for example yara-python, is also not listed)." if "yara" in real else "."))
        log.warning("%s unavailable in Volatility %s", plugin, tool.version)
        return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": message}], message, command=command, duration=0.0)
    out_file = None
    out_path = ""
    state = {"last_activity": started, "progress": 0.0, "errors": []}
    lock = threading.Lock()

    def reader(stream) -> None:
        buffer = b""
        try:
            while True:
                # read1 returns as soon as *any* data is available; read(n) would block until n bytes
                # arrive and delay progress lines (which made slow-but-healthy plugins look hung).
                chunk = stream.read1(512) if hasattr(stream, "read1") else os.read(stream.fileno(), 512)
                if not chunk:
                    break
                buffer += chunk
                parts = re.split(rb"[\r\n]+", buffer)
                buffer = parts.pop()
                for raw in parts:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    with lock:
                        state["last_activity"] = time.monotonic()
                    match = _PROGRESS_RE.match(line)
                    if match:
                        pct = float(match.group(1))
                        with lock:
                            state["progress"] = pct
                        if on_progress:
                            try:
                                on_progress(pct, match.group(2).strip())
                            except Exception:  # noqa: BLE001
                                pass
                    elif not line.startswith("Volatility 3 Framework"):
                        with lock:
                            state["errors"].append(line)
                            del state["errors"][:-300]
        except Exception:  # noqa: BLE001
            log.exception("stderr reader failed for %s", plugin)

    try:
        fd, out_path = tempfile.mkstemp(prefix="mg_", suffix=".json", dir=str(cache_dir()))
        os.close(fd)
        out_file = open(out_path, "wb")
        try:
            proc = subprocess.Popen(
                command, stdout=out_file, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                creationflags=_creation_flags(), env=_env(),
            )
        except OSError as exc:
            return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": str(exc)}],
                                f"Could not start Volatility: {exc}", command=command, duration=time.monotonic() - started)

        thread = threading.Thread(target=reader, args=(proc.stderr,), name=f"vol-stderr-{plugin}", daemon=True)
        thread.start()
        last_size, kill_reason = 0, ""
        while True:
            try:
                proc.wait(timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            try:
                size = os.path.getsize(out_path)
                if size != last_size:
                    last_size = size
                    with lock:
                        state["last_activity"] = now
            except OSError:
                pass
            if cancel is not None and cancel.is_set():
                kill_reason = "cancelled"
            elif now - started > max_seconds:
                kill_reason = f"exceeded the {max_seconds // 60}-minute limit for one plugin"
            else:
                with lock:
                    idle = now - state["last_activity"]
                if idle > idle_timeout:
                    kill_reason = f"produced no output or progress for {int(idle)} seconds (hung)"
            if kill_reason:
                _kill(proc)
                break
        thread.join(timeout=5)
        out_file.close()
        out_file = None
        duration = time.monotonic() - started
        if kill_reason == "cancelled":
            raise AnalysisCancelled("Analysis cancelled.")
        stderr_text = "\n".join(state["errors"])
        if kill_reason:
            message = f"{plugin} {kill_reason}; it was stopped so the rest of the analysis could continue."
            return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": message}], message, command=command, duration=duration)

        rows, raw, parse_error = _read_rows(out_path)
        if proc.returncode != 0:
            message = explain_failure(stderr_text, proc.returncode, plugin, tool, os_info)
            log.warning("%s failed (exit %s) with Volatility %s", plugin, proc.returncode, tool.version)
            return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": message}], message,
                                raw_output=raw[:200_000], command=command, duration=duration)
        if parse_error:
            message = f"{plugin} finished but its output was not valid JSON ({parse_error})."
            return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": message}], message + "\n" + _tail(stderr_text, 6),
                                raw_output=raw[:200_000], command=command, duration=duration)
        if not rows and any(_LOG_ERROR_RE.match(line) for line in state["errors"]):
            # Some plugins (windows.netstat without tcpip symbols) log an ERROR, return nothing and still exit 0.
            # Reporting that as "Completed, 0 rows" would look like "no network connections".
            message = explain_failure(stderr_text, 0, plugin, tool, os_info).replace(
                f"{plugin} failed.", f"{plugin} produced no rows and logged an error (Volatility exited normally).", 1)
            log.warning("%s returned no rows and logged an error with Volatility %s", plugin, tool.version)
            return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": message}], message,
                                command=command, duration=duration)
        warnings = stderr_text if stderr_text and not rows else ""
        return PluginResult(plugin, "Completed", rows, warnings, "", command, duration)
    except AnalysisCancelled:
        raise
    except Exception as exc:  # noqa: BLE001 - one plugin must never take down the analysis
        log.exception("Plugin %s crashed the runner", plugin)
        return PluginResult(plugin, "Failed", [{"Status": "Failed", "Error": str(exc)}], f"Unexpected error: {exc}",
                            command=command, duration=time.monotonic() - started)
    finally:
        if out_file is not None:
            try:
                out_file.close()
            except OSError:
                pass
        if out_path:
            try:
                os.remove(out_path)
            except OSError:
                pass


def _kill(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True,
                           creationflags=_creation_flags(), check=False, timeout=15)
        else:
            proc.kill()
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass
    try:
        proc.wait(timeout=10)
    except Exception:  # noqa: BLE001
        pass


def _read_rows(path: str) -> Tuple[list, str, str]:
    """Return ``(rows, raw_text_if_unparsed, parse_error)``."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        return [], "", f"could not read output: {exc}"
    stripped = text.strip()
    if not stripped:
        return [], "", ""          # plugin legitimately produced no rows
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError as exc:
        # Some builds print a banner before the JSON: retry from the first bracket.
        starts = [i for i in (stripped.find("["), stripped.find("{")) if i >= 0]
        if starts:
            try:
                data = json.loads(stripped[min(starts):])
            except json.JSONDecodeError:
                return [], stripped, exc.msg
        else:
            return [], stripped, exc.msg
    return flatten_rows(_rows_from(data)), "", ""


def _rows_from(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [x if isinstance(x, dict) else {"value": x} for x in raw]
    if isinstance(raw, dict):
        for key in ("rows", "data", "results", "items"):
            if isinstance(raw.get(key), list):
                return _rows_from(raw[key])
        return [raw]
    return [{"Output": str(raw)}]
