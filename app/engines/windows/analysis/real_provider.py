"""Volatility 3 provider: run plugins (collection) -> pipeline (normalization + rules).

Execution plan
--------------
1. validate the dump file and locate/start Volatility (clear errors instead of a silent hang),
2. run ``windows.info`` alone first. It builds/downloads the symbol table once, so the parallel
   plugins that follow do not race to write the same symbol cache,
3. run every other enabled plugin in parallel (``parallel_plugins`` at a time),
4. refuse to continue only when *no* process list could be produced at all; any other failed plugin
   becomes a warning and a "Re-run failed plugins" button in the GUI,
5. hand the plugin results to :func:`app.analysis.pipeline.analyze_plugins`.
"""
from __future__ import annotations

import concurrent.futures as cf
import os
import queue
import threading
import time
from typing import Callable, Dict, List, Optional, Sequence

from app.analysis import ioc as ioc_module, plugin_cache, plugin_timing
from app.engines.windows.analysis import os_profile, plugin_registry as registry, vol2_runner
from app.engines.windows.analysis.normalizer import flatten_rows
from app.analysis.pipeline import analyze_plugins
from app.analysis.volatility_runner import (
    VolatilityTool, check_tool, describe_os, find_volatility, global_args, run_plugin, version_note,
)
from app.analysis.dump import validate_dump  # noqa: F401  (shared by every engine; re-exported here for older callers)
from app.errors import AnalysisCancelled, DumpFileError, VolatilityUnusable
from app.logging_setup import get_logger
from app.models import AnalysisResult, PluginResult

log = get_logger("provider")

Progress = Optional[Callable[[str, int], None]]
PluginEvent = Optional[Callable[[str, str, str], None]]   # (plugin, state, detail)


def _shutdown_pool(pool: cf.ThreadPoolExecutor, futures) -> None:
    """Cancel work that has not started, then wait for running jobs (works on Python 3.8+;
    ``shutdown(cancel_futures=True)`` only exists from 3.9)."""
    for future in futures:
        future.cancel()
    pool.shutdown(wait=True)


class RealProvider:
    """Volatility 3 provider: collection/normalization first, detection second."""

    # The lists live in plugin_registry (one declaration per plugin); these names are kept for existing callers.
    CORE_PLUGINS = registry.names(registry.CORE)
    EXTENDED_PLUGINS = registry.names(registry.EXTENDED)
    OPTIONAL_PLUGINS = registry.names(registry.OPTIONAL)
    REQUIRED_PLUGINS = registry.required_names()

    def __init__(self, settings: Optional[dict] = None):
        self.settings = settings or {}
        enabled = self.settings.get("enabled_plugins")
        names = [n for n in self.CORE_PLUGINS if not enabled or n in enabled or n in self.REQUIRED_PLUGINS]
        self.plugin_names = names
        if self.settings.get("run_extended_plugins"):
            self.plugin_names.extend(self.EXTENDED_PLUGINS)
        # opt-in plugins: the setting holds Settings checkbox ids (a plugin name, or e.g. "run_keys" for several printkey runs)
        chosen = set(self.settings.get("optional_plugins") or [])
        self.skipped: List[str] = []          # explanations for chosen plugins that cannot run (shown as result warnings)
        for spec in registry.REGISTRY:
            if spec.group != registry.OPTIONAL or spec.choice_id not in chosen or spec.name in self.plugin_names:
                continue
            if spec.needs_setting and not str(self.settings.get(spec.needs_setting) or "").strip():
                note = f"{spec.name} was skipped: it needs a value for '{spec.needs_setting}' in Settings (for example the path of your YARA rule file)."
                if note not in self.skipped:
                    self.skipped.append(note)
                continue
            self.plugin_names.append(spec.name)
        self.tool: Optional[VolatilityTool] = None

    # ------------------------------------------------------------------ public
    def run(self, dump_path: str, progress: Progress = None, plugin_event: PluginEvent = None,
            cancel: Optional[threading.Event] = None) -> AnalysisResult:
        dump = validate_dump(dump_path)
        self._notify(progress, "Locating Volatility", 3)
        plugins = self._collect(dump, self.plugin_names, progress, plugin_event, cancel)
        self._require_process_list(plugins)
        iocs, ioc_warnings = ioc_module.load_from_settings(self.settings)
        result = analyze_plugins(dump, plugins, progress, iocs=iocs)
        result.warnings.extend(ioc_warnings + self._skipped_warnings())
        result.tool_info = self._tool_info()
        return result

    def rerun(self, result: AnalysisResult, names: Optional[Sequence[str]] = None, progress: Progress = None,
              plugin_event: PluginEvent = None, cancel: Optional[threading.Event] = None) -> AnalysisResult:
        """Run the given plugins (default: the failed ones) again and rebuild the analysis."""
        dump = validate_dump(result.dump_path)
        todo = list(names) if names else [p.name for p in result.plugins if p.failed]
        if not todo:
            raise ValueError("There are no failed plugins to re-run.")
        fresh = {p.name: p for p in self._collect(dump, todo, progress, plugin_event, cancel, use_cache=False,
                                                  known={p.name: p for p in result.plugins})}
        merged = [fresh.pop(p.name, p) for p in result.plugins]
        merged.extend(fresh.values())
        self._require_process_list(merged)
        iocs, ioc_warnings = ioc_module.load_from_settings(self.settings)
        rebuilt = analyze_plugins(dump, merged, progress, case=result.case, iocs=iocs)
        rebuilt.warnings.extend(ioc_warnings)
        rebuilt.tool_info = {**dict(getattr(result, "tool_info", {}) or {}), **self._tool_info()}
        return rebuilt

    def _tool_info(self) -> Dict[str, str]:
        """What produced this result (saved with the investigation; shown under Computer Info)."""
        from app.analysis.volatility_runner import describe_tool
        info: Dict[str, str] = {"analysed": time.strftime("%Y-%m-%d %H:%M:%S %z")}
        if self.tool is not None:
            info["Volatility 3"] = describe_tool(self.tool)
        vol2 = getattr(self, "_vol2_cache", (None, ""))[0]
        if vol2 is not None:
            info["Volatility 2"] = f"{vol2.description} (version {vol2.version or 'unknown'})"
        return info

    def _skipped_warnings(self) -> List[str]:
        return list(self.skipped)

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _notify(progress: Progress, text: str, value: int) -> None:
        if progress:
            try:
                progress(text, value)
            except Exception:  # noqa: BLE001 - a GUI callback must never break the analysis
                log.exception("progress callback failed")

    @staticmethod
    def _event(callback: PluginEvent, name: str, state: str, detail: str = "") -> None:
        if callback:
            try:
                callback(name, state, detail)
            except Exception:  # noqa: BLE001
                log.exception("plugin event callback failed")

    def _prepare_tool(self) -> VolatilityTool:
        tool = find_volatility(self.settings.get("volatility_path", ""))
        self.tool = check_tool(tool)
        self.tool.global_args = global_args(self.settings)
        log.info("Using Volatility %s via %s (%s plugins listed)", self.tool.version, self.tool.description,
                 "unknown number of" if self.tool.plugins is None else len(self.tool.plugins))
        note = version_note(self.tool)
        if note:
            log.warning(note)
        return self.tool

    def _collect(self, dump: str, names: Sequence[str], progress: Progress, plugin_event: PluginEvent,
                 cancel: Optional[threading.Event], use_cache: Optional[bool] = None,
                 known: Optional[Dict[str, PluginResult]] = None) -> List[PluginResult]:
        """``known``: results of an earlier run (a re-run does not execute windows.info again but still wants the OS for messages)."""
        known = known or {}
        cancel = cancel or threading.Event()
        use_cache = self.settings.get("use_cache", True) if use_cache is None else use_cache
        idle = int(self.settings.get("idle_timeout_seconds", 900))
        limit = int(self.settings.get("max_plugin_seconds", 7200))
        parallel = max(1, int(self.settings.get("parallel_plugins", 3)))

        tool = self._prepare_tool()
        self._notify(progress, f"Using Volatility {tool.version}", 8)
        for name in names:
            self._event(plugin_event, name, "queued", "")

        try:
            image_bytes = os.path.getsize(dump)
        except OSError:
            image_bytes = 0
        events: "queue.Queue[tuple]" = queue.Queue()
        fractions: Dict[str, float] = {n: 0.0 for n in names}
        results: Dict[str, PluginResult] = {}
        vol2_state: Dict[str, object] = {}              # the Volatility 2 tool and the image facts it needs, filled in once windows.info is known

        def overall() -> int:
            return int(10 + 65 * (sum(fractions.values()) / max(1, len(fractions))))

        def job_vol2(name: str) -> PluginResult:
            events.put(("start", name, ""))
            tool = vol2_state["tool"]
            if use_cache:
                hit = plugin_cache.load(dump, name, "vol2-" + (tool.version or "?"))
                if hit is not None:
                    events.put(("done", name, hit))
                    return hit
            profile = vol2_state["profile"]
            res = vol2_runner.run_vol2(tool, dump, name, profile.vol2_profile, kdbg=vol2_state.get("kdbg", ""), dtb=vol2_state.get("dtb", ""),
                                       timeout=min(limit, int(self.settings.get("vol2_timeout_seconds", 1200))), cancel=cancel)
            if use_cache and res.status == "Completed":
                plugin_cache.store(dump, name, "vol2-" + (tool.version or "?"), res)
            events.put(("done", name, res))
            return res

        def job(name: str) -> PluginResult:
            if cancel.is_set():
                raise AnalysisCancelled("Analysis cancelled.")
            if name.startswith("vol2."):
                return job_vol2(name)
            events.put(("start", name, ""))
            if use_cache:
                hit = plugin_cache.load(dump, name, tool.version)
                if hit is not None:
                    events.put(("done", name, hit))
                    return hit
            spec = registry.find(name)
            args = list(spec.args) if spec else []
            if spec and spec.setting_arg:
                key, flag = spec.setting_arg
                args += [flag, str(self.settings.get(key) or "")]
            res = run_plugin(
                tool, dump, name, idle_timeout=idle, max_seconds=limit, cancel=cancel,
                on_progress=lambda pct, msg, n=name: events.put(("progress", n, pct, msg)),
                os_info=describe_os(results.get("windows.info") or known.get("windows.info")),
                volatility_plugin=spec.volatility_plugin if spec else "", args=args,
                alternatives=spec.alternatives if spec else (),
            )
            if use_cache and res.status == "Completed":
                plugin_cache.store(dump, name, tool.version, res)
            if res.status == "Completed" and not res.cached:
                plugin_timing.record(name, res.duration, image_bytes)       # the next run starts the slow plugins first and estimates better
            events.put(("done", name, res))
            return res

        def drain() -> None:
            while True:
                try:
                    item = events.get_nowait()
                except queue.Empty:
                    return
                kind, name = item[0], item[1]
                if kind == "start":
                    self._event(plugin_event, name, "running", "")
                    self._notify(progress, f"Running plugin: {name}", overall())
                elif kind == "progress":
                    pct, msg = item[2], item[3]
                    fractions[name] = max(fractions[name], min(0.99, pct / 100.0))
                    self._event(plugin_event, name, "progress", f"{pct:.0f}% {msg}".strip())
                    self._notify(progress, f"Running plugin: {name}", overall())
                elif kind == "done":
                    res = item[2]
                    fractions[name] = 1.0
                    state = "cached" if res.cached else ("done" if res.status == "Completed" else "failed")
                    if res.status == "Completed":
                        detail = f"{len(res.rows)} rows" if res.cached else f"{len(res.rows)} rows in {res.duration:.0f}s"
                    else:
                        lines = (res.error or "failed").strip().splitlines()
                        detail = (lines[-1] if lines else "failed")[:200]
                    self._event(plugin_event, name, state, detail)
                    self._notify(progress, f"Finished plugin: {name}", overall())

        def execute(batch: List[str], workers: int) -> None:
            if not batch:
                return
            pool = cf.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="vol")
            futures: Dict[cf.Future, str] = {}
            try:
                futures = {pool.submit(job, n): n for n in batch}
                pending = set(futures)
                while pending:
                    drain()
                    done, pending = cf.wait(pending, timeout=0.3, return_when=cf.FIRST_COMPLETED)
                    for future in done:
                        name = futures[future]
                        try:
                            results[name] = future.result()
                        except AnalysisCancelled:
                            raise
                        except Exception as exc:  # noqa: BLE001
                            log.exception("Plugin job %s crashed", name)
                            results[name] = PluginResult(name, "Failed", [{"Status": "Failed", "Error": str(exc)}], f"Unexpected error: {exc}")
                            self._event(plugin_event, name, "failed", str(exc))
                    if cancel.is_set():
                        raise AnalysisCancelled("Analysis cancelled.")
                drain()
            finally:
                _shutdown_pool(pool, list(futures))

        first = [n for n in names if n == "windows.info"]
        rest = [n for n in names if n != "windows.info"]
        started = time.monotonic()
        extra: List[str] = []                                   # Volatility 2 jobs, in the order they were planned
        try:
            execute(first, 1)      # symbols first, on their own
            info = results.get("windows.info") or known.get("windows.info")
            profile = os_profile.from_rows(flatten_rows(info.rows)) if info is not None and info.status == "Completed" else os_profile.OsProfile()
            log.info("Image: %s", profile.name)
            runnable, extra = self._plan(rest, profile, results, fractions, plugin_event, vol2_state, info)
            for name in extra:
                fractions[name] = 0.0
                self._event(plugin_event, name, "queued", "")
            # the slowest plugins first: the run ends when the last one ends, so a 10-minute plugin must not be the one that starts last
            todo = plugin_timing.order(runnable, image_bytes) + extra
            self._notify(progress, f"Estimated time: {plugin_timing.describe(plugin_timing.estimate_total(todo, image_bytes, parallel))} "
                                   f"({len(todo)} plugins, {parallel} at a time; from earlier runs on this computer)", 9)
            execute(todo, parallel)
            fallback = self._vol2_fallback(profile, results, vol2_state, fractions, plugin_event, extra)
            if fallback:
                extra += fallback
                execute(fallback, parallel)
        except AnalysisCancelled:
            cancel.set()
            raise
        log.info("Collected %d plugins in %.0fs", len(results), time.monotonic() - started)
        return [results[n] for n in names if n in results] + [results[n] for n in extra if n in results]

    # ------------------------------------------------------------------ Windows version and Volatility 2
    def _vol2_tool(self):
        """``(tool, problem)``: the configured Volatility 2 (checked once) or why there is none."""
        if not hasattr(self, "_vol2_cache"):
            try:
                tool = vol2_runner.find_vol2(self.settings.get("vol2_path", ""), self.settings.get("python2_path", ""))
                self._vol2_cache = (vol2_runner.check_vol2(tool), "") if tool else (None, "Volatility 2 is not set up (Settings → Volatility 2).")
            except vol2_runner.Vol2Unusable as exc:
                self._vol2_cache = (None, exc.message)
        return self._vol2_cache

    def _plan(self, rest, profile, results, fractions, plugin_event, vol2_state, info):
        """Split the remaining plugins into those that make sense for this Windows and those that are skipped with a reason; plan the
        Volatility 2 network jobs for images Volatility 3 cannot read (NT 5.x: Windows XP / 2003)."""
        runnable, extra = [], []
        asked = [n for n in rest if n.startswith("vol2.")]           # a re-run of Volatility 2 jobs that failed earlier
        rest = [n for n in rest if not n.startswith("vol2.")]
        wanted_network = any(n in ("windows.netscan", "windows.netstat") for n in rest)
        tool, problem = self._vol2_tool() if ((profile.legacy and wanted_network) or asked) else (None, "")
        for name in rest:
            spec = registry.find(name)
            reason = spec.inapplicable(profile) if spec else ""
            if not reason:
                runnable.append(name)
                continue
            if name in ("windows.netscan", "windows.netstat"):
                reason += (" Network connections for this image come from Volatility 2 instead (vol2.connections, vol2.sockets)." if tool is not None
                           else f" {problem or ''} Volatility 2 reads the network tables of XP and 2003 images.".strip())
            results[name] = PluginResult(name, "Skipped", [], reason)
            fractions[name] = 1.0
            self._event(plugin_event, name, "skipped", reason)
        if tool is not None:
            vol2_state.update({"tool": tool, "profile": profile, **os_profile.debug_addresses(flatten_rows(info.rows) if info is not None else [])})
            extra = asked or (list(vol2_runner.FAST_NETWORK) + (list(vol2_runner.DEEP_NETWORK) if self.settings.get("vol2_deep_scan") else []))
            if not profile.vol2_profile:
                for name in extra:
                    results[name] = PluginResult(name, "Skipped", [], f"No Volatility 2 profile is known for {profile.short_name}.")
                    fractions[name] = 1.0
                extra = []
        else:
            for name in asked:
                results[name] = PluginResult(name, "Failed", [{"Status": "Failed", "Error": problem}], problem)
                fractions[name] = 1.0
        return runnable, extra

    def _vol2_fallback(self, profile, results, vol2_state, fractions, plugin_event, already):
        """Vista / 7 / 8: when Volatility 3 could not read the network (usually the tcpip symbols are not available offline), Volatility 2's
        ``netscan`` has built-in profiles and needs no symbol files. Only runs after both Volatility 3 plugins failed."""
        if not (6, 0) <= profile.version < (10, 0) or not profile.vol2_profile:
            return []
        present = [p for p in (results.get(n) for n in ("windows.netscan", "windows.netstat")) if p is not None]
        if not present or not all(p.failed for p in present):
            return []
        tool, _problem = self._vol2_tool()
        if tool is None or "vol2.netscan" in already:
            return []
        info = results.get("windows.info")
        vol2_state.update({"tool": tool, "profile": profile, **os_profile.debug_addresses(flatten_rows(info.rows) if info is not None else [])})
        fractions["vol2.netscan"] = 0.0
        self._event(plugin_event, "vol2.netscan", "queued", "Volatility 3 could not read the network tables; trying Volatility 2")
        return ["vol2.netscan"]

    @staticmethod
    def _require_process_list(plugins: Sequence[PluginResult]) -> None:
        listed = [p for p in plugins if p.name in ("windows.pslist", "windows.psscan", "windows.pstree") and p.status == "Completed" and p.rows]
        if listed:
            return
        failed = [p for p in plugins if p.failed]
        lines = [f"• {p.name}: {((p.error or 'failed').strip().splitlines() or ['failed'])[-1][:300]}" for p in failed[:6]]
        raise VolatilityUnusable(
            "Volatility could not produce a process list for this memory image, so there is nothing to analyse.\n\n"
            + ("\n".join(lines) if lines else "The process plugins returned no rows (is this a Windows memory image?).")
            + "\n\nCommon causes: the image is not a Windows image, the symbol files of this Windows build are not on this computer (Settings → Extra symbol folders), "
              "or the file is truncated/corrupt.",
            "\n\n".join(f"== {p.name} ==\n{p.error}" for p in failed),
        )
