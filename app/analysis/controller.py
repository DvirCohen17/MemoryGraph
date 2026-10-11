"""GUI-facing controller: owns the background task for analysis / loading / re-running plugins."""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QObject, Signal

from app.analysis import ioc as ioc_module
from app.analysis.pipeline import reanalyze
from app.engines import engine_for, engine_for_settings
from app.errors import MemoryGraphError
from app.logging_setup import get_logger
from app.models import AnalysisResult, load_analysis_result
from app.tasks import BackgroundTask

log = get_logger("controller")


class AnalysisController(QObject):
    progress = Signal(str, int)
    plugin_event = Signal(str, str, str)       # plugin, state, detail
    finished = Signal(object)                  # AnalysisResult
    failed = Signal(str, str)                  # message, technical details
    cancelled = Signal()

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._task: Optional[BackgroundTask] = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and self._task.running

    # -- entry points -------------------------------------------------------------------------
    def start(self, dump_path: str, settings: dict) -> bool:
        provider = engine_for_settings(settings).make_provider(settings)
        return self._launch(lambda cancel: provider.run(
            dump_path, self._emit_progress, self._emit_plugin, cancel))

    def rerun_failed(self, result: AnalysisResult, settings: dict) -> bool:
        provider = engine_for(result).make_provider(settings)
        return self._launch(lambda cancel: provider.rerun(
            result, None, self._emit_progress, self._emit_plugin, cancel))

    def run_plugins(self, result: AnalysisResult, settings: dict, names) -> bool:
        """Run the named plugins on the image of ``result`` and merge their output into it (cache is bypassed)."""
        provider = engine_for(result).make_provider(settings)
        return self._launch(lambda cancel: provider.rerun(
            result, list(names), self._emit_progress, self._emit_plugin, cancel))

    def load(self, file_path: str, rebuild: bool = True, settings: Optional[dict] = None) -> bool:
        """Load a saved investigation; ``rebuild`` re-runs normalization + rules on its stored plugin output."""
        def work(cancel):
            self._emit_progress("Reading investigation file", 10)
            try:
                result = load_analysis_result(file_path)
            except (ValueError, OSError) as exc:      # corrupt / wrong / unreadable file: expected, not a crash
                raise MemoryGraphError(f"The investigation could not be opened.\n\n{exc}") from exc
            has_rows = any(p.rows for p in result.plugins)
            if rebuild and has_rows:
                self._emit_progress("Re-analysing stored plugin output with the current rules", 40)
                try:
                    iocs, ioc_warnings = ioc_module.load_from_settings(settings or {})
                    rebuilt = reanalyze(result, self._emit_progress, iocs=iocs)
                    rebuilt.warnings = list(dict.fromkeys(rebuilt.warnings + ioc_warnings))
                    return rebuilt
                except Exception as exc:  # noqa: BLE001 - fall back to the file as saved
                    log.exception("Re-analysis of %s failed, using stored results", file_path)
                    result.warnings.append(f"Could not re-analyse the stored plugin output ({exc}); showing the saved results.")
            self._emit_progress("Opening investigation", 100)
            return result
        return self._launch(work)

    def cancel(self) -> None:
        if self._task is not None:
            self._task.cancel()

    # -- internals ----------------------------------------------------------------------------
    def _emit_progress(self, text: str, value: int) -> None:
        self.progress.emit(text, int(value))

    def _emit_plugin(self, name: str, state: str, detail: str) -> None:
        self.plugin_event.emit(name, state, detail)

    def _launch(self, fn) -> bool:
        if self.is_running:
            log.warning("An analysis is already running; ignoring the new request")
            return False
        task = BackgroundTask(fn, self)
        task.finished.connect(self.finished)
        task.failed.connect(self.failed)
        task.cancelled.connect(self.cancelled)
        self._task = task
        task.start()
        return True
