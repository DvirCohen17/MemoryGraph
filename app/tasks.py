"""Run a function in a background QThread and report back through signals (GUI never freezes)."""
from __future__ import annotations

import threading
from typing import Any, Callable, Optional, Set

from PySide6.QtCore import QObject, QThread, Signal

from app.errors import AnalysisCancelled, MemoryGraphError, format_exception
from app.logging_setup import get_logger

log = get_logger("tasks")
_ACTIVE: Set["BackgroundTask"] = set()   # keeps tasks alive until their thread has finished


class _Worker(QObject):
    done = Signal(object)
    failed = Signal(str, str)      # message, details
    cancelled = Signal()

    def __init__(self, fn: Callable, cancel_event: threading.Event):
        super().__init__()
        self._fn = fn
        self._cancel = cancel_event

    def run(self) -> None:
        try:
            result = self._fn(self._cancel)
        except AnalysisCancelled:
            self.cancelled.emit()
        except MemoryGraphError as exc:
            log.error("Task failed: %s", exc.message)
            self.failed.emit(exc.message, exc.details or format_exception(exc))
        except Exception as exc:  # noqa: BLE001 - report instead of crashing the thread silently
            log.exception("Task crashed")
            self.failed.emit(f"{type(exc).__name__}: {exc}", format_exception(exc))
        else:
            self.done.emit(result)


class BackgroundTask(QObject):
    """``BackgroundTask(fn).start()`` runs ``fn(cancel_event)`` off the GUI thread."""

    finished = Signal(object)
    failed = Signal(str, str)
    cancelled = Signal()

    def __init__(self, fn: Callable[[threading.Event], Any], parent: Optional[QObject] = None):
        super().__init__(parent)
        self._cancel = threading.Event()
        self._thread = QThread()
        self._worker = _Worker(fn, self._cancel)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.done.connect(self._on_done)
        self._worker.failed.connect(self._on_failed)
        self._worker.cancelled.connect(self._on_cancelled)
        self._thread.finished.connect(self._cleanup)
        self._running = False

    @property
    def running(self) -> bool:
        # A plain Python flag: the QThread may already be scheduled for deletion once the task is over.
        return self._running

    def start(self) -> None:
        _ACTIVE.add(self)
        self._running = True
        self._thread.start()

    def cancel(self) -> None:
        self._cancel.set()

    def _end(self) -> None:
        self._running = False          # before emitting, so a handler may immediately start a new task
        self._thread.quit()

    def _on_done(self, result) -> None:
        self._end()
        self.finished.emit(result)

    def _on_failed(self, message: str, details: str) -> None:
        self._end()
        self.failed.emit(message, details)

    def _on_cancelled(self) -> None:
        self._end()
        self.cancelled.emit()

    def _cleanup(self) -> None:
        self._running = False
        _ACTIVE.discard(self)
        self._worker.deleteLater()
        self._thread.deleteLater()
