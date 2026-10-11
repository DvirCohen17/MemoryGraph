"""Error helpers: friendly messages, a global exception hook and a safe-slot decorator."""
from __future__ import annotations

import functools
import inspect
import sys
import threading
import traceback
from typing import Callable, Optional

from app.logging_setup import get_logger

log = get_logger("errors")


class MemoryGraphError(Exception):
    """Base class for errors that already carry a user-friendly message."""

    def __init__(self, message: str, details: str = ""):
        super().__init__(message)
        self.message = message
        self.details = details


class VolatilityNotFound(MemoryGraphError):
    pass


class DumpFileError(MemoryGraphError):
    pass


class AnalysisCancelled(MemoryGraphError):
    pass


class VolatilityUnusable(MemoryGraphError):
    """Volatility ran but cannot read this image (symbols / OS / format)."""


def format_exception(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def short_message(exc: BaseException) -> str:
    if isinstance(exc, MemoryGraphError):
        return exc.message
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def report_exception(exc: BaseException, context: str = "", parent=None, show_dialog: bool = True) -> None:
    """Log the exception and (when a GUI is running) tell the user without crashing."""
    log.error("Unhandled error%s\n%s", f" in {context}" if context else "", format_exception(exc))
    if not show_dialog:
        return
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        if QApplication.instance() is None:
            return
        box = QMessageBox(parent)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle("MemoryGraph — Unexpected error")
        box.setText(short_message(exc))
        box.setInformativeText(
            (f"While: {context}\n\n" if context else "")
            + "The problem was written to the log file. The application is still running."
        )
        box.setDetailedText(format_exception(exc))
        box.exec()
    except Exception:  # never raise from the error reporter
        log.exception("Could not show the error dialog")


def safe_slot(func: Callable) -> Callable:
    """Wrap a GUI slot so an exception is reported instead of silently breaking the UI.

    Qt may pass signal arguments (for example ``clicked(bool)``); extra positional
    arguments the slot does not accept are dropped.
    """
    try:
        params = list(inspect.signature(func).parameters.values())
    except (TypeError, ValueError):
        params = []
    takes_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
    max_positional = len([p for p in params if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)])

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            call_args = args if takes_varargs else args[:max_positional]
            return func(*call_args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the UI boundary
            report_exception(exc, context=getattr(func, "__qualname__", "slot"))
            return None

    return wrapper


def install_global_excepthook() -> None:
    """Route uncaught exceptions (main thread and worker threads) to the log and a dialog."""
    previous = sys.excepthook

    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            previous(exc_type, exc, tb)
            return
        report_exception(exc if exc is not None else exc_type())

    def thread_hook(args):
        if args.exc_value is not None:
            report_exception(args.exc_value, context=f"thread {args.thread.name if args.thread else '?'}", show_dialog=False)

    sys.excepthook = hook
    threading.excepthook = thread_hook
