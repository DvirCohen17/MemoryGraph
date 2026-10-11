"""Shared test setup."""
import pytest


@pytest.fixture(autouse=True)
def isolated_memorygraph_home(tmp_path_factory, monkeypatch):
    """Every test gets its own empty MemoryGraph home (settings, cache, known-good lists): a test never reads or changes the real ~/.memorygraph."""
    monkeypatch.setenv("MEMORYGRAPH_HOME", str(tmp_path_factory.mktemp("mg_home")))


@pytest.fixture(autouse=True)
def no_blocking_dialogs(monkeypatch):
    """A modal message box in a headless test waits for a click that never comes and the whole run hangs. Any dialog a test did not replace itself fails the test at once."""
    try:
        from PySide6 import QtWidgets
    except ImportError:                                   # the pure-logic tests run without Qt
        return

    def blocked(name):
        def raiser(*args, **kwargs):
            raise RuntimeError(f"a modal dialog ({name}) was opened during a test; replace it with monkeypatch")
        return staticmethod(raiser)

    for name in ("information", "warning", "critical", "question"):
        monkeypatch.setattr(QtWidgets.QMessageBox, name, blocked(f"QMessageBox.{name}"))
    for name in ("getText", "getItem", "getInt", "getDouble", "getMultiLineText"):
        monkeypatch.setattr(QtWidgets.QInputDialog, name, blocked(f"QInputDialog.{name}"))
    for name in ("getOpenFileName", "getSaveFileName", "getExistingDirectory", "getOpenFileNames"):
        monkeypatch.setattr(QtWidgets.QFileDialog, name, blocked(f"QFileDialog.{name}"))
    # an error box built by hand (show_error, safe_slot) is shown with exec(): block that too
    monkeypatch.setattr(QtWidgets.QDialog, "exec", lambda self, *a, **k: (_ for _ in ()).throw(RuntimeError(f"{type(self).__name__}.exec() was called during a test; replace it with monkeypatch")))


@pytest.fixture(autouse=True)
def no_motion(monkeypatch):
    """Animations make a test wait for the event loop; motion is off unless a test asks for it (tests/test_engines.py and tests/test_gui_polish.py do)."""
    try:
        from app.windows import motion
    except ImportError:
        return
    monkeypatch.setattr(motion, "ENABLED", False)
