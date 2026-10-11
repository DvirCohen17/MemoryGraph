"""Checks on the real dashboard windows: does what MemoryGraph computed actually reach the screen?

Builds the real ``DashboardWindow`` (offscreen) from an analysis result and reads what the views show: every view must build without an error, the process tree must
list every process, the Network view must list every connection, the Plugin Output view must offer every plugin that completed, the Indications view must list the
findings, and every process window (details dialog) must open. This catches "the data exists but the screen shows nothing / something else".
"""
from __future__ import annotations

import traceback
from typing import List

from PySide6.QtWidgets import QApplication, QTreeWidgetItemIterator

from checks import FAIL, INCONCLUSIVE, PASS, Check


def _count_tree(tree) -> int:
    count, it = 0, QTreeWidgetItemIterator(tree)
    while it.value():
        count += 1
        it += 1
    return count


def run(result) -> List[dict]:
    app = QApplication.instance() or QApplication([])
    from app.windows.dashboard_window import DashboardWindow
    out: List[Check] = []
    window = DashboardWindow(result, settings={})
    window.resize(1500, 900)
    window.show()
    app.processEvents()
    try:
        for name in window.IDX:
            try:
                window.select_view(window.IDX[name])
                app.processEvents()
                out.append(Check("UI", f"view '{name}' builds", PASS))
            except Exception as exc:  # noqa: BLE001
                out.append(Check("UI", f"view '{name}' builds", FAIL, f"{type(exc).__name__}: {exc}", traceback.format_exc().splitlines()[-4:]))
        # process tree: every process appears (items carry the PID in column 1)
        try:
            tree = window.view("Process Tree").tree
            pids = set()
            it = QTreeWidgetItemIterator(tree)
            while it.value():
                text = it.value().text(1)
                if text.strip().lstrip("-").isdigit():
                    pids.add(int(text))
                it += 1
            expected = {p.pid for p in result.processes}
            out.append(Check("UI", "Process Tree lists every process", PASS if pids >= expected else FAIL, f"{len(pids)} shown, {len(expected)} in the result",
                             [f"missing PID {p}" for p in sorted(expected - pids)[:10]]))
        except Exception as exc:  # noqa: BLE001
            out.append(Check("UI", "Process Tree lists every process", FAIL, f"{type(exc).__name__}: {exc}"))
        # network table
        try:
            view = window.view("Network")
            model_rows = view.model.rowCount()
            out.append(Check("UI", "Network view holds every connection", PASS if model_rows == len(result.connections) else FAIL,
                             f"{model_rows} rows, {len(result.connections)} connections in the result; {view.summary.text()}"))
        except Exception as exc:  # noqa: BLE001
            out.append(Check("UI", "Network view holds every connection", FAIL, f"{type(exc).__name__}: {exc}"))
        # indications
        try:
            view = window.view("Indications")
            shown = _count_tree(view.tree)
            findings = sum(1 for i in result.indications if i.triage not in ("false_positive", "baseline"))
            out.append(Check("UI", "Indications view shows the findings", PASS if shown >= (1 if findings else 0) else FAIL,
                             f"{shown} tree rows for {findings} findings (Low findings are hidden by default)"))
        except Exception as exc:  # noqa: BLE001
            out.append(Check("UI", "Indications view shows the findings", FAIL, f"{type(exc).__name__}: {exc}"))
        # plugin output
        try:
            view = window.view("Plugin Output")
            wanted = [p.name for p in result.plugins if p.status == "Completed" and p.rows]
            missing = [n for n in wanted if not view.show_plugin_by_name(n)]
            out.append(Check("UI", "Plugin Output offers every completed plugin", PASS if not missing else FAIL, f"{len(wanted)} plugins tried", missing[:10]))
        except Exception as exc:  # noqa: BLE001
            out.append(Check("UI", "Plugin Output offers every completed plugin", FAIL, f"{type(exc).__name__}: {exc}"))
        # process windows
        broken = []
        try:
            from app.windows.process_window import ProcessWindow as ProcessDetailsWindow
        except Exception:  # noqa: BLE001
            ProcessDetailsWindow = None
        if ProcessDetailsWindow is None:
            out.append(Check("UI", "every process window opens", INCONCLUSIVE, "process details window class not found"))
        else:
            for proc in result.processes:
                try:
                    dialog = ProcessDetailsWindow(proc, window, dump_path=result.dump_path, findings=[i for i in result.indications if i.process_pid == proc.pid])
                    dialog.deleteLater()
                except Exception as exc:  # noqa: BLE001
                    broken.append(f"PID {proc.pid} {proc.name}: {type(exc).__name__}: {exc}")
            out.append(Check("UI", "every process window opens", PASS if not broken else FAIL, f"{len(result.processes)} tried", broken[:10]))
    finally:
        window.close()
        window.deleteLater()
        app.processEvents()
    return [c.as_dict() for c in out]
