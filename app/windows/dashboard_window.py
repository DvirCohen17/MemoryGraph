"""Investigation dashboard: sidebar navigation + lazily-built views.

Every view is created on first use inside its own try/except, so a defect in one view shows an
error panel for that view instead of taking down the whole dashboard.
"""
from __future__ import annotations

from typing import Callable, List, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget,
)

from app.engines import engine_for
from app.analysis.indicators.scoring import active_findings, risk_by_pid
from app.errors import format_exception, safe_slot
from app.logging_setup import get_logger
from app.theme import SEVERITY_COLORS
from app.util import format_time
from app.windows import layout_state, motion
from app.windows.widgets import ElidedLabel, TableModel, info_card, make_table, muted, section_title

log = get_logger("dashboard")


class DashboardWindow(QWidget):
    def __init__(self, result, home=None, settings=None):
        super().__init__()
        self.result = result
        self.engine = engine_for(result)         # the operating-system engine that made (and judges) this result: which views exist, what they are called
        self.home = home
        self.settings = settings if settings is not None else {}      # (an empty dict is still the caller's dict)
        self.setWindowTitle("MemoryGraph — Investigation")
        self.resize(1500, 930)
        self._factories: List[Tuple[str, Callable[[], QWidget]]] = []
        self._built: List[bool] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        header = QFrame()
        header.setObjectName("TopBar")
        h = QHBoxLayout(header)
        h.setContentsMargins(18, 10, 18, 10)
        back = QPushButton("← New analysis")
        back.clicked.connect(self.go_home)
        h.addWidget(back)
        title = QLabel("MEMORYGRAPH")
        title.setObjectName("Brand")
        h.addWidget(title)
        if (getattr(result, "tool_info", None) or {}).get("demo"):
            demo = QLabel("DEMO DATA")
            demo.setObjectName("DemoBanner")
            demo.setToolTip("This investigation is made up to show how a result looks; no memory image was analysed.")
            h.addWidget(demo)
        h.addStretch()
        self.global_search = QLineEdit()
        self.global_search.setPlaceholderText("Global search…")
        self.global_search.setMinimumWidth(120)
        self.global_search.setMaximumWidth(320)
        self.global_search.returnPressed.connect(self.open_search)
        h.addWidget(self.global_search)
        dump = ElidedLabel(result.dump_path)          # long paths are shortened, they must not widen the window
        dump.setObjectName("Muted")
        dump.setMaximumWidth(380)
        dump.setToolTip(result.dump_path)
        h.addWidget(dump)
        failed = [p for p in result.plugins if p.failed]
        self.rerun_button = QPushButton(f"Re-run {len(failed)} failed plugin(s)")
        self.rerun_button.setVisible(bool(failed) and bool(result.dump_path))
        self.rerun_button.clicked.connect(self.rerun_failed)
        h.addWidget(self.rerun_button)
        self.dirty_label = QLabel("● unsaved notes / triage")
        self.dirty_label.setObjectName("Warning")
        self.dirty_label.setToolTip("Your bookmarks, notes and triage decisions are saved with the investigation: use Save Investigation.")
        self.dirty_label.setVisible(False)
        h.addWidget(self.dirty_label)
        save = QPushButton("Save Investigation")
        save.clicked.connect(self.save_current_analysis)
        h.addWidget(save)
        root.addWidget(header)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)
        root.addLayout(body, 1)
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        self.sidebar = sidebar
        sidebar.setFixedWidth(232)
        self.side = QVBoxLayout(sidebar)
        self.side.setContentsMargins(15, 20, 15, 20)
        self.side.setSpacing(7)
        self.stack = motion.AnimatedStack()          # a page change is a short fade
        self.nav: List[QPushButton] = []
        self.nav_indicator = QFrame(sidebar)         # the marker that glides to the selected entry
        self.nav_indicator.setObjectName("NavIndicator")
        self.nav_indicator.resize(4, 22)

        self.case_dirty = False
        flagged = self._flagged_count()
        self.VIEWS = []
        for spec in self.engine.view_specs():
            label = f"Indications ({flagged})" if spec.id == "Indications" and flagged else spec.id
            self.VIEWS.append((label, self._factory_for(spec)))
        self.IDX = {name.split(" (")[0]: i for i, (name, _f) in enumerate(self.VIEWS)}
        for index, (name, factory) in enumerate(self.VIEWS):
            button = QPushButton(name)
            button.setObjectName("Nav")
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self.select_view(i))
            self.side.addWidget(button)
            self.nav.append(button)
            self._factories.append((name, factory))
            self._built.append(False)
            self.stack.addWidget(QWidget())      # placeholder, replaced on first visit
        self.side.addStretch()
        body.addWidget(sidebar)
        body.addWidget(self.stack, 1)
        self.select_view(0)

    # ------------------------------------------------------------------ the navigation marker
    def _indicator_rect(self, index: int):
        from PySide6.QtCore import QRect
        button = self.nav[index]
        height = max(18, int(button.height() * 0.5))
        return QRect(4, button.y() + (button.height() - height) // 2, 4, height)

    def _move_indicator(self, animate: bool = True) -> None:
        index = max(0, self.stack.currentIndex())
        if not self.nav or self.nav[index].height() <= 0:
            return
        target = self._indicator_rect(index)
        if animate and self.isVisible():
            motion.animate_geometry(self.nav_indicator, target)
        else:
            self.nav_indicator.setGeometry(target)
        self.nav_indicator.raise_()
        self.nav_indicator.show()

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._move_indicator(animate=False)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._move_indicator(animate=False)

    # ------------------------------------------------------------------ view management
    def _factory_for(self, spec):
        """The function that builds the view called ``spec.id``; a placeholder page when the engine does not provide it yet. Views are imported when first built."""
        result = self.result
        if not spec.available:
            def placeholder():
                from app.windows.placeholder_view import PlaceholderView
                return PlaceholderView(self.engine, spec, self)
            return placeholder

        def build():
            view_id = spec.id
            if view_id == "Overview":
                return self.make_overview()
            if view_id == "Search":
                from app.windows.search_window import GlobalSearchView as view
            elif view_id == "Process Tree":
                from app.windows.process_tree_window import ProcessTreeView as view
            elif view_id == "Indications":
                from app.windows.indications_window import IndicationsView as view
            elif view_id == "Injection":
                from app.windows.injection_window import InjectionView as view
            elif view_id == "Plugin Output":
                from app.windows.plugin_output_window import PluginOutputView as view
            elif view_id == "Files":
                from app.windows.files_window import FilesView as view
            elif view_id == "Registry":
                from app.windows.registry_window import RegistryView as view
            elif view_id == "Network":
                from app.windows.network_window import NetworkView as view
            elif view_id == "Timeline":
                from app.windows.timeline_window import TimelineView as view
            elif view_id == "Lifetimes":
                from app.windows.lifetimes_window import LifetimesView as view
            elif view_id == "Compare":
                from app.windows.compare_window import CompareView as view
            elif view_id == "Case Notes":
                from app.windows.case_window import CaseView as view
            elif view_id == "Computer Info":
                from app.windows.system_info_window import SystemInfoView as view
            else:
                raise KeyError(f"The dashboard has no view called {view_id!r}")
            return view(result, self)
        return build

    def _ensure(self, index: int) -> QWidget:
        if not self._built[index]:
            name, factory = self._factories[index]
            try:
                widget = factory()
            except Exception as exc:  # noqa: BLE001 - isolate a broken view
                log.exception("View %s failed to build", name)
                widget = self._error_view(name, exc)
            placeholder = self.stack.widget(index)
            self.stack.removeWidget(placeholder)
            placeholder.deleteLater()
            self.stack.insertWidget(index, self._scrolling(widget))
            self._built[index] = True
            layout_state.apply_splitters(self._layout_settings(), name.split(" (")[0], widget)
            layout_state.apply_columns(self._layout_settings(), name.split(" (")[0], widget)
        return self._inner(index)

    @staticmethod
    def _scrolling(widget: QWidget) -> QScrollArea:
        """Every view sits in a scroll area: on a small window the page scrolls, instead of squeezing the lists in it down to their header row
        (each list has a minimum height, see ``make_table``). When the window is large enough the view simply fills it."""
        area = QScrollArea()
        area.setObjectName("ViewScroll")
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setWidget(widget)
        return area

    def _inner(self, index: int) -> QWidget:
        """The view itself (not its scroll area) at ``index``; the placeholder widget while the view is not built."""
        item = self.stack.widget(index)
        return item.widget() if isinstance(item, QScrollArea) and self._built[index] else item

    @staticmethod
    def _error_view(name: str, exc: BaseException) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(35, 35, 35, 35)
        title = QLabel(f"The “{name}” view could not be built")
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(muted("The rest of the investigation still works. The problem was written to the log file."))
        box = QPlainTextEdit(format_exception(exc))
        box.setReadOnly(True)
        layout.addWidget(box, 1)
        return widget

    @safe_slot
    def select_view(self, index: int):
        widget = self._ensure(index)
        self.stack.setCurrentIndex(index)
        for i, button in enumerate(self.nav):
            button.setChecked(i == index)
        self._move_indicator()
        return widget

    def view(self, name: str):
        return self._ensure(self.IDX[name])

    # ------------------------------------------------------------------ remembered layout
    def _layout_settings(self) -> dict:
        return self.home.settings if self.home is not None and hasattr(self.home, "settings") else self.settings

    def capture_layout(self) -> None:
        """Store the splitter positions and column widths of every view that has been opened (called when the app closes)."""
        settings = self._layout_settings()
        for name, index in self.IDX.items():
            if self._built[index]:
                layout_state.capture_splitters(settings, name, self._inner(index))
                layout_state.capture_columns(settings, name, self._inner(index))

    # ------------------------------------------------------------------ case state (notes, bookmarks, triage)
    def _flagged_count(self) -> int:
        return sum(1 for r in risk_by_pid(self.result.indications).values() if r.severity in ("Medium", "High"))

    def mark_dirty(self) -> None:
        self.case_dirty = True
        self.dirty_label.setVisible(True)

    def clear_dirty(self) -> None:
        self.case_dirty = False
        self.dirty_label.setVisible(False)

    def _built_view(self, name: str):
        index = self.IDX[name]
        return self._inner(index) if self._built[index] else None

    def _forget_view(self, name: str) -> None:
        """Drop a built view so it is rebuilt from the current data the next time it is opened."""
        index = self.IDX[name]
        if not self._built[index] or self.stack.currentIndex() == index:
            return
        old = self.stack.widget(index)
        self.stack.removeWidget(old)
        old.deleteLater()
        self.stack.insertWidget(index, QWidget())
        self._built[index] = False

    @safe_slot
    def rebuild_views(self, *_):
        """Drop every built view and rebuild the current one (after a theme / font change: views pick colours when they are built)."""
        current = max(0, self.stack.currentIndex())
        for index in range(len(self._built)):
            if self._built[index]:
                old = self.stack.widget(index)
                self.stack.removeWidget(old)
                old.deleteLater()
                self.stack.insertWidget(index, QWidget())
                self._built[index] = False
        self.select_view(current)

    @safe_slot
    def case_changed(self, *_):
        """A note or bookmark changed (no finding was re-judged)."""
        self.mark_dirty()
        view = self._built_view("Case Notes")
        if view is not None and hasattr(view, "refresh_after_triage"):
            view.refresh_after_triage()

    @safe_slot
    def triage_changed(self, *_):
        """A finding was reviewed / marked false positive / suppressed: scores, counts and colours change."""
        self.mark_dirty()
        try:
            self.engine.apply_timeline_severity(self.result)
        except Exception:  # noqa: BLE001
            log.exception("Applying severity after triage failed")
        flagged = self._flagged_count()
        self.nav[self.IDX["Indications"]].setText(f"Indications ({flagged})" if flagged else "Indications")
        for name in ("Overview", "Timeline"):               # rebuilt lazily on the next visit
            self._forget_view(name)
        for name in ("Indications", "Injection", "Process Tree", "Lifetimes", "Case Notes"):    # refreshed in place (keeps selection and scroll)
            view = self._built_view(name)
            if view is not None and hasattr(view, "refresh_after_triage"):
                view.refresh_after_triage()

    # ------------------------------------------------------------------ overview
    def make_overview(self) -> QWidget:
        result = self.result
        risks = risk_by_pid(result.indications)
        by_pid = {p.pid: p for p in result.processes}
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(35, 30, 35, 25)
        layout.setSpacing(12)
        title = QLabel("Investigation Overview")
        title.setObjectName("Title")
        layout.addWidget(title)
        subtitle = QLabel("Cross-artifact investigation workspace")
        subtitle.setObjectName("Subtitle")
        layout.addWidget(subtitle)

        counts = {s: sum(1 for i in active_findings(result.indications) if i.severity == s) for s in ("High", "Medium", "Low")}
        failed = [p for p in result.plugins if p.failed]
        ran = [p for p in result.plugins if not p.skipped]
        cards = QHBoxLayout()
        cards.addWidget(info_card("Processes", len(result.processes)))
        cards.addWidget(info_card("High findings", counts["High"], "High" if counts["High"] else ""))
        cards.addWidget(info_card("Medium findings", counts["Medium"], "Medium" if counts["Medium"] else ""))
        cards.addWidget(info_card("Plugins ok", f"{len(ran) - len(failed)}/{len(ran)}", "High" if failed else ""))
        cards.addWidget(info_card("Timeline events", len(result.timeline)))
        cards.addWidget(info_card("Connections", len(result.connections) or sum(len(p.network) for p in result.processes)))
        layout.addLayout(cards)

        if result.warnings:
            shown = result.warnings[:6]
            more = f"\n… and {len(result.warnings) - 6} more (see Plugin Output)" if len(result.warnings) > 6 else ""
            warning = QLabel("⚠ " + "\n⚠ ".join(shown) + more)
            warning.setObjectName("Warning")
            warning.setWordWrap(True)
            layout.addWidget(warning)

        facts = []
        if result.capture_time:
            facts.append(f"Memory captured {format_time(result.capture_time)}")
        if result.accounts:
            facts.append(f"{len(result.accounts)} account(s) own processes")
        hidden = sum(1 for p in result.processes if p.hidden)
        if hidden:
            facts.append(f"{hidden} process(es) found by psscan only")
        if facts:
            layout.addWidget(muted("  •  ".join(facts)))

        layout.addWidget(section_title("Top processes to review"))
        ranked = sorted((r for r in risks.values() if r.pid in by_pid), key=lambda r: -r.score)[:12]
        if ranked:
            rows, payloads = [], []
            for risk in ranked:
                proc = by_pid[risk.pid]
                titles = [i.title for i in active_findings(result.indications) if i.process_pid == risk.pid and i.rule_id and not i.rule_id.startswith("CORR")]
                rows.append([risk.severity or "Info", proc.name, proc.pid, risk.score, risk.count, "; ".join(dict.fromkeys(titles))[:160]])
                payloads.append(proc.pid)
            colors = {i: SEVERITY_COLORS.get(rows[i][0], "#76859a") for i in range(len(rows))}
            model = TableModel(["Risk", "Process", "PID", "Score", "Findings", "Why"], rows, payloads=payloads, colors=colors,
                               sort_rows=[[{"High": 3, "Medium": 2, "Low": 1}.get(r[0], 0), r[1].lower(), r[2], r[3], r[4], r[5]] for r in rows])
            view, proxy = make_table(model, [80, 200, 70, 70, 80, 600], sort_column=3, descending=True)
            fit = min(520, 58 + 33 * len(rows))                     # as tall as its rows (the page scrolls when the window is short)
            view.setMinimumHeight(fit)
            view.setMaximumHeight(fit)
            view.doubleClicked.connect(lambda index, p=proxy: self._open_ranked(p.payload_at(index)))
            layout.addWidget(view)
            layout.addWidget(muted("Double-click a row to open that process in the Process Tree. Scores add up one finding per rule; Low findings count little on their own."))
        else:
            layout.addWidget(muted("No process has findings. This is a good sign, but memory analysis is never proof of a clean system."))

        layout.addWidget(muted("Use Global Search to jump from a PID, DLL or endpoint to related evidence. Computer Info holds system metadata and discovered identities."))
        layout.addStretch()
        return widget

    @safe_slot
    def _open_ranked(self, pid):
        if pid:
            self.show_process(pid)

    # ------------------------------------------------------------------ navigation / actions
    @safe_slot
    def show_process(self, pid: int):
        tree = self.select_view(self.IDX["Process Tree"])
        if hasattr(tree, "select_pid") and not tree.select_pid(pid):
            tree.search.clear()
            tree.only_suspicious.setChecked(False)
            tree.hide_exited.setChecked(False)
            tree.rebuild()
            tree.select_pid(pid)

    @safe_slot
    def open_search(self, *_):
        view = self.select_view(self.IDX["Search"])
        if hasattr(view, "query"):
            view.query.setText(self.global_search.text())
            view.query.setFocus()

    @safe_slot
    def go_home(self, *_):
        if self.home is not None:
            self.home.show_home()

    @safe_slot
    def save_current_analysis(self, *_):
        if self.home is not None:
            self.home.save_current_analysis()

    def live_settings(self) -> dict:
        """The settings in force now (Settings changes replace the home window's dict, so prefer it over the one captured at construction)."""
        return self._layout_settings()

    @safe_slot
    def run_plugins(self, names, view: str = "", *_):
        """Run the given plugins on this image now (e.g. windows.filescan from the Files view); the dashboard is rebuilt with the new results."""
        if self.home is not None:
            self.home.run_plugins(list(names), view)

    @safe_slot
    def rerun_failed(self, *_):
        if self.home is not None:
            self.home.rerun_failed()
