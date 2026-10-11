"""Reusable GUI pieces shared by all views.

* ``TableModel`` / ``make_table`` – fast read-only tables (100k+ rows) with sorting, a text filter
  and an optional predicate that receives the row *payload* (any Python object attached to a row).
* small helpers for severity colours, badges, cards and message boxes.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QPoint, QRect, QSize, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QFrame, QHeaderView, QLabel, QLayout, QMessageBox, QTableView, QVBoxLayout,
)

from app.theme import SEVERITY_COLORS

SORT_ROLE = Qt.ItemDataRole.UserRole + 1
_NUMBER = re.compile(r"^-?\d+(?:\.\d+)?$")
MAX_CELL_CHARS = 600


# ----------------------------------------------------------------------------- text helpers
def escape(value: Any) -> str:
    return str(value if value is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


html_escape = escape


def decoded_command_html(command_line: str, pid: int = 0) -> str:
    """HTML block with the decoded ``-EncodedCommand`` payload, or '' when the command line has none.
    Shows where the text came from; the original command line stays the evidence."""
    from app.analysis.decoders import decode_encoded_command
    decoded = decode_encoded_command(command_line)
    if decoded is None:
        return ""
    source = f"windows.cmdline, PID {pid}" if pid else "windows.cmdline"
    cut = " (truncated)" if decoded.truncated else ""
    return (f"<h3>Decoded -EncodedCommand{cut}</h3><p style='color:#76859a'>Decoded from the command line above ({escape(source)}). "
            f"{escape(decoded.note)}.</p><pre style='background:#080b0f;color:#d7e1ea;padding:6px'>{escape(decoded.text)}</pre>")


def severity_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity or "", SEVERITY_COLORS[""])


def badge_html(severity: str, text: Optional[str] = None) -> str:
    color = severity_color(severity)
    label = escape(text if text is not None else (severity or "Info"))
    return (f"<span style='background:{color}33;color:{color};border:1px solid {color};"
            f"border-radius:4px;padding:1px 6px;font-weight:600'>{label}</span>")


# ----------------------------------------------------------------------------- layouts that do not force the window wider
class FlowLayout(QLayout):
    """Lays widgets out left to right and wraps to the next line when the row is full.

    A row of ten controls in a normal horizontal layout makes the whole window at least that wide; in a flow layout the minimum width
    is only the widest single control, so the window can be as narrow as the screen requires.
    """

    def __init__(self, parent=None, h_spacing: int = 8, v_spacing: int = 6):
        super().__init__(parent)
        self._items: List = []
        self._h, self._v = h_spacing, v_spacing
        self.setContentsMargins(0, 0, 0, 0)

    def addItem(self, item) -> None:
        self._items.append(item)

    def count(self) -> int:
        return len(self._items)

    def itemAt(self, index: int):
        return self._items[index] if 0 <= index < len(self._items) else None

    def takeAt(self, index: int):
        return self._items.pop(index) if 0 <= index < len(self._items) else None

    def expandingDirections(self):
        return Qt.Orientation(0)

    def hasHeightForWidth(self) -> bool:
        return True

    def heightForWidth(self, width: int) -> int:
        return self._arrange(QRect(0, 0, width, 0), apply=False)

    def setGeometry(self, rect) -> None:
        super().setGeometry(rect)
        self._arrange(rect, apply=True)

    def sizeHint(self):
        return self.minimumSize()

    def minimumSize(self):
        size = QSize()
        for item in self._items:
            size = size.expandedTo(item.minimumSize())
        margins = self.contentsMargins()
        return size + QSize(margins.left() + margins.right(), margins.top() + margins.bottom())

    def _arrange(self, rect, apply: bool) -> int:
        margins = self.contentsMargins()
        area = rect.adjusted(margins.left(), margins.top(), -margins.right(), -margins.bottom())
        x, y, line_height = area.x(), area.y(), 0
        for item in self._items:
            if item.widget() is not None and not item.widget().isVisibleTo(item.widget().parentWidget()) and item.widget().parentWidget():
                continue
            hint = item.sizeHint()
            if x + hint.width() > area.right() + 1 and line_height > 0:
                x, y, line_height = area.x(), y + line_height + self._v, 0
            if apply:
                item.setGeometry(QRect(QPoint(x, y), hint))
            x += hint.width() + self._h
            line_height = max(line_height, hint.height())
        return y + line_height - rect.y() + margins.bottom()


def compact_combo(combo: QComboBox, chars: int = 20) -> QComboBox:
    """A combo box whose width follows ``chars`` characters instead of its longest item (long items would widen the window)."""
    combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
    combo.setMinimumContentsLength(chars)
    return combo


# ----------------------------------------------------------------------------- labels / cards
class ElidedLabel(QLabel):
    """One-line label that shortens long text with "…" (full text in the tooltip) instead of forcing its window wider."""

    def minimumSizeHint(self):
        return QSize(24, super().minimumSizeHint().height())

    def paintEvent(self, event):
        text = self.text()
        shown = self.fontMetrics().elidedText(text, Qt.TextElideMode.ElideRight, max(1, self.width() - 2 * self.margin() - self.indent()))
        self.setToolTip(text if shown != text else "")
        painter = QPainter(self)
        self.style().drawItemText(painter, self.contentsRect(), int(self.alignment()), self.palette(), self.isEnabled(), shown, self.foregroundRole())


def muted(text: str, wrap: bool = True) -> QLabel:
    label = QLabel(text) if wrap else ElidedLabel(text)
    label.setObjectName("Muted")
    label.setWordWrap(wrap)
    return label


def section_title(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("SectionTitle")
    return label


def banner(text: str, kind: str = "Warning") -> QLabel:
    label = QLabel(text)
    label.setObjectName(kind)
    label.setWordWrap(True)
    return label


def info_card(title: str, value: Any, severity: str = "") -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 12, 16, 12)
    layout.setSpacing(2)
    caption = QLabel(str(title).upper())
    caption.setObjectName("Muted")
    caption.setWordWrap(True)          # a long caption wraps instead of widening the card (and the window)
    layout.addWidget(caption)
    big = QLabel(str(value))
    color = f"color:{severity_color(severity)};" if severity else ""
    big.setStyleSheet(f"font-size:24pt;font-weight:700;{color}")
    layout.addWidget(big)
    return card


stat_card = info_card


# ----------------------------------------------------------------------------- dialogs
def show_error(parent, title: str, message: str, details: str = "") -> None:
    box = QMessageBox(parent)
    box.setIcon(QMessageBox.Icon.Critical)
    box.setWindowTitle(title)
    box.setText(message)
    if details:
        box.setDetailedText(details)
    box.exec()


def show_info(parent, title: str, message: str) -> None:
    QMessageBox.information(parent, title, message)


def confirm(parent, title: str, message: str) -> bool:
    answer = QMessageBox.question(parent, title, message,
                                  QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
    return answer == QMessageBox.StandardButton.Yes


# ----------------------------------------------------------------------------- table model
def _auto_sort_value(value: Any) -> Tuple[int, Any]:
    """Numbers sort numerically, everything else case-insensitively (numbers first)."""
    text = "" if value is None else str(value).strip()
    if _NUMBER.match(text):
        try:
            return (0, float(text))
        except ValueError:
            pass
    return (1, text.lower())


class TableModel(QAbstractTableModel):
    """Read-only model over a list of rows.

    rows       list of sequences with the display text per column
    sort_rows  optional parallel list of sequences with raw sort keys (numbers, epoch seconds, ...)
    payloads   optional parallel list of arbitrary objects (the thing a row stands for)
    colors     optional ``{row_index: "#rrggbb"}`` text colours
    icons      optional ``{row_index: QIcon}`` shown left of the text in ``icon_column``
    """

    def __init__(self, columns: Sequence[str], rows: Optional[List[Sequence[Any]]] = None,
                 sort_rows: Optional[List[Sequence[Any]]] = None, payloads: Optional[List[Any]] = None,
                 colors: Optional[Dict[int, str]] = None, parent=None, icons: Optional[Dict[int, Any]] = None, icon_column: int = 0):
        super().__init__(parent)
        self.icons = icons or {}
        self.icon_column = icon_column
        self.columns = list(columns)
        self.rows: List[Sequence[Any]] = list(rows or [])
        self.sort_rows = sort_rows
        self.payloads = payloads
        self.colors = colors or {}

    # -- Qt model API
    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.columns):
            return self.columns[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row_number, col = index.row(), index.column()
        if not (0 <= row_number < len(self.rows)):
            return None
        row = self.rows[row_number]
        if role == Qt.ItemDataRole.DisplayRole:
            if col >= len(row) or row[col] is None:
                return ""
            text = str(row[col])
            return text if len(text) <= MAX_CELL_CHARS else text[:MAX_CELL_CHARS] + "…"
        if role == Qt.ItemDataRole.ToolTipRole:
            if col < len(row) and row[col] is not None:
                text = str(row[col])
                return text[:2000] if len(text) > 40 else None
            return None
        if role == SORT_ROLE:
            if self.sort_rows is not None and row_number < len(self.sort_rows) and col < len(self.sort_rows[row_number]):
                key = self.sort_rows[row_number][col]
                return key if isinstance(key, tuple) else (0, key) if isinstance(key, (int, float)) else (1, str(key).lower())
            return _auto_sort_value(row[col] if col < len(row) else "")
        if role == Qt.ItemDataRole.DecorationRole:
            return self.icons.get(row_number) if col == self.icon_column else None
        if role == Qt.ItemDataRole.ForegroundRole:
            color = self.colors.get(row_number)
            return QBrush(QColor(color)) if color else None
        return None

    # -- convenience
    def row_values(self, source_row: int) -> Sequence[Any]:
        return self.rows[source_row] if 0 <= source_row < len(self.rows) else []

    def payload(self, source_row: int) -> Any:
        if self.payloads is not None and 0 <= source_row < len(self.payloads):
            return self.payloads[source_row]
        return None


class FilterProxy(QSortFilterProxyModel):
    """Sorting on ``SORT_ROLE``, free-text filter over all columns and an optional predicate."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSortRole(SORT_ROLE)
        self._needle = ""
        self._predicate: Optional[Callable[[Any, Sequence[Any]], bool]] = None

    def set_text(self, text: str) -> None:
        self._needle = (text or "").strip().lower()
        self.invalidateFilter()

    def set_predicate(self, predicate: Optional[Callable[[Any, Sequence[Any]], bool]]) -> None:
        """``predicate(payload, row_values) -> bool``; ``None`` removes the extra filter."""
        self._predicate = predicate
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent) -> bool:
        model = self.sourceModel()
        if model is None:
            return False
        values = model.row_values(source_row)
        if self._predicate is not None:
            try:
                if not self._predicate(model.payload(source_row), values):
                    return False
            except Exception:  # noqa: BLE001 - a faulty filter must not blank the table
                return True
        if self._needle:
            return any(self._needle in str(v).lower() for v in values if v is not None)
        return True

    def lessThan(self, left, right) -> bool:
        a, b = left.data(SORT_ROLE), right.data(SORT_ROLE)
        try:
            return a < b
        except TypeError:
            return str(a) < str(b)

    def payload_at(self, index) -> Any:
        """Payload of the row behind a *proxy* index (as delivered by view signals)."""
        if index is None or not index.isValid():
            return None
        source = self.mapToSource(index)
        return self.sourceModel().payload(source.row()) if source.isValid() else None


MIN_LIST_HEIGHT = 190        # about six rows


def make_table(model: TableModel, widths: Optional[Sequence[int]] = None, sort_column: Optional[int] = None,
               descending: bool = False) -> Tuple[QTableView, FilterProxy]:
    """Build a ready-to-use ``(QTableView, FilterProxy)`` pair for ``model``."""
    proxy = FilterProxy()
    proxy.setSourceModel(model)
    view = QTableView()
    view.setModel(proxy)
    view.setAlternatingRowColors(True)
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setWordWrap(False)
    view.setMinimumHeight(MIN_LIST_HEIGHT)       # a list is never squeezed to its header row: the page scrolls instead (see DashboardWindow._scrolling)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(32)
    view.setShowGrid(False)
    header = view.horizontalHeader()
    header.setStretchLastSection(True)
    header.setHighlightSections(False)
    header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
    header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
    for column, width in enumerate(widths or []):
        if column < model.columnCount():
            view.setColumnWidth(column, int(width))
    view.setSortingEnabled(True)
    if sort_column is not None and 0 <= sort_column < model.columnCount():
        view.sortByColumn(sort_column, Qt.SortOrder.DescendingOrder if descending else Qt.SortOrder.AscendingOrder)
    return view, proxy
