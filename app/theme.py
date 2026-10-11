"""The look of MemoryGraph: one dark theme, built from a small palette.

Every colour in the stylesheet comes from ``PALETTE`` (change a token and the whole interface follows). Qt stylesheets cannot animate, so the movement (fades between views, the
sliding marker in the navigation, the smooth progress bar, the glow of the primary buttons) is in ``app/windows/motion.py``; this module is the still picture.

The dicts ``SEVERITY_COLORS``, ``SEVERITY_BACKGROUNDS`` and ``CATEGORY_COLORS`` are imported by name by the views, which draw findings, badges and the timeline with them.
"""
from __future__ import annotations

import os
import re
from string import Template

PALETTE = {
    "bg": "#080b12",            # the window
    "bg_alt": "#0a0f19",        # sidebar, top bar
    "surface": "#111827",       # cards
    "surface_hi": "#161f31",    # raised: buttons, hovered rows
    "field": "#0b111c",         # inputs, tables, text boxes
    "border": "#1e2a3f",
    "border_hi": "#2f4466",
    "text": "#e8eef9",
    "text_dim": "#b4c0d6",
    "muted": "#8190aa",
    "faint": "#56647d",
    "accent": "#4f8cff",
    "accent_hi": "#6ea1ff",
    "accent2": "#7c5cff",       # the end of the accent gradient
    "accent_soft": "#16294a",   # a selected row, a checked nav entry
    "ok": "#3ecf8e",
    "warn": "#f5b84b",
    "bad": "#ff6b7a",
}

SEVERITY_COLORS = {"High": "#ff6b7a", "Medium": "#ffb454", "Low": "#5aa9ff", "": "#8190aa", "Info": "#8190aa"}
SEVERITY_BACKGROUNDS = {"High": "#34161e", "Medium": "#33250e", "Low": "#12263f"}
CATEGORY_COLORS = {"Process": "#5b9bff", "Network": "#2ec4a6", "Module": "#a78bfa", "System": "#ffd166"}

_TEMPLATE = """
* {
    font-family: "Segoe UI Variable Text", "Segoe UI", "Inter", sans-serif;
    font-size: 10pt;
}

QMainWindow, QDialog, QWidget {
    background: $bg;
    color: $text;
}

QLabel, QCheckBox, QRadioButton {
    background: transparent;
}

QToolTip {
    background: $surface_hi;
    color: $text;
    border: 1px solid $border_hi;
    border-radius: 6px;
    padding: 6px 8px;
}

/* ---------------------------------------------------------------- text */
QLabel#Title {
    font-size: 26pt;
    font-weight: 700;
    color: #f6f9ff;
}

QLabel#Subtitle {
    color: $muted;
    font-size: 11pt;
}

QLabel#SectionTitle {
    font-size: 15pt;
    font-weight: 650;
    color: #f1f5fc;
}

QLabel#Muted {
    color: $muted;
}

QLabel#Brand {
    font-size: 12pt;
    font-weight: 800;
    color: #f6f9ff;
}

QLabel#Eyebrow {
    color: $faint;
    font-size: 8.5pt;
    font-weight: 700;
}

QLabel#Warning {
    color: #f7d58a;
    background: #231d0f;
    border: 1px solid #5a4620;
    border-radius: 10px;
    padding: 9px 12px;
}

QLabel#Error {
    color: #ff9aa6;
}

QLabel#ErrorBanner {
    color: #ff9aa6;
    background: #26111a;
    border: 1px solid #6a2e3b;
    border-radius: 10px;
    padding: 9px 12px;
}

QLabel#DemoBanner {
    color: #c9b8ff;
    background: #1c1736;
    border: 1px solid #4a3d8a;
    border-radius: 8px;
    padding: 4px 10px;
    font-weight: 650;
}

/* ---------------------------------------------------------------- surfaces */
QFrame#Card {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #131c2e, stop:1 #101726);
    border: 1px solid $border;
    border-top: 1px solid #2a3a58;
    border-radius: 16px;
}

QFrame#Card:hover {
    border-color: #2b3d5f;
    border-top-color: #3a5180;
}

QFrame#TopBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d1424, stop:0.55 #0a0f19, stop:1 #0c1220);
    border: none;
    border-bottom: 1px solid $border;
    border-radius: 0px;
}

QFrame#Sidebar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0c1322, stop:1 #080c14);
    border: none;
    border-right: 1px solid $border;
}

QFrame#BundleRow {
    background: $field;
    border: 1px solid $border;
    border-radius: 12px;
}

QFrame#BundleRow QLabel, QFrame#BundleRow QCheckBox {
    background: transparent;
}

QFrame#Separator {
    background: $border;
    border: none;
    max-height: 1px;
    min-height: 1px;
}

QFrame#NavIndicator {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 $accent_hi, stop:1 $accent2);
    border: none;
    border-radius: 2px;
}

QScrollArea#ViewScroll, QScrollArea#PageScroll {
    background: transparent;
    border: none;
}

/* ---------------------------------------------------------------- buttons */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a2438, stop:1 #151e31);
    color: $text;
    border: 1px solid $border_hi;
    border-radius: 10px;
    padding: 9px 18px;
    min-height: 20px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #223049, stop:1 #1b2640);
    border-color: $accent;
}

QPushButton:pressed {
    background: #101827;
    border-color: $accent_hi;
}

QPushButton:focus {
    border-color: $accent_hi;
}

QPushButton:disabled {
    color: $faint;
    background: #0f1624;
    border-color: $border;
}

QPushButton#Primary {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3f7dff, stop:1 $accent2);
    border: 1px solid #6f8fff;
    color: #ffffff;
    font-weight: 700;
    min-height: 30px;
}

QPushButton#Primary:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #5a91ff, stop:1 #906fff);
    border-color: #9db4ff;
}

QPushButton#Primary:pressed {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #356fe6, stop:1 #6a4be0);
}

QPushButton#Primary:disabled {
    background: #1a2640;
    border-color: $border;
    color: $faint;
}

QPushButton#Danger {
    background: #2b141c;
    border-color: #6a2e3b;
    color: #ffb3bc;
}

QPushButton#Danger:hover {
    background: #3a1b25;
    border-color: $bad;
}

QPushButton#Small {
    padding: 5px 13px;
    min-height: 16px;
    border-radius: 8px;
}

QPushButton#Nav {
    text-align: left;
    padding: 11px 16px 11px 18px;
    border-radius: 10px;
    background: transparent;
    border: 1px solid transparent;
    color: $text_dim;
}

QPushButton#Nav:hover {
    background: #131c2e;
    border-color: transparent;
    color: #ffffff;
}

QPushButton#Nav:checked {
    background: $accent_soft;
    border-color: transparent;
    color: #ffffff;
    font-weight: 650;
}

QToolButton#NavTool {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #1a2438, stop:1 #151e31);
    color: $text;
    border: 1px solid $border_hi;
    border-radius: 9px;
    padding: 6px 10px;
    min-width: 16px;
}

QToolButton#NavTool:hover {
    border-color: $accent;
    background: #223049;
}

QToolButton#NavTool:disabled {
    color: $faint;
    background: #0f1624;
    border-color: $border;
}

/* ---------------------------------------------------------------- inputs */
QLineEdit, QPlainTextEdit, QComboBox, QSpinBox, QDoubleSpinBox {
    background: $field;
    border: 1px solid $border_hi;
    border-radius: 10px;
    padding: 8px 11px;
    color: $text;
    selection-background-color: #2a4f9a;
}

QLineEdit:hover, QComboBox:hover, QSpinBox:hover {
    border-color: #3d5a8a;
}

QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border: 1px solid $accent;
}

QLineEdit:disabled {
    color: $faint;
}

QComboBox {
    padding-right: 30px;
}

QSpinBox, QDoubleSpinBox {
    padding-right: 30px;
}

QSpinBox::up-button, QDoubleSpinBox::up-button {
    subcontrol-origin: border;
    subcontrol-position: top right;
    width: 26px;
    border: none;
    margin: 4px 4px 0px 0px;
    background: transparent;
}

QSpinBox::down-button, QDoubleSpinBox::down-button {
    subcontrol-origin: border;
    subcontrol-position: bottom right;
    width: 26px;
    border: none;
    margin: 0px 4px 4px 0px;
    background: transparent;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover, QDoubleSpinBox::up-button:hover, QDoubleSpinBox::down-button:hover {
    background: #1d2a44;
    border-radius: 6px;
}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
    $chevron_up_image
    width: 10px;
    height: 10px;
}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
    $chevron_image
    width: 10px;
    height: 10px;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: center right;
    width: 28px;
    border: none;
    border-left: 1px solid transparent;
}

QComboBox::down-arrow {
    $chevron_image
    width: 12px;
    height: 12px;
}

QComboBox QAbstractItemView {
    background: $surface;
    border: 1px solid $border_hi;
    border-radius: 8px;
    selection-background-color: $accent_soft;
    selection-color: #ffffff;
    outline: none;
    padding: 4px;
}

QCheckBox, QRadioButton {
    spacing: 9px;
    color: #d3dced;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid #3a5075;
    border-radius: 6px;
    background: $field;
}

QCheckBox::indicator:hover {
    border-color: $accent;
}

QCheckBox::indicator:checked {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #4f8cff, stop:1 $accent2);
    border-color: #7f9bff;
    $check_image
}

QGroupBox {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #121a2b, stop:1 #0f1625);
    border: 1px solid $border;
    border-top: 1px solid #28385a;
    border-radius: 14px;
    margin-top: 14px;
    padding: 26px 16px 14px 16px;
    font-weight: 650;
}

QGroupBox::title {
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 16px;
    top: 8px;
    padding: 0;
    color: $accent_hi;
    font-size: 9pt;
    font-weight: 700;
}

/* ---------------------------------------------------------------- lists, tables, trees */
QTreeWidget, QTreeView, QTableWidget, QTableView, QListWidget, QListView {
    background: $field;
    border: 1px solid $border;
    border-radius: 14px;
    alternate-background-color: #0d1422;
    gridline-color: transparent;
    outline: none;
    selection-background-color: $accent_soft;
    selection-color: #ffffff;
}

QTreeWidget::item, QListWidget::item, QTreeView::item, QListView::item {
    padding: 6px 4px;
    border-radius: 6px;
}

QTableView::item, QTableWidget::item {
    padding: 4px 10px;
    border: none;
    border-bottom: 1px solid #101828;
}

QTreeWidget::item:hover, QListWidget::item:hover, QTableView::item:hover, QTableWidget::item:hover, QTreeView::item:hover {
    background: #121c30;
}

QTreeWidget::item:selected, QListWidget::item:selected, QTreeView::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1b3358, stop:1 #14233f);
    color: #ffffff;
}

QTableView::item:selected, QTableWidget::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1b3358, stop:1 #14233f);
    color: #ffffff;
    border-bottom: 1px solid #28457a;
}

QTableView::item:selected:first, QTableWidget::item:selected:first {
    border-left: 3px solid $accent;
}

QHeaderView {
    background: transparent;
    border: none;
}

QHeaderView::section {
    background: #0f1626;
    color: $muted;
    border: none;
    border-bottom: 1px solid #28385a;
    border-left: 1px solid #14203a;
    padding: 10px 12px;
    font-family: "Segoe UI Semibold", "Segoe UI", "Inter", sans-serif;
    font-weight: 600;
    font-size: 8.5pt;
}

QHeaderView::section:first {
    border-left: none;
}

QHeaderView::section:hover {
    color: #ffffff;
    background: #14203a;
}

QTableCornerButton::section {
    background: #0f1626;
    border: none;
}

QListWidget#SettingsNav {
    background: transparent;
    border: none;
    border-radius: 0px;
    padding: 0px;
}

QListWidget#SettingsNav::item {
    padding: 12px 14px;
    margin: 2px 0px;
    border-radius: 10px;
    border-left: 3px solid transparent;
    color: $text_dim;
}

QListWidget#SettingsNav::item:hover {
    background: #131c2e;
    color: #ffffff;
}

QListWidget#SettingsNav::item:selected {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1b3358, stop:1 #14233f);
    border-left: 3px solid $accent;
    color: #ffffff;
    font-weight: 650;
}

QTextBrowser, QTextEdit {
    background: $field;
    border: 1px solid $border;
    border-radius: 12px;
    padding: 10px;
    color: $text;
    selection-background-color: #2a4f9a;
}

QTabWidget::pane {
    border: 1px solid $border;
    border-radius: 12px;
    top: -1px;
}

QTabBar::tab {
    background: transparent;
    color: $muted;
    padding: 10px 17px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
}

QTabBar::tab:hover {
    color: #ffffff;
}

QTabBar::tab:selected {
    color: #ffffff;
    border-bottom: 2px solid $accent;
    font-weight: 650;
}

QProgressBar {
    background: #0f1624;
    border: 1px solid $border;
    border-radius: 9px;
    text-align: center;
    color: $text;
    min-height: 18px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 $accent, stop:1 $accent2);
    border-radius: 8px;
}

QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}

QScrollBar::handle:vertical {
    background: #26354f;
    border-radius: 4px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background: #3a5075;
}

QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 2px;
}

QScrollBar::handle:horizontal {
    background: #26354f;
    border-radius: 4px;
    min-width: 30px;
}

QScrollBar::handle:horizontal:hover {
    background: #3a5075;
}

QScrollBar::add-line, QScrollBar::sub-line {
    width: 0px;
    height: 0px;
}

QScrollBar::add-page, QScrollBar::sub-page {
    background: transparent;
}

QSplitter::handle {
    background: #131c2e;
}

QSplitter::handle:hover {
    background: $accent;
}

QSplitter::handle:horizontal {
    width: 4px;
}

QSplitter::handle:vertical {
    height: 4px;
}

QMenu {
    background: $surface;
    border: 1px solid $border_hi;
    border-radius: 10px;
    padding: 5px;
}

QMenu::item {
    padding: 8px 24px;
    border-radius: 6px;
}

QMenu::item:selected {
    background: $accent_soft;
}

QMenu::separator {
    height: 1px;
    background: $border;
    margin: 5px 8px;
}
"""

MIN_FONT_PT, MAX_FONT_PT, DEFAULT_FONT_PT = 8, 18, 10
_FONT_SIZE = re.compile(r"font-size:\s*(\d+(?:\.\d+)?)pt")
DARK = "Dark"
THEME_CHOICES = [DARK]


def _icon(name: str, points, width: float, colour: str = "#ffffff") -> str:
    """``image: url(...)`` of a small polyline icon drawn once into the MemoryGraph home (empty when it cannot be written; the control then just has no icon)."""
    try:
        from PySide6.QtCore import QPointF, Qt
        from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPolygonF
        from app.paths import app_dir
        folder = app_dir() / "ui"
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / name
        if not target.exists():
            image = QImage(36, 36, QImage.Format.Format_ARGB32)
            image.fill(0)
            painter = QPainter(image)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setPen(QPen(QColor(colour), width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawPolyline(QPolygonF([QPointF(x, y) for x, y in points]))
            painter.end()
            image.save(str(target))
        return "image: url(%s);" % str(target).replace(os.sep, "/")
    except Exception:  # noqa: BLE001 - a missing icon must never stop the application from starting
        return ""


def _check_icon() -> str:
    """The white tick of a checked box."""
    return _icon("check.png", [(9, 19), (15.5, 25.5), (27, 11)], 4.2)


def _chevron_up_icon() -> str:
    """The small up chevron of a spin box."""
    return _icon("chevron_up.png", [(9, 23), (18, 14), (27, 23)], 3.6, "#8aa0c4")


def _chevron_icon() -> str:
    """The small down chevron of a drop-down list."""
    return _icon("chevron.png", [(9, 14), (18, 23), (27, 14)], 3.6, "#8aa0c4")


def build_style() -> str:
    return Template(_TEMPLATE).safe_substitute(PALETTE, check_image=_check_icon(), chevron_image=_chevron_icon(), chevron_up_image=_chevron_up_icon())


APP_STYLE = build_style()
APP_STYLE_DARK_BLUE = APP_STYLE          # older names, kept for callers that still import them: there is only one theme now
APP_STYLE_LIGHT = APP_STYLE
APP_THEMES = {DARK: APP_STYLE}


def resolve_theme(name: str = DARK) -> str:
    """There is one theme; every older setting value ('Light', 'Dark Blue', 'System') means it."""
    return DARK


def scale_fonts(style: str, base_pt: float) -> str:
    """Scale every ``font-size: Npt`` in a stylesheet so the base size (10pt) becomes ``base_pt``."""
    factor = max(MIN_FONT_PT, min(MAX_FONT_PT, base_pt)) / DEFAULT_FONT_PT
    if abs(factor - 1) < 1e-6:
        return style
    return _FONT_SIZE.sub(lambda m: "font-size: %gpt" % (round(float(m.group(1)) * factor * 2) / 2), style)


def get_theme_style(name: str = DARK, font_pt: float = DEFAULT_FONT_PT) -> str:
    """The stylesheet at the given base font size (``name`` is accepted for older callers; there is only the dark theme)."""
    return scale_fonts(APP_STYLE, font_pt)
