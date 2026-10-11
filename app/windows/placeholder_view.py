"""The page of a navigation entry whose view needs engine code that has not been written yet (Linux: Files, Injection, Compare).

The entry is shown instead of hidden, so a missing part is visible and says what it is waiting for.
"""
from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget

from app.windows.widgets import banner, muted


class PlaceholderView(QWidget):
    def __init__(self, engine, spec, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 20)
        layout.setSpacing(12)
        title = QLabel(spec.id)
        title.setObjectName("Title")
        layout.addWidget(title)
        layout.addWidget(banner(f"Not available yet for {engine.label} images.", "Warning"))
        self.reason = muted(spec.reason or f"The {engine.label} engine does not provide this view yet.")
        layout.addWidget(self.reason)
        layout.addWidget(muted(f"The rest of MemoryGraph works on {engine.label} results already. This page appears as soon as the engine in app/engines/{engine.id} "
                               "supplies what it needs, and its entry in the navigation is marked available in the engine's view_specs()."))
        layout.addStretch()
