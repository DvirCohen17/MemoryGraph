from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QProgressBar

class SplashWindow(QDialog):
    finished = Signal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("MemoryGraph")
        self.setFixedSize(560, 330)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(55, 45, 55, 45)
        layout.setSpacing(15)

        logo = QLabel("◉")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo.setStyleSheet("font-size: 42pt; color: #6ea1ff;")
        layout.addWidget(logo)

        title = QLabel("MEMORYGRAPH")
        title.setObjectName("Title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Memory forensics for Windows and Linux")
        subtitle.setObjectName("Subtitle")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        layout.addStretch()

        self.status = QLabel("Initializing...")
        self.status.setObjectName("Muted")
        self.status.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status)

        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        layout.addWidget(self.bar)

        QTimer.singleShot(900, lambda: self.status.setText("Loading interface..."))
        QTimer.singleShot(1700, lambda: self.status.setText("Preparing analysis engine..."))
        QTimer.singleShot(2200, self.finished.emit)

    def showEvent(self, event):
        super().showEvent(event)
        from app.windows import motion
        motion.fade_in(self, 420)
