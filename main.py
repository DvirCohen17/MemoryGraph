import sys

from PySide6.QtWidgets import QApplication

from app.errors import install_global_excepthook
from app.logging_setup import get_logger, setup_logging
from app.settings import load_settings
from app.theme import get_theme_style
from app.windows import motion, screen_fit
from app.windows.home_window import HomeWindow
from app.windows.splash_window import SplashWindow


def main() -> int:
    setup_logging()
    log = get_logger("main")
    install_global_excepthook()
    app = QApplication(sys.argv)
    app.setApplicationName("MemoryGraph")
    screen_fit.install(app)          # every window opens inside the usable screen area (never larger than the screen)
    settings = load_settings()
    app.setStyleSheet(get_theme_style(settings.get("theme", "Dark"), settings.get("font_size", 10)))
    app.glow = motion.GlowFilter(app)
    app.installEventFilter(app.glow)          # the primary buttons glow under the mouse
    log.info("MemoryGraph starting")

    splash = SplashWindow()
    home = HomeWindow()
    splash.finished.connect(home.show)
    splash.finished.connect(splash.close)
    splash.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
