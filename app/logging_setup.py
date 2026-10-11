"""Central logging configuration (file + console)."""
from __future__ import annotations

import logging
import logging.handlers
import sys

from app.paths import log_dir

LOGGER_NAME = "memorygraph"
_configured = False


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    global _configured
    logger = logging.getLogger(LOGGER_NAME)
    if _configured:
        return logger
    logger.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(threadName)s %(name)s: %(message)s")
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir() / "memorygraph.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        logger.addHandler(file_handler)
    except OSError:
        pass  # logging must never stop the application from starting
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    logger.addHandler(console)
    _configured = True
    return logger


def get_logger(name: str = "") -> logging.Logger:
    return logging.getLogger(f"{LOGGER_NAME}.{name}" if name else LOGGER_NAME)
