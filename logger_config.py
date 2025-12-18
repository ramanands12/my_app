"""Logger configuration helpers.

Provides a safe, idempotent `setup_logger` function that configures
a logger with a console handler by default and optional rotating
file handler. Adds type hints and a small usage example.
"""
from typing import Optional, Union
import logging
from logging.handlers import RotatingFileHandler

from config import LOG_LEVEL

__all__ = ["setup_logger"]


def _to_level(level: Union[int, str, None]) -> int:
    """Normalize various level representations to an int level."""
    if level is None:
        return logging.INFO
    if isinstance(level, int):
        return level
    s = str(level).strip()
    if s.isdigit():
        return int(s)
    return logging._nameToLevel.get(s.upper(), logging.INFO)


def setup_logger(
    name: str = "backend",
    level: Optional[Union[int, str]] = None,
    log_file: Optional[str] = None,
    max_bytes: int = 0,
    backup_count: int = 0,
) -> logging.Logger:
    """Create and return a configured logger.

    - Idempotent: calling repeatedly won't attach duplicate handlers.
    - By default logs to the console using `LOG_LEVEL` from `config`.
    - If `log_file` is provided, a RotatingFileHandler is added.

    Args:
        name: logger name.
        level: logging level (int or name). Falls back to `config.LOG_LEVEL`.
        log_file: optional path to a log file (uses rotating handler when set).
        max_bytes: maximum bytes per log file before rotation (0 disables).
        backup_count: number of rotated files to keep.

    Returns:
        Configured `logging.Logger` instance.
    """

    chosen_level = _to_level(level if level is not None else LOG_LEVEL)

    logger = logging.getLogger(name)
    logger.setLevel(chosen_level)
    logger.propagate = False

    formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")

    # Ensure a console handler exists (idempotent)
    has_console = any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    if not has_console:
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(chosen_level)
        logger.addHandler(stream_handler)

    # Optional rotating file handler
    if log_file:
        # Only add a file handler for this filename if one doesn't already exist
        has_file = any(
            isinstance(h, RotatingFileHandler) and getattr(h, "baseFilename", None) == log_file
            for h in logger.handlers
        )
        if not has_file:
            if max_bytes > 0:
                fh = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
            else:
                fh = logging.FileHandler(log_file)
            fh.setFormatter(formatter)
            fh.setLevel(chosen_level)
            logger.addHandler(fh)

    return logger


if __name__ == "__main__":
    # quick manual test
    lg = setup_logger("my_app", level=None)
    lg.debug("Debug message - logger configured")
    lg.info("Info message - logger configured")
