"""Centralized logging setup for Nexus.

Uses stdlib logging. Provides a lightweight adapter that accepts kwargs
without conflicting with LogRecord reserved attributes.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

_CONFIGURED = False

# Reserved LogRecord attributes that must not be overwritten via extra
_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime",
}


def setup_logging(level: str = "INFO", json_format: bool = False) -> None:
    """Configure root logger once."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    numeric = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric)

    for h in root.handlers[:]:
        root.removeHandler(h)

    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(numeric)

    if json_format:
        class JsonFormatter(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                import json
                from datetime import datetime, timezone

                payload = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "level": record.levelname,
                    "logger": record.name,
                    "msg": record.getMessage(),
                }
                if record.exc_info:
                    payload["exc"] = self.formatException(record.exc_info)
                for k, v in record.__dict__.items():
                    if k not in _RESERVED and not k.startswith("_"):
                        try:
                            json.dumps(v)
                            payload[k] = v
                        except (TypeError, ValueError):
                            payload[k] = str(v)
                return json.dumps(payload, default=str)

        handler.setFormatter(JsonFormatter())
    else:
        fmt = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
        handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))

    root.addHandler(handler)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


class BoundLogger:
    """Minimal structlog-like interface that is safe with stdlib logging."""

    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def _log(self, level: int, msg: str, **kwargs: Any) -> None:
        # Move kwargs into a safe extra dict, renaming conflicts
        extra = {}
        for k, v in kwargs.items():
            key = k if k not in _RESERVED else f"ctx_{k}"
            extra[key] = v
        # Append human-readable context to message
        if extra:
            parts = [f"{k}={v}" for k, v in extra.items()]
            msg = f"{msg} | {' '.join(parts)}"
        self._logger.log(level, msg, extra=extra if extra else None)

    def debug(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, **kwargs)

    def info(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, **kwargs)

    def warning(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, **kwargs)

    def error(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, **kwargs)

    def critical(self, msg: str, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, **kwargs)

    def exception(self, msg: str, **kwargs: Any) -> None:
        kwargs.setdefault("exc_info", True)
        # exc_info is handled by logger, not extra
        exc_info = kwargs.pop("exc_info", True)
        extra = {}
        for k, v in kwargs.items():
            key = k if k not in _RESERVED else f"ctx_{k}"
            extra[key] = v
        if extra:
            parts = [f"{k}={v}" for k, v in extra.items()]
            msg = f"{msg} | {' '.join(parts)}"
        self._logger.exception(msg, extra=extra if extra else None)

    def log(self, level: int, msg: str, **kwargs: Any) -> None:
        self._log(level, msg, **kwargs)


def get_bound_logger(name: str) -> BoundLogger:
    return BoundLogger(name)
