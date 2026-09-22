"""JSON logging by default, controlled by LOG_LEVEL and LOG_FORMAT."""

from __future__ import annotations

import logging
import sys

from .config import settings


def configure() -> logging.Logger:
    handler = logging.StreamHandler(sys.stdout)
    if settings.log_format.lower() == "json":
        from pythonjsonlogger import jsonlogger

        handler.setFormatter(jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s  %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.upper())
    return logging.getLogger("polyscore_v2")
