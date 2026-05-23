"""
Structured logging for ARP Guardian.

Provides JSON-formatted log output for forensic analysis alongside
human-readable console output for real-time monitoring.
"""

import logging
import json
import os
import sys
from datetime import datetime


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON lines for machine parsing."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        # Attach extra fields if present (e.g., event data)
        if hasattr(record, "extra_data"):
            log_entry["data"] = record.extra_data
        return json.dumps(log_entry)


class ColorFormatter(logging.Formatter):
    """Console formatter with ANSI colors for severity levels."""

    COLORS = {
        "DEBUG": "\033[36m",      # cyan
        "INFO": "\033[32m",       # green
        "WARNING": "\033[33m",    # yellow
        "ERROR": "\033[31m",      # red
        "CRITICAL": "\033[1;31m", # bold red
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        prefix = f"{color}[{timestamp}] {record.levelname:<8}{self.RESET}"
        return f"{prefix} {self.BOLD}{record.module}{self.RESET}: {record.getMessage()}"


def setup_logger(
    name: str = "arp_guardian",
    level: str = "INFO",
    log_file: str = "data/arp_guardian.log",
) -> logging.Logger:
    """
    Configure and return the application logger.

    Args:
        name: Logger name.
        level: Logging level string.
        log_file: Path to the JSON log file.
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Prevent duplicate handlers on re-init
    if logger.handlers:
        return logger

    # Console handler with colors
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(ColorFormatter())
    logger.addHandler(console)

    # File handler with JSON output
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setFormatter(JsonFormatter())
    logger.addHandler(file_handler)

    return logger
