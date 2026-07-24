"""Per-scanner status, log capture, and remediation hints for the scan CLI."""

from __future__ import annotations

import enum
import logging
import re
import threading
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


class ScannerStatus(enum.Enum):
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class ScannerOutcome:
    name: str
    status: ScannerStatus
    elapsed: float
    warnings: tuple[str, ...] = ()
    error: str | None = None


_current_scanner: ContextVar[str | None] = ContextVar("_current_scanner", default=None)

_REMEDIATION_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"Permission denied reading plist"),
        "Grant Full Disk Access to your terminal in System Settings → Privacy & "
        "Security → Full Disk Access, then re-run the scan.",
    ),
    (
        re.compile(r"(?=.*brew)(?=.*(?:timed out|bundle dump))", re.IGNORECASE),
        "Try running `brew bundle dump --file=-` manually to see what's slow or failing.",
    ),
)


class _ScannerLogCapture(logging.Handler):
    """Buffers WARNING+ log records, attributed to the scanner active when logged."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: dict[str, list[str]] = defaultdict(list)
        self.unattributed: list[str] = []
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        scanner_name = _current_scanner.get()
        message = self.format(record)
        with self._lock:
            if scanner_name is None:
                self.unattributed.append(message)
            else:
                self.records[scanner_name].append(message)

    def pop_records(self, name: str) -> list[str]:
        with self._lock:
            return self.records.pop(name, [])


@contextmanager
def capture_scanner_logs() -> Iterator[_ScannerLogCapture]:
    """Attach a `_ScannerLogCapture` to the `mac2nix` logger for the duration of a scan."""
    handler = _ScannerLogCapture()
    logger = logging.getLogger("mac2nix")
    logger.addHandler(handler)
    logger.propagate = False
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.propagate = True


@contextmanager
def attribute_to_scanner(name: str) -> Iterator[None]:
    """Attribute any WARNING+ log records emitted within this block to `name`."""
    token = _current_scanner.set(name)
    try:
        yield
    finally:
        _current_scanner.reset(token)


def get_remediation_hint(message: str) -> str | None:
    """Return a remediation hint for a scanner warning/error message, if one applies."""
    for pattern, hint in _REMEDIATION_HINTS:
        if pattern.search(message):
            return hint
    return None
