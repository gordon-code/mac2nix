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

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0d\x0e-\x1f\x7f-\x9f]")


def _sanitize_for_display(text: str) -> str:
    """Strip control characters (e.g. ESC, CR) that could inject terminal escape sequences.

    Tab and newline are preserved; every other C0 control character, DEL, and
    the C1 control range (U+0080-U+009F, e.g. the 8-bit CSI U+009B) are
    removed. Applied to any subprocess-derived or exception-derived text before
    it reaches the Rich table or click.echo, since neither strips raw bytes.
    """
    return _CONTROL_CHAR_RE.sub("", text)


_REMEDIATION_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"Permission denied reading plist \(TCC-protected\)"),
        "Grant Full Disk Access to your terminal in System Settings → Privacy & "
        "Security → Full Disk Access, then re-run the scan.",
    ),
    (
        re.compile(r"Permission denied reading plist \(root-only"),
        "This file is owned by root with no read access for other users — this is "
        "expected macOS behavior, not something Full Disk Access can fix.",
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
        message = _sanitize_for_display(self.format(record))
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
