"""Base scanner plugin ABC and plugin registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from pydantic import BaseModel

SCANNER_REGISTRY: dict[str, type[BaseScannerPlugin]] = {}


class BaseScannerPlugin(ABC):
    """Abstract base class for all scanner plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner name matching the corresponding SystemState field."""
        ...

    @abstractmethod
    def scan(self) -> BaseModel:
        """Run the scan and return results as a Pydantic model."""
        ...

    def is_available(self) -> bool:
        """Check if the scanner can run in the current environment.

        Default: always available. Override for scanners requiring external tools.
        """
        return True


def register(name: str) -> Callable[[type[BaseScannerPlugin]], type[BaseScannerPlugin]]:
    """Class decorator factory to register a scanner plugin by name.

    Usage: @register("scanner_name")
    """

    def decorator(cls: type[BaseScannerPlugin]) -> type[BaseScannerPlugin]:
        SCANNER_REGISTRY[name] = cls
        return cls

    return decorator


def get_scanner(name: str) -> type[BaseScannerPlugin]:
    """Get a registered scanner by name. Raises KeyError if not found."""
    return SCANNER_REGISTRY[name]


def get_all_scanners() -> dict[str, type[BaseScannerPlugin]]:
    """Return a copy of all registered scanners."""
    return dict(SCANNER_REGISTRY)
