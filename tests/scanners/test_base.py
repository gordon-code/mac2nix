"""Tests for base scanner ABC, registry, and helper functions."""

from collections.abc import Generator

import pytest
from pydantic import BaseModel

from mac2nix.scanners.base import (
    SCANNER_REGISTRY,
    BaseScannerPlugin,
    get_all_scanners,
    get_scanner,
    register,
)


class DummyResult(BaseModel):
    value: str = "ok"


class MinimalScanner(BaseScannerPlugin):
    """Concrete scanner for testing — minimal implementation."""

    @property
    def name(self) -> str:
        return "minimal"

    def scan(self) -> DummyResult:
        return DummyResult()


@pytest.fixture(autouse=True)
def _isolate_registry() -> Generator[None]:
    """Save and restore SCANNER_REGISTRY around each test."""
    original = dict(SCANNER_REGISTRY)
    SCANNER_REGISTRY.clear()
    yield
    SCANNER_REGISTRY.clear()
    SCANNER_REGISTRY.update(original)


class TestBaseScannerPlugin:
    def test_scanner_is_abstract(self) -> None:
        with pytest.raises(TypeError):
            BaseScannerPlugin()  # type: ignore[abstract]

    def test_is_available_default(self) -> None:
        scanner = MinimalScanner()
        assert scanner.is_available() is True


class TestRegisterDecorator:
    def test_registration(self) -> None:
        registered = register(MinimalScanner)
        assert registered is MinimalScanner
        assert "minimal" in SCANNER_REGISTRY
        assert SCANNER_REGISTRY["minimal"] is MinimalScanner

    def test_registration_multiple(self) -> None:
        class AnotherScanner(BaseScannerPlugin):
            @property
            def name(self) -> str:
                return "another"

            def scan(self) -> DummyResult:
                return DummyResult()

        register(MinimalScanner)
        register(AnotherScanner)
        assert len(SCANNER_REGISTRY) == 2
        assert "minimal" in SCANNER_REGISTRY
        assert "another" in SCANNER_REGISTRY


class TestGetScanner:
    def test_get_scanner_found(self) -> None:
        register(MinimalScanner)
        result = get_scanner("minimal")
        assert result is MinimalScanner

    def test_get_scanner_not_found(self) -> None:
        with pytest.raises(KeyError):
            get_scanner("nonexistent")


class TestGetAllScanners:
    def test_get_all_scanners(self) -> None:
        register(MinimalScanner)
        all_scanners = get_all_scanners()
        assert "minimal" in all_scanners
        assert all_scanners["minimal"] is MinimalScanner

    def test_get_all_scanners_returns_copy(self) -> None:
        register(MinimalScanner)
        copy = get_all_scanners()
        copy["injected"] = MinimalScanner  # type: ignore[assignment]
        assert "injected" not in SCANNER_REGISTRY
