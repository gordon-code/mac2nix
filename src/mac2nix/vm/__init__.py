"""VM integration package for mac2nix."""

from mac2nix.vm._utils import VMConnectionError, VMError, VMTimeoutError
from mac2nix.vm.comparator import FileSystemComparator
from mac2nix.vm.discovery import DiscoveryResult, DiscoveryRunner
from mac2nix.vm.manager import TartVMManager
from mac2nix.vm.validator import (
    DomainScore,
    FidelityReport,
    Mismatch,
    ValidationResult,
    Validator,
    compute_fidelity,
)

__all__ = [
    "DiscoveryResult",
    "DiscoveryRunner",
    "DomainScore",
    "FidelityReport",
    "FileSystemComparator",
    "Mismatch",
    "TartVMManager",
    "VMConnectionError",
    "VMError",
    "VMTimeoutError",
    "ValidationResult",
    "Validator",
    "compute_fidelity",
]
