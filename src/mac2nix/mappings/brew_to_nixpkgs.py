"""Homebrew formula name -> nixpkgs attribute name mapping.

Homebrew formula names and nixpkgs attribute names diverge for a meaningful
slice of common formulae. :func:`get_nixpkgs_equivalent` runs a formula name
through an ordered pipeline of naming rules -- tap stripping, versioned
package patterns (Python/Node/OpenJDK/PostgreSQL/PHP), GNU tool renaming,
dot-to-hyphen normalization, a static override table, and finally an
identity fallback -- to resolve the nixpkgs attribute.

Source: hack/research/feat-research-1777834576-nixpkgs-hm-mapping-tables.md
(Category 1) and hack/plans/2026-05-03-brew-to-nixpkgs-mapping-research.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class NixpkgsEquivalent:
    attr_name: str
    note: str | None = None


# Formulae that are version managers made redundant by Nix's declarative,
# multi-version package model (e.g. pkgs.python313 instead of pyenv).
VERSION_MANAGER_FORMULAE: frozenset[str] = frozenset({"nvm", "pyenv", "rbenv", "tfenv"})

# Static overrides for brew-formula -> nixpkgs-attribute pairs that no
# programmatic rule can derive. A value of `None` marks a formula with no
# nixpkgs equivalent at all -- looked up deliberately, not a fallthrough for
# an unrecognized name.
BREW_TO_NIXPKGS: dict[str, NixpkgsEquivalent | None] = {
    "node": NixpkgsEquivalent("nodejs"),
    "kubernetes-cli": NixpkgsEquivalent("kubectl"),
    "docker": NixpkgsEquivalent(
        "docker-client",
        note="Full pkgs.docker is Linux-only; docker-client is the Darwin client-only equivalent",
    ),
    "openjdk": NixpkgsEquivalent("jdk", note="Alias; pkgs.openjdk is also available"),
    "rust": NixpkgsEquivalent(
        "rustc",
        note="brew rust installs rustc+cargo; consider pkgs.rustup for full toolchain management",
    ),
    "awscli": NixpkgsEquivalent("awscli2", note="v2 is brew's default; pkgs.awscli is v1"),
    "llvm": NixpkgsEquivalent("llvmPackages.clang", note="Use pkgs.llvmPackages_XX.clang for a pinned version"),
    "helm": NixpkgsEquivalent("kubernetes-helm"),
    "yq": NixpkgsEquivalent("yq-go", note="brew yq is mikefarah's Go implementation; nixpkgs yq is python-yq"),
    "ca-certificates": NixpkgsEquivalent("cacert"),
    "jpeg-xl": NixpkgsEquivalent("libjxl"),
    "composer": NixpkgsEquivalent("phpPackages.composer", note="Not top-level; lives under the PHP package set"),
    "telnet": NixpkgsEquivalent(
        "inetutils",
        note="inetutils provides telnet plus other utilities; known aarch64-darwin build failures as of early 2026",
    ),
    "terraform": NixpkgsEquivalent(
        "terraform",
        note="terraform >= 1.6 is BSL-licensed (unfree); pkgs.opentofu is the FOSS alternative",
    ),
    "flux": NixpkgsEquivalent(
        "fluxcd",
        note="Tap-stripped from fluxcd/tap/flux; nixpkgs attribute is fluxcd, not flux",
    ),
    "nvm": None,
    "tfenv": None,
    "xcbeautify": None,
    "cocoapods": None,
    "fastlane": None,
    "mint": None,
    "xclogparser": None,
    "xcodegen": None,
    "xcresultparser": None,
}

_PYTHON_VERSIONED_RE = re.compile(r"^python@3\.(\d+)$")
_NODE_VERSIONED_RE = re.compile(r"^node@(\d+)$")
_OPENJDK_VERSIONED_RE = re.compile(r"^openjdk@(\d+)$")
_POSTGRESQL_VERSIONED_RE = re.compile(r"^postgresql@(\d+)$")
_PHP_VERSIONED_RE = re.compile(r"^php@(\d)\.(\d+)$")
_GNU_TOOL_RE = re.compile(r"^gnu-(.+)$")


def _strip_tap(formula: str) -> str:
    """Rule 1: `org/tap/pkg` -> `pkg` (last path segment)."""
    return formula.rsplit("/", maxsplit=1)[-1]


def _versioned_pattern(name: str) -> str | None:
    """Rules 2-6: versioned patterns for Python, Node, OpenJDK, PostgreSQL, PHP."""
    if match := _PYTHON_VERSIONED_RE.match(name):
        return f"python3{match.group(1)}"
    if match := _NODE_VERSIONED_RE.match(name):
        return f"nodejs_{match.group(1)}"
    if match := _OPENJDK_VERSIONED_RE.match(name):
        return f"jdk{match.group(1)}"
    if match := _POSTGRESQL_VERSIONED_RE.match(name):
        return f"postgresql_{match.group(1)}"
    if match := _PHP_VERSIONED_RE.match(name):
        return f"php{match.group(1)}{match.group(2)}"
    return None


def _strip_gnu_hyphen(name: str) -> str:
    """Rule 7: `gnu-X` -> `gnuX` (e.g. gnu-sed -> gnused)."""
    if match := _GNU_TOOL_RE.match(name):
        return f"gnu{match.group(1)}"
    return name


def _dot_to_hyphen(name: str) -> str:
    """Rule 8: `name.suffix` -> `name-suffix` (e.g. llama.cpp -> llama-cpp)."""
    return name.replace(".", "-")


def get_nixpkgs_equivalent(formula: str) -> NixpkgsEquivalent | None:
    """Resolve a Homebrew formula name to its nixpkgs equivalent.

    Runs *formula* through the ordered pipeline described in the module
    docstring. Returns ``None`` only for formulae in :data:`BREW_TO_NIXPKGS`
    explicitly mapped to ``None`` (macOS/Xcode-only tools with no nixpkgs
    package). Unrecognized formulae fall through to the identity rule and
    resolve to a :class:`NixpkgsEquivalent` with the same name.
    """
    name = _strip_tap(formula)

    if (versioned := _versioned_pattern(name)) is not None:
        return NixpkgsEquivalent(attr_name=versioned)

    name = _strip_gnu_hyphen(name)
    name = _dot_to_hyphen(name)

    if name in BREW_TO_NIXPKGS:
        return BREW_TO_NIXPKGS[name]

    return NixpkgsEquivalent(attr_name=name)


def is_unnecessary_in_nix(formula: str) -> bool:
    """Whether *formula* is a version manager made redundant by Nix."""
    return formula in VERSION_MANAGER_FORMULAE
