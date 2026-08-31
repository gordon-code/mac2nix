"""generate_all() orchestrator -- fans out to each domain generator, then
regenerates a host's configuration.nix generated-imports section from
actual on-disk file existence.

Scoped to the `preferences` domain in this PR. Tasks 7 (shell) and 6
(homebrew) each extend this module with one more sibling `if` block and one
more `(domain, filename, import_line)` triple -- never restructuring the
mechanism.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mac2nix.generators.preferences import WallpaperAsset, generate_preferences
from mac2nix.models.system_state import SystemState

logger = logging.getLogger(__name__)


class Mac2NixError(Exception):
    """Base for every mac2nix-raised, user-facing error across scaffold.py and generate_all()."""


class GenerateError(Mac2NixError):
    """Raised for generate_all() failures -- an unregistered host, etc."""


@dataclass(frozen=True, slots=True)
class GenerateResult:
    """The outcome of one `generate_all()` call.

    `unrecognized` is always empty for a CLI-originated call (the CLI's own
    `_ALLOWED_DOMAINS` membership check rejects those first) -- it exists
    for callers that invoke `generate_all()` directly, bypassing the CLI.
    `homebrew_audit_manifest` is always `None` in this PR; Task 6's PR is
    what first populates it -- the field exists from day one so that PR only
    has to populate it, not add it.
    """

    ran: set[str]
    skipped: dict[str, str]
    unrecognized: frozenset[str]
    homebrew_audit_manifest: list[dict[str, Any]] | None


_META_FILENAME = ".mac2nix-meta.json"

_GENERATE_BEGIN = "# MAC2NIX:GENERATE:BEGIN"
_GENERATE_END = "# MAC2NIX:GENERATE:END"

# (domain, filename, import_line) triples -- `domain` is this module's single
# source of truth for "which domains actually run" (drives both the
# unrecognized-domain check and the on-disk import regeneration below).
# Extended by Task 7 (adds ("shell", "shell.nix", "./shell.nix")) and Task 6
# (adds ("homebrew", "homebrew-packages.nix", "./homebrew-packages.nix")),
# never restructured.
_GENERATED_IMPORT_FILES: list[tuple[str, str, str]] = [
    ("preferences", "preferences.nix", "./preferences.nix"),
]


def _read_host_meta(host_dir: Path) -> dict[str, Any]:
    return json.loads((host_dir / _META_FILENAME).read_text())


def _warn_if_host_imports_hand_edited(host_dir: Path, current_inner: str) -> None:
    try:
        stored_hash = _read_host_meta(host_dir).get("generate_imports_hash")
    except (OSError, json.JSONDecodeError):
        return
    if stored_hash is None:
        return

    if hashlib.sha256(current_inner.encode()).hexdigest() != stored_hash:
        logger.warning(
            "%s's MAC2NIX:GENERATE block doesn't match what generate last wrote there "
            "(likely a hand-edit, or corrupted/manually-deleted host metadata) -- "
            "this regeneration will overwrite it.",
            host_dir / "configuration.nix",
        )


def _store_host_imports_hash(host_dir: Path, inner: str) -> None:
    try:
        meta = _read_host_meta(host_dir)
    except (OSError, json.JSONDecodeError):
        return
    meta["generate_imports_hash"] = hashlib.sha256(inner.encode()).hexdigest()
    (host_dir / _META_FILENAME).write_text(json.dumps(meta, indent=2))


def _write_wallpaper_asset(host_dir: Path, asset: WallpaperAsset) -> None:
    """Write a bundled wallpaper asset under `host_dir/assets/`.

    Mirrors `_warn_if_host_imports_hand_edited`/`_store_host_imports_hash`'s
    hash-tracking pattern: warns if the on-disk file was hand-edited since
    mac2nix last wrote it, and skips a gratuitous rewrite when the content
    hasn't actually changed. Orphaned assets left behind by a wallpaper
    change/removal are an accepted non-goal, consistent with this module's
    existing never-deletes-stale-files behavior for `.nix` outputs.
    """
    dest = host_dir / "assets" / asset.filename

    try:
        meta: dict[str, Any] | None = _read_host_meta(host_dir)
    except (OSError, json.JSONDecodeError):
        meta = None

    if dest.is_file():
        on_disk = dest.read_bytes()
        if meta is not None and meta.get("wallpaper_asset_filename") == asset.filename:
            stored_hash = meta.get("wallpaper_asset_hash")
            if stored_hash is not None and hashlib.sha256(on_disk).hexdigest() != stored_hash:
                logger.warning(
                    "%s doesn't match what generate last wrote there (likely a hand-edit) -- "
                    "this regeneration will overwrite it.",
                    dest,
                )
        if on_disk == asset.data:
            return

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(asset.data)

    if meta is not None:
        meta["wallpaper_asset_filename"] = asset.filename
        meta["wallpaper_asset_hash"] = hashlib.sha256(asset.data).hexdigest()
        (host_dir / _META_FILENAME).write_text(json.dumps(meta, indent=2))


def _regenerate_host_imports(output_dir: Path, hostname: str) -> None:
    """Fully regenerate configuration.nix's sentinel-bounded imports line from
    actual on-disk file existence for this host -- not which domains ran in
    this specific `generate_all()` invocation. This is what makes `generate`
    safely repeatable with a narrower `--domains` subset: an already-present,
    untouched file is never dropped from the imports list.

    Raises :exc:`GenerateError` if configuration.nix is missing or is not a
    regular file, or if it's missing its sentinel markers.
    """
    host_dir = output_dir / "hosts" / "darwin" / hostname
    config_path = host_dir / "configuration.nix"
    if not config_path.is_file():
        msg = (
            f"{config_path} is missing or is not a regular file -- the host directory is "
            "registered but its configuration.nix isn't usable; restore it (see "
            "templates/scaffold/hosts/darwin/configuration.nix) before running generate again"
        )
        raise GenerateError(msg)
    content = config_path.read_text()

    # Anchor to the end of the BEGIN sentinel's own line -- it also carries a
    # trailing "-- generated by ...; do not edit by hand" comment that must
    # survive regeneration verbatim (mirrors _regenerate_flake_hosts_block()
    # in scaffold.py).
    try:
        begin_marker_end = content.index("\n", content.index(_GENERATE_BEGIN)) + 1
        end_marker_start = content.index(_GENERATE_END)
    except ValueError as exc:
        msg = (
            f"{config_path} is missing its {_GENERATE_BEGIN!r}/{_GENERATE_END!r} sentinel "
            "markers -- restore them (see templates/scaffold/hosts/darwin/configuration.nix) "
            "before running generate again"
        )
        raise GenerateError(msg) from exc
    old_inner = content[begin_marker_end:end_marker_start]

    present_imports = [
        import_line for _domain, filename, import_line in _GENERATED_IMPORT_FILES if (host_dir / filename).exists()
    ]
    new_inner = f"  imports = [ {' '.join(present_imports)} ];\n  " if present_imports else "  "

    _warn_if_host_imports_hand_edited(host_dir, old_inner)

    config_path.write_text(content[:begin_marker_end] + new_inner + content[end_marker_start:])
    _store_host_imports_hash(host_dir, new_inner)


def generate_all(system_state: SystemState, output_dir: Path, hostname: str, domains: set[str]) -> GenerateResult:
    """Fill in *hostname*'s already-`add-host`-registered directory from *system_state*.

    Raises :exc:`GenerateError` if *hostname* isn't registered -- `generate`
    only populates an existing host, it never registers one itself. Any
    other exception raised by a domain generator (e.g. a Jinja2 template
    error, an `OSError` writing the output file) propagates uncaught --
    turning it into a clean, user-facing error is the CLI's job, not this
    function's. A failure partway through leaves whichever domains already
    wrote their files on disk as-is: `generate` is safely re-runnable, so a
    subsequent successful call regenerates every requested-and-available
    domain's output again.

    Not safe for concurrent invocations against the same *hostname* --
    its read-modify-write cycle on configuration.nix/.mac2nix-meta.json
    assumes single-operator, sequential use, matching `add_host()`'s own
    documented limitation on flake.nix/.sops.yaml.
    """
    host_dir = output_dir / "hosts" / "darwin" / hostname
    if not host_dir.exists():
        msg = f"host {hostname!r} is not registered under {output_dir} — run `mac2nix add-host` first"
        raise GenerateError(msg)

    ran: set[str] = set()
    skipped: dict[str, str] = {}

    if "preferences" in domains:
        if system_state.preferences is not None and system_state.system is not None:
            generated = generate_preferences(system_state)
            (host_dir / "preferences.nix").write_text(generated.rendered)
            if generated.asset is not None:
                _write_wallpaper_asset(host_dir, generated.asset)
            ran.add("preferences")
        else:
            skipped["preferences"] = "not scanned"

    known_domains = {domain for domain, _filename, _import_line in _GENERATED_IMPORT_FILES}
    unrecognized = domains - known_domains

    _regenerate_host_imports(output_dir, hostname)

    return GenerateResult(ran=ran, skipped=skipped, unrecognized=frozenset(unrecognized), homebrew_audit_manifest=None)
