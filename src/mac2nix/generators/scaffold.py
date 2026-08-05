"""Scaffold generation — init_framework() (host-less framework) and add_host() (per-host registration)."""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import logging
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from mac2nix.generators import Mac2NixError
from mac2nix.generators._nix_render import nix_string

logger = logging.getLogger(__name__)

_HOSTS_BEGIN = "# MAC2NIX:HOSTS:BEGIN"
_HOSTS_END = "# MAC2NIX:HOSTS:END"

_META_FILENAME = ".mac2nix-meta.json"
_STATE_FILENAME = ".mac2nix-state.json"

_TEMPLATES_ROOT = ("templates", "scaffold")


class ScaffoldError(Mac2NixError):
    """Raised for scaffold-generation failures — init_framework(), add_host()."""


def init_framework(output_dir: Path) -> None:
    """Scaffold a host-less nix-darwin + home-manager + sops-nix framework at *output_dir*.

    Copies the static framework templates byte-for-byte — no hostname,
    username, or system is bound yet; registering a host is `add_host()`'s job.

    `templates/scaffold/hosts/` and `templates/scaffold/users/` hold
    `add_host()`'s own per-host/per-user templates (with unsubstituted
    `__HOSTNAME__`/`__USERNAME__` placeholders) — they share the same
    template root as the framework-level files but must never be copied by
    `init`, which is host-less by design.

    Raises :exc:`ScaffoldError` if *output_dir* already exists and is non-empty.
    """
    if output_dir.exists() and any(output_dir.iterdir()):
        msg = f"{output_dir} already exists and is not empty — init never overwrites an existing repo"
        raise ScaffoldError(msg)

    output_dir.mkdir(parents=True, exist_ok=True)

    scaffold_root = importlib.resources.files("mac2nix").joinpath("templates", "scaffold")
    with importlib.resources.as_file(scaffold_root) as real_scaffold_root:
        shutil.copytree(
            real_scaffold_root,
            output_dir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("hosts", "users"),
        )

    gitignore_path = output_dir / "gitignore"
    if gitignore_path.is_file():
        gitignore_path.rename(output_dir / ".gitignore")


# ---------------------------------------------------------------------------
# add_host() and its Step 4-6 helpers
# ---------------------------------------------------------------------------


def _read_template(*parts: str) -> str:
    return importlib.resources.files("mac2nix").joinpath(*_TEMPLATES_ROOT, *parts).read_text()


def _render_placeholders(text: str, hostname: str, username: str) -> str:
    return text.replace("__HOSTNAME__", hostname).replace("__USERNAME__", username)


def _age_key_path(username: str, key_dir: Path | None = None) -> Path:
    return (key_dir or Path(f"/Users/{username}") / ".config" / "sops" / "age") / "keys.txt"


def age_key_path(username: str) -> Path:
    """Public accessor for *username*'s real sops-nix age key path.

    Exists so callers outside this module (the CLI, `mac2nix.onepassword`)
    share this exact construction instead of independently duplicating the
    `/Users/<username>/.config/sops/age/keys.txt` literal and risking the
    two silently drifting apart.
    """
    return _age_key_path(username)


def _write_host_config(host_dir: Path, hostname: str, username: str) -> None:
    host_dir.mkdir(parents=True)
    template = _read_template("hosts", "darwin", "configuration.nix")
    (host_dir / "configuration.nix").write_text(_render_placeholders(template, hostname, username))


def _write_user_file(user_file: Path, hostname: str, username: str) -> None:
    template = _read_template("users", "user.nix")
    user_file.parent.mkdir(parents=True, exist_ok=True)
    user_file.write_text(_render_placeholders(template, hostname, username))


def generate_age_key(username: str, *, key_dir: Path | None = None) -> str:
    """Generate a new sops-nix age key for *username* and return its public fingerprint.

    `key_dir` is a keyword-only test seam — real callers always leave it
    `None`, which resolves the key's parent directory from `username` itself
    (never `Path.home()`), matching the path `lib/helpers.nix` interpolates
    for `sops.age.keyFile`.

    Raises :exc:`ScaffoldError` if `age-keygen` is unavailable, or if a key
    already exists at the target path — an existing key is never regenerated
    or overwritten, since doing so orphans every secret already encrypted to it.
    """
    if shutil.which("age-keygen") is None:
        msg = "age-keygen is not available — install age (e.g. `nix shell nixpkgs#age`) to use add-host"
        raise ScaffoldError(msg)

    key_path = _age_key_path(username, key_dir)

    if key_path.exists():
        msg = (
            f"age key already exists at {key_path} — add-host will not regenerate or overwrite it, "
            "since doing so orphans every secret already encrypted to the old key"
        )
        raise ScaffoldError(msg)

    key_path.parent.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(  # noqa: S603
        ["age-keygen", "-o", str(key_path)],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ScaffoldError(f"age-keygen failed: {result.stderr.strip()}")

    # From here on, a real private key file exists at key_path. Self-clean on
    # any failure so this function's contract is "either returns a valid
    # fingerprint or leaves no file behind" — independent of whether the
    # caller correctly tracks that generation happened.
    try:
        key_path.chmod(0o600)
        actual_mode = stat.S_IMODE(key_path.stat().st_mode)
        if actual_mode != 0o600:
            raise ScaffoldError(f"failed to set age key file permissions to 0600 (got {oct(actual_mode)})")
        return _parse_age_public_key(key_path)
    except Exception:
        key_path.unlink(missing_ok=True)
        raise


def _parse_age_public_key(key_path: Path) -> str:
    for line in key_path.read_text().splitlines():
        if line.startswith("# public key:"):
            return line.removeprefix("# public key:").strip()
    raise ScaffoldError(f"could not find a '# public key:' comment line in {key_path}")


def _load_all_host_metadata(output_dir: Path) -> list[dict[str, Any]]:
    meta_paths = sorted((output_dir / "hosts" / "darwin").glob(f"*/{_META_FILENAME}"))
    return [json.loads(p.read_text()) for p in meta_paths]


def _warn_if_hand_edited(output_dir: Path, current_inner: str) -> None:
    state_path = output_dir / _STATE_FILENAME
    if not state_path.is_file():
        return
    try:
        stored_hash = json.loads(state_path.read_text())["flake_hosts_block_hash"]
    except (json.JSONDecodeError, KeyError, OSError):
        return

    if hashlib.sha256(current_inner.encode()).hexdigest() != stored_hash:
        logger.warning(
            "flake.nix's MAC2NIX:HOSTS block doesn't match what add-host last wrote there "
            "(likely a hand-edit, or corrupted/manually-deleted host metadata) — "
            "this regeneration will overwrite it."
        )


def _store_flake_hosts_hash(output_dir: Path, inner: str) -> None:
    state_path = output_dir / _STATE_FILENAME
    new_hash = hashlib.sha256(inner.encode()).hexdigest()
    state_path.write_text(json.dumps({"flake_hosts_block_hash": new_hash}, indent=2))


def _regenerate_flake_hosts_block(output_dir: Path, metas: list[dict[str, Any]]) -> None:
    """Wholesale-regenerate flake.nix's sentinel-bounded darwinConfigurations block.

    Rebuilds from *metas* (every `.mac2nix-meta.json` sidecar currently on
    disk, sorted — see `_load_all_host_metadata()`), never by patching the
    file in place — correct regardless of call order or prior state.
    """
    flake_path = output_dir / "flake.nix"
    content = flake_path.read_text()

    # Anchor to the end of the BEGIN sentinel's own line (not just past the
    # bare "# MAC2NIX:HOSTS:BEGIN" substring) — the real line also carries a
    # trailing "-- generated by ...; do not edit by hand" comment, which must
    # survive regeneration verbatim rather than being treated as
    # regeneratable content and discarded on the very first add-host call.
    begin_marker_end = content.index("\n", content.index(_HOSTS_BEGIN)) + 1
    end_marker_start = content.index(_HOSTS_END)
    old_inner = content[begin_marker_end:end_marker_start]

    host_lines = [
        f"    {nix_string(m['hostname'])} = mkDarwinSystem {{ hostname = {nix_string(m['hostname'])}; "
        f"system = {nix_string(m['system'])}; users = [ {nix_string(m['username'])} ]; }};"
        for m in metas
    ]
    new_inner = "".join(f"{line}\n" for line in host_lines) + "        "

    _warn_if_hand_edited(output_dir, old_inner)

    flake_path.write_text(content[:begin_marker_end] + new_inner + content[end_marker_start:])
    _store_flake_hosts_hash(output_dir, new_inner)


def _regenerate_sops_yaml(output_dir: Path, metas: list[dict[str, Any]]) -> None:
    """Fully rewrite .sops.yaml from *metas* (every host's `.mac2nix-meta.json` sidecar), then verify it.

    Writes first, then reads the result back and verifies it structurally —
    a real, load-bearing check, not just a test hook: raises `ScaffoldError`
    (aborting the whole `add_host()` call, which triggers rollback) if two
    hosts share an age key, or if any rule's `path_regex`/`key_groups` don't
    scope correctly to their own host.
    """
    creation_rules = [
        {
            "path_regex": f"secrets/{re.escape(m['hostname'])}\\.yaml$",
            "key_groups": [{"age": [m["age_public_key"]]}],
        }
        for m in metas
    ]

    sops_path = output_dir / ".sops.yaml"
    sops_path.write_text(yaml.safe_dump({"creation_rules": creation_rules}, sort_keys=False))

    _verify_sops_yaml(sops_path, metas)


def _verify_sops_yaml(sops_path: Path, metas: list[dict[str, Any]]) -> None:
    try:
        parsed = yaml.safe_load(sops_path.read_text())
    except yaml.YAMLError as exc:
        raise ScaffoldError(f"regenerated .sops.yaml is not valid YAML: {exc}") from exc

    rules = parsed.get("creation_rules", []) if parsed else []
    if len(rules) != len(metas):
        msg = f".sops.yaml verification failed: expected {len(metas)} creation_rules, found {len(rules)}"
        raise ScaffoldError(msg)

    fingerprints = [m["age_public_key"] for m in metas]
    if len(set(fingerprints)) != len(fingerprints):
        msg = "two or more hosts share the same age public key — aborting .sops.yaml regeneration"
        raise ScaffoldError(msg)

    by_hostname = {m["hostname"]: m for m in metas}
    for rule in rules:
        key_groups = rule.get("key_groups", [])
        if len(key_groups) != 1 or set(key_groups[0].keys()) != {"age"} or len(key_groups[0]["age"]) != 1:
            raise ScaffoldError(f".sops.yaml verification failed: malformed key_groups shape in rule {rule!r}")
        fingerprint = key_groups[0]["age"][0]

        path_regex = rule.get("path_regex", "")
        matched_hosts = [m["hostname"] for m in metas if re.search(path_regex, f"secrets/{m['hostname']}.yaml")]
        if len(matched_hosts) != 1:
            msg = (
                f".sops.yaml verification failed: path_regex {path_regex!r} matches "
                f"{matched_hosts}, expected exactly one host"
            )
            raise ScaffoldError(msg)

        expected_fingerprint = by_hostname[matched_hosts[0]]["age_public_key"]
        if fingerprint != expected_fingerprint:
            msg = f".sops.yaml verification failed: rule for {matched_hosts[0]!r} has a mismatched fingerprint"
            raise ScaffoldError(msg)


def _run_sops(cmd: list[str], cwd: Path, env: dict[str, str], step: str) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)  # noqa: S603
    if result.returncode != 0:
        raise ScaffoldError(f"sops {step} failed: {result.stderr.strip()}")
    return result


def _create_host_secrets_file(output_dir: Path, hostname: str, age_key_path: Path) -> None:
    """Create+smoke-test `secrets/{hostname}.yaml`, then overwrite it with an empty document.

    Uses SOPS_AGE_KEY_FILE (never argv) to scope the sops subprocess to this
    host's own key, exercising the `path_regex` entry `_regenerate_sops_yaml()`
    just wrote.
    """
    if shutil.which("sops") is None:
        msg = "sops is not available — install sops (e.g. `nix shell nixpkgs#sops`) to use add-host"
        raise ScaffoldError(msg)

    secrets_dir = output_dir / "secrets"
    secrets_dir.mkdir(exist_ok=True)
    secrets_path = secrets_dir / f"{hostname}.yaml"

    env = {**os.environ, "SOPS_AGE_KEY_FILE": str(age_key_path)}

    secrets_path.write_text(yaml.safe_dump({"_mac2nix_smoke_test": "placeholder"}))
    _run_sops(["sops", "--encrypt", "--in-place", str(secrets_path)], output_dir, env, "smoke-test encrypt")

    decrypted = _run_sops(["sops", "--decrypt", str(secrets_path)], output_dir, env, "smoke-test decrypt")
    if "_mac2nix_smoke_test" not in decrypted.stdout:
        msg = f"sops decrypt round-trip for {secrets_path} did not return the expected smoke-test key"
        raise ScaffoldError(msg)

    secrets_path.write_text(yaml.safe_dump({}))
    _run_sops(["sops", "--encrypt", "--in-place", str(secrets_path)], output_dir, env, "final empty-document encrypt")


def _cleanup_after_failed_add_host(  # noqa: PLR0913
    output_dir: Path,
    hostname: str,
    host_dir: Path,
    user_file: Path,
    *,
    user_file_created: bool,
    age_key_generated: bool,
    username: str,
) -> None:
    """Remove only what this failed `add_host()` call itself created, then self-heal flake.nix/.sops.yaml.

    Re-invokes `_regenerate_flake_hosts_block()`/`_regenerate_sops_yaml()`
    against the now-reduced host set so neither file ends up referencing a
    host whose directory no longer exists. That re-invocation's own failure
    is logged, never raised — the original exception is always what
    propagates, since preserving the real root cause matters more than a
    secondary cleanup-time failure.
    """
    shutil.rmtree(host_dir, ignore_errors=True)

    if user_file_created:
        user_file.unlink(missing_ok=True)

    if age_key_generated:
        _age_key_path(username).unlink(missing_ok=True)

    (output_dir / "secrets" / f"{hostname}.yaml").unlink(missing_ok=True)

    try:
        metas = _load_all_host_metadata(output_dir)
        _regenerate_flake_hosts_block(output_dir, metas)
        _regenerate_sops_yaml(output_dir, metas)
    except Exception:
        logger.warning(
            "Cleanup after failed add-host for %r could not fully regenerate flake.nix/.sops.yaml — "
            "these files may still reference the removed host and require manual inspection.",
            hostname,
        )


def add_host(
    output_dir: Path,
    hostname: str,
    username: str,
    system: str = "aarch64-darwin",
    *,
    confirm_backup: Callable[[str], bool],
) -> str:
    """Register a host with the framework at *output_dir*.

    Generates this host's own sops-nix age key, writes its per-host
    configuration/user files, and wholesale-regenerates flake.nix's host
    block and .sops.yaml from every registered host's metadata.

    `confirm_backup` is invoked once the new age key exists, receiving its
    public fingerprint; returning `False` aborts before flake/sops
    regeneration ever runs.

    Trust boundary: *hostname*/*username* are used directly in path
    construction (`output_dir / "hosts" / "darwin" / hostname`) and are
    **not** validated against a character allowlist here — that check is the
    CLI layer's job (`^[a-z][a-z0-9-]*$`/`^[a-z_][a-z0-9_-]*$`), applied
    before this function is ever called. A hostname like `"../../evil"`
    passed directly to this function would escape `output_dir`. `nix_string()`
    escaping in `_regenerate_flake_hosts_block()` is a separate, independent
    layer guarding against Nix-syntax corruption — it does not substitute for
    the CLI's own path-traversal check.

    Returns the new host's age key public fingerprint.
    Raises :exc:`ScaffoldError` on any failure — anything this specific call
    created is rolled back, and flake.nix/.sops.yaml are re-regenerated
    against the resulting, unchanged host set.

    Not safe for concurrent invocations against the same *output_dir* —
    its read-glob-write cycle on flake.nix/.sops.yaml assumes single-operator,
    sequential use, matching this tool's actual CLI-driven usage pattern.
    """
    # Resolve to absolute up front: _create_host_secrets_file() runs sops
    # with cwd=output_dir *and* a secrets-file argument derived from
    # output_dir — if output_dir were relative, sops would resolve that
    # argument a second time against its own (already output_dir-rooted)
    # cwd, doubling the path and failing with "non-existent file". Verified
    # empirically: `mac2nix add-host some/relative/path ...` hit exactly
    # this before this fix.
    output_dir = output_dir.resolve()

    flake_path = output_dir / "flake.nix"
    if not flake_path.is_file():
        msg = f"{output_dir} is not a mac2nix-scaffolded framework — run `mac2nix init` first"
        raise ScaffoldError(msg)
    flake_content = flake_path.read_text()
    if _HOSTS_BEGIN not in flake_content or _HOSTS_END not in flake_content:
        msg = f"{output_dir} is not a mac2nix-scaffolded framework — run `mac2nix init` first"
        raise ScaffoldError(msg)

    host_dir = output_dir / "hosts" / "darwin" / hostname
    if host_dir.exists():
        raise ScaffoldError(f"host {hostname!r} is already registered")

    user_file = output_dir / "users" / f"{username}.nix"
    user_file_created = False
    age_key_generated = False

    try:
        _write_host_config(host_dir, hostname, username)

        if not user_file.exists():
            user_file_created = True
            _write_user_file(user_file, hostname, username)

        key_path = _age_key_path(username)
        if key_path.resolve().is_relative_to(output_dir.resolve()):
            msg = f"refusing to generate an age key inside {output_dir} — keys must live outside the framework repo"
            raise ScaffoldError(msg)

        fingerprint = generate_age_key(username)
        age_key_generated = True

        if not confirm_backup(fingerprint):
            msg = "age key backup not confirmed — aborting before flake/sops regeneration"
            raise ScaffoldError(msg)

        meta = {"hostname": hostname, "username": username, "system": system, "age_public_key": fingerprint}
        (host_dir / _META_FILENAME).write_text(json.dumps(meta, indent=2))

        metas = _load_all_host_metadata(output_dir)
        _regenerate_flake_hosts_block(output_dir, metas)
        _regenerate_sops_yaml(output_dir, metas)
        _create_host_secrets_file(output_dir, hostname, key_path)
    except Exception:
        _cleanup_after_failed_add_host(
            output_dir,
            hostname,
            host_dir,
            user_file,
            user_file_created=user_file_created,
            age_key_generated=age_key_generated,
            username=username,
        )
        raise

    return fingerprint
