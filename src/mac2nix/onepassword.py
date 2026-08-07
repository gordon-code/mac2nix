"""Optional 1Password CLI (`op`) integration for backing up sops-nix age keys.

Used by `mac2nix add-host --op-vault` as an alternative to the manual
"have you backed this up?" confirmation. A write that's never read back can
silently fail or land wrong (locked vault, stale item, truncated upload) —
`store_age_key()` always verifies by reading the item back and comparing
its content byte-for-byte against the key file on disk before reporting
success, so a caller never has to trust the write alone.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class OnePasswordError(Exception):
    """Raised when `op` is unavailable, unauthenticated, or a write/verify fails."""


def is_available() -> bool:
    return shutil.which("op") is not None


def is_signed_in() -> bool:
    """Check sign-in state without ever triggering an interactive prompt.

    `op signin` blocks on user interaction if not already authenticated;
    `op whoami` never does — it just fails fast with a nonzero exit.
    """
    result = subprocess.run(["op", "whoami"], capture_output=True, text=True, check=False)  # noqa: S607
    return result.returncode == 0


def store_age_key(key_path: Path, *, vault: str, title: str) -> str:
    """Upload *key_path* to 1Password as a Document item, then read it back to verify.

    Returns the created item's ID on success. Raises :exc:`OnePasswordError`
    if `op` is missing, the write fails, or the read-back content doesn't
    match the on-disk key byte-for-byte — the last case is the entire reason
    this function exists instead of a bare `op document create` call: a
    write that "succeeds" but silently stores the wrong (or no) content is
    worse than no backup, since it looks safe.

    Deliberately does not pre-check `is_signed_in()` before attempting the
    write — `op whoami` has a known failure mode where it reports "not
    signed in" while the local vault is still genuinely readable/writable
    (session-state can desync from what `op` actually has access to).
    Attempting the real operation and surfacing its own error message is a
    more reliable signal than a separate pre-flight check that can itself
    be wrong; `is_signed_in()` is still available as its own function for
    callers that want a best-effort availability check.
    """
    if not is_available():
        raise OnePasswordError("`op` is not installed or not on PATH")

    create = subprocess.run(  # noqa: S603
        ["op", "document", "create", str(key_path), "--title", title, "--vault", vault, "--format", "json"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if create.returncode != 0:
        raise OnePasswordError(f"op document create failed: {create.stderr.strip()}")

    # Verified against a real `op document create --format json` response:
    # the created item's identifier comes back as "uuid", not "id" — despite
    # "id" being the field name `op item ...` commands use elsewhere. Caught
    # by an actual op invocation; a schema this function's own tests can't
    # verify by construction, since a mock only ever asserts its own guess.
    try:
        item_id = json.loads(create.stdout)["uuid"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise OnePasswordError(f"op document create returned unexpected output: {create.stdout.strip()}") from exc

    verify = subprocess.run(  # noqa: S603
        ["op", "document", "get", item_id, "--vault", vault],  # noqa: S607
        capture_output=True,
        check=False,
    )
    if verify.returncode != 0:
        stderr = verify.stderr.decode(errors="replace").strip()
        raise OnePasswordError(f"op document get (verify) failed: {stderr}")

    if verify.stdout != key_path.read_bytes():
        raise OnePasswordError("1Password read-back did not match the on-disk age key — treating backup as failed")

    return item_id
