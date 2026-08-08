# YubiKey PIV login + sudo runbook

This runbook covers enabling an *existing* YubiKey's PIV identity (already
provisioned with certificates — this is not a certificate-generation guide)
for macOS login-screen authentication and `sudo`.

**Scope split, and why it matters for how you read this document:**

- **Login** (`sc_auth pair`, the System Settings smartcard toggle) has no
  nix-darwin declarative primitive at all — macOS exposes no config file or
  option for this, only imperative local machine state. Everything below for
  login is manual, one-time, per-machine setup with no automated test
  coverage — you are the verification.
- **Sudo** is just another PAM line, and gets a real nix-darwin option,
  `mac2nix.yubikeyPivSudo.enable` (`modules/darwin/security.nix`). This half
  *does* have real, automated end-to-end test coverage — a virtual PIV card
  is used in this project's own test suite to prove the PAM wiring actually
  authenticates, not merely that it builds (see
  `tests/vm/test_piv_sudo_vm.py`/`tests/vm/test_piv_sudo_native.py`). That
  coverage tests the option's *mechanism*; it does not replace the
  in-person verification in Step 7 below, which is about *your* physical
  key and *your* machine.

Every step below is a non-negotiable prerequisite or verification, not
optional advice — skipping any of them trades a real safety margin for
convenience.

## 1. Verify the PIV PIN and PUK are known, non-default values

A locked PIN can be reset with the PUK. A locked PUK requires wiping the
PIV applet entirely — destroying the existing certificates this runbook
assumes you already have and are not regenerating.

```sh
ykman piv info
```

Confirm you can actually authenticate with the PIN before proceeding — if
you're not certain, verify it now rather than discovering it's wrong at
Step 4 or 5, where a wrong PIN starts consuming retry attempts.

## 2. Set up a password-only fallback admin account

Create a second local administrator account, explicitly excluded from any
smartcard enforcement, **before** enabling anything below. This is the
actual recovery path if the YubiKey is lost, damaged, or misbehaves — not
"recovery mode," not a theoretical safety net.

Document exactly where this account's credentials live (a named entry in
your password manager). If you can't say precisely where they are, this
step isn't done.

## 3. Escrow and verify the FileVault recovery key

Escrow the FileVault personal recovery key (the 24-character key, from
`fdesetup` or System Settings → Privacy & Security → FileVault) in your
password manager, and **confirm it's actually retrievable** — not just
assumed present.

This is a hard prerequisite, not a nice-to-have: on Apple Silicon, pre-boot
disk unlock only recognizes whichever smart card was *last used on that
specific machine*. If this same physical YubiKey is ever used on a
different Mac, this machine's pre-boot unlock could end up depending on a
card state that's since changed. The FileVault recovery key is the only
fallback that doesn't depend on the card's state, on sops-nix, or on
anything else this machine's own disk needs to be unlocked to reach.

## 4. Pair the card and enable smartcard login as "allow"

```sh
sc_auth identities
sc_auth pair -u <username> -h <hash-from-sc_auth-identities>
```

Then enable smartcard login in System Settings → Users & Groups, as
**"allow"** — never **"require"**. With only one physical key and no
backup-issuance path, "require" turns a lost key into a lockout with no
self-service recovery.

## 5. Export the PIV certificate into `pam_p11`'s trust file

`pam_p11` authenticates via a simple challenge-response against a
pre-registered public key or certificate — not full CA-chain/CRL/OCSP
validation. The existing PIV certificate has to be registered once for
this to work.

As a fast, no-YubiKey-needed sanity check before touching the physical key
at all, confirm the package resolves:

```sh
nix build nixpkgs#pam_p11
find "$(nix build nixpkgs#pam_p11 --no-link --print-out-paths)" -iname 'pam_p11.so'
```

`${pkgs.opensc}` is Nix interpolation syntax — it only means something
inside a `.nix` file, not at a shell prompt. At this point in the runbook,
`opensc` isn't in `environment.systemPackages` yet (it's gated behind
`mac2nix.yubikeyPivSudo.enable`, not yet turned on), so `pkcs11-tool` isn't
on `PATH` either. Get both onto `PATH` for this shell session and resolve
`opensc`'s real PKCS#11 module path:

```sh
nix shell nixpkgs#opensc nixpkgs#pam_p11
OPENSC_PKCS11="$(nix build nixpkgs#opensc --no-link --print-out-paths)/lib/opensc-pkcs11.so"
```

Now export the existing certificate (this reads the card, it does not
generate anything new on it):

```sh
pkcs11-tool --list-objects --type cert --module "$OPENSC_PKCS11"
# note the certificate's id from the output above
pkcs11-tool --read-object --type cert --id <id> --module "$OPENSC_PKCS11" --output-file /tmp/piv-cert.cer
mkdir -p ~/.eid && chmod 0755 ~/.eid
openssl x509 -inform DER -in /tmp/piv-cert.cer -outform PEM >> ~/.eid/authorized_certificates
chmod 0644 ~/.eid/authorized_certificates
```

**Fallback, only if a future nixpkgs revision ever stops shipping a working
`pam_p11` for macOS** (not expected — it is currently Hydra-tracked and
binary-cached for aarch64-darwin): edit `/etc/pam.d/sudo_local` directly
and imperatively instead, adding this line above the Touch ID line:

```
auth       sufficient     <path-to-pam_p11.so> <path-to-opensc-pkcs11.so>
```

**This fallback is not permanent and does not survive a rebuild.**
`security.nix`'s `touchIdAuth = lib.mkDefault true` line is unconditional,
which puts `/etc/pam.d/sudo_local` under nix-darwin's `environment.etc`
management the moment `security.nix` is imported — regardless of whether
the YubiKey option is ever turned on. Any manual edit to that file is
silently overwritten (back to Touch-ID-only) the next time you run
`darwin-rebuild switch`, not just after a macOS upgrade. Treat the manual
fallback as something you must re-apply after every switch for as long as
this stopgap is needed — it is not a stable substitute for the declarative
option.

## 6. Enable the option and switch

In the host's `configuration.nix`:

```nix
mac2nix.yubikeyPivSudo.enable = true;
```

```sh
darwin-rebuild switch --flake .#<hostname>
```

(Skip this step if you used the manual fallback in Step 5 instead.)

## 7. Test in this exact order, in person

**Never over SSH-only access** — if any of these fail, you need to be at
the physical machine.

1. Full logout/login cycle, authenticating with the card.
2. `sudo` at a terminal, authenticating with the card.
3. Reboot with the card physically removed. Confirm password login and
   password `sudo` both still work.

Do not consider this runbook followed until all three pass, in this order.

## 8. If the key is lost

Use the fallback admin account from Step 2 to log in and administer the
machine. `sc_auth pair`'s state is local to this machine only — there is
no server-side identity to revoke, and no remote action is needed. Once
you have a replacement key, repeat Steps 4-5 for it.
