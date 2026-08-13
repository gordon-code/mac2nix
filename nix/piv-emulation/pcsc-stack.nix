# A self-hosted PC/SC stack (pcsclite + opensc + yubico-piv-tool) that never
# touches macOS's own proprietary PCSC/CryptoTokenKit service.
#
# Why this exists: nixpkgs' stock `opensc` and `yubico-piv-tool` both default
# to linking Apple's `PCSC.framework` on Darwin (`lib.optional
# (!stdenv.hostPlatform.isDarwin) pcsclite` in opensc's package.nix;
# `withApplePCSC ? stdenv.hostPlatform.isDarwin` in yubico-piv-tool's) --
# correct for a real Mac with a real YubiKey, but Apple's daemon is exactly
# the thing vpcd.nix's own comment documents as a dead end for emulated
# cards on Tart (HIDDriverKit already claims Tart's only synthetic USB
# devices, so ifdreader never gets a live reader for vpcd's bundle no matter
# how it's registered). Overriding both packages to link nixpkgs' own
# pcsclite instead routes them through a pcscd we run ourselves
# (scripts/provision_piv_emulation.py), which loads vpcd via a plain
# reader.conf entry -- no USB device, real or synthetic, required at all.
# Verified end-to-end on real hardware this session: pcscd sees the reader,
# jcardsim/PivApplet present a real ATR, and PKCS#11 login+sign+verify all
# succeed through this exact stack.
#
# This ONLY affects the test harness. The scaffold template
# (templates/scaffold/modules/darwin/security.nix) that real users get
# always references stock `pkgs.opensc` -- correct for their real hardware,
# where Apple's PCSC.framework is exactly the right thing to talk to a real
# YubiKey. tests/vm/test_piv_sudo_vm.py swaps `pkgs.opensc` for this
# derivation's `opensc` via a `nixpkgs.overlays` entry injected into the
# *generated test scaffold's own* configuration.nix, never into the
# template itself.
#
# ipcdir/usbdropdir/serialconfdir are all left at nixpkgs' own defaults
# (ipcdir=/run/pcscd) -- macOS has no /run by default, but
# provision_piv_emulation.py creates /run/pcscd with sudo before starting
# pcscd (the whole script already runs as root). This was previously done
# via a custom -Dipcdir= mesonFlags override pointed at a project-relative
# scratch directory; that path was 104 bytes long, exactly AF_UNIX's
# sun_path limit on Darwin, and the socket bind silently truncated to the
# wrong filename with no error -- confirmed by direct reproduction. Using
# the real, short /run/pcscd path removes an entire derivation-override
# axis and the failure mode that came with it.
{
  pkgs,
}:
let
  # nixpkgs' pcsclite postPatch hardcodes the Linux-style
  # "libpcsclite_real.so.1" name for the libredirect shim's dlopen target.
  # On Darwin, libtool actually produces "libpcsclite_real.1.dylib"
  # (version before the extension, not after) -- confirmed via a real build
  # (`find $out -name 'libpcsclite_real*'`). Without this fix, every
  # pcsclite client (opensc, yubico-piv-tool, pcscd itself) fails to dlopen
  # the real implementation on Darwin specifically, a real upstream nixpkgs
  # bug independent of anything else in this file.
  pcsclite = pkgs.pcsclite.overrideAttrs (old: {
    postPatch = builtins.replaceStrings
      [ ''"$lib/lib/libpcsclite_real.so.1"'' ]
      [ ''"$lib/lib/libpcsclite_real.1.dylib"'' ]
      old.postPatch;
  });

  opensc = pkgs.opensc.overrideAttrs (old: {
    buildInputs = old.buildInputs ++ [ pcsclite ];
    configureFlags = old.configureFlags ++ [
      "--with-pcsc-provider=${pkgs.lib.getLib pcsclite}/lib/libpcsclite${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}"
    ];
  });

  yubicoPivTool = pkgs.yubico-piv-tool.override {
    withApplePCSC = false;
    inherit pcsclite;
  };
in
{
  inherit pcsclite opensc yubicoPivTool;
}
