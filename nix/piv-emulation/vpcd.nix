# Builds vpcd (frankmorgner/vsmartcard's `virtualsmartcard` component, GPLv3,
# confirmed via its COPYING file) -- the virtual PC/SC reader that lets a
# software-only PIV card emulator (jcardsim.nix + pivapplet.nix) register
# as a smartcard reader.
#
# Standalone process, invoked independently -- never linked into mac2nix's
# own Python/Nix code -- so this falls under GPLv3's mere-aggregation
# allowance. Do not vendor its compiled output into anything this project
# ships to end users.
#
# Still built with --enable-infoplist -- but no longer for macOS's own
# *proprietary* CryptoTokenKit/ifdreader PCSC service, which requires
# spoofing a real (or synthetic) USB device's VID/PID in the bundle's
# Info.plist so the daemon's IOKit-based hotplug matching fires. That route
# is a confirmed dead end on Tart specifically: Tart's only two synthetic
# USB devices (keyboard, digitizer) are already claimed by macOS's own
# HIDDriverKit stack, so ifdreader registers the driver bundle but never
# gets a live reader instance for it (real diagnostic evidence:
# system_profiler SPSmartCardsDataType shows the driver registered,
# `Readers:` stays empty).
#
# --enable-infoplist is kept purely because pcsclite's own macOS dynamic
# loader (dyn_macosx.c) calls CFBundleCreate() on whatever LIBPATH a
# reader.conf entry gives it, which requires an actual .bundle directory
# (Info.plist + MacOS/<executable>) -- a bare .dylib fails to load
# ("RFLoadReader failed: 0x80100014", confirmed empirically). The bundle's
# ifdVendorID/ifdProductID fields go unused and are never patched: instead,
# scripts/provision_piv_emulation.py hand-writes a `/etc/reader.conf.d/vpcd`
# entry whose LIBPATH points directly at this built bundle -- vsmartcard's
# own upstream install_readerconf target (Makefile.am, selected when
# --enable-infoplist is *not* passed) documents exactly this reader.conf
# mechanism, just installing a bare .so instead of a bundle, which is why
# it can't be used as-is here. PCSC-lite treats reader.conf.d entries as
# "serial" (non-hotplug) readers that are always available, independent of
# any real or virtual USB device -- there is no VID/PID to spoof and
# nothing for a HID driver to compete for.
#
# Registers against a *self-hosted* nixpkgs pcscd (nix/piv-emulation/
# pcsc-stack.nix), never Apple's proprietary daemon -- verified end-to-end
# on real hardware this session: pcscd loads this exact bundle via
# reader.conf, jcardsim/PivApplet present a real ATR through it, and
# PKCS#11 login+sign+verify all succeed.
#
# Uses nixpkgs' own pcsclite for the ifdhandler.h/wintypes.h/reader.h headers
# (pkg-config discoverable, per configure.ac's default libpcsclite=no path)
# rather than Apple's proprietary PCSC.framework via an ambient `xcode-select`
# lookup -- keeps the build hermetic, and is the same IFD-handler API the
# self-hosted pcsc-stack.nix pcscd actually loads it with at runtime.
{
  fetchFromGitHub,
  stdenv,
  autoreconfHook,
  pkg-config,
  pcsclite,
  python3,
  help2man,
}:
stdenv.mkDerivation {
  pname = "vpcd";
  version = "unstable-2026-08-08";

  src = fetchFromGitHub {
    owner = "frankmorgner";
    repo = "vsmartcard";
    rev = "809675dc982addfc3fdb8cbaf177e4430477b0b2";
    hash = "sha256-I44XrC7v1G9hxaZ9zDlyUVPaSEx5HUAvDRBGsC8DYDs=";
  };

  sourceRoot = "source/virtualsmartcard";

  nativeBuildInputs = [
    autoreconfHook
    pkg-config
    python3
    help2man
  ];
  buildInputs = [ pcsclite ];

  configureFlags = [
    "--enable-infoplist"
    "--enable-serialdropdir=${placeholder "out"}/ifd-vpcd.bundle/Contents/MacOS"
    "--enable-serialconfdir=${placeholder "out"}/ifd-vpcd.bundle/Contents"
  ];

  # ifd-vpcd.c calls log_msg() (via debuglog.h's Log2 macro) but its own
  # Makefile.am never links against a library that provides it -- on Linux
  # this is fine (pcscd, the process that dlopen()s driver .so files,
  # already provides log_msg in its own address space at runtime, and ELF
  # shared libraries tolerate unresolved symbols by default). macOS's
  # linker doesn't tolerate this by default for dylibs; this is the
  # standard fix for a plugin meant to be dlopen()'d by a host process
  # that supplies the missing symbol, matching the real Linux behavior.
  NIX_LDFLAGS = "-undefined dynamic_lookup";

  meta = {
    description = "Virtual PC/SC smart card reader driver (vpcd, from vsmartcard)";
    license = "GPL-3.0-or-later";
    platforms = [ "aarch64-darwin" "x86_64-darwin" ];
  };
}
