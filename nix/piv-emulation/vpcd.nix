# Builds vpcd (frankmorgner/vsmartcard's `virtualsmartcard` component, GPLv3,
# confirmed via its COPYING file) -- the virtual PC/SC reader that lets a
# software-only PIV card emulator (jcardsim.nix + pivapplet.nix) register
# with macOS's own smartcard stack.
#
# Standalone process, invoked independently -- never linked into mac2nix's
# own Python/Nix code -- so this falls under GPLv3's mere-aggregation
# allowance. Do not vendor its compiled output into anything this project
# ships to end users.
#
# Configured to match the real, official `make osx` build target's own
# recipe (virtualsmartcard/MacOSX/Makefile.am): --enable-infoplist plus
# pointing --enable-serialdropdir/--enable-serialconfdir directly at a
# bundle-shaped path under $out, which assembles a real
# ifd-vpcd.bundle/Contents/{MacOS,Info.plist} layout purely through those
# install-path choices -- there is no separate "bundle template" mechanism.
# Uses nixpkgs' own pcsclite for the ifdhandler.h/wintypes.h/reader.h headers
# (pkg-config discoverable, per configure.ac's default libpcsclite=no path)
# rather than Apple's proprietary PCSC.framework via an ambient `xcode-select`
# lookup -- keeps the build hermetic, and is proven ABI-compatible with
# macOS's real SmartCardServices daemon: Apple's own shipped CCID driver
# (ifd-ccid.bundle) is itself built against this exact same portable
# PC/SC IFD-handler API.
#
# The resulting bundle's ifdVendorID/ifdProductID must be patched by the
# provisioning script (scripts/provision_piv_emulation.py) with a
# caller-supplied VID/PID *after* this builds, not baked in here -- the VM
# and native-runner execution contexts use different, discovered-not-assumed
# target devices.
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
