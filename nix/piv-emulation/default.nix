# Local, flake-internal PIV-emulation derivations -- NOT part of the
# generated scaffold output shipped to real hosts (see
# templates/scaffold/flake.nix). Only ever consumed by this project's own
# test suite (tests/vm/test_piv_sudo_vm.py, tests/vm/test_piv_sudo_native.py)
# via scripts/provision_piv_emulation.py.
#
# nixpkgs is pinned explicitly (not `<nixpkgs>`) because this project has no
# top-level flake.lock to pin it otherwise, and `<nixpkgs>` resolves through
# the machine-local Nix registry -- on a Determinate Nix install that's
# `flakehub.com/f/DeterminateSystems/nixpkgs-weekly/*`, a rolling reference
# that changes every week independent of any local state. jcardsim.nix's
# `mvnHash` pins the exact byte content of its Maven-deps fetch, which is
# produced by `maven.buildMavenPackage`'s own nixpkgs-version-dependent
# implementation -- confirmed empirically: a hash verified against one
# week's nixpkgs mismatched a fresh Tart VM's bootstrap of the *same*
# `<nixpkgs>` reference days later. Pinning here makes that hash (and this
# whole derivation set) actually reproducible across machines and time.
let
  pinnedNixpkgs = fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/70ce234312134a463ba7728e94da2486a1d237ac.tar.gz";
    sha256 = "1ify0rml5kx1fggk6hrzc26y98ni445s2kbkfc5x3jpkkagir3jz";
  };
in
{ pkgs ? import pinnedNixpkgs { } }:
let
  pcscStack = import ./pcsc-stack.nix { inherit pkgs; };
in
{
  vpcd = pkgs.callPackage ./vpcd.nix { };
  jcardsim = pkgs.callPackage ./jcardsim.nix { };
  pivapplet = pkgs.callPackage ./pivapplet.nix { };
  inherit (pcscStack) pcsclite opensc yubicoPivTool;

  # A JRE to run jcardsim's compiled VSmartCard with. jcardsim.nix itself
  # only needs jdk8 to *compile* (its pom.xml targets Java 1.7), but that's a
  # build-time-only dependency, not something the built jar carries with it
  # -- confirmed by a real failure: a Tart VM never has `java` on PATH at
  # all otherwise ("Unable to locate a Java Runtime"), a bug never caught
  # before because provisioning always failed earlier at VID/PID
  # registration. Any modern JRE runs jcardsim's old-bytecode jar fine (JVMs
  # are backwards compatible) -- this is just nixpkgs' current default JDK.
  jdk = pkgs.jdk;
}
