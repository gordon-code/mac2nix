# Local, flake-internal PIV-emulation derivations -- NOT part of the
# generated scaffold output shipped to real hosts (see
# templates/scaffold/flake.nix). Only ever consumed by this project's own
# test suite (tests/vm/test_piv_sudo_vm.py, tests/vm/test_piv_sudo_native.py)
# via scripts/provision_piv_emulation.py.
{ pkgs ? import <nixpkgs> { } }:
{
  vpcd = pkgs.callPackage ./vpcd.nix { };
  jcardsim = pkgs.callPackage ./jcardsim.nix { };
  pivapplet = pkgs.callPackage ./pivapplet.nix { };
}
