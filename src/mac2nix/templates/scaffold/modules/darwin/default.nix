{ config, lib, pkgs, ... }:

{
  imports = [
    ./homebrew.nix
    ./security.nix
  ];
}
