{ config, lib, pkgs, hostname, ... }:

{
  imports = lib.optional (builtins.pathExists (../hosts/darwin + "/${hostname}/packages.nix")) (
    ../hosts/darwin + "/${hostname}/packages.nix"
  );

  home.username = "__USERNAME__";
  home.homeDirectory = "/Users/__USERNAME__";
  home.stateVersion = "26.05";

  programs.home-manager.enable = true;
}
