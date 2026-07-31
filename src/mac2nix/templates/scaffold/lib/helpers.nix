{ inputs }:

{ hostname, system, users }:

let
  inherit (inputs) darwin home-manager nix-homebrew mac-app-util determinate sops-nix homebrew-core homebrew-cask;
  primaryUser = builtins.elemAt users 0;
in
darwin.lib.darwinSystem {
  specialArgs = { inherit inputs hostname; };
  modules = [
    sops-nix.darwinModules.sops
    nix-homebrew.darwinModules.nix-homebrew
    mac-app-util.darwinModules.default
    determinate.darwinModules.default
    home-manager.darwinModules.home-manager

    {
      nixpkgs.hostPlatform = system;
      # Required by nix-darwin whenever an option that used to apply to the
      # invoking user (e.g. homebrew.enable) is set, now that system
      # activation always runs as root — per host, from its own user list.
      system.primaryUser = primaryUser;

      sops.defaultSopsFile = ../secrets + "/${hostname}.yaml";
      sops.age.keyFile = "/Users/${primaryUser}/.config/sops/age/keys.txt";

      nix-homebrew = {
        enable = true;
        user = primaryUser;
        taps = {
          "homebrew/homebrew-core" = homebrew-core;
          "homebrew/homebrew-cask" = homebrew-cask;
        };
        mutableTaps = false;
      };

      home-manager.useGlobalPkgs = true;
      home-manager.useUserPackages = true;
      home-manager.extraSpecialArgs = { inherit inputs hostname; };
      home-manager.sharedModules = [ ../modules/home-manager/default.nix ];
      home-manager.users = builtins.listToAttrs (
        map (u: { name = u; value = import (../users + "/${u}.nix"); }) users
      );
    }

    ../modules/darwin/default.nix
    (../hosts/darwin + "/${hostname}/configuration.nix")
  ];
}
