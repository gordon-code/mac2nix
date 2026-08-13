{
  description = "mac2nix -- scan macOS system state and generate nix-darwin configuration";

  # Minimal packaging for `nix run` -- delegates to `uv` for the actual Python
  # dependency resolution/venv management (this project's own established
  # convention, per CLAUDE.md's "use uv for all Python work"), rather than
  # reimplementing that as a native Nix Python closure (uv2nix, etc.). This
  # exists specifically so `Validator._scan_vm()` (src/mac2nix/vm/validator.py)
  # can `nix run <this-repo-or-a-copy-of-it> -- scan` from inside a VM that
  # only has Nix bootstrapped, not `uv` itself -- `uv` is fetched from
  # nixpkgs as part of this flake's own closure.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
      ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
    in
    {
      apps = forEachSystem (
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = {
            type = "app";
            # `--project ${self}` points uv at a read-only Nix store path for
            # source/dependency resolution -- uv must never try to create its
            # venv there (its own default, and any ambient
            # $UV_PROJECT_ENVIRONMENT override, both assume a writable
            # project root). Force the venv into a fresh, writable temp dir
            # instead, independent of the caller's environment.
            program = toString (
              pkgs.writeShellScript "mac2nix" ''
                export UV_PROJECT_ENVIRONMENT="$(${pkgs.coreutils}/bin/mktemp -d)/venv"
                exec ${pkgs.uv}/bin/uv run --project ${self} mac2nix "$@"
              ''
            );
          };
        }
      );
    };
}
