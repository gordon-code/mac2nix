{ ... }:

{
  # Shared Homebrew activation policy — not scanned cask/brew data, which is
  # per-host and lives under hosts/darwin/<hostname>/ once `mac2nix generate`
  # has run.
  homebrew = {
    enable = true;
    onActivation = {
      autoUpdate = true;
      upgrade = true;
      cleanup = "zap";
    };
    caskArgs = {
      require_sha = true;
    };
  };
}
