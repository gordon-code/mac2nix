{ config, lib, pkgs, ... }:
{
  options.mac2nix.yubikeyPivSudo.enable = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = "Require or allow YubiKey PIV smartcard authentication for sudo, in addition to Touch ID.";
  };

  config = {
    security.pam.services.sudo_local.touchIdAuth = lib.mkDefault true;
    environment.systemPackages = lib.mkIf config.mac2nix.yubikeyPivSudo.enable [ pkgs.pam_p11 pkgs.opensc ];
    # pam_p11 does a simple challenge-response against a pre-registered
    # public key/cert (no CA-chain/CRL checking) -- see docs/runbooks/yubikey-piv.md
    # for the one-time cert export this requires. sufficient, not required: a
    # lost/unavailable card must never lock sudo behind the card alone.
    security.pam.services.sudo_local.text = lib.mkIf config.mac2nix.yubikeyPivSudo.enable (
      lib.mkAfter "auth       sufficient     ${pkgs.pam_p11}/lib/security/pam_p11.so ${pkgs.opensc}/lib/opensc-pkcs11.so"
    );
  };
}
