"""Non-``system.defaults`` scanner fields -> nix-darwin option paths.

Covers the environment, fonts, launchd, networking, power, programs,
security, and time nix-darwin modules -- everything Tier 1-mappable outside
the ``system.defaults.*`` tree. :data:`FONT_TO_NIXPKGS` and
:func:`get_font_nixpkgs` resolve installed font filenames to nixpkgs
attributes; :data:`LAUNCHD_LABEL_TO_SERVICE` and :data:`LAUNCHD_KEYS_TO_DROP`
support routing ``launch_agents`` scanner output to native ``services.*``
modules or raw ``launchd.*.serviceConfig``; the remaining dicts are direct
scanner-field-name -> nix-darwin-option-path lookups.

Source: hack/research/feat-research-1746309600-nix-darwin-non-defaults-options.md
"""

from __future__ import annotations

import fnmatch
import re

# ---------------------------------------------------------------------------
# Fonts (fonts.packages)
# ---------------------------------------------------------------------------

# Keys are the output of `_normalize_font_name`, not raw display names. Nerd
# Font variants keep a trailing "nf" marker post-normalization specifically
# so they don't collide with their base-font counterpart (e.g. "Fira Code"
# and "FiraCode NF" both reduce to "firacode" once whitespace/case/"NF" are
# treated as pure noise -- the "nf" marker is what nixpkgs.nerd-fonts.* needs
# to stay distinct from pkgs.fira-code). A value of `None` marks a font with
# a confirmed, deliberate lack of a nixpkgs equivalent (Apple system fonts).
FONT_TO_NIXPKGS: dict[str, str | None] = {
    # Developer / monospace fonts
    "firacode": "pkgs.fira-code",
    "jetbrainsmono": "pkgs.jetbrains-mono",
    "hack": "pkgs.hack-font",
    "sourcecodepro": "pkgs.source-code-pro",
    "cascadiacode": "pkgs.cascadia-code",
    "inconsolata": "pkgs.inconsolata",
    "iosevka": "pkgs.iosevka",
    "iosevkaterm": "pkgs.iosevka",
    "victormono": "pkgs.victor-mono",
    "ibmplexmono": "pkgs.ibm-plex",
    "monaspace": "pkgs.monaspace",
    "recursive": "pkgs.recursive",
    "recursivemono": "pkgs.recursive",
    "overpass": "pkgs.overpass",
    "overpassmono": "pkgs.overpass",
    "maplemono": "pkgs.maple-mono",
    "juliamono": "pkgs.julia-mono",
    "commitmono": "pkgs.commit-mono",
    "dejavu": "pkgs.dejavu_fonts",
    "dejavusans": "pkgs.dejavu_fonts",
    "dejavuserif": "pkgs.dejavu_fonts",
    "dejavusansmono": "pkgs.dejavu_fonts",
    # Nerd Font variants (pkgs.nerd-fonts.<name> -- old pkgs.nerdfonts is removed)
    "firacodenf": "pkgs.nerd-fonts.fira-code",
    "jetbrainsmononf": "pkgs.nerd-fonts.jetbrains-mono",
    "hacknf": "pkgs.nerd-fonts.hack",
    "saucecodepronf": "pkgs.nerd-fonts.sauce-code-pro",
    "caskaydiacovenf": "pkgs.nerd-fonts.caskaydia-cove",
    "caskaydiamononf": "pkgs.nerd-fonts.caskaydia-mono",
    "iosevkanf": "pkgs.nerd-fonts.iosevka",
    "iosevkatermnf": "pkgs.nerd-fonts.iosevka-term",
    "victormononf": "pkgs.nerd-fonts.victor-mono",
    "blexmononf": "pkgs.nerd-fonts.blex-mono",
    "inconsolatanf": "pkgs.nerd-fonts.inconsolata",
    "monaspacenf": "pkgs.nerd-fonts.monaspace",
    "geistmononf": "pkgs.nerd-fonts.geist-mono",
    "meslolgsnf": "pkgs.nerd-fonts.meslo-lg",
    "dejavusansmononf": "pkgs.nerd-fonts.dejavu-sans-mono",
    "robotomononf": "pkgs.nerd-fonts.roboto-mono",
    "ubuntunf": "pkgs.nerd-fonts.ubuntu",
    "ubuntumononf": "pkgs.nerd-fonts.ubuntu-mono",
    "mononokinf": "pkgs.nerd-fonts.mononoki",
    "0xprotonf": "pkgs.nerd-fonts.0xproto",
    "commitmononf": "pkgs.nerd-fonts.commit-mono",
    "zedmononf": "pkgs.nerd-fonts.zed-mono",
    "symbolsonly": "pkgs.nerd-fonts.symbols-only",
    "symbolsnf": "pkgs.nerd-fonts.symbols-only",
    # Google Fonts / UI fonts
    "inter": "pkgs.inter",
    "roboto": "pkgs.roboto",
    "robotomono": "pkgs.roboto-mono",
    "opensans": "pkgs.open-sans",
    "lato": "pkgs.lato",
    "notosans": "pkgs.noto-fonts",
    "notoserif": "pkgs.noto-fonts",
    "notocjksans": "pkgs.noto-fonts-cjk-sans",
    "notocoloremoji": "pkgs.noto-fonts-color-emoji",
    "ubuntu": "pkgs.ubuntu-classic",
    "cantarell": "pkgs.cantarell-fonts",
    "atkinsonhyperlegible": "pkgs.atkinson-hyperlegible-next",
    "firasans": "pkgs.fira",
    "liberation": "pkgs.liberation_ttf",
    # Icon fonts
    "fontawesome": "pkgs.font-awesome",
    "materialdesignicons": "pkgs.material-design-icons",
    # Microsoft legacy (core fonts + Vista fonts)
    "arial": "pkgs.corefonts",
    "times": "pkgs.corefonts",
    "timesnewroman": "pkgs.corefonts",
    "courier": "pkgs.corefonts",
    "couriernew": "pkgs.corefonts",
    "cambria": "pkgs.vistafonts",
    "calibri": "pkgs.vistafonts",
    "consolas": "pkgs.vistafonts",
    # Apple system fonts -- bundled with macOS, no nixpkgs equivalent
    "sfpro": None,
    "sfmono": None,
    "sfcompact": None,
    "newyork": None,
    "menlo": None,
    "monaco": None,
    "lucidagrande": None,
    "helveticaneue": None,
    "avenir": None,
    "avenirnext": None,
    "futura": None,
    "gillsans": None,
    "optima": None,
    "palatino": None,
    "baskerville": None,
    "didot": None,
}

_FONT_EXTENSION_RE = re.compile(r"\.(ttf|otf|ttc|dfont|woff2?|collection)$", re.IGNORECASE)
_NERD_FONT_PHRASE_RE = re.compile(r"nerd[\s_-]*font(?:[\s_-]*(?:mono|propo|complete))?", re.IGNORECASE)
_NERD_FONT_ABBR_RE = re.compile(r"(?:^|[\s_-])nf$", re.IGNORECASE)
_WEIGHT_SUFFIX_RE = re.compile(
    r"[\s_-]*(extralight|extrabold|semibold|demibold|bolditalic|regular|italic|medium|light|black|thin|heavy|book|bold)$",
    re.IGNORECASE,
)
_SEPARATOR_RE = re.compile(r"[\s_-]+")


def _normalize_font_name(name: str) -> str:
    """Reduce a font filename/display name to a bare lookup key.

    Strips the file extension, weight suffixes (Regular/Bold/Italic/...),
    and separator noise. "Nerd Font"/"NF" suffixes are folded into a
    canonical trailing ``nf`` marker rather than dropped outright, since
    Nerd Font variants and their base fonts otherwise normalize to the
    same string (see :data:`FONT_TO_NIXPKGS`).
    """
    stripped = _FONT_EXTENSION_RE.sub("", name).strip()

    is_nerd_font = False
    without_phrase = _NERD_FONT_PHRASE_RE.sub("", stripped)
    if without_phrase != stripped:
        stripped = without_phrase
        is_nerd_font = True
    without_abbr = _NERD_FONT_ABBR_RE.sub("", stripped)
    if without_abbr != stripped:
        stripped = without_abbr
        is_nerd_font = True

    changed = True
    while changed:
        without_weight = _WEIGHT_SUFFIX_RE.sub("", stripped)
        changed = without_weight != stripped
        stripped = without_weight

    normalized = _SEPARATOR_RE.sub("", stripped).lower()
    return f"{normalized}nf" if is_nerd_font else normalized


def get_font_nixpkgs(font_name: str) -> str | None:
    """Resolve a font filename/display name to its nixpkgs attribute path.

    Returns `None` for fonts with no nixpkgs equivalent (Apple system
    fonts) as well as for names with no exact normalized match -- no fuzzy
    matching is attempted.
    """
    return FONT_TO_NIXPKGS.get(_normalize_font_name(font_name))


# ---------------------------------------------------------------------------
# Launchd (launchd.{agents,daemons,user.agents}.<name>.serviceConfig)
# ---------------------------------------------------------------------------

# Apple plist keys seen in real LaunchAgent/LaunchDaemon plists that have no
# corresponding nix-darwin serviceConfig option. serviceConfig is a closed
# submodule -- passing these through unmodified fails Nix evaluation.
LAUNCHD_KEYS_TO_DROP: frozenset[str] = frozenset(
    {
        "LegacyTimers",
        "AssociatedBundleIdentifiers",
        "EnablePressuredExit",
        "BundleProgram",
        "MaterializeDatalessFiles",
        "LimitLoadToHardware",
        "LimitLoadFromHardware",
    }
)

# Ordered (fnmatch-glob-pattern, nix-darwin-service-path) pairs. Order
# matters: specific labels/prefixes are listed before broad wildcard
# patterns so the more precise match is tried first.
LAUNCHD_LABEL_TO_SERVICE: list[tuple[str, str]] = [
    ("org.nixos.nix-daemon", "services.nix-daemon"),
    ("org.nixos.activate-system", "services.activate-system"),
    ("org.nixos.nix-gc", "nix.gc"),
    ("org.nixos.nix-optimise", "nix.optimise"),
    ("com.tailscale.tailscaled", "services.tailscale"),
    ("org.pqrs.karabiner.*", "services.karabiner-elements"),
    ("com.openssh.sshd", "services.openssh"),
    ("*yabai*", "services.yabai"),
    ("*skhd*", "services.skhd"),
    ("*aerospace*", "services.aerospace"),
    ("*spacebar*", "services.spacebar"),
    ("*sketchybar*", "services.sketchybar"),
    ("*jankyborders*", "services.jankyborders"),
    ("*borders*", "services.jankyborders"),
    ("*emacs*", "services.emacs"),
    ("*lorri*", "services.lorri"),
    ("*buildkite*", "services.buildkite-agents"),
    ("*gitlab-runner*", "services.gitlab-runner"),
    ("*github-runner*", "services.github-runners"),
    ("*hercules-ci*", "services.hercules-ci-agent"),
    ("*cachix*", "services.cachix-agent"),
    ("*dnscrypt*", "services.dnscrypt-proxy"),
    ("*dnsmasq*", "services.dnsmasq"),
    ("*nextdns*", "services.nextdns"),
    ("*tailscale*", "services.tailscale"),
    ("*redis*", "services.redis"),
    ("*postgresql*", "services.postgresql"),
    ("*postgres*", "services.postgresql"),
    ("*netbird*", "services.netbird"),
    ("*wg-quick*", "networking.wg-quick"),
    ("*wireguard*", "networking.wg-quick"),
]


def get_launchd_service(label: str) -> str | None:
    """Resolve a launchd Label to a native nix-darwin service option path.

    Returns `None` if *label* matches no known service -- the caller
    should fall back to a generic ``launchd.*.serviceConfig`` mapping.
    """
    for pattern, service in LAUNCHD_LABEL_TO_SERVICE:
        if fnmatch.fnmatch(label, pattern):
            return service
    return None


def is_launchd_key_droppable(key: str) -> bool:
    """Whether *key* is an Apple plist key with no serviceConfig equivalent."""
    return key in LAUNCHD_KEYS_TO_DROP


# ---------------------------------------------------------------------------
# Power (power.sleep.*, power.restartAfterPowerFailure, networking.wakeOnLan)
# ---------------------------------------------------------------------------

# pmset key -> nix-darwin option path. Only pmset settings with a direct
# nix-darwin equivalent are listed; nix-darwin applies these globally via
# `systemsetup` (no per-AC/battery control). Everything else (hibernatemode,
# standby, lidwake, etc.) has no nix-darwin option and is Tier 3
# (activation script) -- omitted here rather than mapped to `None`.
POWER_SETTING_MAP: dict[str, str] = {
    "displaysleep": "power.sleep.display",
    "sleep": "power.sleep.computer",
    "disksleep": "power.sleep.harddisk",
    "autorestart": "power.restartAfterPowerFailure",
    "womp": "networking.wakeOnLan.enable",
}


def get_power_nix_option(pmset_key: str) -> str | None:
    """Resolve a pmset setting name to its nix-darwin option path."""
    return POWER_SETTING_MAP.get(pmset_key)


# ---------------------------------------------------------------------------
# Programs (programs.{zsh,bash,fish}.enable, programs.tmux.enable)
# ---------------------------------------------------------------------------

SHELL_PROGRAM_MAP: dict[str, str] = {
    "zsh": "programs.zsh.enable",
    "bash": "programs.bash.enable",
    "fish": "programs.fish.enable",
    "tmux": "programs.tmux.enable",
}


def get_shell_program(shell_type: str) -> str | None:
    """Resolve a shell/multiplexer type to its `programs.<name>.enable` path."""
    return SHELL_PROGRAM_MAP.get(shell_type)


# ---------------------------------------------------------------------------
# Networking (networking.hostName, networking.dns, ...)
# ---------------------------------------------------------------------------

NETWORKING_MAP: dict[str, str] = {
    "hostname": "networking.hostName",
    "computer_name": "networking.computerName",
    "local_hostname": "networking.localHostName",
    "dns_servers": "networking.dns",
    "search_domains": "networking.search",
    "known_network_services": "networking.knownNetworkServices",
}


# ---------------------------------------------------------------------------
# Security (security.pam.*, security.pki.*, networking.applicationFirewall.*)
# ---------------------------------------------------------------------------

# The Application Firewall migrated FROM `system.defaults.alf.*` (removed)
# TO `networking.applicationFirewall.*` -- firewall fields route through
# the networking module here, not system.defaults.
SECURITY_MAP: dict[str, str] = {
    "touch_id_sudo": "security.pam.services.sudo_local.touchIdAuth",
    "custom_certificates": "security.pki.certificates",
    "firewall_enabled": "networking.applicationFirewall.enable",
    "firewall_stealth_mode": "networking.applicationFirewall.enableStealthMode",
    "firewall_block_all_incoming": "networking.applicationFirewall.blockAllIncoming",
}


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------

TIMEZONE_NIX_OPTION = "time.timeZone"
