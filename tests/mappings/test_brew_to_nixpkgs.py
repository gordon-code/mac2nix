"""Tests for brew_to_nixpkgs mapping."""

from mac2nix.mappings.brew_to_nixpkgs import (
    BREW_TO_NIXPKGS,
    VERSION_MANAGER_FORMULAE,
    NixpkgsEquivalent,
    get_nixpkgs_equivalent,
    is_unnecessary_in_nix,
)


class TestProgrammaticRules:
    """One test per rule in the 9-rule ordered pipeline."""

    def test_rule1_tap_stripping(self) -> None:
        assert get_nixpkgs_equivalent("oven-sh/bun/bun") == NixpkgsEquivalent("bun")

    def test_rule2_python_versioned(self) -> None:
        assert get_nixpkgs_equivalent("python@3.13") == NixpkgsEquivalent("python313")

    def test_rule3_node_versioned(self) -> None:
        assert get_nixpkgs_equivalent("node@22") == NixpkgsEquivalent("nodejs_22")

    def test_rule4_openjdk_versioned(self) -> None:
        assert get_nixpkgs_equivalent("openjdk@17") == NixpkgsEquivalent("jdk17")

    def test_rule5_postgresql_versioned(self) -> None:
        assert get_nixpkgs_equivalent("postgresql@14") == NixpkgsEquivalent("postgresql_14")

    def test_rule6_php_versioned(self) -> None:
        assert get_nixpkgs_equivalent("php@8.3") == NixpkgsEquivalent("php83")

    def test_rule7_gnu_tool_hyphen_removal(self) -> None:
        assert get_nixpkgs_equivalent("gnu-sed") == NixpkgsEquivalent("gnused")
        assert get_nixpkgs_equivalent("gnu-tar") == NixpkgsEquivalent("gnutar")

    def test_rule8_dot_to_hyphen(self) -> None:
        assert get_nixpkgs_equivalent("llama.cpp") == NixpkgsEquivalent("llama-cpp")

    def test_rule9_static_override(self) -> None:
        assert get_nixpkgs_equivalent("helm") == NixpkgsEquivalent("kubernetes-helm")


class TestRuleOrdering:
    def test_tap_stripped_versioned_formula_resolves_through_multiple_rules(self) -> None:
        """A tap-prefixed versioned formula must be tap-stripped (rule 1) before
        the versioned-pattern rule (rule 2) can match it."""
        assert get_nixpkgs_equivalent("user/tap/python@3.12") == NixpkgsEquivalent("python312")

    def test_tap_stripped_name_still_resolves_via_static_dict(self) -> None:
        """fluxcd/tap/flux strips to "flux", which only resolves correctly
        via the static override table (identity alone would be wrong)."""
        result = get_nixpkgs_equivalent("fluxcd/tap/flux")
        assert result is not None
        assert result.attr_name == "fluxcd"

    def test_tap_prefix_alone_would_be_wrong_without_stripping(self) -> None:
        """Sanity check: the raw tap-prefixed string is not a valid nixpkgs
        attribute -- stripping is required for a correct result."""
        result = get_nixpkgs_equivalent("hashicorp/tap/terraform")
        assert result is not None
        assert result.attr_name == "terraform"
        assert "/" not in result.attr_name


class TestStaticNameMismatches:
    def test_node(self) -> None:
        assert get_nixpkgs_equivalent("node") == NixpkgsEquivalent("nodejs")

    def test_kubernetes_cli(self) -> None:
        assert get_nixpkgs_equivalent("kubernetes-cli") == NixpkgsEquivalent("kubectl")

    def test_awscli(self) -> None:
        assert get_nixpkgs_equivalent("awscli") == NixpkgsEquivalent(
            "awscli2", note="v2 is brew's default; pkgs.awscli is v1"
        )

    def test_yq(self) -> None:
        result = get_nixpkgs_equivalent("yq")
        assert result is not None
        assert result.attr_name == "yq-go"

    def test_ca_certificates(self) -> None:
        assert get_nixpkgs_equivalent("ca-certificates") == NixpkgsEquivalent("cacert")

    def test_jpeg_xl(self) -> None:
        assert get_nixpkgs_equivalent("jpeg-xl") == NixpkgsEquivalent("libjxl")

    def test_rust(self) -> None:
        result = get_nixpkgs_equivalent("rust")
        assert result is not None
        assert result.attr_name == "rustc"

    def test_llvm(self) -> None:
        result = get_nixpkgs_equivalent("llvm")
        assert result is not None
        assert result.attr_name == "llvmPackages.clang"

    def test_composer(self) -> None:
        result = get_nixpkgs_equivalent("composer")
        assert result is not None
        assert result.attr_name == "phpPackages.composer"

    def test_telnet(self) -> None:
        result = get_nixpkgs_equivalent("telnet")
        assert result is not None
        assert result.attr_name == "inetutils"

    def test_openjdk_unversioned(self) -> None:
        result = get_nixpkgs_equivalent("openjdk")
        assert result is not None
        assert result.attr_name == "jdk"


class TestDockerDarwinSpecific:
    def test_docker_maps_to_docker_client(self) -> None:
        result = get_nixpkgs_equivalent("docker")
        assert result is not None
        assert result.attr_name == "docker-client"
        assert result.note is not None
        assert "Linux-only" in result.note


class TestIdentityFallback:
    def test_unrecognized_but_plausible_formula(self) -> None:
        assert get_nixpkgs_equivalent("ripgrep") == NixpkgsEquivalent("ripgrep")

    def test_completely_unknown_formula(self) -> None:
        assert get_nixpkgs_equivalent("some-brand-new-formula") == NixpkgsEquivalent("some-brand-new-formula")


class TestNoNixpkgsEquivalent:
    def test_nvm_is_none(self) -> None:
        assert get_nixpkgs_equivalent("nvm") is None

    def test_tfenv_is_none(self) -> None:
        assert get_nixpkgs_equivalent("tfenv") is None

    def test_xcbeautify_is_none(self) -> None:
        assert get_nixpkgs_equivalent("xcbeautify") is None

    def test_cocoapods_is_none(self) -> None:
        assert get_nixpkgs_equivalent("cocoapods") is None

    def test_fastlane_is_none(self) -> None:
        assert get_nixpkgs_equivalent("fastlane") is None

    def test_mint_is_none(self) -> None:
        assert get_nixpkgs_equivalent("mint") is None

    def test_xclogparser_is_none(self) -> None:
        assert get_nixpkgs_equivalent("xclogparser") is None

    def test_xcodegen_is_none(self) -> None:
        assert get_nixpkgs_equivalent("xcodegen") is None

    def test_xcresultparser_is_none(self) -> None:
        assert get_nixpkgs_equivalent("xcresultparser") is None


class TestIsUnnecessaryInNix:
    def test_version_manager_formula(self) -> None:
        assert is_unnecessary_in_nix("pyenv") is True

    def test_non_version_manager_formula(self) -> None:
        assert is_unnecessary_in_nix("ripgrep") is False

    def test_all_version_managers_flagged(self) -> None:
        for formula in VERSION_MANAGER_FORMULAE:
            assert is_unnecessary_in_nix(formula) is True


class TestBrewToNixpkgsTableIntegrity:
    def test_none_entries_are_deliberate_not_missing_keys(self) -> None:
        """Explicit None values differ from an absent key: absent keys fall
        through to the identity rule, while None entries are terminal."""
        none_entries = {name for name, value in BREW_TO_NIXPKGS.items() if value is None}
        assert none_entries == {
            "nvm",
            "tfenv",
            "xcbeautify",
            "cocoapods",
            "fastlane",
            "mint",
            "xclogparser",
            "xcodegen",
            "xcresultparser",
        }
