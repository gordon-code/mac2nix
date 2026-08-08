# Builds arekinath/PivApplet (MPL-2.0, confirmed via the
# `Copyright (c) 2017, Alex Wilson` header in PivApplet.java -- no repo-root
# LICENSE file exists, but the per-file header is a real, sufficient grant)
# from source.
#
# PivApplet's GitHub Releases publish pre-built .cap files, but those are
# packaged for installation onto a real card (or a jcardsim configured with
# its commercial GlobalPlatform card-manager module) via GlobalPlatformPro's
# `gp.jar --install`. The free/open-source jcardsim this project uses
# (jcardsim.nix) doesn't carry that card-manager applet -- its own
# jcardsim.cfg loads an applet directly by Java class name
# (com.licel.jcardsim.card.applet.0.Class=net.cooperi.pivapplet.PivApplet),
# which needs PivApplet's raw compiled .class files, not a packaged .cap.
# This is the exact recipe PivApplet's own test setup uses (test/jcardsim.cfg,
# `ant` then `java -cp bin/:...`), not a mac2nix-invented alternative.
#
# Uses JavaCard Classic Development Kit 2.2.2 (a different kit version than
# jcardsim.nix's 3.0.5 -- PivApplet's own README specifies JC_HOME pointing
# at a 2.2.2 kit), from the same martinpaljak/oracle_javacard_sdks mirror
# jcardsim.nix already uses and documents the trade-off for.
{
  lib,
  fetchFromGitHub,
  stdenv,
  jdk8,
  ant,
}:
let
  jc222Kit = fetchFromGitHub {
    owner = "martinpaljak";
    repo = "oracle_javacard_sdks";
    rev = "6a75ec0d6913db236d354f154df7dbc9573d976d";
    hash = lib.fakeHash;
    sparseCheckout = [ "jc222_kit" ];
  };
in
stdenv.mkDerivation {
  pname = "pivapplet";
  version = "unstable-2026-08-08";

  src = fetchFromGitHub {
    owner = "arekinath";
    repo = "PivApplet";
    rev = "5cb14a9e8d16e92fbad73dcad86a219a9210554f";
    # ext/ant is a git submodule (martinpaljak/ant-javacard) -- needed to
    # build (build.xml's `dist` target runs `<ant dir="ext/ant"/>` first).
    # ext/jpp-1.0.3.jar (the other build-time tool build.xml needs) is a
    # plain committed file, not a submodule, so a normal fetch already
    # includes it.
    fetchSubmodules = true;
    hash = lib.fakeHash;
  };

  nativeBuildInputs = [
    jdk8
    ant
  ];

  JC_HOME = "${jc222Kit}/jc222_kit";

  # build.xml's `dist` target builds ext/ant (ant-javacard) first, then
  # preprocesses+compiles+packages the applet -- see build.xml's own
  # `dist`/`preprocess` targets. Real network access to Maven Central
  # (ant-javacard's own build dependency) is required and not available in
  # this project's dev sandbox -- see jcardsim.nix's identical note.
  buildPhase = ''
    runHook preBuild
    ant dist
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r bin/. $out/
    runHook postInstall
  '';

  meta = {
    description = "PIV applet for JavaCard (arekinath/PivApplet), built for jcardsim's direct class-loading mode";
    license = "MPL-2.0";
  };
}
