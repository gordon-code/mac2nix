# Builds arekinath's jcardsim fork (Apache-2.0, confirmed via its pom.xml's
# <licenses> block -- GitHub's repo-level license detector finds nothing here,
# but the license is real).
#
# jcardsim's own pom.xml declares oracle.javacard:api_classic as a compile
# dependency, installed via `mvn install-file` from a real Oracle JavaCard
# Development Kit -- not resolvable from any public Maven repo, and Oracle's
# license doesn't permit redistributing that SDK freely. This derivation uses
# martinpaljak/oracle_javacard_sdks, the de facto mirror the open-source
# JavaCard community already relies on for exactly this problem (PivApplet's
# own build tooling, ant-javacard, points people at the same mirror) --
# accepted as a real, documented trade-off, not a silent workaround.
#
# Built with jdk8 explicitly: jcardsim's pom.xml targets java.version 1.7,
# which modern JDKs (9+) refuse to compile for. The separate `integration-test`
# phase (maven-antrun-plugin, needing tools.jar -- removed in JDK 9+) is never
# reached, since buildMavenPackage's default `package` goal stops before that
# lifecycle phase.
{
  lib,
  fetchFromGitHub,
  fetchurl,
  maven,
  jdk8,
}:
let
  apiClassicJar = fetchurl {
    url = "https://raw.githubusercontent.com/martinpaljak/oracle_javacard_sdks/6a75ec0d6913db236d354f154df7dbc9573d976d/jc305u4_kit/lib/api_classic.jar";
    hash = "sha256-xDCNvuGS3D8SUJEhZg0HG0b6vUQjxL+XFH4DnB0WLtg=";
  };

  installApiClassic = ''
    mvn -B install:install-file \
      -Dfile=${apiClassicJar} \
      -DgroupId=oracle.javacard \
      -DartifactId=api_classic \
      -Dversion=3.0.5 \
      -Dpackaging=jar \
      -Dmaven.repo.local=$out/.m2
  '';
in
maven.buildMavenPackage {
  pname = "jcardsim";
  version = "3.0.5-SNAPSHOT-mac2nix";

  src = fetchFromGitHub {
    owner = "arekinath";
    repo = "jcardsim";
    rev = "4c766cfb48c43507f9a30a1443e7214d2073a430";
    hash = "sha256-0akp8BAp6QxGuBrDFEg0ED/F98bCkO2WQSocYqWszyI=";
  };

  mvnJdk = jdk8;
  mvnGoal = "package";
  doCheck = false;

  # api_classic must already be in the local repo before the dependency
  # prefetch's own `mvn package` runs, or that prefetch itself fails outright
  # trying (and failing) to resolve it from a real repo.
  mvnFetchExtraArgs = {
    preBuild = installApiClassic;
  };
  # [ASSUMPTION: verify on first real build] lib.fakeHash is a deliberate
  # placeholder, not an oversight -- this project's own dev sandbox has no
  # network route to repo.maven.apache.org (confirmed: github.com/
  # cache.nixos.org fetches all work fine from here; Maven Central does
  # not, even with the build sandbox disabled, so the restriction sits
  # below Nix's own sandboxing). Any environment with real network access
  # (CI, a Tart VM) will report the correct hash on first build via Nix's
  # standard "hash mismatch: got sha256-..." error -- replace this value
  # with that real hash once available, the same way vpcd.nix's and
  # pivapplet.nix's hashes were already verified for real in this session.
  mvnHash = lib.fakeHash;

  meta = {
    description = "Pure-Java Card Runtime simulator (arekinath fork, vpcd-enabled)";
    license = "Apache-2.0";
  };
}
