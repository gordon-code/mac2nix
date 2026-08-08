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
  fetchFromGitHub,
  fetchurl,
  maven,
  jdk8,
  runCommand,
}:
let
  apiClassicJar = fetchurl {
    url = "https://raw.githubusercontent.com/martinpaljak/oracle_javacard_sdks/6a75ec0d6913db236d354f154df7dbc9573d976d/jc305u4_kit/lib/api_classic.jar";
    hash = "sha256-xDCNvuGS3D8SUJEhZg0HG0b6vUQjxL+XFH4DnB0WLtg=";
  };

  # jcardsim's own pom.xml has a maven-install-plugin execution bound
  # directly to the build lifecycle, reading `${env.JC_CLASSIC_HOME}/lib/
  # api_classic.jar` -- a real, on-disk directory shaped exactly like a JC
  # kit's own layout is what it actually needs, not a manually-run
  # `install:install-file` invocation (verified against a real build: a
  # separate manual install-file call put the jar in the local repo, but
  # left this pom-bound execution failing on the literal, unexpanded
  # "${env.JC_CLASSIC_HOME}" string, since the env var itself was never set).
  jcClassicHome = runCommand "jc-classic-home" { } ''
    mkdir -p $out/lib
    cp ${apiClassicJar} $out/lib/api_classic.jar
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
  env.JC_CLASSIC_HOME = "${jcClassicHome}";

  # Verified against a real build: Maven resolves a project's own
  # compile-scope dependencies before running that same build's phase-bound
  # plugin executions, so the pom-bound install-file execution (which
  # would otherwise satisfy oracle.javacard:api_classic) can never run in
  # time to help a single `mvn package` invocation compile itself -- this
  # is exactly why upstream's own documented build is two separate
  # invocations (`mvn initialize` then `mvn clean install`), not one.
  # `afterDepsSetup` is an existing extension point in buildMavenPackage's
  # own generated buildPhase (runs after the offline .m2 cache is staged,
  # before the real `mvn package`) -- this is that first `mvn initialize`
  # pass, scoped to the local repo copy the real build will use.
  afterDepsSetup = ''
    mvn initialize -Dmaven.repo.local=$mvnDeps/.m2
  '';

  # The dependency-prefetch derivation (fetchedMavenDeps) runs the full
  # `mvn package` goal too, in non-offline mode -- it hits the exact same
  # ordering problem, so it needs its own `mvn initialize` pass first,
  # against its own local repo path ($out/.m2, not $mvnDeps/.m2).
  mvnFetchExtraArgs = {
    env.JC_CLASSIC_HOME = "${jcClassicHome}";
    preBuild = ''
      mvn initialize -Dmaven.repo.local=$out/.m2
    '';
  };
  mvnHash = "sha256-LqPIhjDVFHjohWZXNd8lOgHK7AgRno6hkgByhuLtxzo="; # verified via a real build this session

  # buildMavenPackage has no default installPhase -- the shaded jar
  # (target/jcardsim-3.0.5-SNAPSHOT.jar, already replaced in place by the
  # shade plugin's first execution per the build log) is the one the
  # documented `-cp bin/:jcardsim-3.0.5-SNAPSHOT.jar` classpath usage
  # expects -- not the separate -android.jar the second shade execution
  # also produces, which is for a different (Android) target entirely.
  installPhase = ''
    mkdir -p $out/share/java
    cp target/jcardsim-3.0.5-SNAPSHOT.jar $out/share/java/
  '';

  meta = {
    description = "Pure-Java Card Runtime simulator (arekinath fork, vpcd-enabled)";
    license = "Apache-2.0";
  };
}
