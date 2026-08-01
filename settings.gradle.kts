rootProject.name = "reachlayer"

include(
    "core",
    "connectors:api",
    "connectors:fortify",
    "connectors:blackduck",
    "reachability",
    "enrich:epss",
    "enrich:kev",
    "enrich:blastradius",
    "scoring",
    "advisor:api",
    "advisor:providers:noop",
    "advisor:providers:anthropic",
    "output:api",
    "output:github-pr",
    "output:sarif",
    "cmd",
    "fixtures:vulnerable-spring-app",
    "fixtures:corpus-generator",
)

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        // Required transitively by org.soot-oss:sootup.java.bytecode (dex2jar/dex-tools).
        maven("https://jitpack.io")
    }
}
