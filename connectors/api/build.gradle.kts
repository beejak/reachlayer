// Distinct from the root `dev.reachlayer` group: connectors:api, advisor:api, and output:api
// all share the leaf project name "api", so without a distinct group per module they'd all
// resolve to the identical default coordinate dev.reachlayer:api and Gradle would silently
// substitute one for another wherever more than one is on the same classpath at once (as in
// cmd, the first module to depend on all three simultaneously). This does not change this
// project's Gradle path — `project(":connectors:api")` references elsewhere are unaffected.
group = "dev.reachlayer.connectors"

// The jar filename (used when packaging cmd's flat lib/ distribution) is derived from
// archivesName, not group — without this, connectors:api, advisor:api, and output:api would
// still all produce a file literally named "api-0.1.0-SNAPSHOT.jar", colliding when copied into
// the same directory even though their Gradle coordinates now differ.
base.archivesName.set("connectors-api")

dependencies {
    api(project(":core"))
}
