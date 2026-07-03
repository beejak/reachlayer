// Distinct from the root `dev.reachlayer` group: connectors:api, advisor:api, and output:api
// all share the leaf project name "api", so without a distinct group per module they'd all
// resolve to the identical default coordinate dev.reachlayer:api and Gradle would silently
// substitute one for another wherever more than one is on the same classpath at once (as in
// cmd, the first module to depend on all three simultaneously). This does not change this
// project's Gradle path — `project(":advisor:api")` references elsewhere are unaffected.
group = "dev.reachlayer.advisor"

// See connectors/api/build.gradle.kts for why archivesName must also be disambiguated (jar
// filename comes from archivesName, not group).
base.archivesName.set("advisor-api")

dependencies {
    api(project(":core"))
}
