val slf4jVersion: String by rootProject.extra

dependencies {
    implementation(project(":core"))
    implementation(project(":reachability"))
    implementation(project(":connectors:api"))
    implementation(project(":connectors:fortify"))
    implementation(project(":connectors:blackduck"))
    implementation(project(":enrich:epss"))
    implementation(project(":enrich:kev"))
    implementation(project(":enrich:blastradius"))
    implementation(project(":scoring"))

    // Real compiled bytecode backing ReachabilityCorpus (dev.reachlayer.evals.fixtures). Unlike
    // reachability's own dependency on this fixture (testImplementation, since only its *test*
    // code touches it), ReachabilityCorpus lives in this module's *main* sourceSet — it's shared
    // by both the eval tests and EvalRunner.main() — and imports ReachableVulnerableComponent
    // directly (same resolution pattern as ReachabilityTaggerFixtureIT), so the dependency has to
    // be visible from main. Hence `implementation`, not `testImplementation`, here.
    implementation(project(":fixtures:vulnerable-spring-app"))

    // Surfaces ReachabilityTagger's log.warn(...) diagnostics during eval runs/tests (otherwise
    // silently dropped by the NOP slf4j binding) — see reachability/build.gradle.kts for the same
    // rationale. Deliberately `runtimeOnly`, not `testRuntimeOnly`: the `runEvals` JavaExec task
    // uses `sourceSets["main"].runtimeClasspath` (EvalRunner.main() lives in main, not test), so a
    // test-scoped dependency here would be invisible to it and diagnostics would go silently
    // missing during scoreboard generation specifically, even though they'd still show up in
    // `:evals:test`. No other module depends on `:evals`, so there's no consumer whose own slf4j
    // binding this could shadow.
    runtimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}

tasks.register<JavaExec>("runEvals") {
    group = "verification"
    description = "Regenerates evals/scoreboard.md"
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("dev.reachlayer.evals.EvalRunner")
    workingDir = rootProject.projectDir
}
