val sootupVersion: String by rootProject.extra

dependencies {
    api(project(":core"))

    // SootUp: call-graph construction (CHA) over the app-under-analysis bytecode. Pinned to
    // 1.1.2 — verified directly against the published 1.1.2 API docs
    // (https://soot-oss.github.io/SootUp/v1.1.2/call-graph-construction/) and against the actual
    // 1.1.2 jars on Maven Central. Newer 1.3.0 removes the JavaProject/JavaProjectBuilder API used
    // here in favor of constructing a JavaView directly from a list of AnalysisInputLocations, and
    // 2.0.0 renames several artifacts (e.g. sootup.java.bytecode -> sootup.java.bytecode.frontend);
    // 1.1.2 is the version with a stable, documented, verified API surface for this MVP.
    implementation("org.soot-oss:sootup.core:$sootupVersion")
    implementation("org.soot-oss:sootup.java.core:$sootupVersion")
    implementation("org.soot-oss:sootup.java.bytecode:$sootupVersion") {
        // dex2jar/Android r8 are only needed for SootUp's .dex/.apk frontend, which this
        // module never uses (we only analyze plain JVM .class/.jar bytecode). Excluding
        // this avoids a transitive dependency on Google's Maven repo for an unused feature.
        exclude(group = "com.github.ThexXTURBOXx.dex2jar", module = "dex-tools")
    }
    implementation("org.soot-oss:sootup.callgraph:$sootupVersion")

    // ASM: used only for entry-point discovery (dev.reachlayer.reach.entrypoints), which needs to
    // read raw class/method/annotation structure but not a resolved type hierarchy. See the
    // class-level Javadoc on EntryPointScanner for the rationale over using SootUp's own
    // annotation model for this.
    implementation("org.ow2.asm:asm:9.10.1")

    // Real compiled bytecode to validate the end-to-end reachable/unreachable call-graph tagging
    // against (see ReachabilityTaggerFixtureIT).
    testImplementation(project(":fixtures:vulnerable-spring-app"))

    // Surfaces ReachabilityTagger's log.warn(...) diagnostics during tests (otherwise silently
    // dropped by the NOP slf4j binding) — this class degrades failures to UNKNOWN by design, so
    // seeing *why* is essential for debugging test failures here.
    val slf4jVersion: String by rootProject.extra
    testRuntimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}
