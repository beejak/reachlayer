val woodstoxVersion: String by rootProject.extra

dependencies {
    api(project(":core"))
    implementation(project(":connectors:api"))
    implementation("com.fasterxml.woodstox:woodstox-core:$woodstoxVersion")
}

// Synthetic fixtures live at the repo root (fixtures/) so they're shared/reviewable in one
// place; expose them on this module's test classpath rather than duplicating the files.
sourceSets {
    test {
        resources {
            srcDir(rootProject.file("fixtures/sample-fpr"))
        }
    }
}
