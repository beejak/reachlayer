// Generates larger, varied synthetic Fortify FVDL + Black Duck JSON corpora for the evaluation
// pipeline (see docs/evaluation-pipeline.md). Deliberately dependency-light for main code -- it
// only builds XML/JSON strings, no parsing. Test-time dependencies on the real connectors verify
// generated output actually round-trips through them without error.
dependencies {
    testImplementation(project(":connectors:fortify"))
    testImplementation(project(":connectors:blackduck"))
    testImplementation(project(":core"))
}
