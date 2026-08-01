import com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar

val picocliVersion: String by rootProject.extra
val slf4jVersion: String by rootProject.extra

plugins {
    id("com.github.johnrengelman.shadow") version "8.1.1"
    application
}

dependencies {
    implementation(project(":core"))
    implementation(project(":connectors:api"))
    implementation(project(":connectors:fortify"))
    implementation(project(":connectors:blackduck"))
    implementation(project(":reachability"))
    implementation(project(":enrich:epss"))
    implementation(project(":enrich:kev"))
    implementation(project(":enrich:blastradius"))
    implementation(project(":scoring"))
    implementation(project(":advisor:api"))
    implementation(project(":advisor:providers:noop"))
    implementation(project(":advisor:providers:anthropic"))
    implementation(project(":output:api"))
    implementation(project(":output:github-pr"))
    implementation(project(":output:sarif"))

    implementation("info.picocli:picocli:$picocliVersion")
    runtimeOnly("org.slf4j:slf4j-simple:$slf4jVersion")
}

application {
    mainClass.set("dev.reachlayer.cli.Main")
}

tasks.named<ShadowJar>("shadowJar") {
    archiveBaseName.set("cmd")
    archiveClassifier.set("all")
    archiveVersion.set("")
    mergeServiceFiles()
}

tasks.named("build") {
    dependsOn(tasks.named("shadowJar"))
}
