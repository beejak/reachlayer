plugins {
    java
}

// Centralized dependency versions. Kept simple (no version catalog) since the
// module count is small enough that this stays readable.
object Versions {
    const val jackson = "2.17.2"
    const val woodstox = "6.6.2"
    const val picocli = "4.7.6"
    const val junit = "5.10.3"
    const val slf4j = "2.0.13"
    const val sootup = "1.1.2"
    const val snakeyaml = "2.2"
}

allprojects {
    group = "dev.reachlayer"
    version = "0.1.0-SNAPSHOT"

    repositories {
        mavenCentral()
        // Required transitively by org.soot-oss:sootup.java.bytecode (dex2jar/dex-tools).
        maven("https://jitpack.io")
    }
}

subprojects {
    apply(plugin = "java-library")

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    tasks.withType<JavaCompile>().configureEach {
        options.encoding = "UTF-8"
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        // SootUp's CHA call-graph construction over the full JDK runtime image (reachability
        // module's fixture IT) is memory-hungry; Gradle's default test worker heap (512m) OOMs.
        maxHeapSize = "2g"
        testLogging {
            events("passed", "skipped", "failed")
            exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
        }
    }

    dependencies {
        val implementation by configurations
        val testImplementation by configurations
        val testRuntimeOnly by configurations

        implementation("org.slf4j:slf4j-api:${Versions.slf4j}")

        testImplementation("org.junit.jupiter:junit-jupiter:${Versions.junit}")
        testImplementation("org.junit.jupiter:junit-jupiter-params:${Versions.junit}")
        testRuntimeOnly("org.junit.platform:junit-platform-launcher")
        testImplementation("org.assertj:assertj-core:3.26.3")
    }
}

// Expose versions to subprojects via extra properties so their build.gradle.kts
// files can reference `rootProject.extra["jacksonVersion"]` etc.
extra["jacksonVersion"] = Versions.jackson
extra["woodstoxVersion"] = Versions.woodstox
extra["picocliVersion"] = Versions.picocli
extra["junitVersion"] = Versions.junit
extra["slf4jVersion"] = Versions.slf4j
extra["sootupVersion"] = Versions.sootup
extra["snakeyamlVersion"] = Versions.snakeyaml
