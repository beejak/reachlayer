val jacksonVersion: String by rootProject.extra

dependencies {
    implementation(project(":core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}
