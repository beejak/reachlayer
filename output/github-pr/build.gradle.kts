val jacksonVersion: String by rootProject.extra

dependencies {
    implementation(project(":output:api"))
    implementation(project(":core"))
    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
}
