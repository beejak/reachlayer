val jacksonVersion: String by rootProject.extra
val snakeyamlVersion: String by rootProject.extra

dependencies {
    api("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    api("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:$jacksonVersion")
    implementation("org.yaml:snakeyaml:$snakeyamlVersion")
}
