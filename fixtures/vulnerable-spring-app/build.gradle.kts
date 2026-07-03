dependencies {
    // Only for the MVC annotations (@RestController, @GetMapping, ...) to exist on compiled
    // .class files so dev.reachlayer.reach.entrypoints can discover them. This module is never
    // executed — no spring-boot-starter-web, no application context, no runtime. It exists purely
    // to be compiled into real bytecode that the reachability module's tests point SootUp at.
    implementation("org.springframework:spring-web:6.2.8")
}
