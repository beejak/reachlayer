package dev.reachlayer.fixtures.vulnapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately-vulnerable fixture controller used to validate the {@code reachability} module
 * end-to-end (PLAN.md §7, §10 step 4 and step 8).
 *
 * <p>{@link #reach()} is a genuine Spring MVC entry point — the class is annotated
 * {@code @RestController} and the method is annotated {@code @GetMapping} — that directly calls
 * {@link ReachableVulnerableComponent#unsafeMethod()}, simulating a vulnerable third-party
 * dependency method that IS reachable from the application's attack surface.
 *
 * <p>This module is never run (no {@code spring-boot-starter-web}, no application context, no
 * {@code main} method) — it exists only to be compiled into real bytecode for SootUp to analyze
 * statically.
 */
@RestController
public class VulnerableController {

    @GetMapping("/reach")
    public String reach() {
        return new ReachableVulnerableComponent().unsafeMethod();
    }
}
