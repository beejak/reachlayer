package dev.reachlayer.fixtures.vulnapp;

import java.util.function.Supplier;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Deliberately-vulnerable fixture controller, structurally like {@link VulnerableController}
 * except that the discovered Spring MVC entry point dispatches to
 * {@link LambdaVulnerableComponent#unsafeMethod()} through a {@link Supplier} lambda rather than a
 * direct method call — see {@code docs/reachability-caveats.md}'s invokedynamic/lambda gap note,
 * which this fixture exists to reproduce (or disprove).
 */
@RestController
public class LambdaDispatchController {

    @GetMapping("/lambda-reach")
    public String reachViaLambda() {
        Supplier<String> supplier = () -> new LambdaVulnerableComponent().unsafeMethod();
        return supplier.get();
    }
}
