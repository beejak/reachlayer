package dev.reachlayer.fixtures.vulnapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * A Spring MVC entry point whose body compiles to an {@code invokedynamic} call site bootstrapped
 * via {@code java.lang.invoke.StringConcatFactory} (default {@code javac} string-concatenation
 * strategy since Java 9) rather than {@code java.lang.invoke.LambdaMetafactory} — used to confirm
 * {@link dev.reachlayer.reach.callgraph.LambdaAwareChaAlgorithm} safely falls back to the stock
 * CHA algorithm's behavior (no call target, no crash) for {@code invokedynamic} sites that aren't
 * lambda/method-reference dispatch, rather than assuming every {@code invokedynamic} site is one.
 */
@RestController
public class StringConcatController {

    @GetMapping("/concat")
    public String concat(@RequestParam String name) {
        // Local-variable concatenation (not a compile-time constant) forces javac to emit a real
        // invokedynamic/StringConcatFactory call site rather than folding this at compile time.
        return "Hello, " + name + "!";
    }
}
