package dev.reachlayer.evals;

import static org.assertj.core.api.Assertions.assertThatCode;

import dev.reachlayer.core.pipeline.Orchestrator;
import dev.reachlayer.core.spi.ScanSource;
import dev.reachlayer.evals.fixtures.NeverFailScenarios;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Regression guard for PLAN.md §2 principle 1 ("never fail or block the build") at the
 * orchestration level, exercised against each adversarial wiring in {@link NeverFailScenarios}: a
 * connector whose {@code ingest()} always throws, each pipeline stage always throwing, an output
 * renderer whose {@code render()} always throws, and everything broken at once.
 *
 * <p>{@link Orchestrator} already wraps every stage/renderer in its own try/catch (see {@code
 * safeStage} and {@code renderAll} in {@code Orchestrator}), so every scenario here is expected to
 * PASS today. These tests exist to catch a *future* regression that removes that protection, not
 * to fix a current bug.
 */
class NeverFailBuildInvariantTest {

    @TestFactory
    List<DynamicTest> orchestratorNeverLetsAnExceptionEscape() {
        Map<String, Orchestrator> scenarios = NeverFailScenarios.scenarios();
        return scenarios.entrySet().stream()
                .map(entry -> DynamicTest.dynamicTest(
                        entry.getKey(),
                        () -> assertThatCode(() -> entry.getValue()
                                        .run(List.of(ScanSource.ofPath(Path.of("test/repo"))), "test/repo"))
                                .as(
                                        "Orchestrator.run must never let an exception escape when '%s' "
                                                + "(PLAN.md principle 1: never fail or block the build)",
                                        entry.getKey())
                                .doesNotThrowAnyException()))
                .toList();
    }
}
