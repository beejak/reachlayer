package dev.reachlayer.evals.fixtures;

import dev.reachlayer.core.model.BlastRadius;
import dev.reachlayer.core.model.Cvss;
import dev.reachlayer.core.model.Epss;
import dev.reachlayer.core.model.Finding;
import dev.reachlayer.core.model.FindingKind;
import dev.reachlayer.core.model.Reachability;
import java.util.List;
import java.util.Set;

/**
 * A small, hand-crafted set of six findings designed so naive CVSS-only sorting gets the fix
 * priority order visibly wrong, and Reachlayer's blended risk score (PLAN.md §8:
 * {@code base}/{@code exploit}/{@code reachMult}/{@code blastMult}, see {@code docs/scoring.md})
 * should get it right. Backs {@code RiskRankingEvalTest} and {@link
 * dev.reachlayer.evals.EvalRunner}.
 *
 * <p>The "ground truth" top-3 (see {@link #groundTruthTop3Ids()}) is a judgment call, not derived
 * from any formula — it represents what a careful security engineer would triage first given the
 * scenario story attached to each finding below. Reasoning is documented inline on {@link
 * #groundTruthTop3Ids()}.
 *
 * <p>Like {@link ReachabilityCorpus}, this scenario should only grow: a new hand-crafted case
 * belongs here whenever the scorer is found to mis-rank a realistic combination of signals.
 */
public final class RankingScenario {

    private RankingScenario() {}

    private static final String A_HIGH_CVSS_UNREACHABLE = "rank-a-high-cvss-unreachable";
    private static final String B_MODERATE_CVSS_REACHABLE_KEV = "rank-b-moderate-cvss-reachable-kev";
    private static final String C_HIGH_CVSS_REACHABLE_INTERNET = "rank-c-high-cvss-reachable-internet";
    private static final String D_LOW_CVSS_UNREACHABLE = "rank-d-low-cvss-unreachable";
    private static final String E_HIGH_CVSS_UNKNOWN_REACHABILITY = "rank-e-high-cvss-unknown-reachability";
    private static final String F_MEDIUM_CVSS_REACHABLE_PII_SECRETS = "rank-f-medium-cvss-reachable-pii-secrets";

    public static List<Finding> findings() {
        return List.of(
                // (a) Very high CVSS but UNREACHABLE and no exploit/blast-radius signal at all. A
                // naive CVSS-only sort puts this #1; nobody can actually reach the vulnerable code.
                Finding.builder()
                        .id(A_HIGH_CVSS_UNREACHABLE)
                        .source("synthetic")
                        .kind(FindingKind.SCA)
                        .cve(List.of("CVE-2024-0001"))
                        .severity("critical")
                        .cvss(new Cvss(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
                        .reachability(Reachability.UNREACHABLE)
                        .kev(false)
                        .blastRadius(BlastRadius.NONE)
                        .title("Deserialization RCE in an unused admin-only module")
                        .build(),

                // (b) Moderate CVSS but REACHABLE, KEV-listed (actively exploited in the wild), and
                // sitting on an internet-facing path that touches auth. Should be fixed first
                // despite a CVSS more than 4 points lower than (a).
                Finding.builder()
                        .id(B_MODERATE_CVSS_REACHABLE_KEV)
                        .source("synthetic")
                        .kind(FindingKind.SCA)
                        .cve(List.of("CVE-2024-0002"))
                        .severity("medium")
                        .cvss(new Cvss(5.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"))
                        .reachability(Reachability.REACHABLE)
                        .epss(new Epss(0.9, 0.9, "2026-06-30"))
                        .kev(true)
                        .blastRadius(new BlastRadius(true, true, false, false, List.of()))
                        .title("Auth-bypass in login filter, actively exploited (KEV)")
                        .build(),

                // (c) High CVSS, REACHABLE, internet-facing, with meaningful EPSS. Genuinely
                // dangerous by every signal at once.
                Finding.builder()
                        .id(C_HIGH_CVSS_REACHABLE_INTERNET)
                        .source("synthetic")
                        .kind(FindingKind.SCA)
                        .cve(List.of("CVE-2024-0003"))
                        .severity("critical")
                        .cvss(new Cvss(9.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"))
                        .reachability(Reachability.REACHABLE)
                        .epss(new Epss(0.5, 0.5, "2026-06-30"))
                        .kev(false)
                        .blastRadius(new BlastRadius(true, false, false, false, List.of()))
                        .title("Path traversal reachable from a public file-download endpoint")
                        .build(),

                // (d) Low CVSS, UNREACHABLE, no other signal. Correctly low priority under any
                // reasonable ordering — included so the scenario isn't just "high vs low CVSS".
                Finding.builder()
                        .id(D_LOW_CVSS_UNREACHABLE)
                        .source("synthetic")
                        .kind(FindingKind.SCA)
                        .cve(List.of("CVE-2024-0004"))
                        .severity("low")
                        .cvss(new Cvss(3.0, "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"))
                        .reachability(Reachability.UNREACHABLE)
                        .kev(false)
                        .blastRadius(BlastRadius.NONE)
                        .title("Minor info leak in a dead code path")
                        .build(),

                // (e) High CVSS but reachability UNKNOWN (call-graph analysis inconclusive) and no
                // exploit evidence. A naive CVSS sort ranks this above (f); a human triager would
                // place it behind confirmed-reachable findings that carry real exploit or
                // blast-radius evidence, since UNKNOWN is neither a confirmed path nor a signal.
                Finding.builder()
                        .id(E_HIGH_CVSS_UNKNOWN_REACHABILITY)
                        .source("synthetic")
                        .kind(FindingKind.SAST)
                        .cwe(List.of("CWE-89"))
                        .severity("high")
                        .cvss(new Cvss(8.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:N"))
                        .reachability(Reachability.UNKNOWN)
                        .kev(false)
                        .blastRadius(BlastRadius.NONE)
                        .title("Possible SQL injection, reachability inconclusive")
                        .build(),

                // (f) Only moderate CVSS but REACHABLE, with real (if partial) exploit evidence and
                // a path that touches PII and secrets. Naive CVSS sorting buries this below (a) and
                // (e); Reachlayer's blast-radius + exploit weighting should surface it well above
                // both.
                Finding.builder()
                        .id(F_MEDIUM_CVSS_REACHABLE_PII_SECRETS)
                        .source("synthetic")
                        .kind(FindingKind.SCA)
                        .cve(List.of("CVE-2024-0005"))
                        .severity("medium")
                        .cvss(new Cvss(6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"))
                        .reachability(Reachability.REACHABLE)
                        .epss(new Epss(0.3, 0.3, "2026-06-30"))
                        .kev(false)
                        .blastRadius(new BlastRadius(false, false, true, true, List.of()))
                        .title("Credential-logging bug reachable from a background job")
                        .build());
    }

    /**
     * Hand-labeled "top 3 that actually matter" for this scenario.
     *
     * <p>Reasoning: (b), (c), and (f) are all confirmed {@code REACHABLE} and each carries at
     * least one independent real-world signal beyond raw CVSS — KEV membership, meaningful EPSS,
     * or exposure of auth/PII/secrets. (a) is excluded despite having the highest CVSS because it
     * is {@code UNREACHABLE}: no code path exists to trigger it, the textbook case naive
     * CVSS-sorting gets wrong. (e) is excluded despite a high CVSS because its reachability is
     * {@code UNKNOWN} and it has no corroborating exploit evidence, so a careful triager would not
     * rank it above three findings with confirmed reachability and real signal. (d) is excluded as
     * genuinely low priority (low CVSS, {@code UNREACHABLE}, no signal at all).
     */
    public static Set<String> groundTruthTop3Ids() {
        return Set.of(
                B_MODERATE_CVSS_REACHABLE_KEV, C_HIGH_CVSS_REACHABLE_INTERNET, F_MEDIUM_CVSS_REACHABLE_PII_SECRETS);
    }
}
