package dev.reachlayer.fixtures.corpusgen;

/**
 * A generated pair of synthetic scanner exports (Fortify FVDL XML + Black Duck JSON), plus the
 * finding counts each one contains, so callers/tests don't have to re-parse to know what to
 * expect. See {@link CorpusGenerator}.
 */
public record GeneratedCorpus(String fvdlXml, String blackDuckJson, int sastFindingCount, int scaFindingCount) {
}
