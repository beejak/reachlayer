# Security Policy

Reachlayer processes security scanner output (Fortify, Black Duck) and, when configured, calls
external APIs (EPSS, CISA KEV, the GitHub REST API, and optionally the Anthropic API). Taking
security issues in a security tool seriously is not optional.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security vulnerability. Instead:

1. Use GitHub's private vulnerability reporting for this repository (Security tab → "Report a
   vulnerability"), if enabled, or
2. Email the maintainers directly (see the repository's contact information on GitHub) with a
   description of the issue, steps to reproduce, and the potential impact.

We aim to acknowledge reports within a reasonable timeframe and will work with you on a
coordinated disclosure timeline before any public writeup.

## Scope

In scope:
- Vulnerabilities in Reachlayer's own code (the modules under this repository) — e.g. injection
  issues in the Fortify/Black Duck parsers, XXE in the FVDL XML parser, path traversal, secrets
  handling issues in the CLI or GitHub Action.
- Supply-chain concerns in this repository's own dependencies or build configuration.

Out of scope:
- Vulnerabilities in Fortify, Black Duck, GitHub, EPSS, CISA KEV, or Anthropic themselves —
  report those to the respective vendor.
- The inherent unsoundness of static reachability analysis (documented, expected, and not a
  security bug in Reachlayer — see `docs/reachability-caveats.md`). A finding Reachlayer tags
  `unreachable` that turns out to be reachable is a known, disclosed limitation, not a
  vulnerability report.

## Design-level security notes

- The `FvdlParser` (Fortify XML ingestion) disables DTD processing and external entity resolution
  to prevent XXE — see `connectors/fortify`'s `FvdlParserTest` for a test that verifies this.
- No real vendor scanner output is ever bundled in this repository or its test fixtures — see
  `PLAN.md` §9 risk #6 and `CONTRIBUTING.md`.
- Reachlayer never fails or blocks a build (a deliberate design principle, not a security
  guarantee) — see `README.md`'s design principles. This means Reachlayer itself cannot be used as
  a merge gate, which also means it cannot be the *sole* control against introducing a
  vulnerability; it is advisory triage context, not a security boundary.
