# Feature 004: Second Scan Engine

## Summary

The scanner runs one engine: a project-owned rule pack of regex, shell-AST, dependency
and JSON-pointer rules. This feature adds a second, independent engine —
[`cisco-ai-defense/skill-scanner`](https://github.com/cisco-ai-defense/skill-scanner),
Apache 2.0 — and makes the two engines' results separately attributable in the catalog,
the API and the UI.

The point is not more findings. A registry that flags everything is a registry whose
verdicts get ignored, which is worse than no scanner at all. The point is
**coverage that the rule pack structurally cannot reach**, **attribution** so a reviewer
knows which engine made a claim, and **a verdict that is never `clean` when an engine that
was supposed to run did not**.

## Why a second engine

The rule pack matches patterns the project's authors thought to write down. Its four
matchers (`shell-ast`, `regex`, `dep-manifest`, `schema-path`) share one blind spot: they
read the bundle as text and shell syntax. They cannot see

- a payload encoded as base64, hex, or unicode escapes, then decoded at run time;
- zero-width and bidirectional-override characters hiding instructions from a human
  reviewer while an agent still reads them;
- compiled Python (`.pyc`) shipped without source;
- dataflow from a credential read to a network write across function boundaries;
- known-malware byte signatures.

Cisco's engine covers those with four analyzers that need no API key and no network:
`static_analyzer` (YAML rules plus YARA), `bytecode_analyzer`, `pipeline_analyzer` and
`behavioral_analyzer` (AST dataflow). Published research on this ecosystem
([Snyk ToxicSkills](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/))
puts prompt injection in 36% of sampled skills and 91% of confirmed-malicious skills, with
obfuscation as the standard delivery method — the exact class the rule pack misses.

## Non-goals

- **No cross-engine correlation.** When both engines flag the same file, both findings are
  stored. Merging them into one "corroborated" finding is a scoring system, and a scoring
  system nobody calibrated is a way to hide findings. Out of scope.
- **No LLM, VirusTotal or Cisco AI Defense analyzer.** They need an API key and a network
  call. The scanner role reaches no network (principle II) and the engine service reaches
  none either.
- **No dynamic analysis.** Every Cisco analyzer this feature enables is static. Nothing
  from a bundle is executed, sourced, imported or evaluated, by us or by the engine.
- **Not a replacement.** The rule pack stays. It encodes this project's own policy
  (declared-capability comparison, expected-host sets) that a generic engine has no input
  for.

## Requirements

### Engine hosting

- **R1** The engine runs as its own service, from its own image, built from a Python base
  image with a pinned `cisco-ai-skill-scanner` version and no code this project writes.
  It serves the tool's own `skill-scanner-api` REST server.
- **R2** The engine service holds no database credential, no object-store credential and
  no identity credential, and its network denies egress. Its only reachable peer is the
  scanner role, over one port, on an internal compose network.
- **R3** The scanner role keeps its distroless image. No Python, no interpreter and no
  subprocess is added to any image this project builds.
- **R4** `docker compose up` brings the engine up with the rest of the stack, with no
  manual step (principle VI).

### Analysis

- **R5** The scanner submits the bundle it has already extracted and capped, re-serialised
  as a zip, to the engine's `/scan-upload`. It never hands the engine an object-store key,
  a URL, or a shared filesystem path.
- **R6** Every optional analyzer that would reach a network or an API key is sent
  explicitly false on every request. The request builder is the only place a toggle can be
  set, and a configuration that would enable one is a startup error, not a request-time
  decision.
- **R7** The engine's five severities map onto the schema's three: `critical` and `high`
  to `high`, `medium` to `medium`, `low` to `low`, `info` is dropped.
- **R8** A finding below the report threshold (default `medium`) is not stored as a
  finding. It is counted on the engine's check row as a warning. This is what keeps a
  version from being flagged by a pile of low-severity noise.

### Verdict integrity

- **R9** A scan whose engine did not complete is never recorded `clean`. When the engine
  is unreachable, errors, or times out, and retries are exhausted, the scan records a
  high-severity finding under rule id `ENG-UNAVAILABLE` and the version is `flagged`.
  A reviewer can override it like any other finding.
- **R10** `AGENT_MANAGER_SCAN_ENGINE_REQUIRED` (default true) selects that behaviour. Set
  false, an unavailable engine records a warning on the check row instead and the rule
  pack's verdict stands alone.
- **R11** The engine reports `findings_count`, `is_safe` and `max_severity` alongside the
  findings array. When those disagree with what this project parsed — a count above zero
  that yielded no mapped finding, or `is_safe: false` with nothing mapped — the scan is
  treated as degraded under R9. This is the guard against the engine's response shape
  changing under a version bump.

### Attribution

- **R12** `finding` and `scan_check` each carry an `engine` column. Existing rows are
  `rulepack`. The engine's rows are `skill-scanner`.
- **R13** The API exposes `engine` on a finding and on a check row. The findings list and
  the check matrix group by it, so a reviewer reads "the rule pack passed, the second
  engine failed" rather than one undifferentiated list.
- **R14** A finding's rule id is stored as the engine reported it. Ids are not rewritten
  or prefixed; the `engine` column is what disambiguates two engines using the same id.

### Reproducibility

- **R15** The scan fingerprint recorded on `scan.pack_version` — already
  `<declared>+<digest>` and already documented as opaque — is extended to cover every
  engine that ran, including the pinned engine version read from `/health`. Upgrading the
  engine therefore makes the next scan of an already-scanned version run rather than be
  suppressed by its own idempotency guard.
- **R16** Deploying this feature changes the fingerprint for every version in the catalog.
  Re-scanning is driven by the existing `rescan-sweep` job, not by a migration.

## Acceptance

1. A bundle carrying a base64-encoded `curl | sh` payload that the rule pack passes is
   flagged, with the finding attributed to `skill-scanner`.
2. A bundle the rule pack flags is still flagged with the engine stopped.
3. With the engine stopped and `SCAN_ENGINE_REQUIRED` true, a clean bundle is `flagged`
   with an `ENG-UNAVAILABLE` finding, not `clean`.
4. The same bundle scanned twice at one engine version records one scan row; after the
   pinned engine version changes, a second.
5. The engine service, given a shell in its container, cannot reach Postgres, MinIO or the
   internet.
6. A response whose `findings_count` disagrees with the mapped findings degrades the scan
   rather than recording it clean.
