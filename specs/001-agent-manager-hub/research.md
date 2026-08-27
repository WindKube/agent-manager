# Phase 0 Research — Agent Manager

**Feature**: `001-agent-manager-hub` | **Date**: 2026-08-27

Thirteen open questions from `plan.md`. Each resolved with a decision, a rationale, and
what was rejected. R1 is load-bearing — it changes requirements in `spec.md`.

---

## R1. The real package specs, and what they do not contain

**Decision**: Both specs are real and current, and **both manifests shown in the design are
non-conformant**. Validate against the published schemas; rewrite the seed fixtures; and
**change the capability model from *declared* to *inferred*.**

Agent Plugins 1.0.0 (`agentplugins/agent-plugins-spec`, shipped 2026-08-06, CC-BY-4.0 spec
/ Apache-2.0 code) defines `plugin.json` as:

```
$id:      https://agent-plugins.org/schemas/1.0.0/plugin.schema.json
required: $schema, name
permitted: $schema, name, version, description, author{name,email,url},
           homepage, repository, license, keywords[], extensions{}
additionalProperties: false
```

Ten fields, closed set. `extensions` is keyed by reverse-domain namespace and the spec
states it "assigns no semantics to namespace object contents". Schema 1.1.0 has an
**identical** plugin field set, and — corrected by diffing the vendored copies — an
**identical** `mcp.json` too: both files differ between the two versions only in the `$id`,
the `const` on `$schema` and the version named in the prose `description`, and 1.0.0's
`mcp.schema.json` already requires `{$schema, mcpServers}`. See
`internal/domain/pkgspec/schemas/PROVENANCE.md`.

Agent Skills (`agentskills.io`) defines `SKILL.md` frontmatter with required `name` and
`description`, optional `license`, `metadata`, `compatibility`, and an **experimental**
`allowed-tools`. Keys outside that set fail validation. Critically, the spec says
`allowed-tools` "grants pre-approval for the listed tools but does not block others" — it
is not an enforcement mechanism.

What the design shows and the specs do not have:

| Design manifest field | Reality |
| --- | --- |
| `agentPluginsVersion`, `publisher`, `components`, `signature` | rejected — `additionalProperties: false` |
| `spec: "openplugin/v1"`, `providers`, `entry` | rejected; not the standard at all |
| `network: {allow: [...]}` | **no such concept in either spec** |
| `filesystem: {read: [...], write: [...]}` | **no such concept in either spec** |

**Consequence — the capability model inverts.** The design's "Declared capabilities" panel
and FR-027's "compare hosts against the manifest's declared allowlist" both assume a
manifest that declares permissions. No conformant manifest can. So:

- Capabilities become **inferred by the scanner** from static analysis: hosts from the
  shell AST and from URLs in instruction files; filesystem scope from read/write targets
  in scripts; shell capability from the presence and shape of commands.
- The catalog stores an **expected** capability set, written by the publisher at
  registration or by a reviewer, under this project's own reverse-domain key in the
  spec-sanctioned `extensions` field (`extensions["dev.agent-manager"]`). That is
  conformant, and it is the only place the spec permits us to put it.
- A finding is then **inferred ≠ expected**, which is a strictly better control than
  "author's claim ≠ author's behaviour". A self-declared allowlist is worthless as
  security anyway: whoever writes the payload writes the manifest.

`signature` likewise has no manifest home; it becomes registry-side metadata
(`signature.sig` beside the bundle, plus a row), not a manifest field. See R9.

**Rationale**: conforming to a published, multi-vendor standard is the entire value of the
catalog. A registry that only accepts manifests its own mockup invented would reject every
real plugin on day one.

**Alternatives rejected**: (a) implement the design's manifest verbatim — produces a
registry incompatible with every conformant plugin; (b) accept both shapes — doubles the
validation surface and lets non-conformant packages in through a permanent side door;
(c) drop the capabilities screen — it is the most valuable review surface in the product,
and inference makes it *more* trustworthy, not less.

**Spec changes required**: FR-004 (schema references), FR-016–FR-019 (inferred vs.
declared), FR-027 (compare against expected set, not manifest), FR-048 (signature is
registry-side). The design's seed manifests get rewritten to conformant ones.

---

## R2. Rule-pack format

**Decision**: YAML, one document per rule, versioned as a whole with a `packVersion` that
is recorded on every scan. A rule is:

```yaml
id: SH-NET-002
severity: high
check: network-allowlist          # which registered Check consumes this rule
title: Undeclared network egress
detail: |                          # prose shown in the finding pane
  ...
match:
  kind: shell-ast                  # shell-ast | regex | schema-path | dep-manifest
  command: [curl, wget, http, httpie]
  extract: url-argument            # named extractor -> the evidence host
  condition: host-not-in-expected  # named predicate over the inferred/expected sets
evidence:
  quote: matched-node              # matched-node | matched-line | schema-error
fixtures:
  trips:     scan/fixtures/SH-NET-002/hostile
  clean:     scan/fixtures/SH-NET-002/benign
```

`match.kind` selects a registered matcher; `command`/`extract`/`condition` are the
matcher's own vocabulary. Rules never contain executable logic — a new *class* of
detection is a new Go matcher plus a `kind`; a new *instance* is a YAML file.

The four seeded rules map cleanly: `SH-NET-002` → `shell-ast`; `SH-INJ-011` → `regex` over
instruction files; `SH-DEP-004` → `dep-manifest` with a `version-unpinned` condition;
`SH-FS-007` → `schema-path` over the expected-capability document.

**Rationale**: satisfies SC-010 (new rule with no rebuild) while keeping the bug-prone part
— AST walking, extraction — in tested Go rather than in a config DSL that grows into a
programming language.

**Alternatives rejected**: CEL or Rego expressions per rule (a whole evaluation runtime and
a second language to debug, for four rules); rules as Go functions (fails SC-010); regex-only
(cannot express "curl to a host absent from the expected set" without false positives on
comments and strings).

---

## R3. Extraction caps

**Decision**, all configurable, these as defaults:

| Cap | Value | Why this number |
| --- | --- | --- |
| Compressed upload | 25 MB | The design states it. |
| Total decompressed | 250 MB | 10:1 over the upload cap. Real plugin trees are text; anything past this is not a plugin. |
| Compression ratio | 100:1, checked continuously | A 25 MB zip bomb expands to gigabytes. Ratio is checked as bytes stream, not after. |
| Entry count | 10,000 | The largest seeded plugin has ~30 files. Three orders of headroom. |
| Single entry | 25 MB | No individual file in a plugin needs more; caps the decompression-bomb-in-one-member case. |
| Path depth | 32 | `skills/x/references/y/z` is depth 5. |
| Path length | 1,024 bytes | Below every filesystem limit we might later write to. |
| Extraction wall-clock | 60 s | Bounds a pathological archive that passes every size check. |

Rejected outright regardless of caps: absolute paths, any `..` component after cleaning,
symlinks, hardlinks, device/FIFO members, and duplicate paths within one archive.

**Rationale**: these are security parameters, so each gets a stated reason rather than a
round number. The ratio check is the one that actually stops bombs — a size cap alone lets
a 24 MB archive consume 249 MB before it trips.

**Alternatives rejected**: trusting the archive's declared sizes (attacker-controlled);
extracting to a temp dir and measuring after (the bomb has already landed).

---

## R4. Catalog query shape

**Decision**: two round trips issued concurrently — one for the filtered page, one for the
facet counts. Indexes: GIN on `tags text[]`, GIN on the `tsvector` search column, btree on
`(category)`, `(verdict)`, `(uses DESC)`, `(updated_at DESC)`.

The two queries run against the **base tables**, not against `catalog_entry`. R12 makes that
projection conditional on a measurement, and the measurement passed without it: p95 14.2 ms
at 10,000 packages / 50,000 versions against SC-003's 300 ms budget. `catalog_entry` does not
exist and principle VIII's single-projection allowance is unspent. Two of the indexes above
also turn out not to be reached at that size — see the note in
`internal/api/queries/catalog_bench_integration_test.go` on why the planner is right to
seq-scan `version` for a tag filter.

Facet counts follow the way each facet **combines**, and the two facets combine differently
(FR-013), so one blanket rule is wrong for one of them:

- **Categories are disjunctive (OR).** Each option is counted with the **category filter
  removed** and every other filter kept — the standard disjunctive-facet semantic. Selecting
  a second category can only widen the result set, so a count that ignored the current
  category selection is exactly what the reader will get by clicking.
- **Tags are conjunctive (AND).** Each option is counted **against the current result set**,
  filters and all — a drill-down count. Removing the tag facet's own filter here would
  overstate every option by the intersection the reader is about to lose: with `aws`
  selected, `terraform` would advertise every package carrying `terraform` rather than the
  ones carrying both, and clicking it would return fewer rows than the menu promised.

The rule for both is therefore "count what selecting this option would actually yield". For a
disjunctive facet that means dropping its own filter; for a conjunctive one it means keeping
it. This was originally written as own-filter-removed for both; the tags half was wrong.

**Rationale**: one round trip forces either a `GROUPING SETS` monster or counting in Go over
a full scan. Two concurrent queries are simpler, independently cacheable, and the latency
is `max()` not `sum()`.

**Alternatives rejected**: `GROUPING SETS` in one statement (unreadable, and it recomputes
the page); counting in the application (unbounded memory at 10k packages); a search engine
(a second datastore for a workload Postgres handles at this scale — see SC-003).

---

## R5. Outbox relay

**Decision**: an `outbox` table in the application database, written in the same
transaction as the mutation. A relay goroutine hosted in the **api** role drains it:
`LISTEN outbox_new` for latency, plus a 10-second sweep so a missed notification costs
seconds rather than forever. Rows are claimed with `FOR UPDATE SKIP LOCKED`, inserted into
River, then marked done; delivered rows are pruned after 24 hours.

Delivery is **at-least-once**. Idempotency key is `(job_kind, subject_id, subject_version)`
persisted on the job's target row, not in the queue: a `fetch` for a version that already
has committed bytes is a no-op, a `scan` for a version that already has a scan at the
current `packVersion` is a no-op.

River's periodic jobs (the rescan policy) live entirely in the queue database and enqueue a
`rescan-sweep` job; that job reads the application database through the normal path and
writes its fan-out to the outbox like anything else.

**Rationale**: principle IX requires the guarantee that separate databases removed. The
relay in `api` rather than a fourth role keeps the deployable count where the design put it
and puts the relay next to the transactions that feed it.

**Alternatives rejected**: enqueue directly after commit (the classic dual-write bug — a
crash between commit and enqueue silently loses the scan); a dedicated relay role (a fifth
container for a goroutine); logical decoding / CDC (an operational dependency far heavier
than the problem).

---

## R6. Local IdP device-flow and groups parity — RESOLVED BY MEASUREMENT

**Original decision**: Dex, with verification owed on two points — that the device
authorisation grant is enabled, and that `groups` appears in the ID token for a
*static-password* user, since a static connector's claim support has historically lagged its
OIDC connector.

**Measured 2026-08-27 against real containers. Dex fails the second point, so the stated
fallback is taken: the local IdP is Keycloak.**

| | Dex v2.44.0 | Keycloak 26.5 |
| --- | --- | --- |
| `device_authorization_endpoint` advertised | yes | yes |
| `device_code` in `grant_types_supported` | yes | yes |
| `groups` in `scopes_supported` | yes | — |
| **`groups` claim in the ID token, static/local user** | **no** | **yes** |
| **`groups` differs per user** | n/a | yes — `['eng-platform']` vs `['eng-security']` |
| Startup to a live discovery document | ~2 s | 9 s |

Dex's `staticPasswords` entries carry `email`, `hash`, `username` and `userID` and no groups
field. Adding `groups: [...]` is accepted without warning and **silently ignored** — Dex logs
nothing and starts normally, so it fails as a missing claim at run time rather than as a
config error at boot. Requesting `scope=openid email groups profile` returns an ID token with
`iss/sub/aud/exp/iat/at_hash/email/email_verified/name` and no `groups`.

That makes FR-037's group→role mapping and the quickstart's "log in as anowak and step 4
returns a different set" impossible to demonstrate locally, because the claim is the input to
`group_role_map`. 9 seconds is well inside SC-001's five-minute budget, and Keycloak needs one
realm-import JSON, no cloud account and no credential anyone has to obtain — so SC-001 still
holds in full and the concern that made Dex attractive does not materialise.

**Consequence for the code**: Keycloak's frontchannel URLs (`issuer`, authorisation, device)
must be browser-reachable and its backchannel URLs (token, JWKS) container-reachable, and one
`KC_HOSTNAME` cannot be both. `KC_HOSTNAME_BACKCHANNEL_DYNAMIC=true` derives the backchannel
URLs from the request's Host header and leaves `issuer` alone; go-oidc then needs
`oidc.InsecureIssuerURLContext` because it otherwise refuses a document whose `issuer`
differs from the URL it was fetched from. Hence `AGENT_MANAGER_OIDC_DISCOVERY_URL`, and the
`iss` claim is still checked against `AGENT_MANAGER_OIDC_ISSUER`.

**Rationale unchanged**: FR-056 requires the device flow to work with no external account.
Testing the CLI path against a mocked token endpoint would leave the real path unexercised
until staging.

**Alternatives rejected**: Keycloak by default (slow start, heavy image, more config for the
same coverage); a hand-rolled OIDC stub (tests our own bugs, not the protocol).

---

## R7. Datastar interaction budget

**Decision**: **Proven before any other UI work begins.** The first UI task is a spike of
the catalog's typeahead-filtered multi-select facet with live counts — the hardest
interaction in the design — and it gates the rest of the frontend.

Approach: facet menu open/close and checkbox state live in datastar signals client-side; a
debounced (150 ms) SSE round trip re-renders the result table and the counts. The option
list is filtered client-side from a payload sent when the menu opens, so typing costs no
round trip.

**Exit criterion**: typing in the facet filter feels instant with 50 options, and toggling
a facet updates the table within 300 ms at seeded scale. If it does not, the fallback is
Alpine.js for local menu state with datastar retained for server-driven table updates —
still no npm, still no build step.

**Rationale**: this is the single decision that could be wrong in a way that costs a
rewrite. It is cheap now and expensive in week three.

**Alternatives rejected**: committing all ten screens first and discovering the ceiling
late; adding React for one widget (drags in the whole toolchain the stack was chosen to
avoid).

---

## R8. Usage counting

**Decision**: two distinct numbers, both derived, neither self-reported.

- **Uses** = `count(distinct profile)` containing the package. There is no people count
  beside it: a membership row can name a group, and neither the schema nor the OIDC claims
  record a group's size, so the design's "42 people across 4 profiles" cannot be produced
  from anything this system stores. Profiles is the number, and FR-009 says so.
  Aggregated per request in the catalog query — R12's measurement removed the
  `catalog_entry` refresh this line assumed.
- **Installs** = count of `sync_event` rows, written when a client fetches a resolved
  revision that contains the package. Aggregated by a nightly River job into a counter
  column.

No write occurs on a catalog read. A sync writes one `sync_event` per sync, not per
package; the per-package fan-out happens in the aggregation job.

**Rationale**: FR-050 already requires an audit row per sync, so the event exists. Counting
from it is free and honest; a counter incremented on read would both lie and add a write to
the hottest path.

**Alternatives rejected**: `UPDATE ... SET uses = uses + 1` on view (write amplification on
reads, and it measures curiosity rather than use); publisher-reported numbers (unverifiable,
and this is a governance tool).

---

## R9. Signature policy without verification

**Decision**: signatures are **registry-side metadata**, not manifest fields (R1). Each
version carries a nullable `signature` record: `{ref, kind, subject_digest, verified_at,
verified_by, result}`. `kind` is `none` today with `cosign-bundle` reserved.

The `require signed bundles` policy in this phase refuses publication of a version whose
`signature.ref` is absent. It does **not** claim cryptographic verification, and the UI
says exactly that: *"signature present, not verified"*. When `sigstore-go` lands it fills
`verified_at`/`result` on the same rows — no schema migration.

**Rationale**: the honest half-measure is a real control (it forces publishers to attach
something and makes the gap auditable). Rendering an unverified signature as a green tick
would be worse than having no signature feature at all.

**Alternatives rejected**: shipping the policy toggle as a no-op (a security control that
does nothing is a lie in the UI); blocking the whole feature on Sigstore (defers eight
other stories behind a rabbit hole).

---

## R10. `safeurl` behavioural parity

**Decision**: adopt `github.com/doyensec/safeurl`, **gated on a project-owned test suite**
that must pass before it is used anywhere:

1. Public hostname 302-redirecting to `http://127.0.0.1:8080` → refused at the hop.
2. Hostname resolving to both a public and a private address → refused.
3. Redirect to `http://169.254.169.254/latest/meta-data/` → refused.
4. DNS rebinding: a name that resolves public on first lookup and private on the connect →
   refused.
5. Non-HTTP schemes (`file://`, `gopher://`) → refused.
6. A legitimate public host → allowed, proving the control is not vacuous.

If any of 1–5 passes through, fall back to an owned ~60-line client using
`net.Dialer.Control`, which validates the address actually being connected to and therefore
re-runs on every hop and every address in a rotation.

**Rationale**: this capability used to be inherited from `go-modules/safefetch`. Dropping
that dependency means the behaviour is now this project's to prove, and the failure mode is
silent — an SSRF control that does not fire looks identical to one that does.

**Alternatives rejected**: trusting the library's README (test 6 exists precisely so we
notice a control that refuses everything); writing our own from the start (reinvents a
maintained library before knowing it is inadequate).

---

## R11. Atlas isolation

**Decision**: two databases (`agent_manager`, `river`), two connection URLs, two migration
tools. Atlas is pointed at `agent_manager` only and therefore *cannot* see River's tables —
the hazard is structural, not configured.

Still verified by a test: migrate River fully, run `atlas migrate diff`, assert the
generated migration is empty. That test also catches the reverse mistake of someone later
pointing both URLs at one database.

Compose runs two chained init containers:

```
postgres (healthy)
  └─> migrate-schema  (arigaio/atlas:latest-community-alpine, migrate apply)
        └─> migrate-queue  (agent-manager migrate queue — River's own migrator)
              └─> api, web, fetcher, scanner
```

`atlas migrate diff` needs a dev database (`docker://postgres/16/dev`) and therefore a
Docker socket; that is a developer-machine and CI concern. `atlas migrate apply` needs
neither, so the init container is plain.

**Rationale**: a diff-based tool with `DROP TABLE` in its vocabulary should not be able to
observe tables it does not own.

**Alternatives rejected**: one database with a `river` schema and Atlas scope exclusions
(preserves transactional enqueue, but one misconfigured `--schema` flag drops the queue);
Atlas managing River's schema too (couples our migration history to a dependency's).

---

## R12. Is the projection actually needed?

**Decision**: **Build it last and only on evidence.** Generate a 10k-package / 50k-version
dataset, run the R4 queries against the base tables with the stated indexes, and measure
p95. If it meets SC-003's 300 ms, the projection is **not built** and principle VIII's one
sanctioned projection stays unspent.

Rationale for the ordering: a projection is a permanent consistency liability — every
mutation path must remember to update it, forever. Postgres with a GIN index over 10k rows
is very likely fast enough; 10k rows is small. Adding the projection speculatively means
paying that tax for a problem that may not exist.

If it is needed, the rule from principle VIII binds: synchronous on structural change (a
new package appears instantly), asynchronous on verdict change (`Scanning` → `Clean` may
lag, which the design already renders as a visible state).

**Alternatives rejected**: building it up front (unfalsifiable — nobody removes a
projection once written); denormalising into the `packages` table (same tax, less
reversible).

---

## R13. `gocloud.dev/blob` escape hatches

**Decision**: `gocloud.dev/blob` for the data path — `s3blob` in production and compose,
`memblob` in unit tests, `fileblob` for a container-free dev mode. The Storage screen's
bucket-settings report (object lock, SSE-KMS, versioning, retention) uses
`bucket.As(&s3Client)` to reach the underlying `*s3.Client`; no second client is
constructed.

`internal/blob` wraps all of it and owns what gocloud does not model: the key layout from
the design, sha256 digesting on write, and **commit-last visibility** — bundle bytes,
manifest, scan report and signature are written to a staging prefix, then the `index.json`
pointer is written last. A version is visible only once that pointer names it, satisfying
FR-008 without needing transactional object storage.

**Verification owed**: confirm `memblob` is faithful enough for the bundle pipeline's unit
tests (it has no versioning and no object lock, which is fine — those are only read by the
admin path, which is integration-tested against MinIO).

**Rationale**: `memblob` removes a testcontainer from the inner loop, which is the single
biggest lever on test-suite speed here.

**Alternatives rejected**: `aws-sdk-go-v2/service/s3` directly (loses `memblob`, and the
Storage screen still needs the raw client either way, so gocloud costs nothing); MinIO's
own client (ties the code to a server we only run locally).

---

## Resolved requirement changes

`spec.md` is amended by R1 and R9:

| Requirement | Change |
| --- | --- |
| FR-004 | Validate against the *published* schemas, named by `$id`. |
| FR-016–FR-019 | Capabilities are **inferred** by the scanner; an *expected* set may be recorded under `extensions["dev.agent-manager"]`. |
| FR-027 | Compare discovered hosts against the **expected** set, not a manifest allowlist. |
| FR-048 | Signature is registry-side metadata; the policy enforces presence, and the UI states it is unverified. |
| Assumptions | The design's manifests are non-conformant and its seed fixtures are rewritten. |
