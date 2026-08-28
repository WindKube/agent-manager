# Vendored schemas

Fetched 2026-08-27 from `agentplugins/agent-plugins-spec@main`
(`https://raw.githubusercontent.com/agentplugins/agent-plugins-spec/main/schemas/<version>/<file>`),
spec CC-BY-4.0 / code Apache-2.0. Embedded rather than fetched at run time: validation must
work offline and must not depend on a third party's uptime or on a schema changing under a
released version.

| File | sha256 |
| --- | --- |
| `1.0.0-plugin.schema.json` | `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883` |
| `1.0.0-mcp.schema.json` | `6539175bfcdf43085855183e86da40ea94b166547a72b47ae9a0a390516d3acb` |
| `1.1.0-plugin.schema.json` | `fdc7bb3962c48c9d2d561641d2bc96225c94ca69c4087010241b9423a290370f` |
| `1.1.0-mcp.schema.json` | `f227ec2c0e40cd23051bd7a6ba1f64789eff7773d4e481d80002ab9fd3c45137` |

## A correction to research.md R1, found by diffing them

R1 said "Schema 1.1.0 has an identical plugin field set; only `mcp.json` changed (now
`{$schema, mcpServers}`, both required)". Measured: **`mcp.json` is identical too.** Both
versions of both files differ only in the `$id`, the `const` on `$schema`, and the version
named in the prose `description`. 1.0.0's `mcp.schema.json` already requires
`{$schema, mcpServers}`.

So the version dispatch has exactly one job — accept either `$schema` `$id` — and there is
no field-set difference to branch on. The R1 sentence in
`specs/001-agent-manager-hub/research.md` has been corrected to say so, and that correction
is the only edit this layer made to that file.

## Agent Skills

`agentskills.io` publishes **no JSON Schema** (`/schemas/skill.schema.json`,
`/schema/skill.json` and `/spec` all 404). `skill-frontmatter.schema.json` in this directory
is therefore **written by this project** from the field set in research.md R1, and is marked
as such in its own `description`. It is not a vendored artefact and must not be presented as
one.
