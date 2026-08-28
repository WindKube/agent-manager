-- Drop `agents-md` from sync_target_kind.
--
-- HAND-WRITTEN, and it has to be. `atlas migrate diff` refuses this change:
--
--   Error: reordering enum "sync_target_kind" value "codex" is not supported
--
-- Postgres enum values are positional, so removing a value from the middle
-- renumbers every value after it, and Atlas will not emit that. There is no way
-- to remove `agents-md` without moving `codex`. Nothing in this schema orders by
-- `sync_target.target`, so the renumbering is semantically free — checked, not
-- assumed. Once this is applied, `atlas migrate diff` reports the directory in
-- sync against the desired state in internal/store/schema/01-enums.sql.
--
-- WHY the value goes rather than staying as an unused option. `agents-md` names a
-- convention that documents only a repository-root AGENTS.md and no per-user
-- location, and one shared markdown file cannot be installed per package, marked
-- with a package and version, given a distinct directory per publisher, swapped
-- atomically, or pruned by path. It was never an install target in the sense the
-- other two are — research gate R2 in specs/002-agent-manager-cli/plan.md has the
-- evidence. Leaving the value in place while the API refuses it is the worse
-- half-state: a row can still be written with it directly, and then nothing can
-- render that row. Reintroducing it later is another migration, which is the
-- correct cost of the decision rather than a reason to avoid making it.
--
-- The DELETE below is not data loss. `sync_target` is (profile, target, enabled):
-- a row enabling a target that no longer exists enables nothing, so the row is
-- meaningless rather than informative. Without it the USING cast fails on any
-- such row and the migration cannot apply at all.

DELETE FROM "public"."sync_target" WHERE "target"::text = 'agents-md';

ALTER TYPE "public"."sync_target_kind" RENAME TO "sync_target_kind_without_agents_md";

CREATE TYPE "public"."sync_target_kind" AS ENUM ('claude-code', 'codex');

ALTER TABLE "public"."sync_target"
  ALTER COLUMN "target" TYPE "public"."sync_target_kind"
  USING "target"::text::"public"."sync_target_kind";

DROP TYPE "public"."sync_target_kind_without_agents_md";
