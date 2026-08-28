# Atlas configuration for the `agent_manager` application schema.
#
# There is deliberately ONE env and it points at `agent_manager` only. The `river`
# database is never described here (constitution principle IX, R11): Atlas has
# DROP TABLE in its vocabulary and River owns its own migrations, so keeping the
# queue outside this file is what makes the isolation structural rather than
# configured. T025 asserts `atlas migrate diff` is empty against a fully
# River-migrated cluster, which only holds while that stays true.
#
# The desired state is internal/store/schema/, whose files Atlas applies to the
# throwaway dev database in lexicographic order:
#
#   01-enums.sql        create type ... — Bun emits no DDL for enum types
#   02-tables.sql       GENERATED from the Bun models by `task migrate:schema`
#   03-constraints.sql  checks, the foreign keys the loader cannot emit,
#                       collation, indexes
#
# `.bin/atlas` is the Apache-licensed community build, which rejects the
# `external_schema` and `composite_schema` data sources ("not supported by the
# community version"). That is why 02-tables.sql is a checked-in generated file
# rather than a loader invocation in this config: run `task migrate:schema` after
# any change to internal/store/models, and review the diff.
#
# Layers 01 and 03 exist because a Bun struct tag can only express columns,
# primary keys, unique constraints and foreign keys. These three files together
# are the WHOLE desired state, so a constraint or index that lives only in a
# hand-written migration is DROPped by the next `atlas migrate diff` — which is
# why T015's checks and T017's indexes are in 03-constraints.sql and not in a
# migration.
#
# Roles and grants are the one exception. Atlas models neither, so it will not
# create them and cannot drop them; they live in the hand-written
# roles_and_grants migration.

env "bun" {
  src = "file://internal/store/schema"
  dev = "docker://postgres/16/dev"

  migration {
    dir = "file://internal/store/migrations"
  }

  format {
    migrate {
      diff = "{{ sql . \"  \" }}"
    }
  }
}
