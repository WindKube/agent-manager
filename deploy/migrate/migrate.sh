#!/bin/sh
# The deployment's migration job: both schemas, in order, in one container.
#
# Two tools because there are two owners. Atlas wrote the .sql files under
# /migrations and keeps atlas_schema_revisions; the queue's schema is River's
# own and River's CLI is what applies it. Neither may see the other's tables,
# which is also why they are two databases and two credentials.
#
# `set -e` is the whole failure policy: a queue migrated against an application
# schema that did not apply is a deployment that fails at its first query
# instead of here.
set -eu

: "${AGENT_MANAGER_DATABASE_URL:?the application database url is required}"
: "${AGENT_MANAGER_RIVER_DATABASE_URL:?the queue database url is required}"
: "${AGENT_MANAGER_MIGRATIONS_DIR:=/migrations}"

echo "migrate: applying the application schema"
atlas migrate apply \
  --dir "file://${AGENT_MANAGER_MIGRATIONS_DIR}" \
  --url "${AGENT_MANAGER_DATABASE_URL}"

echo "migrate: applying the queue schema"
river migrate-up \
  --line main \
  --database-url "${AGENT_MANAGER_RIVER_DATABASE_URL}"

echo "migrate: done"
