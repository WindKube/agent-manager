#!/bin/sh
# Every schema this hub owns, applied in order, in one container.
#
# Two migrators run here because there are two databases and only one of them is
# ours to describe: Atlas owns the application schema, and River owns its queue's
# and ships its own migrator, which is a subcommand of this project's binary. They
# must not be merged — Atlas diffing against a River-managed database would
# propose dropping every table it did not generate.
#
# Order is not arbitrary. `migrate queue` is reached only if the application
# schema applied cleanly, so a half-migrated deployment stops at the first
# failure rather than leaving two databases at different versions.
#
# Reads two credentials, and they are different roles on purpose:
#   AGENT_MANAGER_DATABASE_URL        am_migrate, which owns the application schema
#   AGENT_MANAGER_RIVER_DATABASE_URL  am_queue, which owns the queue database
set -eu

: "${AGENT_MANAGER_DATABASE_URL:?set AGENT_MANAGER_DATABASE_URL to the am_migrate DSN}"
: "${AGENT_MANAGER_RIVER_DATABASE_URL:?set AGENT_MANAGER_RIVER_DATABASE_URL to the am_queue DSN}"

echo "migrate: applying the application schema"
atlas migrate apply --dir "file:///migrations" --url "$AGENT_MANAGER_DATABASE_URL"

echo "migrate: applying the queue schema"
agent-manager migrate queue

echo "migrate: done"
