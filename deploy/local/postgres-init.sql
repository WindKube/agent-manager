-- Local-only cluster bootstrap. Runs once, from docker-entrypoint-initdb.d.
--
-- The split of work is deliberate and matches data-model.md: this file is the
-- DEPLOYMENT's half — which databases exist, who owns them, and the role
-- passwords. The migration's half is the grants
-- (internal/store/migrations/20260827150200_roles_and_grants.sql), which is why
-- no grant on an application table appears here.
--
-- The roles are created here as well as guarded-for in the migration because a
-- role cannot log in without a password and a password in a migration is a
-- credential in git. These passwords are local-development values and the stack
-- they unlock listens only on the compose network.

create role am_migrate login password 'local-development-am-migrate';
create role am_api     login password 'local-development-am-api';
create role am_fetcher login password 'local-development-am-fetcher';
create role am_scanner login password 'local-development-am-scanner';

-- The queue is a separate database with a single role that owns it, so River's
-- own migrator needs no grant from us and Atlas can never see its tables
-- (constitution principle IX, R11). One role here is not a weaker boundary than
-- four: the isolation being protected is between the queue and the application
-- schema, not between the roles inside the queue.
create role am_queue login password 'local-development-am-queue';
create database river owner am_queue;

-- agent_manager itself is created by POSTGRES_DB, so only its ownership is set
-- here. am_migrate has to own the schema before it can apply the first
-- migration; the migration cannot grant itself the right to run.
--
-- CREATE on the database, not just on the schema: Atlas records applied versions
-- in its own `atlas_schema_revisions` schema, and creating a schema is a
-- database-level privilege. Without it `migrate apply` fails on its very first
-- statement with `permission denied for database agent_manager (42501)`.
grant create, connect on database agent_manager to am_migrate;

\connect agent_manager
alter schema public owner to am_migrate;
grant all on schema public to am_migrate;
