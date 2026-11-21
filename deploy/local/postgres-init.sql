-- Local-only cluster bootstrap, run by the postgres-init one-shot on every
-- `up`, so it is idempotent: a role added later (am_notifier) gets its password
-- on an existing volume too, not only on a fresh one.
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
--
-- am_queue owns the queue database alone, so River's own migrator needs no
-- grant from us and Atlas can never see its tables (constitution principle IX,
-- R11).
do $$
declare
  r record;
begin
  for r in select * from (values
    ('am_migrate', 'local-development-am-migrate'),
    ('am_api', 'local-development-am-api'),
    ('am_fetcher', 'local-development-am-fetcher'),
    ('am_scanner', 'local-development-am-scanner'),
    ('am_notifier', 'local-development-am-notifier'),
    ('am_queue', 'local-development-am-queue')
  ) as v(name, password) loop
    if exists (select 1 from pg_roles where rolname = r.name) then
      execute format('alter role %I login password %L', r.name, r.password);
    else
      execute format('create role %I login password %L', r.name, r.password);
    end if;
  end loop;
end
$$;

select 'create database river owner am_queue'
where not exists (select 1 from pg_database where datname = 'river') \gexec

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
