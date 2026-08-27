-- Layer 1 of the desired state (see atlas.hcl).
--
-- Bun emits no DDL for enum types, so these come from here. The value sets are a
-- verbatim copy of models.EnumDDL(), which reads the same map that every Valid()
-- reads; TestEnumTypesInTheDatabaseMatchTheGoConstSets in
-- internal/store/store_test.go asserts the migrated database against
-- models.EnumTypes(), so a drift between this file and the Go const sets fails
-- the integration suite rather than surfacing as a runtime insert error.

create type actor_kind as enum ('identity', 'system');
create type audit_kind as enum ('fetch', 'scan', 'approve', 'profile', 'share', 'sync', 'login');
create type capability_level as enum ('scoped', 'allowlisted', 'review');
create type capability_source as enum ('inferred', 'expected');
create type check_result as enum ('pass', 'fail', 'warn');
create type component_kind as enum ('skill', 'mcp', 'ext');
create type device_auth_state as enum ('pending', 'approved', 'consumed', 'expired', 'denied');
create type dist_tag as enum ('latest', 'archived', 'none');
create type entry_mode as enum ('latest', 'pinned', 'range');
create type finding_severity as enum ('low', 'medium', 'high');
create type finding_state as enum ('open', 'approved', 'rejected');
create type membership_role as enum ('owner', 'maintainer', 'reviewer', 'consumer');
create type org_role as enum ('catalog-admin', 'scanner-reviewer', 'profile-consumer', 'read-only');
create type outbox_state as enum ('pending', 'delivered');
create type package_kind as enum ('plugin', 'skill');
create type package_visibility as enum ('organisation', 'team', 'private');
create type profile_visibility as enum ('organisation', 'shared', 'private');
create type scan_gate as enum ('block', 'approval', 'warn-with-override');
create type signature_kind as enum ('none', 'cosign-bundle');
create type signature_result as enum ('verified', 'invalid', 'error');
create type subject_kind as enum ('user', 'group');
create type sync_target_kind as enum ('claude-code', 'agents-md', 'codex');
create type verdict as enum ('scanning', 'clean', 'flagged', 'rejected');
create type version_policy as enum ('floating-latest', 'pinned', 'range');
