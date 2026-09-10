-- am_api holds DELETE on group_role_map and category.
--
-- This was an oversight in 20260827150200_roles_and_grants.sql, not a
-- deliberate withholding: am_api is the role that mediates every mutation on
-- both tables, and neither is on the withheld-grant list. A CRUD screen with
-- no working delete on its own rows is half a feature, unlike outbox,
-- profile_entry, membership, session, device_authorization and revision, each
-- of which has its own reason to keep DELETE off am_api.
grant delete on table group_role_map, category to am_api;
