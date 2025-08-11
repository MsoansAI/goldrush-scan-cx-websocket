## GoHighLevel Subaccount Snapshot

Purpose: Living reference of the GoHighLevel (GHL) subaccount and how it maps to our backend (Node server + Supabase). Keep this updated to maintain consistent, secure syncing between CRM and database.

Last updated: 2025-08-11
Environment: production

### 1) Identity and App Configuration
- Location IDs:
  - sbZmSdZiZECyTSZgIYo9 → GoldRush Sports Coffee - Bengaluru
- Server URL: <not required>
- Frontend URL: https://grsc-scan-frontend.vercel.app
- Supabase URL: https://gaghicnkogwtprilbuex.supabase.co
- Supabase anon key present in env: yes

### 2) Tokens and Installations
- Not used (Marketplace OAuth flow removed for this project)

### 3) Users, Roles, and Access Mapping
- Supabase auth provider: Supabase Auth (managed via Admin API)
- Internal profile table: `public.internal_users`
  - Columns: id (uuid matches `auth.users.id`), email, ghl_user_id, role (admin|staff|member), first_name, last_name, is_active
- Access mapping table: not required (single location; all users have access)
  - Keys: (user_id, ghl_location_id), role (admin|staff)
- Mappings (current):
  - auth.users (latest): kavya.rai@woap.in, sindhura.setty@gmail.com, m10.pro.cel@gmail.com
  - CRM users to ensure exist in Supabase and map roles:
    - Kavya Rai — kavya.rai@woap.in — ghl_user_id=e4cQnR8KxUduKMKVeDEs — Account-User → staff
    - Gold Rush — hello@goldrushcoffee.world — ghl_user_id=CapRaM3yJz4QMlLJIt4f — Account-Admin → admin
  - Access: all users can access the single location

### 4) Webhooks and Integrations
- GHL webhooks: <list subscribed events and endpoints if any>
- Other integrations impacting data sync:
  - Petpooja: Edge Function `petpooja-webhook` (Supabase) [documented separately]
- API proxy endpoint: `POST /api/proxy` (server)
  - Requires Bearer token (Supabase JWT)
  - Body: { ghl_location_id, endpoint, method, data? }

### 5) Data Flows
- Nightly CRM sync (proposed): fetch contacts/companies from GHL for the single location and upsert into Supabase

### 6) Security Baseline
- Environment variables required (server):
  - SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY
- Supabase RLS (recommended/enforced):
  - `internal_users`: RLS enabled; policies present (users self-read/update, admin manage, public validation read)
  - `ghl_installations`: RLS enabled; policies present (public validation read, admin manage)
  - `user_location_access`: not created yet (see migration); once created, enforce staff location scoping
  - Inserts/updates via SECURITY DEFINER RPCs (confirmed for `store_ghl_installation`, `get_ghl_location_token`)
- Tokens are never sent to clients; only proxied server-side

### 7) Monitoring and Auditing
- Server logs: Railway/host stdout, includes token refresh and proxy access
- Supabase logs: API, Postgres, Edge Functions
- Advisors: run security/performance advisors after schema changes

### 8) Known Gaps / TODO
- Ensure Supabase users exist with correct roles (admin/staff) and link `ghl_user_id`
- Implement nightly GHL CRM sync (single location)
- Remove OAuth marketplace code paths from server (initiate/callback/decrypt)
- Review advisors: remove SECURITY DEFINER views; set search_path in functions; add missing FK indexes; set RLS posture for Petpooja tables to server-only

### 9) How to Update This Snapshot
- On new location installation:
  - Add location to “Location IDs” and tokens status
  - Update `user_location_access` assignments
- On staff changes:
  - Update `internal_users` and mapping table
- On scope changes:
  - Update scopes section and re-authorize if needed
- On webhook changes:
  - Update list and verify signatures/secrets

---

## Inputs needed from you to complete/maintain this document
Provide these items to fully populate and keep this reference in sync:

1) Core identifiers and config
- Confirm location details (we have 1: sbZmSdZiZECyTSZgIYo9 → name/address)

2) Users and permissions
- CSV or list of GHL users: email, ghl_user_id, role (admin/staff/member)
- Mapping to Supabase (if known): auth.users.id or we will derive post-creation
- Per-user location access (user → [location_id])

3) Webhooks
- List of enabled GHL webhooks: event type, delivery URL, signing/verification details
- Any third-party integrations (e.g., Petpooja) touching CRM/Supabase: endpoint URLs and secrets

4) OAuth and tokens
- Scopes required/used by the app
- Any special re-auth constraints by agency or location
- Confirmation of token rotation cadence if different from default

5) Supabase details
- Project ref/URL, anon key present in server env (yes/no)
- Confirmation of RLS enabled on: internal_users, ghl_installations (and any other tables holding CRM data)
- Confirmation RPCs `store_ghl_installation`, `get_ghl_location_token` exist, are SECURITY DEFINER, and restricted to service role

6) Operational notes
- Points of contact for CRM ownership
- Incident/rollback checklist for token revocation or scope changes

With the above, I will fill all placeholders, validate RLS and RPC protections, and ensure the server and Supabase schemas reflect the current GHL subaccount state.

