### 2025-08-11

- Added `src/lib/supabase.js` to centralize Supabase client creation (admin and user clients) with env validation.
- Added `src/middleware/auth.js` middleware to enforce Bearer auth and inject `req.user` and `req.supabase`.
- Added `src/services/ghlService.js` to encapsulate GHL installation storage, token retrieval, and refresh.
- Refactored `server.js` to use the new modules, reduce direct `createClient` usage, and tighten selected columns.
- Secured routes: applied `requireAuth` to `GET /api/locations` and `POST /api/proxy`.
- Tests: added `tests/auth.middleware.test.js` and `tests/supabase.client.test.js`.
- Fixed tests to use `/api/proxy` (was `/api/ghl-proxy`) and simplified mock credentials endpoint.
- Added SQL migration `supabase/sql/2025-08-11_rls_policies.sql` to enable RLS and define least-privilege policies for `internal_users`, `ghl_installations`, and new `user_location_access` mapping, plus indexes.

- Created `docs/GHL_SUBACCOUNT_SNAPSHOT.md` — a living snapshot/template for the GoHighLevel subaccount, including required inputs to keep CRM and Supabase in sync.

