-- 2025-08-11: RLS hardening, indexes, and access model
-- This script assumes tables exist: auth.users, internal_users, ghl_installations
-- It also adds a join table for user-to-location access and implements least-privilege policies.

begin;

-- Ensure pgcrypto for token encryption if needed later
create extension if not exists pgcrypto;

-- Access mapping table
create table if not exists public.user_location_access (
  user_id uuid not null references auth.users(id) on delete cascade,
  ghl_location_id text not null,
  role text not null check (role in ('admin', 'staff')),
  created_at timestamptz not null default now(),
  primary key (user_id, ghl_location_id)
);

alter table public.user_location_access enable row level security;

-- Baseline policy: users can see their own access mappings
drop policy if exists "users can read own access mappings" on public.user_location_access;
create policy "users can read own access mappings"
  on public.user_location_access
  for select
  to authenticated
  using (user_id = auth.uid());

-- internal_users RLS
alter table public.internal_users enable row level security;

-- Users can read their own internal_users row
drop policy if exists "users can read own internal profile" on public.internal_users;
create policy "users can read own internal profile"
  on public.internal_users
  for select
  to authenticated
  using (id = auth.uid());

-- Admins can read all internal users via role check
drop policy if exists "admins can read all internal users" on public.internal_users;
create policy "admins can read all internal users"
  on public.internal_users
  for select
  to authenticated
  using (
    exists (
      select 1 from public.internal_users iu
      where iu.id = auth.uid() and iu.role = 'admin'
    )
  );

-- ghl_installations RLS
alter table public.ghl_installations enable row level security;

-- Admins can read all installations
drop policy if exists "admins can read all installations" on public.ghl_installations;
create policy "admins can read all installations"
  on public.ghl_installations
  for select
  to authenticated
  using (
    exists (
      select 1 from public.internal_users iu
      where iu.id = auth.uid() and iu.role = 'admin'
    )
  );

-- Staff can read installations they are granted access to
drop policy if exists "staff can read assigned installations" on public.ghl_installations;
create policy "staff can read assigned installations"
  on public.ghl_installations
  for select
  to authenticated
  using (
    exists (
      select 1 from public.user_location_access ula
      where ula.user_id = auth.uid() and ula.ghl_location_id = ghl_installations.ghl_location_id
    )
  );

-- Optional: limit updates/inserts to service role via RPCs only
-- No update/insert/delete policies are defined; use SECURITY DEFINER RPCs instead.

-- Harden RPCs: ensure they are SECURITY DEFINER and validate caller
-- Note: adjust owner to the service role and add checks inside functions.
-- Example wrapper (pseudo, adapt to your existing function definitions):
-- alter function public.store_ghl_installation(...) security definer set search_path = public;
-- comment on function public.store_ghl_installation is 'Stores/updates GHL installation tokens. Only callable by service role.';

-- Indexes for performance
create index if not exists idx_ghl_installations_location_id on public.ghl_installations(ghl_location_id);
create index if not exists idx_ghl_installations_status on public.ghl_installations(installation_status);
create index if not exists idx_ghl_installations_token_expiry on public.ghl_installations(location_token_expires_at);

commit;

