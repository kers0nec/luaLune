-- LuaLune database schema
-- Run this once in the Supabase SQL editor for the project behind LuaLune.
-- Auth itself is Supabase email/username + password auth; everything else lives here.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------- profiles
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  username text not null unique,
  plan text not null default 'free' check (plan in ('free','pro','premium')),
  role text not null default 'user' check (role in ('user','admin')),
  status text not null default 'active' check (status in ('active','suspended','terminated')),
  suspended_until timestamptz,
  suspension_reason text,
  tos_version text,
  created_at timestamptz not null default now()
);

create index if not exists profiles_username_idx on public.profiles(lower(username));

-- Automatically create the application profile when Supabase Auth creates a user.
-- This runs with the function owner's privileges so email confirmation can happen
-- before the user has an authenticated database session.
drop trigger if exists on_auth_user_created on auth.users;
drop function if exists public.handle_new_user();
create function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $
begin
  insert into public.profiles (id, email, username)
  values (
    new.id,
    coalesce(new.email, ''),
    left(regexp_replace(coalesce(new.raw_user_meta_data->>'username', split_part(coalesce(new.email, ''), '@', 1)), '[^a-zA-Z0-9._-]', '', 'g'), 24)
  )
  on conflict (id) do nothing;
  return new;
end;
$;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();


-- ----------------------------------------------------------------- scripts
create table if not exists public.scripts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  engine text not null default 'payload' check (engine in ('payload','flow','none')),
  build_id text not null,
  code text not null,
  source_bytes integer not null default 0,
  output_bytes integer not null default 0,
  key_required boolean not null default false,
  public boolean not null default true,
  warnings jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists scripts_owner_created_idx on public.scripts(owner_id, created_at desc);
create index if not exists scripts_public_idx on public.scripts(id) where public = true;

-- -------------------------------------------------------------------- keys
create table if not exists public.script_keys (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  script_id uuid references public.scripts(id) on delete cascade,
  value text not null unique,
  label text not null default '',
  duration_seconds integer,
  hwid text,
  uses integer not null default 0,
  last_used_at timestamptz,
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists script_keys_owner_idx on public.script_keys(owner_id, created_at desc);
create index if not exists script_keys_value_idx on public.script_keys(value);

-- --------------------------------------------------------------- whitelist
create table if not exists public.whitelist_entries (
  id uuid primary key default gen_random_uuid(),
  script_id uuid not null references public.scripts(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  hwid text not null,
  label text not null default '',
  created_at timestamptz not null default now(),
  unique (script_id, hwid)
);

create index if not exists whitelist_script_idx on public.whitelist_entries(script_id);

-- ---------------------------------------------------------- sharing/invites
create table if not exists public.invites (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  code text not null unique,
  kind text not null default 'workspace' check (kind in ('workspace','plan')),
  plan text check (plan in ('free','pro','premium')),
  max_uses integer not null default 1,
  uses integer not null default 0,
  last_used_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create table if not exists public.shares (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  owner_username text not null,
  script_id uuid references public.scripts(id) on delete cascade,
  shared_with text not null,
  created_at timestamptz not null default now()
);

create index if not exists shares_owner_idx on public.shares(owner_id);
create index if not exists shares_target_idx on public.shares(lower(shared_with));

-- ------------------------------------------------------------------- usage
create table if not exists public.usage_counters (
  user_id uuid not null references auth.users(id) on delete cascade,
  month text not null,
  count integer not null default 0,
  primary key (user_id, month)
);

create table if not exists public.tos_acceptances (
  user_id uuid primary key references auth.users(id) on delete cascade,
  version text not null,
  accepted_at timestamptz not null default now()
);

-- ------------------------------------------------------------- server only
create table if not exists public.execution_logs (
  id uuid primary key default gen_random_uuid(),
  script_id uuid references public.scripts(id) on delete cascade,
  owner_id uuid references auth.users(id) on delete cascade,
  status text not null,
  code text,
  key_value text,
  hwid text,
  ip_hash text,
  user_agent text,
  created_at timestamptz not null default now()
);

create index if not exists execution_logs_script_idx on public.execution_logs(script_id, created_at desc);

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null,
  level text not null default 'info',
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

-- --------------------------------------------------------------- RLS rules
alter table public.profiles enable row level security;
alter table public.scripts enable row level security;
alter table public.script_keys enable row level security;
alter table public.whitelist_entries enable row level security;
alter table public.invites enable row level security;
alter table public.shares enable row level security;
alter table public.usage_counters enable row level security;
alter table public.tos_acceptances enable row level security;
alter table public.execution_logs enable row level security;
alter table public.announcements enable row level security;

-- profiles: you can read and rename your own row
drop policy if exists "own profile read" on public.profiles;
create policy "own profile read" on public.profiles for select to authenticated using (auth.uid() = id);
drop policy if exists "own profile write" on public.profiles;
create policy "own profile write" on public.profiles for update to authenticated using (auth.uid() = id);

-- scripts: owners manage theirs, the public loader may read public builds
drop policy if exists "owners read scripts" on public.scripts;
create policy "owners read scripts" on public.scripts for select to authenticated using (auth.uid() = owner_id);
drop policy if exists "owners insert scripts" on public.scripts;
create policy "owners insert scripts" on public.scripts for insert to authenticated with check (auth.uid() = owner_id);
drop policy if exists "owners update scripts" on public.scripts;
create policy "owners update scripts" on public.scripts for update to authenticated using (auth.uid() = owner_id);
drop policy if exists "owners delete scripts" on public.scripts;
create policy "owners delete scripts" on public.scripts for delete to authenticated using (auth.uid() = owner_id);
drop policy if exists "loaders read public scripts" on public.scripts;
create policy "loaders read public scripts" on public.scripts for select to anon using (public = true);

-- keys / whitelist: owner only (the loader uses the service key server side)
drop policy if exists "owners manage keys" on public.script_keys;
create policy "owners manage keys" on public.script_keys for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);

drop policy if exists "owners manage whitelist" on public.whitelist_entries;
create policy "owners manage whitelist" on public.whitelist_entries for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);

-- invites: owners manage the ones they created; any signed in user may look a code up to redeem it
drop policy if exists "owners manage invites" on public.invites;
create policy "owners manage invites" on public.invites for all to authenticated using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
drop policy if exists "invites are redeemable" on public.invites;
create policy "invites are redeemable" on public.invites for select to authenticated using (true);

-- shares: you see the ones you created and the ones aimed at you
drop policy if exists "shares visible to both sides" on public.shares;
create policy "shares visible to both sides" on public.shares for select to authenticated
  using (auth.uid() = owner_id or lower(shared_with) = lower(coalesce(auth.jwt() ->> 'username', '')));
drop policy if exists "owners create shares" on public.shares;
create policy "owners create shares" on public.shares for insert to authenticated with check (auth.uid() = owner_id);
drop policy if exists "either side removes a share" on public.shares;
create policy "either side removes a share" on public.shares for delete to authenticated using (auth.uid() = owner_id);

-- counters, terms and logs stay server side
drop policy if exists "own usage" on public.usage_counters;
create policy "own usage" on public.usage_counters for select to authenticated using (auth.uid() = user_id);
drop policy if exists "own terms acceptance" on public.tos_acceptances;
create policy "own terms acceptance" on public.tos_acceptances for select to authenticated using (auth.uid() = user_id);
drop policy if exists "owners read their logs" on public.execution_logs;
create policy "owners read their logs" on public.execution_logs for select to authenticated using (auth.uid() = owner_id);

-- announcements are public reading
drop policy if exists "announcements are public" on public.announcements;
create policy "announcements are public" on public.announcements for select to anon, authenticated using (true);
