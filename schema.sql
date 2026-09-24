create extension if not exists pgcrypto;

create table if not exists public.scripts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null check (char_length(name) between 1 and 80),
  payload text not null,
  secret_key text not null,
  public boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.scripts enable row level security;

drop policy if exists "owners can read scripts" on public.scripts;
create policy "owners can read scripts" on public.scripts
for select to authenticated using (auth.uid() = owner_id);

drop policy if exists "owners can create scripts" on public.scripts;
create policy "owners can create scripts" on public.scripts
for insert to authenticated with check (auth.uid() = owner_id);

drop policy if exists "owners can delete scripts" on public.scripts;
create policy "owners can delete scripts" on public.scripts
for delete to authenticated using (auth.uid() = owner_id);

drop policy if exists "public loaders can read public scripts" on public.scripts;
create policy "public loaders can read public scripts" on public.scripts
for select to anon using (public = true);

create index if not exists scripts_owner_created_idx on public.scripts(owner_id,created_at desc);
create index if not exists scripts_public_idx on public.scripts(id) where public = true;
