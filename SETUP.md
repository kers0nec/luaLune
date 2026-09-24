# LuaLune deployment

LuaLune is a single Node/Express service: it serves the gold themed dashboard and
the API, and it serves protected builds from `/loader/:id`.

## 1. Run it locally

```bash
npm install
npm start          # http://localhost:10000
npm test           # 39 tests, including Lua VM round trips of generated builds
```

With no Supabase environment variables LuaLune starts in self contained mode:
accounts, sessions, scripts, keys, logs and invite codes live in memory and reset
when the process restarts. Useful for previews, demos and development.

## 2. Supabase (persistent mode)

1. Create a Supabase project.
2. Open the SQL editor and run **schema.sql** from this repository once. It creates
   `profiles`, `scripts`, `script_keys`, `whitelist_entries`, `invites`, `shares`,
   `usage_counters`, `tos_acceptances`, `execution_logs` and `announcements`, and
   enables row level security so users only touch their own rows.
3. In Supabase → Authentication → Providers, keep email/password enabled. Email
   confirmation is optional; if you turn it on, new accounts must confirm before
   their first sign in.
4. Set the environment variables on your host:

   - `SUPABASE_URL` = your project URL
   - `SUPABASE_ANON_KEY` = your publishable/anon key

   Never put a service role key in the repository or the browser.

Without Supabase configured the app falls back to the built-in auth (scrypt
password hashes + HMAC signed session tokens) and the in-memory store.

## 3. Deploy

This repository ships a `Dockerfile`; Render builds it and the server listens on
`PORT` automatically.

Environment checklist:

| Variable | Required | Notes |
| --- | --- | --- |
| `SUPABASE_URL` | for persistence | Project URL. |
| `SUPABASE_ANON_KEY` | for persistence | Publishable/anon key. |
| `LUALUNE_AUTH_SECRET` | recommended | Signs local session tokens. Generate with `openssl rand -hex 32`. |
| `LUALUNE_DOMAIN` | optional | Shown in metadata; used as the log hashing salt. |
| `LUALUNE_ADMINS` | optional | Comma separated emails granted admin access. |

Health check: `GET /healthz` → `LuaLune OK`.

## 4. First admin

Sign up normally, then either add your email to `LUALUNE_ADMINS` or promote the
account in SQL:

```sql
update public.profiles set role = 'admin' where username = 'your_username';
```

Admins get the Admin tab: platform stats, plan and status changes, and broadcasts
that appear at the top of every page.

## 5. What to verify after deploying

- `GET /healthz` returns `LuaLune OK`.
- Signing up requires the human check to be solved in the browser.
- Creating a script returns a loader URL, and fetching that URL returns text.
- A script marked *key required* returns a denial stub without a valid key.
- `GET /api/meta` reports the store and auth mode in use.
