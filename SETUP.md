# LuaLune deployment

LuaLune is a single Node/Express service: it serves the gold themed dashboard and
the API, and it serves protected builds from `/loader/:id`.

## 1. Run it locally

```bash
npm install
npm start          # http://localhost:10000
npm test           # 65 tests, including Lua VM round trips of generated builds
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
   confirmation is optional: LuaLune confirms sign-ups itself when
   `SUPABASE_SERVICE_ROLE_KEY` is set (required for username-only accounts,
   whose generated `user@users.lualune.local` address cannot receive mail).
4. Set the environment variables on your host:

   - `SUPABASE_URL` = your project URL
   - `SUPABASE_ANON_KEY`
  - `SUPABASE_SERVICE_ROLE_KEY` — **Render/server only**; never put this in the browser or GitHub = your publishable/anon key

   Never put a service role key in the repository or the browser.

Without Supabase configured the app falls back to the built-in auth (scrypt
password hashes + HMAC signed session tokens) and the in-memory store. Accounts
and the token signing secret are persisted to `data/auth-local.json`, so local
logins survive restarts.

## 3. Deploy

This repository ships a `Dockerfile`; Render builds it and the server listens on
`PORT` automatically.

Environment checklist:

| Variable | Required | Notes |
| --- | --- | --- |
| `SUPABASE_URL` | for persistence | Project URL. |
| `SUPABASE_ANON_KEY` | for persistence | Publishable/anon key. |
| `SUPABASE_SERVICE_ROLE_KEY` | recommended | Server-only admin key. Auto-confirms sign-ups so username-only accounts can always log in. |
| `LUALUNE_AUTH_SECRET` | recommended | Signs local session tokens. Generate with `openssl rand -hex 32`. |
| `LUALUNE_DOMAIN` | optional | Shown in metadata; used as the log hashing salt. |
| `LUALUNE_ADMINS` | optional | Comma separated emails granted admin access. |

Health check: `GET /healthz` → `LuaLune OK`.

## Troubleshooting sign-in

| Symptom | Cause and fix |
| --- | --- |
| "Invalid username or password" although the password is right | The Supabase account is unconfirmed ("Confirm email" is on and the account cannot receive mail). Add `SUPABASE_SERVICE_ROLE_KEY` and restart — the next login auto-confirms the account. |
| Login returns 502 "Could not reach the account database" | `schema.sql` was not run, or the Supabase keys are wrong/expired. Re-run `schema.sql` in the SQL editor. |
| Every account disappears after each deploy | The instance runs without Supabase, so storage is memory only. Add `SUPABASE_URL` / `SUPABASE_ANON_KEY`. |
| "Too many sign-in attempts" | Per-IP rate limit (60 per 10 min). Wait or raise `LUALUNE_RATE_AUTH`. |

### Optional: Lune Obfuscator engine (Prometheus)

LuaLune ships with its own engines and works without any external bundle. To also
offer the AST-level Lune Obfuscator engine that earlier deployments used:

```bash
npm install wasmoon
git clone https://github.com/prometheus-lua/Prometheus vendor/prometheus
```

`GET /api/meta` then reports it as available and it appears in the dashboard engine
picker. When it is missing, a request for that engine is built with
*LuaLune Obfuscator - Vault* and the response includes a warning explaining why.

The Lune Obfuscator engine is based on Prometheus by Elias Oelschner
(https://github.com/prometheus-lua/Prometheus, MIT); keep that attribution in place
when you deploy it.

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
- Signing up creates an account immediately, with no CAPTCHA or application-side signup throttle.
- Creating a script returns a loader URL, and fetching that URL returns text.
- Each engine builds and runs: `payload`, `flow`, `vault` (and `none`).
- `npm test` passes locally before you deploy — it executes generated builds in a
  Lua VM and compares their output with the original script.
- A script marked *key required* returns a denial stub without a valid key.
- `GET /api/meta` reports the store and auth mode in use.


## Supabase Auth configuration

Set the Supabase Auth **Site URL** to your deployed LuaLune URL and add that same URL to the allowed Redirect URLs. Supabase requires the Site URL/Redirect URL configuration for email confirmation and password-reset redirects. citeturn0search0turn0search1

Run the current `schema.sql` after the profile trigger changes. The server-side secret key is required for the server's profile/admin data operations; keep it only in Render environment variables. Supabase documents that server-side secret/service keys bypass RLS and must never be exposed client-side. citeturn2search3turn2search9
