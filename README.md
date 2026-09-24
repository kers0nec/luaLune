# LuaLune

Luau/Lua protection platform built around the **LuaLune Obfuscator**.

LuaLune takes a Lua or Luau script, protects it, and hands back a loader URL you can
paste into any executor. It ships with accounts, plans, a key system, HWID
whitelisting, execution logs, workspace sharing and an admin console.

```
loadstring(game:HttpGet("https://<your-domain>/loader/<script-id>"))()
```

---

## Engines

| Engine | What it does |
| --- | --- |
| **LuaLune Obfuscator** (`payload`) | Encrypts the whole chunk (Park–Miller keystream, per-build seed), splits the ciphertext into shuffled segments, ships a randomized runtime decoder, verifies an Adler-style integrity checksum before decoding and rebuilds the chunk in memory with `loadstring`. |
| **LuaLune Obfuscator - Flow** (`flow`) | Source-to-source: scope-aware identifier renaming, control-flow flattening, encrypted string tables with a memoized decoder, split number literals and dead-code injection. Output stays valid Luau, so it also runs on Luau-only executors. |
| **None** | Stores the script untouched (useful for diffing engines or shipping open source scripts). |

Every pass is conservative. If a construct cannot be transformed without risking a
behaviour change (repeat/until, goto, Luau if-expressions, top-level varargs,
shadowed globals, `<const>` attributes) the pass disables itself and the build is
returned with a warning instead of a broken script.

The engine never claims to be more than it is: obfuscation raises the cost of
reading your source, it is not encryption for secrets. Do not put API keys inside
a script you protect.

---

## Quick start

```bash
npm install
npm start          # http://localhost:10000
```

Without `SUPABASE_URL` / `SUPABASE_ANON_KEY` LuaLune runs fully self contained:
accounts, sessions and data live in memory (great for a local run or a preview
sandbox, wiped on restart). Configure Supabase to make it persistent.

```bash
npm test           # 39 tests: obfuscator, API, fuzz round trips through a Lua VM
```

### Environment

| Variable | Purpose |
| --- | --- |
| `PORT` | HTTP port (default `10000`, Render sets it automatically). |
| `SUPABASE_URL` / `SUPABASE_ANON_KEY` | Enables Supabase auth + Postgres storage. Run `schema.sql` once. |
| `LUALUNE_AUTH_SECRET` | Signs local session tokens when Supabase is not configured. |
| `LUALUNE_DOMAIN` | Domain shown in metadata and used for log hashing salt. |
| `LUALUNE_ADMINS` | Comma separated emails that always get admin access. |
| `LUALUNE_RATE_AUTH` / `LUALUNE_RATE_BUILD` / `LUALUNE_RATE_LOADER` | Requests allowed per window (60 / 10 min, 30 / min, 240 / min by default). |

---

## API

| Method | Route | Notes |
| --- | --- | --- |
| `GET` | `/healthz` | Health check → `LuaLune OK`. |
| `GET` | `/api/meta` | Brand, engines, plans, terms version. |
| `GET` | `/api/plans`, `/api/tos`, `/api/announcements` | Public catalogue. |
| `GET` | `/api/captcha` | Proof-of-work human check challenge. |
| `POST` | `/api/auth/signup`, `/api/auth/login` | Username + password (email optional). |
| `GET` | `/api/auth/me`, `POST /api/auth/logout` | Session. |
| `POST` | `/api/tos/accept` | Accept the current terms version. |
| `GET/POST` | `/api/scripts` | List / create protected scripts. |
| `GET/PATCH/DELETE` | `/api/scripts/:id` | Read metadata, rename, toggle public, delete. |
| `POST` | `/api/scripts/:id/rebuild` | Re-obfuscate new source; the loader URL stays the same. |
| `GET` | `/api/scripts/:id/view` | The protected build as text (owner only). |
| `GET` | `/api/scripts/:id/logs` | Execution logs (Pro/Premium). |
| `GET/POST/DELETE` | `/api/keys` | Key system: `?duration=test\|1d\|3d\|7d\|30d\|forever`. |
| `GET/POST/DELETE` | `/api/whitelist` | HWID whitelist per script. |
| `GET/POST/DELETE` | `/api/invites`, `/api/invites/redeem` | Invite codes for workspace access or plan upgrades. |
| `GET/POST/DELETE` | `/api/shares` | Workspace sharing (Pro/Premium). |
| `GET` | `/api/admin/*` | Stats, users, plan/status changes, broadcasts. |
| `GET` | `/loader/:id?key=...&hwid=...` | What executors fetch. Runs the key, HWID and status checks, then returns the build. |

`loader/:id` answers with a plain-text Lua file in every case — a denial is a small
stub that calls `error()`, so an executor never sees a HTML error page.

---

## Plans

| | Free | Pro ($6) | Premium ($14) |
| --- | --- | --- | --- |
| Scripts | 3 | 25 | unlimited |
| Builds / month | 25 | 500 | unlimited |
| Keys | 5 | 100 | unlimited |
| HWID entries / script | 25 | 250 | unlimited |
| Execution logs | — | yes | yes |
| Workspace sharing | — | yes | yes |

One-time payment per tier, monthly build counters, limits enforced server side.

---

## Layout

```
server.js            Express API, loader endpoint, static host
lib/obfuscator.js    the LuaLune Obfuscator (lexer, passes, payload engine)
lib/plans.js         plan catalogue and limit checks
lib/loader.js        loader banners, snippets and denial stubs
lib/captcha.js       proof-of-work human check
lib/ratelimit.js     fixed window rate limiting (api, builds, loader)
lib/auth.js          Supabase auth or built-in scrypt auth
lib/store.js         memory or Supabase storage adapter
lib/tos.js           terms of service text and version
index.html           gold themed single page app
styles.css           theme
tests/               node:test suites incl. a Lua VM round-trip harness
schema.sql           Supabase schema + row level security
```

## Hardening

- Human check on signup (proof of work, no third party and no tracking).
- Per-IP rate limits on sign-in, builds and the loader; a throttled loader call
  still returns Lua (a denial stub), never HTML.
- Loader requests are checked server side for key, expiry, key/script binding and
  HWID before any protected source leaves the server.
- Row level security in `schema.sql`; the browser never sees another user's rows.
- Sessions are bearer tokens (Supabase or HMAC signed locally, 30 day expiry).

## Tests

`tests/luavm.js` embeds a Lua 5.3 VM (fengari) so every generated build is
actually executed and its printed output is compared against the original script.
The fuzz suite runs ten construct-heavy scripts through both engines with the
options toggled on and off.

## Legal

LuaLune is a protection tool. Users are responsible for what they protect with it.
See the in-app Terms of Service for the acceptable use rules.
