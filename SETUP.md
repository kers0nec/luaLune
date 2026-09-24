# LuaLune deployment

## 1. Supabase

Open the SQL Editor for the Supabase project configured for LuaLune and run **schema.sql** from this repository once.

The schema creates the scripts table and Row Level Security policies. Auth itself is handled by Supabase email/password auth.

## 2. Render

This repository now runs as a Node/Express service instead of nginx.

Set these Render environment variables:

- `SUPABASE_URL` = your Supabase project URL
- `SUPABASE_ANON_KEY` = your Supabase publishable/anon key

Do not put a service-role key in the repository or browser.

Render should use the repository Dockerfile. The server listens on Render's `PORT` automatically.

## 3. What is implemented

- Email/password signup and login with an optional display name
- Persistent Supabase sessions
- Authenticated dashboard
- Server-side script obfuscation
- Per-script public loader endpoint
- One-line `loadstring(game:HttpGet(...))()` generation
- Script listing and deletion
- Supabase RLS so users only manage their own scripts
- Public loader reads only scripts marked public
- `/healthz` health check

The obfuscator uses a generated XOR key and hex payload. This is obfuscation, not cryptographic secrecy; do not treat it as a way to protect a secret that must remain confidential.
