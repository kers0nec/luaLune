/**
 * Auth regression tests for the failures seen in production:
 *
 *  1. Supabase projects ship with "Confirm email" enabled. Username-only
 *     accounts get an email at users.lualune.local that cannot receive mail,
 *     so the account stayed unconfirmed and every login said
 *     "Invalid username or password". Signup must auto-confirm (with the
 *     admin key) and login must rescue already-stuck accounts.
 *  2. Without an admin key the errors must say what is actually wrong
 *     instead of pretending the password was incorrect.
 *  3. Local-mode accounts, signing secret and revoked tokens must survive a
 *     restart (they used to live only in process memory).
 */
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

process.env.NODE_ENV = "test";
process.env.LUALUNE_DATA_DIR = (await import("node:fs")).mkdtempSync((await import("node:os")).tmpdir() + "/lualune-auth-test-");

const { createAuth } = await import("../lib/auth.js");

/** Fake of the slice of @supabase/supabase-js that lib/auth uses. */
function fakeSupabase({ confirmEmailEnabled = true, withAdmin = true } = {}) {
  const state = { users: new Map(), idSeq: 0 };
  const user = (email) => state.users.get(String(email).toLowerCase());
  const confirmed = (record) => record.email_confirmed_at !== null;

  const remote = {
    auth: {
      async signUp({ email, password }) {
        if (user(email)) {
          if (!confirmed(user(email))) return { data: { user: null, session: null }, error: null }; // resend, no session
          return { data: { user: null, session: null }, error: { message: "User already registered" } };
        }
        const record = { id: `u-${++state.idSeq}`, email: String(email).toLowerCase(), password, email_confirmed_at: confirmEmailEnabled ? null : new Date().toISOString(), user_metadata: {} };
        state.users.set(record.email, record);
        return {
          data: { user: { id: record.id, email: record.email, user_metadata: {} }, session: confirmEmailEnabled ? null : { access_token: `tok-${record.id}` } },
          error: null,
        };
      },
      async signInWithPassword({ email, password }) {
        const record = user(email);
        if (!record || record.password !== password) return { data: { user: null, session: null }, error: { message: "Invalid login credentials" } };
        if (!confirmed(record)) return { data: { user: null, session: null }, error: { message: "Email not confirmed" } };
        return { data: { user: { id: record.id, email: record.email, user_metadata: {} }, session: { access_token: `tok-${record.id}` } }, error: null };
      },
      async getUser(token) {
        const id = String(token || "").replace(/^tok-/, "");
        for (const record of state.users.values()) {
          if (record.id === id) return { data: { user: { id: record.id, email: record.email, user_metadata: {} } }, error: null };
        }
        return { data: { user: null }, error: { message: "Invalid token" } };
      },
    },
  };

  const admin = withAdmin
    ? {
        auth: {
          admin: {
            async listUsers({ page = 1, perPage = 200 } = {}) {
              const all = [...state.users.values()];
              const slice = all.slice((page - 1) * perPage, page * perPage);
              return { data: { users: slice.map((r) => ({ id: r.id, email: r.email })) }, error: null };
            },
            async updateUserById(id, patch) {
              for (const record of state.users.values()) {
                if (record.id === id) {
                  if (patch.email_confirm) record.email_confirmed_at = new Date().toISOString();
                  return { data: { user: { id: record.id } }, error: null };
                }
              }
              return { data: null, error: { message: "User not found" } };
            },
          },
        },
      }
    : null;

  return { remote, admin, state };
}

const memoryStore = () => ({
  async getProfile() { return null; },
  async createProfile({ id, email, username }) { return { id, email, username, username_lower: String(username).toLowerCase() }; },
});

test("signup with an unreceivable confirmation email gets auto-confirmed and returns a session", async () => {
  const fake = fakeSupabase();
  const auth = createAuth({ store: memoryStore(), remote: fake.remote, admin: fake.admin });

  const result = await auth.signup({ username: "stuckuser", password: "password123" });
  assert.equal(result.error, undefined);
  assert.equal(result.needsConfirmation, false, `expected a live session, got: ${JSON.stringify(result)}`);
  assert.ok(result.session?.access_token, "signup must return a usable session when the email cannot be confirmed by the user");

  // The very login that used to fail forever now works.
  const login = await auth.login({ identifier: "stuckuser", password: "password123" });
  assert.equal(login.error, undefined);
  assert.ok(login.session?.access_token);
});

test("login rescues an account that is already stuck unconfirmed", async () => {
  const fake = fakeSupabase();
  const auth = createAuth({ store: memoryStore(), remote: fake.remote, admin: fake.admin });

  // Simulate a pre-fix account: created, confirmation pending.
  const seeded = await fake.remote.auth.signUp({ email: "olduser@users.lualune.local", password: "password123" });
  assert.equal(seeded.data.session, null, "test setup: account starts unconfirmed");

  const login = await auth.login({ identifier: "olduser", password: "password123" });
  assert.equal(login.error, undefined, `rescue failed: ${JSON.stringify(login)}`);
  assert.ok(login.session?.access_token, "stuck account must be confirmed and signed in");

  // Second login is clean.
  const again = await auth.login({ identifier: "olduser@users.lualune.local", password: "password123" });
  assert.ok(again.session?.access_token);
});

test("wrong password still says invalid credentials, not something misleading", async () => {
  const fake = fakeSupabase();
  const auth = createAuth({ store: memoryStore(), remote: fake.remote, admin: fake.admin });
  await auth.signup({ username: "honesty", password: "password123" });
  const bad = await auth.login({ identifier: "honesty", password: "wrong-pass" });
  assert.equal(bad.error, "Invalid username or password.");
});

test("without an admin key the errors explain the confirmation deadlock", async () => {
  const fake = fakeSupabase({ withAdmin: false });
  const auth = createAuth({ store: memoryStore(), remote: fake.remote, admin: null });

  const result = await auth.signup({ username: "nokey", password: "password123" });
  assert.equal(result.needsConfirmation, true);
  assert.match(result.message, /SUPABASE_SERVICE_ROLE_KEY/, "operator must be told how to fix the instance");

  await fake.remote.auth.signUp({ email: "stuck2@users.lualune.local", password: "password123" });
  const login = await auth.login({ identifier: "stuck2", password: "password123" });
  assert.match(login.error, /confirmed/i, "must not claim the password was wrong");
  assert.doesNotMatch(login.error, /^Invalid username or password\.$/);
});

test("local mode: accounts and sessions survive a restart", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lualune-auth-"));
  try {
    const first = createAuth({ store: memoryStore(), secret: undefined, dataDir: dir });
    const created = await first.signup({ username: "restart", password: "password123" });
    const oldToken = created.session.access_token;

    // "Restart": a brand new auth instance over the same data dir, no secret env.
    const second = createAuth({ store: memoryStore(), secret: undefined, dataDir: dir });
    assert.equal(second._users.size, 1, "accounts must be reloaded from disk");

    const login = await second.login({ identifier: "restart", password: "password123" });
    assert.ok(login.session?.access_token, "login must work after a restart");

    const me = await second.verify(oldToken);
    assert.equal(me?.username, "restart", "sessions issued before the restart must stay valid");

    // Logout revocation also survives restarts.
    await second.logout(login.session.access_token);
    const third = createAuth({ store: memoryStore(), secret: undefined, dataDir: dir });
    assert.equal(await third.verify(login.session.access_token), null, "revoked tokens stay revoked");
    // Other sessions unaffected.
    const fresh = await third.login({ identifier: "restart", password: "password123" });
    assert.ok(await third.verify(fresh.session.access_token));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("local mode: duplicate signup and wrong password behave", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lualune-auth-"));
  try {
    const auth = createAuth({ store: memoryStore(), dataDir: dir });
    await auth.signup({ username: "dupe", password: "password123" });
    const dupe = await auth.signup({ username: "dupe", password: "password123" });
    assert.equal(dupe.error, "That account already exists.");
    const bad = await auth.login({ identifier: "dupe", password: "wrong-pass" });
    assert.equal(bad.error, "Invalid username or password.");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
