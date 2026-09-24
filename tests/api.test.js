import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "";
process.env.SUPABASE_ANON_KEY = "";
// Keep the auth threshold tiny so this file proves signup does not use it.
process.env.LUALUNE_RATE_AUTH = "3";
// Fresh auth state per run so repeated `npm test` never sees stale accounts.
process.env.LUALUNE_DATA_DIR = (await import("node:fs")).mkdtempSync((await import("node:os")).tmpdir() + "/lualune-test-");

const { app, store } = await import("../server.js");
const { runLua } = await import("./luavm.js");
const { TOS_VERSION } = await import("../lib/tos.js");

let server;
let base;

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, "127.0.0.1", resolve);
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(() => server?.close());

async function api(pathname, { method = "GET", token, body, raw } = {}) {
  const res = await fetch(base + pathname, {
    method,
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (raw) return { status: res.status, text: await res.text() };
  const json = res.status === 204 ? {} : await res.json().catch(() => ({}));
  return { status: res.status, ...json };
}

async function signup(username, password = "password123") {
  const res = await api("/api/auth/signup", {
    method: "POST",
    body: { username, password },
  });
  assert.equal(res.status, 201, JSON.stringify(res));
  return res.session.access_token;
}

const SAMPLE = `local message = "LuaLune works"\nlocal function shout(text)\n  return string.upper(text)\nend\nprint(shout(message))\nfor i = 1, 2 do print("tick", i) end\n`;

test("public endpoints are LuaLune branded and discord free", async () => {
  const health = await api("/healthz", { raw: true });
  assert.equal(health.status, 200);
  assert.match(health.text, /LuaLune OK/);

  const meta = await api("/api/meta");
  assert.equal(meta.name, "LuaLune");
  assert.equal(meta.product, "LuaLune Obfuscator");
  assert.ok(meta.engines.some((e) => e.name === "LuaLune Obfuscator"));
  assert.ok(!JSON.stringify(meta).toLowerCase().includes("discord"), "no discord anywhere in meta");

  const plans = await api("/api/plans");
  assert.deepEqual(plans.plans.map((p) => p.id), ["free", "pro", "premium"]);
  assert.equal(plans.billing, "one-time payment");

  const tos = await api("/api/tos");
  assert.equal(tos.version, TOS_VERSION);
  assert.ok(tos.sections.length >= 5);
});

test("signup has no CAPTCHA or application-side slow mode", async () => {
  const direct = await api("/api/auth/signup", { method: "POST", body: { username: "nocaptcha", password: "password123" } });
  assert.equal(direct.status, 201, JSON.stringify(direct));
  assert.ok(direct.session?.access_token);

  // LUALUNE_RATE_AUTH applies to sign-in and reset attempts, not new accounts.
  const created = await Promise.all(Array.from({ length: 4 }, (_, i) =>
    api("/api/auth/signup", { method: "POST", body: { username: `openuser${i}`, password: "password123" } }),
  ));
  assert.ok(created.every((result) => result.status === 201), JSON.stringify(created.find((result) => result.status !== 201)));

  const removed = await api("/api/captcha");
  assert.equal(removed.status, 404);
});

test("signup, login and session round trip", async () => {
  const token = await signup("kers0ne");
  const me = await api("/api/auth/me", { token });
  assert.equal(me.status, 200);
  assert.equal(me.user.username, "kers0ne");
  assert.equal(me.profile.plan, "free");
  assert.equal(me.profile.email, null, "internal login address stays private");

  const login = await api("/api/auth/login", { method: "POST", body: { identifier: "kers0ne", password: "password123" } });
  assert.equal(login.status, 200);
  assert.ok(login.session.access_token);

  const wrong = await api("/api/auth/login", { method: "POST", body: { identifier: "kers0ne", password: "wrongpassword" } });
  assert.equal(wrong.status, 401);

  const anon = await api("/api/scripts");
  assert.equal(anon.status, 401);
});

test("creating a script obfuscates it and the loader actually runs", async () => {
  const token = await signup("builder");
  const created = await api("/api/scripts", { method: "POST", token, body: { name: "My script", source: SAMPLE, engine: "payload" } });
  assert.equal(created.status, 201, JSON.stringify(created));
  assert.equal(created.script.engine, "payload");
  assert.equal(created.script.engineName, "LuaLune Obfuscator");
  assert.ok(created.stats.buildId);
  assert.ok(created.loader.startsWith("loadstring(game:HttpGet("));

  const served = await api(`/loader/${created.script.id}`, { raw: true });
  assert.equal(served.status, 200);
  assert.ok(!served.text.includes("LuaLune works"), "protected source must not leak");
  const run = runLua(served.text);
  assert.ok(run.ok, `loader failed: ${run.error}`);
  assert.equal(run.output, "LUALUNE WORKS\ntick\t1\ntick\t2");
});

test("flow engine scripts are delivered readable-but-transformed and still run", async () => {
  const token = await signup("flowuser");
  const created = await api("/api/scripts", { method: "POST", token, body: { name: "Flow", source: SAMPLE, engine: "flow" } });
  assert.equal(created.status, 201);
  const served = await api(`/loader/${created.script.id}`, { raw: true });
  assert.ok(!served.text.includes('"LuaLune works"'), "strings must be encrypted");
  const run = runLua(served.text);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, "LUALUNE WORKS\ntick\t1\ntick\t2");

  const view = await api(`/api/scripts/${created.script.id}/view`, { token, raw: true });
  assert.equal(view.status, 200);
  assert.match(view.text, /LuaLune Obfuscator/);
});

test("free plan limits are enforced", async () => {
  const token = await signup("limited");
  for (let i = 0; i < 3; i++) {
    const res = await api("/api/scripts", { method: "POST", token, body: { name: `s${i}`, source: SAMPLE, engine: "payload" } });
    assert.equal(res.status, 201, JSON.stringify(res));
  }
  const tooMany = await api("/api/scripts", { method: "POST", token, body: { name: "s4", source: SAMPLE } });
  assert.equal(tooMany.status, 402);
  assert.match(tooMany.error, /limit reached/i);
  assert.equal(tooMany.upgrade, true);

  const logs = await api("/api/scripts", { token });
  const logRes = await api(`/api/scripts/${logs.scripts[0].id}/logs`, { token });
  assert.equal(logRes.status, 402, "execution logs are a paid feature");
});

test("key system gates the loader and writes execution logs", async () => {
  const token = await signup("keymaster");
  const created = await api("/api/scripts", { method: "POST", token, body: { name: "Gated", source: SAMPLE, engine: "payload", key_required: true } });
  assert.equal(created.status, 201);
  const id = created.script.id;

  const noKey = await api(`/loader/${id}`, { raw: true });
  assert.equal(noKey.status, 403);
  assert.match(noKey.text, /requires a key/);

  const keys = await api("/api/keys", { method: "POST", token, body: { duration: "1d", amount: 2, script_id: id, label: "beta" } });
  assert.equal(keys.status, 201);
  assert.equal(keys.keys.length, 2);
  const value = keys.keys[0].value;

  const withKey = await api(`/loader/${id}?key=${value}`, { raw: true });
  assert.equal(withKey.status, 200);
  assert.ok(runLua(withKey.text).ok);

  const badKey = await api(`/loader/${id}?key=LL-NOPE-NOPE`, { raw: true });
  assert.equal(badKey.status, 403);
  assert.match(badKey.text, /invalid key/);

  await store.updateProfile((await api("/api/auth/me", { token })).user.id, { plan: "premium" });
  const logs = await api(`/api/scripts/${id}/logs`, { token });
  assert.equal(logs.status, 200);
  const statuses = logs.logs.map((l) => l.status);
  assert.ok(statuses.includes("ok"), JSON.stringify(statuses));
  assert.ok(statuses.includes("denied"), JSON.stringify(statuses));
});

test("HWID whitelist binds a key to a device", async () => {
  const token = await signup("hwiduser");
  const created = await api("/api/scripts", { method: "POST", token, body: { name: "Bound", source: SAMPLE, key_required: true } });
  const id = created.script.id;
  const wl = await api("/api/whitelist", { method: "POST", token, body: { script_id: id, hwid: "device-abc-123", label: "main pc" } });
  assert.equal(wl.status, 201);
  const key = (await api("/api/keys", { method: "POST", token, body: { duration: "forever", script_id: id } })).keys[0];

  const first = await api(`/loader/${id}?key=${key.value}&hwid=device-abc-123`, { raw: true });
  assert.equal(first.status, 200);

  const other = await api(`/loader/${id}?key=${key.value}&hwid=device-other`, { raw: true });
  assert.equal(other.status, 403);
  assert.match(other.text, /another device/);

  const entries = await api(`/api/whitelist?script_id=${id}`, { token });
  assert.equal(entries.entries.length, 1);
  const removed = await api(`/api/whitelist/${entries.entries[0].id}?script_id=${id}`, { method: "DELETE", token });
  assert.equal(removed.status, 204);
});

test("invites upgrade plans and shares grant workspace access", async () => {
  const owner = await signup("owner");
  const mate = await signup("mate");

  const invite = await api("/api/invites", { method: "POST", token: owner, body: { kind: "plan", plan: "pro" } });
  assert.equal(invite.status, 201);
  const redeemed = await api("/api/invites/redeem", { method: "POST", token: mate, body: { code: invite.invite.code } });
  assert.equal(redeemed.status, 200);
  const mateMe = await api("/api/auth/me", { token: mate });
  assert.equal(mateMe.profile.plan, "pro");

  const script = await api("/api/scripts", { method: "POST", token: owner, body: { name: "Shared", source: SAMPLE } });
  const ownerMe = await api("/api/auth/me", { token: owner });
  const blockedShare = await api("/api/shares", { method: "POST", token: owner, body: { username: "mate", script_id: script.script.id } });
  assert.equal(blockedShare.status, 402, "workspace sharing is a paid feature");
  await store.updateProfile(ownerMe.user.id, { plan: "pro" });
  const share = await api("/api/shares", { method: "POST", token: owner, body: { username: "mate", script_id: script.script.id } });
  assert.equal(share.status, 201);

  const mateScripts = await api("/api/scripts", { token: mate });
  assert.equal(mateScripts.shared.length, 1);
  const readable = await api(`/api/scripts/${script.script.id}`, { token: mate });
  assert.equal(readable.status, 200);
  const notOwner = await api(`/api/scripts/${script.script.id}`, { method: "DELETE", token: mate });
  assert.equal(notOwner.status, 404, "shared access is read only");
});

test("rebuilding keeps the loader URL and rotates the build", async () => {
  const token = await signup("rebuilder");
  const created = await api("/api/scripts", { method: "POST", token, body: { name: "Rotate", source: SAMPLE } });
  const id = created.script.id;
  const rebuilt = await api(`/api/scripts/${id}/rebuild`, { method: "POST", token, body: { source: SAMPLE + 'print("extra")\n', engine: "flow" } });
  assert.equal(rebuilt.status, 200);
  assert.notEqual(rebuilt.stats.buildId, created.stats.buildId);
  assert.equal(rebuilt.script.engine, "flow");
  const served = await api(`/loader/${id}`, { raw: true });
  const run = runLua(served.text);
  assert.ok(run.ok, run.error);
  assert.match(run.output, /extra/, "rebuilt source should run");
});

test("admin can read stats, change plans and broadcast", async () => {
  const token = await signup("rootadmin");
  const me = await api("/api/auth/me", { token });
  await store.updateProfile(me.user.id, { role: "admin" });

  const denied = await api("/api/admin/stats", { token: await signup("notadmin") });
  assert.equal(denied.status, 403);

  const stats = await api("/api/admin/stats", { token });
  assert.equal(stats.status, 200);
  assert.ok(stats.stats.users >= 5);

  const users = await api("/api/admin/users", { token });
  assert.ok(users.users.length >= 5);

  const target = users.users.find((u) => u.username === "limited");
  const upgraded = await api(`/api/admin/users/${target.id}`, { method: "PATCH", token, body: { plan: "premium" } });
  assert.equal(upgraded.profile.plan, "premium");

  const suspended = await api(`/api/admin/users/${target.id}`, { method: "PATCH", token, body: { status: "suspended", suspended_until: new Date(Date.now() + 60000).toISOString(), reason: "testing" } });
  assert.equal(suspended.profile.status, "suspended");

  const broadcast = await api("/api/admin/announcements", { method: "POST", token, body: { title: "Build 2.0 is live", body: "New LuaLune Obfuscator engines.", level: "info" } });
  assert.equal(broadcast.status, 201);
  const publicList = await api("/api/announcements");
  assert.equal(publicList.announcements.length, 1);
  assert.equal(publicList.announcements[0].title, "Build 2.0 is live");
});

test("suspended accounts are locked out", async () => {
  const token = await signup("suspendeduser");
  const me = await api("/api/auth/me", { token });
  await store.updateProfile(me.user.id, { status: "suspended", suspended_until: new Date(Date.now() + 60000).toISOString() });
  const res = await api("/api/scripts", { token });
  assert.equal(res.status, 423);
});

test("terms updates must be accepted before building", async () => {
  const token = await signup("tosuser");
  const me = await api("/api/auth/me", { token });
  await store.updateProfile(me.user.id, { tos_version: "2000-01-01" });
  const blocked = await api("/api/scripts", { method: "POST", token, body: { name: "x", source: SAMPLE } });
  assert.equal(blocked.status, 428);
  const accepted = await api("/api/tos/accept", { method: "POST", token, body: { version: TOS_VERSION } });
  assert.equal(accepted.status, 200);
  const after = await api("/api/scripts", { method: "POST", token, body: { name: "x", source: SAMPLE } });
  assert.equal(after.status, 201);
});

test("the gold dashboard is served with the LuaLune brand and no discord links", async () => {
  const page = await fetch(`${base}/`);
  const html = await page.text();
  assert.equal(page.status, 200);
  assert.match(html, /LuaLune Obfuscator/);
  assert.match(html, /\/styles\.css/);
  assert.match(html, /\/logo-256\.png/, "hero logo missing");
  assert.match(html, /\/logo-64\.png/, "nav logo missing");
  assert.ok(!/discord/i.test(html), "discord must not appear in the app");

  const css = await (await fetch(`${base}/styles.css`)).text();
  assert.match(css, /#f5c542/, "gold accent missing");

  const logo = await fetch(`${base}/logo.png`);
  assert.equal(logo.status, 200);
  assert.match(logo.headers.get("content-type") || "", /image\/png/);

  const meta = await (await fetch(`${base}/api/meta`)).json();
  assert.ok(meta.engines.some((e) => e.id === "lune" && e.available === false), "an uninstalled optional engine must report itself as unavailable");
  assert.ok(meta.engines.filter((e) => !e.external).every((e) => e.available), "built in engines are always available");

  const manifest = await (await fetch(`${base}/manifest.json`)).json();
  assert.match(manifest.name, /LuaLune/);
  assert.equal(manifest.theme_color, "#f5c542");
});

test("unknown routes fall back to the app, api routes 404 as json", async () => {
  const page = await fetch(`${base}/dashboard/plans`);
  assert.equal(page.status, 200);
  assert.match(await page.text(), /LuaLune/);
  const missing = await api("/api/nope");
  assert.equal(missing.status, 404);
});
