import test from "node:test";
import assert from "node:assert/strict";

process.env.NODE_ENV = "test";
process.env.SUPABASE_URL = "";
process.env.SUPABASE_ANON_KEY = "";
process.env.LUALUNE_DATA_DIR = (await import("node:fs")).mkdtempSync((await import("node:os")).tmpdir() + "/lualune-test-");

const lune = await import("../lib/lune.js");
const { app, store } = await import("../server.js");
const { syntaxCheck } = await import("./luavm.js");

let server;
let base;

test.before(async () => {
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});
test.after(() => server?.close());

test("the Lune Obfuscator engine reports itself as unavailable without the bundle", async () => {
  assert.equal(await lune.available(), false, "no vendor/prometheus in this checkout");
  assert.match(lune.unavailableReason(), /not installed|vendor|wasmoon/i);
  await assert.rejects(() => lune.obfuscate("print(1)"), /Lune Obfuscator/);
});

test("the attribution and profile mapping match the engine contract", () => {
  assert.match(lune.ATTRIBUTION, /Prometheus/);
  assert.match(lune.ATTRIBUTION, /prometheus-lua\/Prometheus/);
});

test("the anti-tamper wrapper is valid Lua and preserves the script", () => {
  const source = 'local x = 1\nprint("wrapped", x)\n';
  const wrapped = lune.wrapWithAntiTamper(source);
  assert.ok(wrapped.includes(source), "original source must be inside the wrapper");
  assert.match(wrapped, /__ll_verify/);
  assert.match(wrapped, /GetService\("Players"\)/);
  const parsed = syntaxCheck(wrapped);
  assert.ok(parsed.ok, "wrapper is not valid Lua: " + parsed.error);
});

test("asking for the Lune engine falls back to Vault with a clear warning", async () => {
  const challenge = await (await fetch(`${base}/api/captcha`)).json();
  const solved = await (await fetch(`${base}/api/captcha/solve`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(challenge) })).json();
  const signup = await (await fetch(`${base}/api/auth/signup`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "luneuser", password: "password123", captcha: challenge.challenge, captchaNonce: solved.nonce }),
  })).json();
  const token = signup.session.access_token;

  const built = await (await fetch(`${base}/api/scripts`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
    body: JSON.stringify({ name: "lune request", engine: "lune", source: 'print("fallback works")\n' }),
  })).json();

  assert.equal(built.script.engine, "vault", "fallback engine should be vault");
  assert.equal(built.script.engineName, "LuaLune Obfuscator - Vault");
  assert.equal(built.warnings.length, 1);
  assert.match(built.warnings[0], /Lune Obfuscator engine is not installed/);

  // and the build it produced still works
  const served = await (await fetch(`${base}/loader/${built.script.id}`)).text();
  const { runLua } = await import("./luavm.js");
  const run = runLua(served);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, "fallback works");

  await store.updateProfile(signup.user.id, { plan: "premium" });
});
