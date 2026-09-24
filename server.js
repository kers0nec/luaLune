/**
 * LuaLune API + static host.
 *
 * Everything the dashboard talks to lives here. Routes are thin: limits come
 * from lib/plans, protection comes from lib/obfuscator, storage from lib/store.
 */
import express from "express";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { obfuscate, ENGINES } from "./lib/obfuscator.js";
import * as lune from "./lib/lune.js";
import { buildLoader, denialLoader, loaderSnippet } from "./lib/loader.js";
import { PLANS, planFor, limit, checkLimit, monthKey, publicPlans } from "./lib/plans.js";
import { issueChallenge, verifyChallenge, solve } from "./lib/captcha.js";
import { TOS_VERSION, tosSummary } from "./lib/tos.js";
import { createStore } from "./lib/store.js";
import { createAuth, normalizeUsername, isLocalEmail } from "./lib/auth.js";
import { createLimiter } from "./lib/ratelimit.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const store = createStore();
const auth = createAuth({ store });

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);
app.use(express.json({ limit: "4mb" }));
app.use(express.text({ limit: "4mb", type: ["text/plain", "application/x-lua"] }));

// Rate limits: sign-in attempts are cheap to spam, so they get the tightest budget.
// The loader answers plain text (an executor cannot read JSON), so it is handed a
// denial stub instead when a client floods it.
const authLimiter = createLimiter({ windowMs: 10 * 60_000, max: Number(process.env.LUALUNE_RATE_AUTH || 60), message: "Too many sign-in attempts. Wait a few minutes." });
const buildLimiter = createLimiter({ windowMs: 60_000, max: Number(process.env.LUALUNE_RATE_BUILD || 30), message: "Slow down: too many builds per minute." });
const loaderLimiter = createLimiter({
  windowMs: 60_000,
  max: Number(process.env.LUALUNE_RATE_LOADER || 240),
  message: "Too many loader requests.",
  onLimit: (req, res, retryAfter) => res.status(429).type("text/plain").send(denialLoader({ reason: `too many requests, retry in ${retryAfter}s`, scriptId: req.params.id, code: "rate_limited" })),
});

const BRAND = {
  name: "LuaLune",
  product: "LuaLune Obfuscator",
  domain: process.env.LUALUNE_DOMAIN || "lualune.onrender.com",
  logo: "/logo.png",
  accent: "#f5c542",
  store: store.kind,
  auth: auth.mode,
  tosVersion: TOS_VERSION,
};

/* ------------------------------------------------------------- helpers */

const fail = (res, status, message, extra = {}) => res.status(status).json({ error: message, ...extra });

function bearer(req) {
  const header = req.headers.authorization || "";
  return header.startsWith("Bearer ") ? header.slice(7) : null;
}

async function authed(req, res, next) {
  const token = bearer(req);
  if (!token) return fail(res, 401, "Authentication required.");
  const user = await auth.verify(token);
  if (!user) return fail(res, 401, "Session expired. Sign in again.");
  const profile = await store.getProfile(user.id);
  if (!profile) return fail(res, 401, "Account profile missing. Sign in again.");
  if (profile.status === "terminated") return fail(res, 403, "This account has been terminated for violating the Terms of Service.");
  if (profile.status === "suspended" && profile.suspended_until && new Date(profile.suspended_until) > new Date()) {
    return fail(res, 423, "Account suspended.", { suspendedUntil: profile.suspended_until, reason: profile.suspension_reason || null });
  }
  req.token = token;
  req.user = user;
  req.profile = profile;
  req.plan = profile.plan || "free";
  next();
}

function adminOnly(req, res, next) {
  const admins = String(process.env.LUALUNE_ADMINS || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const isAdmin = req.profile?.role === "admin" ||
    admins.includes(String(req.user?.username || "").toLowerCase()) ||
    admins.includes(String(req.user?.email || "").toLowerCase());
  if (!isAdmin) return fail(res, 403, "Admin access required.");
  next();
}

/**
 * Build a protected script. The optional Lune Obfuscator engine (Prometheus in a
 * WASM VM) is used when it is installed; otherwise the same request is served by
 * LuaLune's own Vault engine and the response says so.
 */
async function buildProtected(source, options) {
  if (options.engine !== "lune") return obfuscate(source, options);
  if (await lune.available()) {
    const code = await lune.obfuscate(source, { preset: options.preset || "medium", antiTamper: options.harden !== false });
    return {
      code,
      engine: "lune",
      warnings: [],
      stats: {
        engine: "lune",
        engineName: ENGINES.lune.name,
        buildId: crypto.randomBytes(6).toString("hex"),
        sourceBytes: Buffer.byteLength(source, "utf8"),
        outputBytes: Buffer.byteLength(code, "utf8"),
        ratio: +(Buffer.byteLength(code) / Math.max(1, Buffer.byteLength(source, "utf8"))).toFixed(2),
        passes: ["ast-transform", "anti-tamper"],
      },
    };
  }
  const built = obfuscate(source, { ...options, engine: "vault" });
  built.warnings = [
    ...built.warnings,
    "The Lune Obfuscator engine is not installed on this instance, so this build was made with LuaLune Obfuscator - Vault instead.",
  ];
  return built;
}

function obfuscatorOptions(req) {
  const engine = ENGINES[req.body?.engine] ? req.body.engine : "payload";
  return {
    engine,
    rename: req.body?.rename !== false,
    strings: req.body?.strings !== false,
    numbers: req.body?.numbers !== false,
    junk: req.body?.junk !== false,
    flatten: req.body?.flatten !== false,
    harden: req.body?.harden !== false,
    preset: ["minify", "weak", "light", "medium", "balanced", "strong", "heavy", "maximum"].includes(String(req.body?.preset || "").toLowerCase())
      ? String(req.body.preset).toLowerCase()
      : "medium",
  };
}

const keyFor = (req) => {
  const raw = String(req.query?.key || req.headers["x-lualune-key"] || "").trim();
  return raw || null;
};

const ipHash = (req) => crypto.createHash("sha256").update(String(req.ip || "") + "|" + BRAND.domain).digest("hex").slice(0, 16);

async function ensureTos(req, res) {
  if (req.profile.tos_version === TOS_VERSION) return true;
  fail(res, 428, "Terms of Service updated. Accept the new terms to continue.", { tos: tosSummary() });
  return false;
}

/* ----------------------------------------------------------- public meta */

app.get("/healthz", (_, res) => res.type("text").send("LuaLune OK\n"));

app.get("/api/meta", async (_, res) => {
  const luneReady = await lune.available();
  res.json({
    ...BRAND,
    authAutoConfirm: auth.adminReady,
    engines: Object.values(ENGINES).map((engine) => ({
      ...engine,
      available: engine.external ? luneReady : true,
      ...(engine.external && !luneReady ? { unavailableReason: lune.unavailableReason() } : {}),
    })),
    plans: publicPlans(),
    tosVersion: TOS_VERSION,
  });
});

app.get("/api/plans", (_, res) => res.json({ plans: publicPlans(), billing: "one-time payment" }));

app.get("/api/tos", (_, res) => res.json(tosSummary()));

app.get("/api/announcements", async (_, res) => {
  const items = await store.listAnnouncements();
  res.json({ announcements: items.map(({ id, title, body, level, created_at, expires_at }) => ({ id, title, body, level, created_at, expires_at })) });
});

/* --------------------------------------------------------------- captcha */

app.get("/api/captcha", (req, res) => {
  const difficulty = Number(req.query.difficulty) || 16;
  res.json(issueChallenge({ difficulty: Math.min(Math.max(difficulty, 8), 20) }));
});

/** Server-side solve endpoint, used by tests and by headless clients. */
app.post("/api/captcha/solve", (req, res) => {
  const { challenge, difficulty } = req.body || {};
  if (!challenge) return fail(res, 400, "Challenge required.");
  res.json(solve(challenge, difficulty || 16));
});

/* ------------------------------------------------------------------ auth */

app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const { username, email, password, redirectTo } = req.body || {};
  const captcha = verifyChallenge(req.body?.captcha, req.body?.captchaNonce, {});
  if (!captcha.ok) return fail(res, 400, captcha.reason);

  let result;
  try {
    result = await auth.signup({ username, email, password, redirectTo });
  } catch (e) {
    console.error("signup failed:", e.message);
    return fail(res, 502, "Could not create the account — the auth backend is unreachable or misconfigured. Check SUPABASE_URL / SUPABASE_ANON_KEY / SUPABASE_SERVICE_ROLE_KEY.");
  }
  if (result.error) return fail(res, 400, result.error);
  try {
    await store.acceptTos(result.user.id, TOS_VERSION);
    await store.updateProfile(result.user.id, { tos_version: TOS_VERSION });
  } catch (e) {
    // The account exists; profile housekeeping can be retried on next login.
    console.error("signup profile sync failed:", e.message);
  }
  res.status(201).json(result);
});

app.post("/api/auth/reset-password", authLimiter, async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const redirectTo = String(req.body?.redirectTo || process.env.LUALUNE_AUTH_REDIRECT || "");
  const result = await auth.resetPassword(email, redirectTo || undefined);
  if (result.error) return fail(res, 400, result.error);
  res.json({ ok: true, message: "If an account exists for that email, a password reset email has been sent." });
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  const { identifier, username, email, password } = req.body || {};
  const result = await auth.login({ identifier: identifier || username || email, password });
  if (result.error) return fail(res, 401, result.error);
  const profile = await store.getProfile(result.user.id);
  if (profile?.status === "terminated") return fail(res, 403, "This account has been terminated.");
  res.json({
    ...result,
    profile: profile ? publicProfile(profile) : null,
    tosUpdateRequired: profile?.tos_version !== TOS_VERSION,
  });
});

app.post("/api/auth/update-password", async (req, res) => {
  const token = bearer(req);
  if (!token) return fail(res, 401, "Reset session expired. Request a new reset email.");
  const password = String(req.body?.password || "");
  const result = await auth.updatePassword(token, password);
  if (result.error) return fail(res, 400, result.error);
  res.json({ ok: true });
});

app.get("/api/auth/me", authed, async (req, res) => {
  const usage = await store.getUsage(req.user.id);
  res.json({
    user: req.user,
    profile: publicProfile(req.profile),
    usage: { ...usage, limit: limit(req.plan, "obfuscationsPerMonth") },
    tosUpdateRequired: req.profile.tos_version !== TOS_VERSION,
  });
});

app.post("/api/auth/logout", async (req, res) => {
  await auth.logout(bearer(req));
  res.status(204).end();
});

app.post("/api/tos/accept", authed, async (req, res) => {
  if (String(req.body?.version || TOS_VERSION) !== TOS_VERSION) return fail(res, 400, "Unknown terms version.");
  await store.acceptTos(req.user.id, TOS_VERSION);
  await store.updateProfile(req.user.id, { tos_version: TOS_VERSION });
  res.json({ ok: true, version: TOS_VERSION });
});

function publicProfile(profile) {
  return {
    id: profile.id,
    username: profile.username,
    email: isLocalEmail(profile.email) ? null : profile.email,
    plan: profile.plan || "free",
    role: profile.role || "user",
    status: profile.status || "active",
    suspended_until: profile.suspended_until || null,
    tos_version: profile.tos_version || null,
    created_at: profile.created_at,
  };
}

/* --------------------------------------------------------------- scripts */

app.get("/api/scripts", authed, async (req, res) => {
  const [scripts, shared] = await Promise.all([
    store.listScripts(req.user.id),
    store.listSharesWith(req.user.username),
  ]);
  res.json({
    scripts: scripts.map(scriptSummary),
    shared: shared.map((s) => ({ ...s })),
    usage: await store.getUsage(req.user.id),
  });
});

app.post("/api/scripts", authed, buildLimiter, async (req, res) => {
  if (!(await ensureTos(req, res))) return;
  const name = String(req.body?.name || "").trim() || `script-${Date.now().toString(36)}`;
  const source = typeof req.body?.source === "string" ? req.body.source : "";
  if (name.length < 1 || name.length > 80) return fail(res, 400, "Name must be 1-80 characters.");
  if (source.length < 1) return fail(res, 400, "Script source is required.");
  if (Buffer.byteLength(source) > 2 * 1024 * 1024) return fail(res, 400, "Script must be under 2 MB.");

  const options = obfuscatorOptions(req);
  const count = await store.countScripts(req.user.id);
  const scriptsCheck = checkLimit(req.plan, "scripts", count);
  if (!scriptsCheck.allowed) return fail(res, 402, scriptsCheck.reason, { upgrade: true });
  const usage = await store.getUsage(req.user.id);
  const usageCheck = checkLimit(req.plan, "obfuscationsPerMonth", 0, usage.month, usage);
  if (!usageCheck.allowed) return fail(res, 402, usageCheck.reason, { upgrade: true });

  let built;
  try {
    built = await buildProtected(source, options);
  } catch (err) {
    return fail(res, 400, err.message || "Failed to obfuscate script.");
  }
  const script = await store.createScript({
    owner_id: req.user.id,
    name,
    engine: built.engine,
    build_id: built.stats.buildId,
    code: built.code,
    source_bytes: built.stats.sourceBytes,
    output_bytes: built.stats.outputBytes,
    key_required: !!req.body?.key_required,
    public: req.body?.public !== false,
    warnings: built.warnings,
  });
  await store.bumpUsage(req.user.id);

  res.status(201).json({
    script: scriptSummary(script),
    stats: built.stats,
    warnings: built.warnings,
    loader: loaderSnippet({ origin: originOf(req), scriptId: script.id }),
  });
});

app.get("/api/scripts/:id", authed, async (req, res) => {
  const script = await store.getScript(req.params.id);
  if (!script) return fail(res, 404, "Script not found.");
  const shared = (await store.listSharesWith(req.user.username)).some((s) => s.script_id === script.id);
  if (script.owner_id !== req.user.id && !shared) return fail(res, 403, "Not your script.");
  res.json({ script: { ...scriptSummary(script), warnings: script.warnings || [], stats: { sourceBytes: script.source_bytes, outputBytes: script.output_bytes, buildId: script.build_id } } });
});

/** Re-run the obfuscator over new source for the same script (keeps the loader URL). */
app.post("/api/scripts/:id/rebuild", authed, buildLimiter, async (req, res) => {
  if (!(await ensureTos(req, res))) return;
  const script = await store.getScript(req.params.id);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  const source = typeof req.body?.source === "string" ? req.body.source : "";
  if (!source) return fail(res, 400, "Script source is required.");
  if (Buffer.byteLength(source) > 2 * 1024 * 1024) return fail(res, 400, "Script must be under 2 MB.");

  const usage = await store.getUsage(req.user.id);
  const usageCheck = checkLimit(req.plan, "obfuscationsPerMonth", 0, usage.month, usage);
  if (!usageCheck.allowed) return fail(res, 402, usageCheck.reason, { upgrade: true });

  let built;
  try {
    built = await buildProtected(source, obfuscatorOptions(req));
  } catch (err) {
    return fail(res, 400, err.message || "Failed to rebuild script.");
  }
  const updated = await store.updateScript(script.id, {
    engine: built.engine,
    build_id: built.stats.buildId,
    code: built.code,
    source_bytes: built.stats.sourceBytes,
    output_bytes: built.stats.outputBytes,
    warnings: built.warnings,
    ...(req.body?.name ? { name: String(req.body.name).slice(0, 80) } : {}),
    ...(req.body?.key_required === undefined ? {} : { key_required: !!req.body.key_required }),
    ...(req.body?.public === undefined ? {} : { public: !!req.body.public }),
  });
  await store.bumpUsage(req.user.id);
  res.json({ script: scriptSummary(updated), stats: built.stats, warnings: built.warnings });
});

app.patch("/api/scripts/:id", authed, async (req, res) => {
  const script = await store.getScript(req.params.id);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  const patch = {};
  if (req.body?.name !== undefined) {
    const name = String(req.body.name).trim();
    if (!name || name.length > 80) return fail(res, 400, "Name must be 1-80 characters.");
    patch.name = name;
  }
  if (req.body?.key_required !== undefined) patch.key_required = !!req.body.key_required;
  if (req.body?.public !== undefined) patch.public = !!req.body.public;
  const updated = await store.updateScript(script.id, patch);
  res.json({ script: scriptSummary(updated) });
});

app.delete("/api/scripts/:id", authed, async (req, res) => {
  const script = await store.getScript(req.params.id);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  await store.deleteScript(script.id);
  res.status(204).end();
});

app.get("/api/scripts/:id/view", authed, async (req, res) => {
  const script = await store.getScript(req.params.id);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  res.type("text/plain").send(buildLoader({
    code: script.code,
    name: script.name,
    buildId: script.build_id,
    engine: script.engine,
    scriptId: script.id,
    engineName: ENGINES[script.engine]?.name,
  }));
});

app.get("/api/scripts/:id/logs", authed, async (req, res) => {
  const script = await store.getScript(req.params.id);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  if (req.plan === "free") return fail(res, 402, "Execution logs are available on Pro and Premium.", { upgrade: true });
  const logs = await store.listLogs(script.id, Math.min(Number(req.query.limit) || 25, 100));
  res.json({ logs });
});

function scriptSummary(script) {
  return {
    id: script.id,
    name: script.name,
    engine: script.engine,
    engineName: ENGINES[script.engine]?.name || script.engine,
    build_id: script.build_id,
    source_bytes: script.source_bytes,
    output_bytes: script.output_bytes,
    key_required: !!script.key_required,
    public: script.public !== false,
    created_at: script.created_at,
    updated_at: script.updated_at,
  };
}

/* ------------------------------------------------------------------ keys */

const KEY_DURATIONS = [
  { id: "test", label: "30 seconds (test)", seconds: 30 },
  { id: "1d", label: "1 day", seconds: 86400 },
  { id: "3d", label: "3 days", seconds: 86400 * 3 },
  { id: "7d", label: "7 days", seconds: 86400 * 7 },
  { id: "30d", label: "30 days", seconds: 86400 * 30 },
  { id: "forever", label: "Forever", seconds: null },
];

function makeKeyValue(prefix = "LL") {
  return `${prefix}-${crypto.randomBytes(4).toString("hex").toUpperCase()}-${crypto.randomBytes(4).toString("hex").toUpperCase()}`;
}

const keyState = (key) => {
  if (key.expires_at && new Date(key.expires_at) < new Date()) return "expired";
  return "active";
};

app.get("/api/keys", authed, async (req, res) => {
  const keys = await store.listKeys(req.user.id);
  res.json({
    durations: KEY_DURATIONS,
    keys: keys.map((k) => ({ ...k, state: keyState(k) })),
  });
});

app.post("/api/keys", authed, async (req, res) => {
  const count = await store.countKeys(req.user.id);
  const check = checkLimit(req.plan, "keys", count);
  if (!check.allowed) return fail(res, 402, check.reason, { upgrade: true });

  const duration = KEY_DURATIONS.find((d) => d.id === req.body?.duration) || KEY_DURATIONS[1];
  const amount = Math.min(Math.max(Number(req.body?.amount) || 1, 1), 50);
  const scriptId = req.body?.script_id || null;
  if (scriptId) {
    const script = await store.getScript(scriptId);
    if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  }

  const created = [];
  for (let i = 0; i < amount; i++) {
    created.push(await store.createKey({
      owner_id: req.user.id,
      script_id: scriptId,
      value: req.body?.value ? `${String(req.body.value).slice(0, 40)}-${i + 1}` : makeKeyValue(),
      label: String(req.body?.label || "").slice(0, 60),
      duration_seconds: duration.seconds,
      expires_at: duration.seconds ? new Date(Date.now() + duration.seconds * 1000).toISOString() : null,
    }));
  }
  res.status(201).json({ keys: created.map((k) => ({ ...k, state: keyState(k) })), durations: KEY_DURATIONS });
});

app.post("/api/keys/:id/reset", authed, async (req, res) => {
  const keys = await store.listKeys(req.user.id);
  const key = keys.find((k) => k.id === req.params.id);
  if (!key) return fail(res, 404, "Key not found.");
  const updated = await store.updateKey(key.id, { hwid: null, uses: 0 });
  res.json({ key: { ...updated, state: keyState(updated) } });
});

app.delete("/api/keys/:id", authed, async (req, res) => {
  const keys = await store.listKeys(req.user.id);
  if (!keys.some((k) => k.id === req.params.id)) return fail(res, 404, "Key not found.");
  await store.deleteKey(req.params.id);
  res.status(204).end();
});

/* ------------------------------------------------------------- whitelist */

app.get("/api/whitelist", authed, async (req, res) => {
  const scriptId = String(req.query.script_id || "");
  const script = await store.getScript(scriptId);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  const entries = await store.listWhitelist(scriptId);
  res.json({ entries, limit: limit(req.plan, "whitelistPerScript") });
});

app.post("/api/whitelist", authed, async (req, res) => {
  const scriptId = String(req.body?.script_id || "");
  const script = await store.getScript(scriptId);
  if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  const hwid = String(req.body?.hwid || "").trim();
  if (hwid.length < 4 || hwid.length > 128) return fail(res, 400, "HWID must be 4-128 characters.");
  const current = await store.countWhitelist(scriptId);
  const check = checkLimit(req.plan, "whitelistPerScript", current);
  if (!check.allowed) return fail(res, 402, check.reason, { upgrade: true });
  const entry = await store.addWhitelist({ script_id: scriptId, owner_id: req.user.id, hwid, label: String(req.body?.label || "").slice(0, 60) });
  res.status(201).json({ entry });
});

app.delete("/api/whitelist/:id", authed, async (req, res) => {
  const entries = await store.listWhitelist(String(req.query.script_id || req.body?.script_id || ""));
  if (!entries.some((e) => e.id === req.params.id)) return fail(res, 404, "Entry not found.");
  await store.removeWhitelist(req.params.id);
  res.status(204).end();
});

/* ------------------------------------------------------- invites/sharing */

function inviteCode() {
  return `LL-${crypto.randomBytes(3).toString("hex").toUpperCase()}-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
}

app.get("/api/invites", authed, async (req, res) => {
  const invites = await store.listInvites(req.user.id);
  res.json({ invites });
});

app.post("/api/invites", authed, async (req, res) => {
  const kind = req.body?.kind === "plan" ? "plan" : "workspace";
  const invite = await store.createInvite({
    owner_id: req.user.id,
    code: inviteCode(),
    kind,
    plan: kind === "plan" && PLANS[req.body?.plan] ? req.body.plan : null,
    max_uses: Math.min(Math.max(Number(req.body?.max_uses) || 1, 1), 100),
  });
  res.status(201).json({ invite });
});

app.delete("/api/invites/:id", authed, async (req, res) => {
  const invites = await store.listInvites(req.user.id);
  if (!invites.some((i) => i.id === req.params.id)) return fail(res, 404, "Invite not found.");
  await store.deleteInvite(req.params.id);
  res.status(204).end();
});

app.post("/api/invites/redeem", authed, async (req, res) => {
  const code = String(req.body?.code || "").trim().toUpperCase();
  const invite = await store.getInviteByCode(code);
  if (!invite) return fail(res, 404, "That invite code is not valid.");
  if (invite.uses >= (invite.max_uses || 1)) return fail(res, 409, "That invite code has been used up.");
  if (invite.kind === "plan" && invite.plan) {
    await store.updateProfile(req.user.id, { plan: invite.plan });
    await store.useInvite(code, req.user.id);
    return res.json({ ok: true, plan: invite.plan, message: `Invite applied. You are on the ${planFor(invite.plan).name} plan.` });
  }
  const share = await store.createShare({
    owner_id: invite.owner_id,
    owner_username: req.profile.username,
    script_id: req.body?.script_id || null,
    shared_with: req.user.username,
  });
  await store.useInvite(code, req.user.id);
  res.json({ ok: true, share, message: "Workspace access granted." });
});

app.get("/api/shares", authed, async (req, res) => {
  const [mine, withMe] = await Promise.all([store.listSharesByOwner(req.user.id), store.listSharesWith(req.user.username)]);
  res.json({ mine, withMe });
});

app.post("/api/shares", authed, async (req, res) => {
  const target = normalizeUsername(req.body?.username);
  if (!target) return fail(res, 400, "Enter a username to share with.");
  if (target === req.user.username) return fail(res, 400, "That is your own account.");
  const current = await store.listSharesByOwner(req.user.id);
  const check = checkLimit(req.plan, "shares", current.length);
  if (!check.allowed) return fail(res, 402, check.reason, { upgrade: true });
  const scriptId = req.body?.script_id || null;
  if (scriptId) {
    const script = await store.getScript(scriptId);
    if (!script || script.owner_id !== req.user.id) return fail(res, 404, "Script not found.");
  }
  const share = await store.createShare({ owner_id: req.user.id, owner_username: req.user.username, script_id: scriptId, shared_with: target });
  res.status(201).json({ share });
});

app.delete("/api/shares/:id", authed, async (req, res) => {
  const [mine, withMe] = await Promise.all([store.listSharesByOwner(req.user.id), store.listSharesWith(req.user.username)]);
  const mine_match = mine.find((s) => s.id === req.params.id);
  const withMe_match = withMe.find((s) => s.id === req.params.id);
  if (!mine_match && !withMe_match) return fail(res, 404, "Share not found.");
  await store.deleteShare(req.params.id);
  res.status(204).end();
});

/* ----------------------------------------------------------------- admin */

app.get("/api/admin/stats", authed, adminOnly, async (_, res) => {
  const stats = await store.stats();
  res.json({ stats, store: store.kind, auth: auth.mode, month: monthKey() });
});

app.get("/api/admin/users", authed, adminOnly, async (req, res) => {
  const users = await store.listProfiles({ limit: 100, search: String(req.query.search || "") });
  res.json({ users: users.map(publicProfile) });
});

app.patch("/api/admin/users/:id", authed, adminOnly, async (req, res) => {
  const patch = {};
  if (PLANS[req.body?.plan]) patch.plan = req.body.plan;
  if (["active", "suspended", "terminated"].includes(req.body?.status)) {
    patch.status = req.body.status;
    patch.suspended_until = req.body?.suspended_until || null;
    patch.suspension_reason = req.body?.reason || null;
  }
  if (req.body?.role) patch.role = req.body.role === "admin" ? "admin" : "user";
  const profile = await store.updateProfile(req.params.id, patch);
  if (!profile) return fail(res, 404, "User not found.");
  res.json({ profile: publicProfile(profile) });
});

app.post("/api/admin/announcements", authed, adminOnly, async (req, res) => {
  const title = String(req.body?.title || "").trim().slice(0, 120);
  const body = String(req.body?.body || "").trim().slice(0, 2000);
  if (!title || !body) return fail(res, 400, "Title and body are required.");
  const item = await store.createAnnouncement({ title, body, level: req.body?.level || "info", expires_at: req.body?.expires_at || null });
  res.status(201).json({ announcement: item });
});

app.delete("/api/admin/announcements/:id", authed, adminOnly, async (req, res) => {
  await store.deleteAnnouncement(req.params.id);
  res.status(204).end();
});

/* ---------------------------------------------------------------- loader */

app.get("/loader/:id", loaderLimiter, async (req, res) => {

  const script = await store.getPublicScript(req.params.id);
  if (!script) {
    return res.status(404).type("text/plain").send(denialLoader({ reason: "script not found", scriptId: req.params.id, code: "not_found" }));
  }

  const key = keyFor(req);
  const hwid = String(req.query?.hwid || "").trim() || null;
  const logBase = { script_id: script.id, owner_id: script.owner_id, ip_hash: ipHash(req), user_agent: String(req.headers["user-agent"] || "").slice(0, 200), hwid, key_value: key };

  const deliver = async () => {
    await store.addLog({ ...logBase, status: "ok" }).catch(() => {});
    res.type("text/plain").send(buildLoader({
      code: script.code,
      name: script.name,
      buildId: script.build_id,
      engine: script.engine,
      scriptId: script.id,
      engineName: ENGINES[script.engine]?.name,
    }));
  };

  if (!script.key_required) return deliver();

  if (!key) {
    await store.addLog({ ...logBase, status: "denied", code: "missing_key" }).catch(() => {});
    return res.status(403).type("text/plain").send(denialLoader({ reason: "this script requires a key", scriptId: script.id, code: "missing_key" }));
  }

  const record = await store.getKeyByValue(key);
  if (!record || record.owner_id !== script.owner_id) {
    await store.addLog({ ...logBase, status: "denied", code: "invalid_key" }).catch(() => {});
    return res.status(403).type("text/plain").send(denialLoader({ reason: "invalid key", scriptId: script.id, code: "invalid_key" }));
  }
  if (record.script_id && record.script_id !== script.id) {
    await store.addLog({ ...logBase, status: "denied", code: "key_script_mismatch" }).catch(() => {});
    return res.status(403).type("text/plain").send(denialLoader({ reason: "key is bound to another script", scriptId: script.id, code: "key_script_mismatch" }));
  }
  if (keyState(record) === "expired") {
    await store.addLog({ ...logBase, status: "denied", code: "expired_key" }).catch(() => {});
    return res.status(403).type("text/plain").send(denialLoader({ reason: "key expired", scriptId: script.id, code: "expired_key" }));
  }

  const whitelist = await store.listWhitelist(script.id);
  if (whitelist.length) {
    if (record.hwid && record.hwid !== hwid) {
      await store.addLog({ ...logBase, status: "denied", code: "hwid_mismatch" }).catch(() => {});
      return res.status(403).type("text/plain").send(denialLoader({ reason: "key is bound to another device", scriptId: script.id, code: "hwid_mismatch" }));
    }
    if (!record.hwid && hwid && !whitelist.some((w) => w.hwid === hwid)) {
      await store.addLog({ ...logBase, status: "denied", code: "hwid_not_listed" }).catch(() => {});
      return res.status(403).type("text/plain").send(denialLoader({ reason: "device is not whitelisted", scriptId: script.id, code: "hwid_not_listed" }));
    }
    if (!record.hwid && hwid) await store.updateKey(record.id, { hwid });
  }

  await store.updateKey(record.id, { uses: (record.uses || 0) + 1, last_used_at: new Date().toISOString() }).catch(() => {});
  return deliver();
});

/* ----------------------------------------------------------- static + SPA */

app.use(express.static(__dirname, { extensions: ["html"] }));
app.use((req, res) => {
  if (req.path.startsWith("/api/") || req.path.startsWith("/loader/")) return res.status(404).json({ error: "Not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
});

const originOf = (req) => `${req.protocol}://${req.get("host")}`;

export { app, store, auth };

if (process.env.NODE_ENV !== "test" && process.argv[1] && path.resolve(process.argv[1]) === path.join(__dirname, "server.js")) {
  const port = Number(process.env.PORT || 10000);
  app.listen(port, "0.0.0.0", () => {
    console.log(`LuaLune listening on ${port} (store=${store.kind}, auth=${auth.mode})`);
  });
}
