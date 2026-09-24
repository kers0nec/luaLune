/**
 * Authentication.
 *
 * With Supabase configured this delegates to Supabase Auth. Without it (local
 * runs, previews, tests) LuaLune runs its own email/username + password auth
 * with scrypt hashes and signed session tokens, so the whole product still
 * works end to end.
 */
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,24}$/;
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;
const LOCAL_DOMAIN = "users.lualune.local";
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "");
}

export function emailForUsername(username) {
  return `${normalizeUsername(username)}@${LOCAL_DOMAIN}`;
}

export function isLocalEmail(email) {
  return String(email || "").toLowerCase().endsWith(`@${LOCAL_DOMAIN}`);
}

export function validateSignup({ username, email, password }) {
  const userOk = USERNAME_RE.test(normalizeUsername(username));
  const emailOk = emailRegex.test(String(email || "").trim());
  if (!userOk && !emailOk) {
    return "Provide a username (3-24 chars, letters/numbers/._-) or a valid email address.";
  }
  if (email && !emailOk) return "Enter a valid email address.";
  if (username && !userOk) {
    return "Username must be 3-24 characters and use only letters, numbers, dot, underscore or hyphen.";
  }
  if (String(password || "").length < 8) return "Password must be at least 8 characters.";
  return null;
}

const hashPassword = (password) => {
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString("hex")}$${derived.toString("hex")}`;
};

const verifyPassword = (password, stored) => {
  const [scheme, salt, digest] = String(stored || "").split("$");
  if (scheme !== "scrypt" || !salt || !digest) return false;
  const derived = crypto.scryptSync(String(password), Buffer.from(salt, "hex"), 64);
  const expected = Buffer.from(digest, "hex");
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
};

const b64u = (input) => Buffer.from(input).toString("base64url");

export function createAuth({ store, url = process.env.SUPABASE_URL, anonKey = process.env.SUPABASE_ANON_KEY, secret } = {}) {
  const secretKey = secret || process.env.LUALUNE_AUTH_SECRET || crypto.randomBytes(32).toString("hex");
  const remote = url && anonKey ? createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } }) : null;
  const users = new Map(); // memory mode only: email -> {id, email, username, password}
  const revoked = new Set();

  const signToken = (userId) => {
    const payload = b64u(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS }));
    const mac = crypto.createHmac("sha256", secretKey).update(payload).digest("base64url");
    return `${payload}.${mac}`;
  };

  const readToken = (token) => {
    const [payload, mac] = String(token || "").split(".");
    if (!payload || !mac) return null;
    const expected = crypto.createHmac("sha256", secretKey).update(payload).digest("base64url");
    const a = Buffer.from(mac);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
      const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      if (!data.exp || data.exp < Math.floor(Date.now() / 1000)) return null;
      return data;
    } catch {
      return null;
    }
  };

  async function ensureProfile({ id, email, username }) {
    let profile = await store.getProfile(id);
    if (!profile) profile = await store.createProfile({ id, email, username });
    return profile;
  }

  return {
    mode: remote ? "supabase" : "local",
    client: remote,

    async signup({ username, email, password, redirectTo }) {
      const error = validateSignup({ username, email, password });
      if (error) return { error };
      const clean = normalizeUsername(username) || (email ? normalizeUsername(email.split("@")[0]) : "");
      const address = String(email || "").trim().toLowerCase() || (clean ? emailForUsername(clean) : "");
      if (!address) return { error: "Email or username is required." };

      if (remote) {
        const { data, error: authError } = await remote.auth.signUp({
          email: address,
          password,
          options: { data: { username: clean }, emailRedirectTo: redirectTo || process.env.LUALUNE_AUTH_REDIRECT || undefined },
        });
        if (authError) return { error: authError.message };
        if (!data.user) return { error: "Signup failed." };
        const profile = await ensureProfile({ id: data.user.id, email: address, username: clean });
        return {
          user: { id: data.user.id, email: address, username: profile.username },
          session: data.session ? { access_token: data.session.access_token } : null,
          needsConfirmation: !data.session,
        };
      }

      if (users.has(address)) return { error: "That account already exists." };
      const id = crypto.randomUUID();
      users.set(address, { id, email: address, username: clean, password: hashPassword(password) });
      await ensureProfile({ id, email: address, username: clean });
      return { user: { id, email: address, username: clean }, session: { access_token: signToken(id) }, needsConfirmation: false };
    },

    async login({ identifier, password }) {
      const raw = String(identifier || "").trim();
      if (!raw || !password) return { error: "Email and password are required." };
      const looksLikeEmail = raw.includes("@");
      const address = looksLikeEmail ? raw.toLowerCase() : emailForUsername(raw);

      if (remote) {
        const { data, error: authError } = await remote.auth.signInWithPassword({ email: address, password });
        if (authError) return { error: "Invalid email or password." };
        const username = data.user.user_metadata?.username || normalizeUsername(address.split("@")[0]);
        const profile = await ensureProfile({ id: data.user.id, email: address, username });
        return { user: { id: data.user.id, email: address, username: profile.username }, session: { access_token: data.session.access_token } };
      }

      const record = users.get(address);
      if (!record || !verifyPassword(password, record.password)) return { error: "Invalid email or password." };
      return { user: { id: record.id, email: record.email, username: record.username }, session: { access_token: signToken(record.id) } };
    },


    async resetPassword(email, redirectTo) {
      const address = String(email || "").trim().toLowerCase();
      if (!emailRegex.test(address)) return { error: "Enter a valid email address." };
      if (!remote) return { error: "Password reset requires Supabase to be configured." };
      const { error } = await remote.auth.resetPasswordForEmail(address, { redirectTo: redirectTo || process.env.LUALUNE_AUTH_REDIRECT || undefined });
      if (error) return { error: error.message };
      return { ok: true };
    },


    async updatePassword(token, password) {
      if (String(password || "").length < 8) return { error: "Password must be at least 8 characters." };
      if (!remote) return { error: "Password changes require Supabase to be configured." };
      const scoped = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false, autoRefreshToken: false } });
      const { error } = await scoped.auth.updateUser({ password: String(password) });
      if (error) return { error: error.message };
      return { ok: true };
    },

    /** Resolve a bearer token to a user. */
    async verify(token) {
      if (!token) return null;
      if (revoked.has(token)) return null;
      if (remote) {
        const { data, error } = await remote.auth.getUser(token);
        if (error || !data.user) return null;
        const username = data.user.user_metadata?.username || normalizeUsername(String(data.user.email || "").split("@")[0]);
        return { id: data.user.id, email: data.user.email, username };
      }
      const payload = readToken(token);
      if (!payload) return null;
      const record = [...users.values()].find((u) => u.id === payload.sub);
      if (!record) return null;
      return { id: record.id, email: record.email, username: record.username };
    },

    async logout(token) {
      if (remote && token) {
        try { await remote.auth.signOut(); } catch { /* token may already be gone */ }
      }
      if (token) revoked.add(token);
      return true;
    },

    /** Memory-mode helper so tests can seed accounts without HTTP. */
    _users: users,
  };
}

export default { createAuth, normalizeUsername, emailForUsername, validateSignup };
