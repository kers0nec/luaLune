/**
 * Authentication.
 *
 * With Supabase configured this delegates to Supabase Auth. Without it (local
 * runs, previews, tests) LuaLune runs its own email/username + password auth
 * with scrypt hashes and signed session tokens, so the whole product still
 * works end to end.
 *
 * Two things that used to break logins in the field, now handled here:
 *
 * 1. Email confirmation. Supabase projects ship with "Confirm email" enabled,
 *    but LuaLune accounts may only have a username — their generated address
 *    (user@users.lualune.local) can never receive the confirmation mail, so the
 *    account could never sign in ("Invalid username or password" forever).
 *    When SUPABASE_SERVICE_ROLE_KEY is set, LuaLune confirms the account
 *    itself during signup, and rescues already-stuck accounts at login.
 * 2. Restarts. In local mode accounts and the token signing secret used to
 *    live only in process memory, so every restart wiped every user. Both are
 *    now persisted to <dataDir>/auth-local.json and survive restarts.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createClient } from "@supabase/supabase-js";
import { TOS_VERSION } from "./tos.js";

const USERNAME_RE = /^[a-zA-Z0-9._-]{3,24}$/;
const TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;
const LOCAL_DOMAIN = "users.lualune.local";
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const EMAIL_NOT_CONFIRMED = /email[ _-]?not[ _-]?confirmed|hasn'?t\s+been\s+confirmed|not\s+been\s+confirmed|confirm(ed)?\s+your\s+email|confirm(ed)?\s+email\s+first/i;

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
  const clean = normalizeUsername(username) || (email ? normalizeUsername(email.split("@")[0]) : "");
  const userOk = USERNAME_RE.test(clean);
  if (!userOk) {
    return "Provide a username (3-24 characters: letters, numbers, dot, underscore, hyphen).";
  }
  if (email && !emailRegex.test(String(email).trim())) return "Enter a valid email address.";
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

/** Map raw provider errors to messages that do not lie to the user. */
function friendlyAuthError(error) {
  const raw = String(error?.message || "");
  if (EMAIL_NOT_CONFIRMED.test(raw)) return "This account's email has not been confirmed yet. Confirm it, then sign in again.";
  if (/invalid\s+login\s+credentials/i.test(raw)) return "Invalid username or password.";
  if (/rate\s*limit|too\s+many\s+requests/i.test(raw)) return "Too many attempts. Wait a minute and try again.";
  if (/signup\s+requires\s+a\s+valid\s+password|password\s+should\s+be\s+at\s+least/i.test(raw)) return "Password must be at least 8 characters.";
  if (/user\s+already\s+(registered|exists)/i.test(raw)) return "That account already exists.";
  return raw || "Authentication failed.";
}

export function createAuth({
  store,
  url = process.env.SUPABASE_URL,
  anonKey = process.env.SUPABASE_ANON_KEY,
  serviceKey = process.env.SUPABASE_SERVICE_ROLE_KEY,
  secret,
  dataDir = process.env.LUALUNE_DATA_DIR || path.join(process.cwd(), "data"),
  /** dependency injection for tests */
  remote: remoteOverride,
  admin: adminOverride,
} = {}) {
  const remote = remoteOverride !== undefined ? remoteOverride : (url && anonKey ? createClient(url, anonKey, { auth: { persistSession: false, autoRefreshToken: false } }) : null);
  const admin = adminOverride !== undefined ? adminOverride : (url && serviceKey ? createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } }) : null);

  /* --------------------------------------------- local-mode durable state */
  const stateFile = path.join(dataDir, "auth-local.json");
  let persisted = { secret: null, users: [], revoked: [] };
  try {
    const parsed = JSON.parse(fs.readFileSync(stateFile, "utf8"));
    if (parsed && typeof parsed === "object") persisted = { secret: null, users: [], revoked: [], ...parsed };
  } catch { /* first boot or read-only FS: start fresh */ }

  const secretKey = secret
    || process.env.LUALUNE_AUTH_SECRET
    || (typeof persisted.secret === "string" && persisted.secret)
    || crypto.randomBytes(32).toString("hex");

  const users = new Map(); // memory mode only: email -> {id, email, username, password}
  for (const record of Array.isArray(persisted.users) ? persisted.users : []) {
    if (record && record.email && record.password && record.id) {
      users.set(String(record.email).toLowerCase(), record);
    }
  }
  const revoked = new Set(Array.isArray(persisted.revoked) ? persisted.revoked : []);

  const save = () => {
    // Atomic write (tmp + rename): a crash mid-write cannot corrupt the
    // previous state. The account list is tiny, so sync is fine here.
    try {
      fs.mkdirSync(dataDir, { recursive: true });
      const payload = JSON.stringify({ secret: secretKey, users: [...users.values()], revoked: [...revoked].slice(-1000) }, null, 2);
      const tmp = `${stateFile}.tmp`;
      fs.writeFileSync(tmp, payload);
      fs.renameSync(tmp, stateFile);
    } catch { /* read-only filesystem: memory mode still works */ }
  };
  save(); // persist a freshly generated secret on first boot so sessions survive restarts

  const signToken = (userId) => {
    // jti keeps every token unique: without it, logging out and back in within
    // the same second re-issued the exact token that had just been revoked.
    const payload = b64u(JSON.stringify({ sub: userId, exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS, jti: crypto.randomBytes(8).toString("hex") }));
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
    if (!profile) profile = await store.createProfile({ id, email, username, tos_version: TOS_VERSION });
    return profile;
  }

  /**
   * Confirm a Supabase auth user by email via the admin API. Used when email
   * confirmation is enabled and the account cannot receive mail (username-only
   * signups), both at signup and as a rescue for accounts stuck before this
   * fix existed.
   */
  async function confirmUserByEmail(address) {
    if (!admin) return false;
    const target = String(address).toLowerCase();
    try {
      const PAGE = 200;
      for (let page = 1; page <= 10; page++) {
        const { data, error } = await admin.auth.admin.listUsers({ page, perPage: PAGE });
        if (error || !Array.isArray(data?.users) || data.users.length === 0) break;
        const match = data.users.find((u) => String(u.email || "").toLowerCase() === target);
        if (match) {
          const { error: updateError } = await admin.auth.admin.updateUserById(match.id, { email_confirm: true });
          return !updateError;
        }
        if (data.users.length < PAGE) break;
      }
    } catch { /* fall through: the caller reports an honest error */ }
    return false;
  }

  return {
    mode: remote ? "supabase" : "local",
    client: remote,
    adminReady: !!admin,

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
        if (authError) return { error: friendlyAuthError(authError) };
        if (!data.user) return { error: "Signup failed." };

        // Email confirmation enabled? Username-only accounts cannot receive
        // the mail, so confirm the account ourselves and hand back a session.
        let session = data.session;
        if (!session && admin) {
          const ok = await confirmUserByEmail(address);
          if (ok) {
            const { data: signedIn, error: signInError } = await remote.auth.signInWithPassword({ email: address, password });
            if (!signInError && signedIn?.session) session = signedIn.session;
          }
        }

        const profile = await ensureProfile({ id: data.user.id, email: address, username: clean });
        return {
          user: { id: data.user.id, email: address, username: profile.username },
          session: session ? { access_token: session.access_token } : null,
          needsConfirmation: !session,
          ...(session ? {} : {
            message: admin
              ? "Account created, but it could not be auto-confirmed. Try signing in; if that fails, confirm the user in the Supabase dashboard."
              : "Account created. This server cannot auto-confirm sign-ups (set SUPABASE_SERVICE_ROLE_KEY to enable it), so confirm the email first if sign-in fails.",
          }),
        };
      }

      if (users.has(address)) return { error: "That account already exists." };
      const id = crypto.randomUUID();
      users.set(address, { id, email: address, username: clean, password: hashPassword(password) });
      save();
      await ensureProfile({ id, email: address, username: clean });
      return { user: { id, email: address, username: clean }, session: { access_token: signToken(id) }, needsConfirmation: false };
    },

    async login({ identifier, password }) {
      const raw = String(identifier || "").trim();
      if (!raw || !password) return { error: "Username and password are required." };
      const looksLikeEmail = raw.includes("@");
      const address = looksLikeEmail ? raw.toLowerCase() : emailForUsername(raw);

      if (remote) {
        let { data, error: authError } = await remote.auth.signInWithPassword({ email: address, password });

        // Rescue accounts that were created before auto-confirm existed:
        // confirm them server-side, then retry the sign-in once.
        if (authError && EMAIL_NOT_CONFIRMED.test(String(authError.message || ""))) {
          if (await confirmUserByEmail(address)) {
            ({ data, error: authError } = await remote.auth.signInWithPassword({ email: address, password }));
          } else {
            return { error: "This account's email was never confirmed and it cannot receive the confirmation mail. Set SUPABASE_SERVICE_ROLE_KEY on the server so LuaLune can confirm it automatically, or confirm the user in the Supabase dashboard." };
          }
        }

        if (authError) return { error: friendlyAuthError(authError) };
        if (!data?.session) return { error: "Sign-in failed. Try again." };
        const username = data.user.user_metadata?.username || normalizeUsername(address.split("@")[0]);
        const profile = await ensureProfile({ id: data.user.id, email: address, username });
        return { user: { id: data.user.id, email: address, username: profile.username }, session: { access_token: data.session.access_token } };
      }

      const record = users.get(address);
      if (!record || !verifyPassword(password, record.password)) return { error: "Invalid username or password." };
      return { user: { id: record.id, email: record.email, username: record.username }, session: { access_token: signToken(record.id) } };
    },


    async resetPassword(email, redirectTo) {
      const address = String(email || "").trim().toLowerCase();
      if (!emailRegex.test(address)) return { error: "Enter a valid email address." };
      if (!remote) return { error: "Password reset requires Supabase to be configured." };
      const { error } = await remote.auth.resetPasswordForEmail(address, { redirectTo: redirectTo || process.env.LUALUNE_AUTH_REDIRECT || undefined });
      if (error) return { error: friendlyAuthError(error) };
      return { ok: true };
    },


    async updatePassword(token, password) {
      if (String(password || "").length < 8) return { error: "Password must be at least 8 characters." };
      if (!remote) return { error: "Password changes require Supabase to be configured." };
      const scoped = createClient(url, anonKey, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false, autoRefreshToken: false } });
      const { error } = await scoped.auth.updateUser({ password: String(password) });
      if (error) return { error: friendlyAuthError(error) };
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
      if (token) {
        revoked.add(token);
        save();
      }
      return true;
    },

    /** Memory-mode helper so tests can seed accounts without HTTP. */
    _users: users,
    _confirmUserByEmail: confirmUserByEmail,
  };
}

export default { createAuth, normalizeUsername, emailForUsername, validateSignup };
