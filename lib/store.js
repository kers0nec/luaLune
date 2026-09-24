/**
 * Storage layer.
 *
 * One interface, two adapters:
 *   - memory    : used when SUPABASE_URL is not configured (local dev, tests, preview)
 *   - supabase  : used in production, backed by schema.sql with RLS enabled
 *
 * Routes only ever talk to this interface, so the whole API can be exercised
 * without a database.
 */
import crypto from "node:crypto";
import { createClient } from "@supabase/supabase-js";
import { monthKey } from "./plans.js";

export const uid = () => crypto.randomUUID();
const now = () => new Date().toISOString();

/* ------------------------------------------------------------------ memory */

function memoryStore() {
  const db = {
    profiles: new Map(),
    scripts: new Map(),
    keys: new Map(),
    whitelist: new Map(),
    invites: new Map(),
    shares: new Map(),
    logs: [],
    announcements: new Map(),
    usage: new Map(),
    tos: new Map(),
  };
  const rows = (map) => [...map.values()].map((r) => ({ ...r }));
  const newest = (list, field = "created_at") => list.slice().sort((a, b) => String(b[field]).localeCompare(String(a[field])));

  return {
    kind: "memory",
    async getProfile(id) { return db.profiles.get(id) ? { ...db.profiles.get(id) } : null; },
    async getProfileByUsername(username) {
      const key = String(username || "").toLowerCase();
      return rows(db.profiles).find((p) => p.username.toLowerCase() === key) || null;
    },
    async createProfile(record) {
      const profile = {
        id: record.id || uid(),
        email: record.email || "",
        username: record.username,
        plan: record.plan || "free",
        role: record.role || "user",
        status: "active",
        suspended_until: null,
        tos_version: null,
        created_at: now(),
      };
      db.profiles.set(profile.id, profile);
      return { ...profile };
    },
    async updateProfile(id, patch) {
      const current = db.profiles.get(id);
      if (!current) return null;
      Object.assign(current, patch);
      return { ...current };
    },
    async listProfiles({ limit = 50, search = "" } = {}) {
      const q = search.toLowerCase();
      return newest(rows(db.profiles).filter((p) => !q || p.username.toLowerCase().includes(q) || p.email.toLowerCase().includes(q))).slice(0, limit);
    },
    async countProfiles() { return db.profiles.size; },

    async listScripts(ownerId) {
      return newest(rows(db.scripts).filter((s) => s.owner_id === ownerId));
    },
    async createScript(record) {
      const script = {
        id: record.id || uid(),
        owner_id: record.owner_id,
        name: record.name,
        engine: record.engine,
        build_id: record.build_id,
        code: record.code,
        source_bytes: record.source_bytes || 0,
        output_bytes: record.output_bytes || 0,
        key_required: !!record.key_required,
        public: record.public !== false,
        warnings: record.warnings || [],
        created_at: now(),
        updated_at: now(),
      };
      db.scripts.set(script.id, script);
      return { ...script };
    },
    async getScript(id) { return db.scripts.get(id) ? { ...db.scripts.get(id) } : null; },
    async getPublicScript(id) {
      const script = db.scripts.get(id);
      return script && script.public ? { ...script } : null;
    },
    async updateScript(id, patch) {
      const current = db.scripts.get(id);
      if (!current) return null;
      Object.assign(current, patch, { updated_at: now() });
      return { ...current };
    },
    async deleteScript(id) {
      const existed = db.scripts.delete(id);
      for (const [keyId, key] of db.keys) if (key.script_id === id) db.keys.delete(keyId);
      for (const [entryId, entry] of db.whitelist) if (entry.script_id === id) db.whitelist.delete(entryId);
      return existed;
    },
    async countScripts(ownerId) { return rows(db.scripts).filter((s) => s.owner_id === ownerId).length; },
    async countAllScripts() { return db.scripts.size; },

    async listKeys(ownerId) {
      return newest(rows(db.keys).filter((k) => k.owner_id === ownerId));
    },
    async createKey(record) {
      const key = {
        id: record.id || uid(),
        owner_id: record.owner_id,
        script_id: record.script_id || null,
        value: record.value,
        label: record.label || "",
        duration_seconds: record.duration_seconds,
        hwid: null,
        uses: 0,
        created_at: now(),
        expires_at: record.expires_at || null,
      };
      db.keys.set(key.id, key);
      return { ...key };
    },
    async getKeyByValue(value) {
      return rows(db.keys).find((k) => k.value === value) || null;
    },
    async updateKey(id, patch) {
      const current = db.keys.get(id);
      if (!current) return null;
      Object.assign(current, patch);
      return { ...current };
    },
    async deleteKey(id) { return db.keys.delete(id); },
    async countKeys(ownerId) { return rows(db.keys).filter((k) => k.owner_id === ownerId).length; },

    async listWhitelist(scriptId) {
      return newest(rows(db.whitelist).filter((w) => w.script_id === scriptId));
    },
    async addWhitelist(record) {
      const entry = {
        id: record.id || uid(),
        script_id: record.script_id,
        owner_id: record.owner_id,
        hwid: record.hwid,
        label: record.label || "",
        created_at: now(),
      };
      db.whitelist.set(entry.id, entry);
      return { ...entry };
    },
    async removeWhitelist(id) { return db.whitelist.delete(id); },
    async countWhitelist(scriptId) { return rows(db.whitelist).filter((w) => w.script_id === scriptId).length; },

    async listInvites(ownerId) { return newest(rows(db.invites).filter((i) => i.owner_id === ownerId)); },
    async createInvite(record) {
      const invite = {
        id: record.id || uid(),
        owner_id: record.owner_id,
        code: record.code,
        kind: record.kind || "workspace", // workspace | plan
        plan: record.plan || null,
        max_uses: record.max_uses ?? 1,
        uses: 0,
        created_at: now(),
      };
      db.invites.set(invite.id, invite);
      return { ...invite };
    },
    async getInviteByCode(code) { return rows(db.invites).find((i) => i.code === String(code || "").toUpperCase()) || null; },
    async useInvite(code, userId) {
      const invite = await this.getInviteByCode(code);
      if (!invite) return null;
      invite.uses += 1;
      invite.last_used_by = userId;
      db.invites.set(invite.id, invite);
      return { ...invite };
    },
    async deleteInvite(id) { return db.invites.delete(id); },

    async listSharesByOwner(ownerId) { return newest(rows(db.shares).filter((s) => s.owner_id === ownerId)); },
    async listSharesWith(username) { return newest(rows(db.shares).filter((s) => s.shared_with === String(username || "").toLowerCase())); },
    async createShare(record) {
      const share = {
        id: record.id || uid(),
        owner_id: record.owner_id,
        owner_username: record.owner_username,
        script_id: record.script_id,
        shared_with: String(record.shared_with).toLowerCase(),
        created_at: now(),
      };
      db.shares.set(share.id, share);
      return { ...share };
    },
    async deleteShare(id) { return db.shares.delete(id); },

    async addLog(record) {
      const entry = {
        id: record.id || uid(),
        script_id: record.script_id,
        owner_id: record.owner_id,
        status: record.status,
        code: record.code || null,
        key_value: record.key_value || null,
        hwid: record.hwid || null,
        country: null,
        ip_hash: record.ip_hash || null,
        user_agent: record.user_agent || null,
        created_at: now(),
      };
      db.logs.push(entry);
      if (db.logs.length > 5000) db.logs.splice(0, db.logs.length - 5000);
      return { ...entry };
    },
    async listLogs(scriptId, limit = 25) {
      return db.logs.filter((l) => l.script_id === scriptId).slice(-limit).reverse().map((l) => ({ ...l }));
    },
    async countLogs() { return db.logs.length; },

    async listAnnouncements() {
      return newest(rows(db.announcements)).filter((a) => !a.expires_at || a.expires_at > now());
    },
    async createAnnouncement(record) {
      const item = {
        id: record.id || uid(),
        title: record.title,
        body: record.body,
        level: record.level || "info",
        created_at: now(),
        expires_at: record.expires_at || null,
      };
      db.announcements.set(item.id, item);
      return { ...item };
    },
    async deleteAnnouncement(id) { return db.announcements.delete(id); },

    async getUsage(userId) {
      const entry = db.usage.get(userId);
      const month = monthKey();
      if (!entry || entry.month !== month) return { month, count: 0 };
      return { month: entry.month, count: entry.count };
    },
    async bumpUsage(userId) {
      const month = monthKey();
      const entry = db.usage.get(userId);
      const next = { month, count: entry && entry.month === month ? entry.count + 1 : 1 };
      db.usage.set(userId, next);
      return next;
    },

    async getTos(userId) { return db.tos.get(userId) || null; },
    async acceptTos(userId, version) {
      const entry = { user_id: userId, version, accepted_at: now() };
      db.tos.set(userId, entry);
      return entry;
    },

    async stats() {
      return {
        users: db.profiles.size,
        scripts: db.scripts.size,
        keys: db.keys.size,
        executions: db.logs.length,
        announcements: db.announcements.size,
      };
    },
  };
}

/* ---------------------------------------------------------------- supabase */

function supabaseStore(url, anonKey) {
  const clientFor = (token) => createClient(url, anonKey, {
    global: { headers: token ? { Authorization: `Bearer ${token}` } : {} },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const service = clientFor(null);

  const one = async (query) => {
    const { data, error } = await query;
    if (error) throw new Error(error.message);
    return data && data.length ? data[0] : null;
  };
  const many = async (query) => {
    const { data, error } = await query;
    if (error) throw new Error(error.message);
    return data || [];
  };

  return {
    kind: "supabase",
    client: service,
    clientFor,
    forUser: (token) => {
      const scoped = clientFor(token);
      return {
        async listScripts(ownerId) { return many(scoped.from("scripts").select("id,name,engine,build_id,source_bytes,output_bytes,key_required,public,warnings,created_at,updated_at").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
        async createScript(record) { return one(scoped.from("scripts").insert(record).select("*")); },
        async getScript(id) { return one(scoped.from("scripts").select("*").eq("id", id)); },
        async updateScript(id, patch) { return one(scoped.from("scripts").update({ ...patch, updated_at: new Date().toISOString() }).eq("id", id).select("*")); },
        async deleteScript(id) { const { error } = await scoped.from("scripts").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
        async listKeys(ownerId) { return many(scoped.from("script_keys").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
        async createKey(record) { return one(scoped.from("script_keys").insert(record).select("*")); },
        async updateKey(id, patch) { return one(scoped.from("script_keys").update(patch).eq("id", id).select("*")); },
        async deleteKey(id) { const { error } = await scoped.from("script_keys").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
        async listWhitelist(scriptId) { return many(scoped.from("whitelist_entries").select("*").eq("script_id", scriptId).order("created_at", { ascending: false })); },
        async addWhitelist(record) { return one(scoped.from("whitelist_entries").insert(record).select("*")); },
        async removeWhitelist(id) { const { error } = await scoped.from("whitelist_entries").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
        async countWhitelist(scriptId) { return (await many(scoped.from("whitelist_entries").select("id").eq("script_id", scriptId))).length; },
        async addLog(record) { return one(scoped.from("execution_logs").insert(record).select("*")); },
        async listLogs(scriptId, limit = 25) { return many(scoped.from("execution_logs").select("*").eq("script_id", scriptId).order("created_at", { ascending: false }).limit(limit)); },
        async listSharesByOwner(ownerId) { return many(scoped.from("shares").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
        async listSharesWith(username) { return many(scoped.from("shares").select("*").eq("shared_with", String(username || "").toLowerCase()).order("created_at", { ascending: false })); },
        async createShare(record) { return one(scoped.from("shares").insert(record).select("*")); },
        async deleteShare(id) { const { error } = await scoped.from("shares").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
        async listInvites(ownerId) { return many(scoped.from("invites").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
        async createInvite(record) { return one(scoped.from("invites").insert(record).select("*")); },
        async deleteInvite(id) { const { error } = await scoped.from("invites").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
      };
    },

    async getProfile(id) { return one(service.from("profiles").select("*").eq("id", id)); },
    async getProfileByUsername(username) { return one(service.from("profiles").select("*").ilike("username", String(username || "").toLowerCase())); },
    async createProfile(record) { return one(service.from("profiles").insert({ ...record, created_at: new Date().toISOString() }).select("*")); },
    async updateProfile(id, patch) { return one(service.from("profiles").update(patch).eq("id", id).select("*")); },
    async listProfiles({ limit = 50, search = "" } = {}) {
      let query = service.from("profiles").select("*").order("created_at", { ascending: false }).limit(limit);
      if (search) query = query.ilike("username", `%${search}%`);
      return many(query);
    },
    async countProfiles() { return (await many(service.from("profiles").select("id"))).length; },

    async listScripts(ownerId) { return many(service.from("scripts").select("id,name,engine,build_id,source_bytes,output_bytes,key_required,public,warnings,created_at,updated_at").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
    async createScript(record) { return one(service.from("scripts").insert(record).select("*")); },
    async getScript(id) { return one(service.from("scripts").select("*").eq("id", id)); },
    async getPublicScript(id) { return one(service.from("scripts").select("*").eq("id", id).eq("public", true)); },
    async updateScript(id, patch) { return one(service.from("scripts").update({ ...patch, updated_at: new Date().toISOString() }).eq("id", id).select("*")); },
    async deleteScript(id) { const { error } = await service.from("scripts").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
    async countScripts(ownerId) { return (await many(service.from("scripts").select("id").eq("owner_id", ownerId))).length; },
    async countAllScripts() { return (await many(service.from("scripts").select("id"))).length; },

    async listKeys(ownerId) { return many(service.from("script_keys").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
    async createKey(record) { return one(service.from("script_keys").insert(record).select("*")); },
    async getKeyByValue(value) { return one(service.from("script_keys").select("*").eq("value", value)); },
    async updateKey(id, patch) { return one(service.from("script_keys").update(patch).eq("id", id).select("*")); },
    async deleteKey(id) { const { error } = await service.from("script_keys").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
    async countKeys(ownerId) { return (await many(service.from("script_keys").select("id").eq("owner_id", ownerId))).length; },

    async listWhitelist(scriptId) { return many(service.from("whitelist_entries").select("*").eq("script_id", scriptId).order("created_at", { ascending: false })); },
    async addWhitelist(record) { return one(service.from("whitelist_entries").insert(record).select("*")); },
    async removeWhitelist(id) { const { error } = await service.from("whitelist_entries").delete().eq("id", id); if (error) throw new Error(error.message); return true; },
    async countWhitelist(scriptId) { return (await many(service.from("whitelist_entries").select("id").eq("script_id", scriptId))).length; },

    async listInvites(ownerId) { return many(service.from("invites").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
    async createInvite(record) { return one(service.from("invites").insert(record).select("*")); },
    async getInviteByCode(code) { return one(service.from("invites").select("*").eq("code", String(code || "").toUpperCase())); },
    async useInvite(code, userId) {
      const invite = await this.getInviteByCode(code);
      if (!invite) return null;
      return one(service.from("invites").update({ uses: (invite.uses || 0) + 1, last_used_by: userId }).eq("id", invite.id).select("*"));
    },
    async deleteInvite(id) { const { error } = await service.from("invites").delete().eq("id", id); if (error) throw new Error(error.message); return true; },

    async listSharesByOwner(ownerId) { return many(service.from("shares").select("*").eq("owner_id", ownerId).order("created_at", { ascending: false })); },
    async listSharesWith(username) { return many(service.from("shares").select("*").eq("shared_with", String(username || "").toLowerCase()).order("created_at", { ascending: false })); },
    async createShare(record) { return one(service.from("shares").insert(record).select("*")); },
    async deleteShare(id) { const { error } = await service.from("shares").delete().eq("id", id); if (error) throw new Error(error.message); return true; },

    async addLog(record) { return one(service.from("execution_logs").insert(record).select("*")); },
    async listLogs(scriptId, limit = 25) { return many(service.from("execution_logs").select("*").eq("script_id", scriptId).order("created_at", { ascending: false }).limit(limit)); },
    async countLogs() { return (await many(service.from("execution_logs").select("id"))).length; },

    async listAnnouncements() { return many(service.from("announcements").select("*").order("created_at", { ascending: false }).limit(10)); },
    async createAnnouncement(record) { return one(service.from("announcements").insert(record).select("*")); },
    async deleteAnnouncement(id) { const { error } = await service.from("announcements").delete().eq("id", id); if (error) throw new Error(error.message); return true; },

    async getUsage(userId) {
      const entry = await one(service.from("usage_counters").select("*").eq("user_id", userId));
      const month = monthKey();
      if (!entry || entry.month !== month) return { month, count: 0 };
      return { month: entry.month, count: entry.count };
    },
    async bumpUsage(userId) {
      const month = monthKey();
      const usage = await this.getUsage(userId);
      const count = usage.count + 1;
      await service.from("usage_counters").upsert({ user_id: userId, month, count });
      return { month, count };
    },

    async getTos(userId) { return one(service.from("tos_acceptances").select("*").eq("user_id", userId)); },
    async acceptTos(userId, version) {
      return one(service.from("tos_acceptances").upsert({ user_id: userId, version, accepted_at: new Date().toISOString() }).select("*"));
    },

    async stats() {
      const [users, scripts, keys, executions] = await Promise.all([
        this.countProfiles(),
        this.countAllScripts(),
        (await many(service.from("script_keys").select("id"))).length,
        this.countLogs(),
      ]);
      return { users, scripts, keys, executions };
    },
  };
}

export function createStore({ url = process.env.SUPABASE_URL, anonKey = process.env.SUPABASE_ANON_KEY } = {}) {
  if (url && anonKey) return supabaseStore(url, anonKey);
  return memoryStore();
}

export default { createStore, memoryStore };
