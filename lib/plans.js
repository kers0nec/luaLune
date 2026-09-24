/**
 * LuaLune plans and usage limits.
 * A limit of -1 means unlimited.
 */

export const PLANS = {
  free: {
    id: "free",
    name: "Free",
    price: 0,
    blurb: "Everything you need to protect a first script.",
    limits: { scripts: 3, obfuscationsPerMonth: 25, keys: 5, whitelistPerScript: 25, shares: 0 },
    features: ["LuaLune Obfuscator", "LuaLune Obfuscator - Flow", "Public loader URLs", "Key system (5 keys)"],
  },
  pro: {
    id: "pro",
    name: "Pro",
    price: 6,
    blurb: "For people shipping scripts on a schedule.",
    limits: { scripts: 25, obfuscationsPerMonth: 500, keys: 100, whitelistPerScript: 250, shares: 5 },
    features: ["Everything in Free", "25 protected scripts", "500 builds per month", "Execution logs", "Workspace sharing", "HWID whitelist"],
  },
  premium: {
    id: "premium",
    name: "Premium",
    price: 14,
    blurb: "Unlimited builds, keys and delivery.",
    limits: { scripts: -1, obfuscationsPerMonth: -1, keys: -1, whitelistPerScript: -1, shares: -1 },
    features: ["Everything in Pro", "Unlimited scripts and builds", "Unlimited keys and whitelist entries", "Priority build queue", "API access"],
  },
};

export const PLAN_ORDER = ["free", "pro", "premium"];

export function planFor(id) {
  return PLANS[id] || PLANS.free;
}

/** Resolve a limit for a plan, defaulting to the free tier. */
export function limit(planId, field) {
  const plan = planFor(planId);
  const value = plan.limits[field];
  return value === undefined ? 0 : value;
}

export function isUnlimited(planId, field) {
  return limit(planId, field) === -1;
}

/** Monthly usage window key, e.g. "2026-09". */
export function monthKey(date = new Date()) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

/**
 * @returns {{allowed:boolean, reason?:string}}
 */
export function checkLimit(planId, field, current, month = monthKey(), usage = {}) {
  const max = limit(planId, field);
  if (max === -1) return { allowed: true };
  if (field === "obfuscationsPerMonth") {
    const used = usage.month === month ? usage.count : 0;
    if (used >= max) {
      return { allowed: false, reason: `Obfuscation limit reached for ${month} (${max} on the ${planFor(planId).name} plan). Upgrade for more builds.` };
    }
    return { allowed: true };
  }
  if (current >= max) {
    return { allowed: false, reason: `${planFor(planId).name} plan limit reached for ${field.replace(/([A-Z])/g, " $1").toLowerCase()} (${max}).` };
  }
  return { allowed: true };
}

export function publicPlans() {
  return PLAN_ORDER.map((id) => {
    const p = PLANS[id];
    return { id: p.id, name: p.name, price: p.price, blurb: p.blurb, limits: p.limits, features: p.features };
  });
}
