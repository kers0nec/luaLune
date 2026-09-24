/**
 * In-memory rate limiter.
 *
 * Fixed window counters per key (IP, key value or account). It is deliberately
 * dependency free: a LuaLune instance is a single small service, and the windows
 * only need to blunt brute force attempts, not survive a restart.
 */

export function createLimiter({ windowMs = 60_000, max = 120, keyOf = (req) => req.ip, message = "Too many requests. Slow down and try again.", onLimit } = {}) {
  const hits = new Map();
  let lastSweep = Date.now();

  const sweep = (now) => {
    if (now - lastSweep < windowMs) return;
    lastSweep = now;
    for (const [key, entry] of hits) if (entry.reset <= now) hits.delete(key);
  };

  const middleware = (req, res, next) => {
    const now = Date.now();
    sweep(now);
    const key = String(keyOf(req) ?? "anonymous");
    const entry = hits.get(key);
    if (!entry || entry.reset <= now) {
      hits.set(key, { count: 1, reset: now + windowMs });
      res.setHeader("X-RateLimit-Limit", max);
      res.setHeader("X-RateLimit-Remaining", max - 1);
      return next();
    }
    entry.count += 1;
    res.setHeader("X-RateLimit-Limit", max);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, max - entry.count));
    if (entry.count > max) {
      const retryAfter = Math.ceil((entry.reset - now) / 1000);
      res.setHeader("Retry-After", retryAfter);
      if (onLimit) return onLimit(req, res, retryAfter);
      return res.status(429).json({ error: message, retryAfter });
    }
    return next();
  };

  middleware.reset = () => hits.clear();
  middleware.size = () => hits.size;
  return middleware;
}

/** Text-response variant used by the loader endpoint (executors expect Lua, not JSON). */
export function createTextLimiter(options = {}) {
  const limiter = createLimiter(options);
  return (req, res, next) => limiter(req, res, () => next());
}

export default { createLimiter, createTextLimiter };
