import test from "node:test";
import assert from "node:assert/strict";
import { createLimiter } from "../lib/ratelimit.js";

function fakeRes() {
  const headers = {};
  return {
    statusCode: 200, body: null, headers,
    setHeader(k, v) { headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
}

test("allows traffic up to the limit then answers 429 with retry headers", () => {
  const limiter = createLimiter({ windowMs: 60_000, max: 3 });
  const req = { ip: "1.2.3.4" };
  let passed = 0;
  for (let i = 0; i < 3; i++) limiter(req, fakeRes(), () => passed++);
  assert.equal(passed, 3);
  const res = fakeRes();
  limiter(req, res, () => { throw new Error("should not pass"); });
  assert.equal(res.statusCode, 429);
  assert.equal(res.headers["X-RateLimit-Remaining"], 0);
  assert.ok(res.headers["Retry-After"] >= 1);
  assert.match(res.body.error, /Too many requests/);
});

test("tracks clients separately and expires windows", () => {
  const limiter = createLimiter({ windowMs: 10, max: 1 });
  limiter({ ip: "a" }, fakeRes(), () => {});
  const blocked = fakeRes();
  limiter({ ip: "a" }, blocked, () => { throw new Error("a should be limited"); });
  assert.equal(blocked.statusCode, 429);

  const other = fakeRes();
  limiter({ ip: "b" }, other, () => {});
  assert.equal(other.statusCode, 200, "a second client is unaffected");

  return new Promise((resolve) => setTimeout(() => {
    const afterWindow = fakeRes();
    limiter({ ip: "a" }, afterWindow, () => {});
    assert.equal(afterWindow.statusCode, 200, "window expired");
    limiter.reset();
    assert.equal(limiter.size(), 0);
    resolve();
  }, 25));
});

test("custom key and onLimit hook are honoured", () => {
  const seen = [];
  const limiter = createLimiter({
    windowMs: 60_000, max: 1,
    keyOf: (req) => req.headers["x-key"],
    onLimit: (req, res) => { seen.push(req.headers["x-key"]); res.status(429).send("lua"); },
  });
  limiter({ ip: "x", headers: { "x-key": "abc" } }, fakeRes(), () => {});
  const res = fakeRes();
  res.send = (text) => { res.text = text; return res; };
  limiter({ ip: "x", headers: { "x-key": "abc" } }, res, () => {});
  assert.equal(res.statusCode, 429);
  assert.equal(res.text, "lua");
  assert.deepEqual(seen, ["abc"]);
});
