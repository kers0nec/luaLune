/**
 * LuaLune human check.
 *
 * A dependency-free proof-of-work challenge: the server hands out a random
 * challenge, the browser hashes challenge+nonce until the digest starts with
 * `difficulty` zero bits, and the server re-checks the work before accepting a
 * signup. No third party, no tracking, no keys to configure.
 */
import crypto from "node:crypto";

const DEFAULT_DIFFICULTY = 16; // leading zero bits (~65k hashes, well under a second)
const TTL_MS = 5 * 60 * 1000;

const issued = new Map(); // challenge -> {expires, used}

function sweep() {
  const now = Date.now();
  for (const [challenge, entry] of issued) if (entry.expires < now) issued.delete(challenge);
}

export function issueChallenge({ difficulty = DEFAULT_DIFFICULTY } = {}) {
  sweep();
  const challenge = crypto.randomBytes(16).toString("hex");
  issued.set(challenge, { expires: Date.now() + TTL_MS, used: false, difficulty });
  return { challenge, difficulty, expiresIn: Math.floor(TTL_MS / 1000) };
}

export function solve(challenge, difficulty) {
  let nonce = 0;
  const prefix = "0".repeat(Math.ceil(difficulty / 4));
  for (;;) {
    const digest = crypto.createHash("sha256").update(challenge + nonce).digest("hex");
    if (digest.startsWith(prefix)) return { nonce: String(nonce), digest };
    nonce++;
  }
}

/** Verify a solved challenge. Each challenge may only be spent once. */
export function verifyChallenge(challenge, nonce, { difficulty = DEFAULT_DIFFICULTY } = {}) {
  sweep();
  const entry = issued.get(String(challenge || ""));
  if (!entry) return { ok: false, reason: "Human check expired. Try again." };
  if (entry.used) return { ok: false, reason: "Human check already used. Try again." };
  if (entry.expires < Date.now()) { issued.delete(challenge); return { ok: false, reason: "Human check expired. Try again." }; }
  const want = Math.max(difficulty, entry.difficulty || 0);
  const digest = crypto.createHash("sha256").update(String(challenge) + String(nonce ?? "")).digest("hex");
  const bits = leadingZeroBits(digest);
  if (bits < want) return { ok: false, reason: "Human check failed. Try again." };
  entry.used = true;
  return { ok: true, bits };
}

function leadingZeroBits(hex) {
  let bits = 0;
  for (const ch of hex) {
    const v = parseInt(ch, 16);
    if (v === 0) { bits += 4; continue; }
    bits += 3 - Math.floor(Math.log2(v));
    break;
  }
  return bits;
}

export function _reset() {
  issued.clear();
}
