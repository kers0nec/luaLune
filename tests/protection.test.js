import test from "node:test";
import assert from "node:assert/strict";
import { obfuscate, buildVault, buildPayload, xorNibbleTable, keystream, checksum } from "../lib/obfuscator.js";
import { runLua } from "./luavm.js";

const SAMPLE = `local secret = "vault engine string"\nlocal function twice(n)\n  return n * 2\nend\nprint(secret)\nprint(twice(21))\nfor i = 1, 3 do print("line", i) end\n`;

test("vault engine runs identically and hides the source", () => {
  const baseline = runLua(SAMPLE);
  const built = obfuscate(SAMPLE, { engine: "vault" });
  assert.deepEqual(built.warnings, []);
  assert.ok(!built.code.includes("vault engine string"), "vault build leaked a string");
  const run = runLua(built.code);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, baseline.output);
  for (const pass of ["cascade-encryption", "per-segment-checksums", "decoy-records", "magic-marker", "environment-guard"]) {
    assert.ok(built.stats.passes.includes(pass), "missing pass " + pass + ": " + built.stats.passes.join(","));
  }
});

test("vault engine needs no bit32 at all", () => {
  const built = obfuscate(SAMPLE, { engine: "vault" });
  assert.ok(!/\bbit32\b/.test(built.code), "vault build must not reference bit32");
  const withBit32 = runLua(built.code, { withBit32: true });
  const without = runLua(built.code, { withBit32: false });
  assert.ok(withBit32.ok && without.ok, withBit32.error || without.error);
  assert.equal(withBit32.output, without.output);
});

test("payload engine also runs without bit32 (nibble table xor)", () => {
  const built = obfuscate(SAMPLE, { engine: "payload" });
  assert.ok(!/\bbit32\b/.test(built.code), "payload build must not reference bit32");
  const run = runLua(built.code);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, runLua(SAMPLE).output);
});

test("the embedded xor table is a real xor and is obfuscated in the build", () => {
  const table = xorNibbleTable();
  for (let a = 0; a < 16; a++) for (let b = 0; b < 16; b++) assert.equal(table[a * 16 + b], a ^ b);
  const built = obfuscate(SAMPLE, { engine: "vault" });
  // the raw table would appear as the printable-ish sequence 0,1,2,3,0,1,2,3...
  assert.ok(!/\\000\\001\\002\\003/.test(built.code), "xor table shipped in the clear");
});

test("tampering with a vault build trips the per-segment checksum", () => {
  const built = obfuscate(SAMPLE, { engine: "vault" });
  const records = [...built.code.matchAll(/"((?:\\\d{3})+)"\s*,\s*\d+\s*,\s*\d+/g)];
  assert.ok(records.length >= 3, "expected several checksummed segments");
  // Records are shuffled and include decoys, so corrupt all of them: whichever
  // segment the dispatcher actually reads is guaranteed to be damaged.
  const flip = (literal) => {
    const bytes = literal.match(/\\\d{3}/g).map((chunk) => Number(chunk.slice(1)));
    bytes[0] = (bytes[0] + 1) % 256;
    return bytes.map((b) => "\\" + String(b).padStart(3, "0")).join("");
  };
  let tampered = built.code;
  for (const record of records) {
    // keep the checksum tail intact (the flip is length preserving, so earlier
    // match offsets stay valid while we walk the list)
    const patched = record[0].replace(record[1], flip(record[1]));
    tampered = tampered.slice(0, record.index) + patched + tampered.slice(record.index + record[0].length);
  }
  assert.notEqual(tampered, built.code, "tamper step did not modify the build");
  const run = runLua(tampered);
  assert.equal(run.ok, false, "tampered build should not run");
  assert.match(run.error, /build integrity check failed/);
});

test("a hooked environment is refused by the runtime guard", () => {
  const built = obfuscate(SAMPLE, { engine: "vault" });
  // pretend an executor is lying about string.char
  const hooked = `local __real = string.char\nstring.char = function(b) return __real(b == 65 and 66 or b) end\n` + built.code;
  const run = runLua(hooked);
  assert.equal(run.ok, false, "guard should have refused this environment");
  assert.match(run.error, /unsupported or hooked environment/);

  const flowBuild = obfuscate(SAMPLE, { engine: "flow" });
  const flowHooked = `local __real = string.byte\nstring.byte = function(...) return __real(...) end\n` + flowBuild.code;
  assert.ok(runLua(flowHooked).ok, "an honest wrapper must not be rejected");
});

test("harden can be turned off per build", () => {
  const built = obfuscate(SAMPLE, { engine: "vault", harden: false });
  assert.ok(!built.stats.passes.includes("environment-guard"));
  assert.ok(!/unsupported or hooked environment/.test(built.code));
  assert.ok(runLua(built.code).ok);
});

test("flow engine splits strings across two pools with decoys", () => {
  const built = obfuscate(SAMPLE, { engine: "flow" });
  assert.ok(built.stats.passes.includes("string-pools"));
  assert.match(built.code, /__LLslots=/);
  assert.ok(!built.code.includes('"vault engine string"'));
  const run = runLua(built.code);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, runLua(SAMPLE).output);
});

test("every engine survives a large script", () => {
  let big = "local acc = 0\n";
  for (let i = 0; i < 120; i++) big += `acc = acc + ${i}\nprint("step", ${i}, acc)\n`;
  const baseline = runLua(big);
  assert.ok(baseline.ok, baseline.error);
  for (const engine of ["payload", "vault", "flow"]) {
    const built = obfuscate(big, { engine });
    const run = runLua(built.code);
    assert.ok(run.ok, engine + ": " + run.error);
    assert.equal(run.output, baseline.output, engine + " changed output");
  }
});

test("vault and payload builds stay distinct build over build", () => {
  const a = obfuscate(SAMPLE, { engine: "vault" });
  const b = obfuscate(SAMPLE, { engine: "vault" });
  assert.notEqual(a.code, b.code);
  assert.notEqual(a.stats.buildId, b.stats.buildId);
  const c = obfuscate(SAMPLE, { engine: "payload" });
  assert.notEqual(a.code, c.code, "engines must not emit identical builds");
});

test("payload and vault ciphertexts are not interchangeable", () => {
  const payload = buildPayload(SAMPLE);
  const vault = buildVault(SAMPLE);
  assert.notEqual(payload, vault);
  assert.ok(keystream(1, 8).length === 8);
  assert.notEqual(checksum(Buffer.from("a")), checksum(Buffer.from("b")));
  assert.ok(runLua(payload).ok);
  assert.ok(runLua(vault).ok);
});
