import test from "node:test";
import assert from "node:assert/strict";
import { obfuscate, tokenize, analyze, ENGINES, checksum, keystream } from "../lib/obfuscator.js";
import { runLua } from "./luavm.js";

const SAMPLES = {
  basics: `
local greeting = "hello world"
local count = 3
local function add(a, b)
  return a + b
end
print(greeting)
print("sum:", add(count, 4))
for i = 1, count do
  print("i=" .. i)
end
local t = { name = "lualune", version = 2, list = {1, 2, 3} }
print(t.name, t.version, #t.list)
`,
  closures: `
local counter = 0
local function make(step)
  local seen = {}
  return function()
    counter = counter + step
    seen[#seen + 1] = counter
    return counter, #seen
  end
end
local next1 = make(2)
print(next1())
print(next1())
local obj = {}
function obj:describe(label)
  return label .. ":" .. tostring(self.value)
end
obj.value = 41
print(obj:describe("v"))
print(obj["value"])
`,
  stringsAndMath: `
local msg = "line1\\nline2"
local hex = "\\x41\\x42"
print(msg)
print(hex, #hex)
print(2 ^ 8, 10 % 3, 7 / 2)
local x = 0xff
print(x)
while x > 250 do
  x = x - 10
  print("x", x)
end
`,
  topReturn: `
local value = 10
print("before")
if value > 5 then
  print("big")
end
print("after")
`,
  repeatAndGoto: `
local i = 0
repeat
  i = i + 1
  print("r", i)
until i >= 3
for j = 1, 2 do
  if j == 2 then goto done end
  print("j", j)
end
::done::
print("finished")
`,
  varargsTopLevel: `
local args = { ... }
print("args", #args)
local function f(a, b, ...)
  return a, b, select("#", ...)
end
print(f(1, 2, 3, 4, 5))
`,
};

function roundTrip(name, source, options, vmOptions = {}) {
  const before = runLua(source, vmOptions);
  assert.ok(before.ok, `baseline ${name} failed: ${before.error}`);
  const built = obfuscate(source, options);
  const after = runLua(built.code, vmOptions);
  assert.ok(after.ok, `${name} [${options.engine}] failed to run: ${after.error}\n---\n${built.code.slice(0, 1200)}`);
  assert.equal(after.output, before.output, `${name} [${options.engine}] changed program output`);
  return built;
}

test("lexer round-trips a Luau flavoured script", () => {
  const src = `local x: number = 1\nx += 2\nif x > 2 then continue end\nlocal s = [[long]] .. [=[also]=] .. "esc\\n"\nexport type Point = { x: number, y: number }\nprint(x, s)`;
  const tokens = tokenize(src);
  assert.ok(tokens.length > 20);
  const info = analyze(tokens);
  assert.equal(info.seen.compound, true, "compound assignment should be detected");
  assert.equal(info.seen.typeDecl, true, "type declarations should be detected");
  assert.equal(info.seen.ifExpr, false, "a statement `if` is not an if-expression");

  const expr = analyze(tokenize(`local function f(a)\n  local x = if a then 1 else 2\n  return x\nend`));
  assert.equal(expr.safeToRename, false, "Luau if-expressions must disable renaming");
  assert.ok(expr.reasons.join(" ").includes("unbalanced"), "unbalanced blocks must be reported: " + expr.reasons);
});

test("payload engine keeps behaviour and hides the source", () => {
  for (const [name, src] of Object.entries(SAMPLES)) {
    const built = roundTrip(name, src, { engine: "payload" });
    assert.ok(!built.code.includes("hello world"), "payload engine leaked a plaintext string");
    assert.ok(built.code.includes("LuaLune Obfuscator"), "protected build is not branded");
    assert.deepEqual(built.warnings, []);
  }
});

test("payload engine produces a different build every time", () => {
  const a = obfuscate(SAMPLES.basics, { engine: "payload" });
  const b = obfuscate(SAMPLES.basics, { engine: "payload" });
  assert.notEqual(a.code, b.code);
  assert.notEqual(a.stats.buildId, b.stats.buildId);
});

test("flow engine keeps behaviour", () => {
  for (const [name, src] of Object.entries(SAMPLES)) {
    const built = roundTrip(name, src, { engine: "flow" });
    assert.ok(built.stats.passes.length > 0);
  }
});

test("flow engine renames locals and encrypts strings", () => {
  const built = obfuscate(SAMPLES.basics, { engine: "flow" });
  assert.ok(!/greeting/.test(built.code), "local name survived renaming");
  assert.ok(!built.code.includes('"hello world"'), "string literal survived encryption");
  assert.ok(built.stats.renamed > 0);
  assert.ok(built.stats.strings > 0);
  assert.ok(built.stats.passes.includes("control-flow-flattening"), "expected flattening: " + JSON.stringify(built.stats));
});

test("globals are never renamed, even after a bare local declaration", () => {
  const source = `local pending\nprint("hi", pending)\nlocal value = 2\ntostring(value)\nmath.floor(1.5)\nprint(type(pending))\n`;
  // the flow engine keeps globals intact (the payload engine encrypts the lot)
  const flowed = obfuscate(source, { engine: "flow" }).code.replace(/\s+/g, "");
  assert.match(flowed, /print\(/, "flow engine renamed print");
  assert.match(flowed, /tostring\(/, "flow engine renamed tostring");
  assert.match(flowed, /math\.floor\(/, "flow engine renamed math.floor");
  const built = obfuscate(source, { engine: "flow" });
  const run = runLua(built.code);
  assert.ok(run.ok, run.error);
  assert.equal(run.output, runLua(source).output);
});

test("flow engine warns instead of breaking risky scripts", () => {
  const built = obfuscate(SAMPLES.repeatAndGoto, { engine: "flow" });
  assert.ok(built.warnings.join(" ").includes("repeat/until"));
  assert.equal(built.stats.passes.includes("identifier-renaming"), false);
  const vm = obfuscate(SAMPLES.varargsTopLevel, { engine: "flow" });
  assert.ok(!vm.stats.passes.includes("control-flow-flattening"), "top level varargs must disable flattening");
});

test("both engines survive a table constructor full of strings and junk injection", () => {
  const src = `local t = { ["a"] = 1, b = 2, "c", function() return "d" end }\nfor k, v in pairs(t) do print(type(v)) end\nprint(t.b)`;
  roundTrip("table", src, { engine: "flow", junkDensity: 1 });
  roundTrip("table", src, { engine: "payload" });
});

test("none engine stores the script verbatim", () => {
  const built = obfuscate(SAMPLES.basics, { engine: "none" });
  assert.equal(built.code, SAMPLES.basics);
  assert.equal(built.engine, "none");
});

test("generated builds run with and without bit32 present", () => {
  const built = obfuscate(SAMPLES.closures, { engine: "payload" });
  const withBit32 = runLua(built.code, { withBit32: true });
  const without = runLua(built.code, { withBit32: false });
  assert.ok(withBit32.ok, withBit32.error);
  assert.ok(without.ok, without.error);
  assert.equal(withBit32.output, without.output);
});

test("tampering with a protected build trips the integrity check", () => {
  const built = obfuscate(SAMPLES.basics, { engine: "payload" });
  const tampered = built.code.replace(/\\"/g, '\\"').replace(/^(local __LL[0-9a-f]+=\{")/m, '$1\\09');
  const res = runLua(tampered);
  if (tampered !== built.code) {
    assert.ok(!res.ok || res.output !== runLua(built.code).output, "tampered build behaved like the original");
  }
});

test("keystream and checksum are stable and deterministic", () => {
  const a = keystream(12345, 64);
  const b = keystream(12345, 64);
  assert.deepEqual([...a], [...b]);
  assert.notDeepEqual([...a], [...keystream(12346, 64)]);
  assert.equal(checksum(Buffer.from("abc")), checksum(Buffer.from("abc")));
});

test("engine catalogue is LuaLune branded and discord free", () => {
  assert.equal(ENGINES.payload.name, "LuaLune Obfuscator");
  assert.ok(ENGINES.flow.name.startsWith("LuaLune Obfuscator"));
  assert.ok(!JSON.stringify(ENGINES).toLowerCase().includes("discord"));
});
