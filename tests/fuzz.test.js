import test from "node:test";
import assert from "node:assert/strict";
import { obfuscate } from "../lib/obfuscator.js";
import { runLua } from "./luavm.js";

/**
 * Ten scripts that use the constructs which usually break naive obfuscators:
 * nested closures, method calls, table constructors, mixed scopes, shadowing,
 * varargs, string escapes and float maths.
 */
const SCRIPTS = {
  scopes: `
local x = 1
do
  local x = 2
  print("inner", x)
end
print("outer", x)
local function outer(a)
  local b = a * 2
  return function(c)
    return a + b + c
  end
end
print(outer(1)(3))
`,
  methods: `
local obj = { value = 7, name = "counter" }
function obj.bump(self, by)
  self.value = self.value + by
  return self.value
end
function obj:double()
  return self:get() * 2
end
function obj:get()
  return self.value
end
print(obj:bump(3), obj:double(), obj.name)
print(obj["value"], #obj.name)
`,
  strings: `
local a = "quote\\"inside"
local b = 'single\\'quote'
local c = "tab\\tnew\\nline"
local d = [[long
bracket]]
print(a)
print(b)
print(c)
print(d)
print("len", #a, #b, #c, #d)
`,
  numeric: `
print(1 + 2 * 3)
print(10 / 4)
print(2 ^ 10)
print(7 % 3)
print(1e3, 0.5, 100000)
local big = 1234567890
print(big + 1)
print(math.floor(3.99), math.max(2, 9))
`,
  controlflow: `
local total = 0
for i = 1, 5 do
  if i % 2 == 0 then
    total = total + i
  else
    total = total - i
  end
end
print("total", total)
local i = 0
while i < 3 do
  i = i + 1
end
print("while", i)
for _, name in ipairs({"a", "b"}) do
  print("name", name)
end
`,
  tables: `
local t = {
  1, 2, 3,
  nested = { deep = { "x", "y" } },
  ["quoted key"] = true,
  fn = function(v) return v * 2 end,
}
t[#t + 1] = "tail"
for i = 1, #t do print("idx", i, t[i]) end
print(t.nested.deep[2], t["quoted key"], t.fn(21))
`,
  recursion: `
local function fact(n)
  if n <= 1 then return 1 end
  return n * fact(n - 1)
end
print(fact(6))
local fib
fib = function(n)
  if n < 2 then return n end
  return fib(n - 1) + fib(n - 2)
end
print(fib(10))
`,
  varargs: `
local function pack(...)
  local n = select("#", ...)
  return n, ...
end
local n, a, b = pack("x", "y")
print(n, a, b)
local function tail(...)
  return select(2, ...)
end
print(tail(1, 2, 3))
`,
  shadow: `
local value = 10
local function set(value)
  value = value + 1
  return value
end
print(value, set(value), value)
local shared = "outer"
local function reader() return shared end
do
  local shared = "inner"
  print(reader(), shared)
end
`,
  declarations: `
local a, b, c = 1, 2, 3
local pending
print(a, b, c, pending)
local first,
      second
first = "one"
second = "two"
print(first, second)
local x = 5
local x2, y = x * 2, x * 3
local bare
if x2 > 5 then bare = y end
print(x2, y, bare)
`,
  bigger: `
local registry = {}
local function register(name, handler)
  registry[name] = handler
  return #registry > 0
end
register("greet", function(who) return "hello " .. who end)
register("shout", function(who) return string.upper("hello " .. who) end)
local order = {}
for name in pairs(registry) do order[#order + 1] = name end
table.sort(order)
for _, name in ipairs(order) do
  print(name, registry[name]("lualune"))
end
local sum = 0
for i = 1, 10 do sum = sum + i end
print("sum", sum)
`,
};

for (const [name, source] of Object.entries(SCRIPTS)) {
  const baseline = runLua(source);
  test(`fuzz: ${name} survives every engine`, () => {
    assert.ok(baseline.ok, `baseline failed: ${baseline.error}`);
    for (const engine of ["payload", "flow", "vault", "none"]) {
      for (const options of [{}, { junkDensity: 1 }, { rename: false }, { strings: false, numbers: false }, { harden: false }]) {
        const built = obfuscate(source, { engine, ...options });
        const run = runLua(built.code);
        assert.ok(run.ok, `${name}/${engine}/${JSON.stringify(options)} failed: ${run.error}`);
        assert.equal(run.output, baseline.output, `${name}/${engine}/${JSON.stringify(options)} changed output`);
      }
    }
  });
}

test("fuzz: builds stay valid with and without bit32", () => {
  const built = obfuscate(SCRIPTS.controlflow, { engine: "payload" });
  const a = runLua(built.code, { withBit32: true });
  const b = runLua(built.code, { withBit32: false });
  assert.ok(a.ok && b.ok, a.error || b.error);
  assert.equal(a.output, b.output);
});

test("fuzz: repeated builds of the same source always run the same", () => {
  for (let i = 0; i < 12; i++) {
    const built = obfuscate(SCRIPTS.bigger, { engine: ["payload", "flow", "vault"][i % 3] });
    const run = runLua(built.code);
    assert.ok(run.ok, `iteration ${i}: ${run.error}`);
    assert.equal(run.output, runLua(SCRIPTS.bigger).output, `iteration ${i} changed output`);
  }
});
