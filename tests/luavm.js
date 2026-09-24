/**
 * Tiny Lua VM harness used by the test suite.
 *
 * fengari is a Lua 5.3 VM compiled to JS, which is close enough to Luau to prove
 * that generated builds actually run and produce identical output. The harness
 * can optionally inject a `bit32` library so both branches of the runtime xor
 * helper (bit32 fast path and pure-Lua fallback) get exercised.
 */
import { lauxlib, lua, lualib, to_luastring } from "fengari";

const PRELUDE = `
__out = {}
print = function(...)
  local t = {}
  for i = 1, select("#", ...) do t[i] = tostring((select(i, ...))) end
  __out[#__out + 1] = table.concat(t, "\\t")
end
`;

// A minimal stand-in for Luau's bit32 so the generated builds take the fast xor path.
const BIT32 = `
bit32 = {}
local function bxor2(a, b)
  local r, m = 0, 1
  for _ = 1, 32 do
    local x, y = a % 2, b % 2
    if x ~= y then r = r + m end
    a = (a - x) / 2
    b = (b - y) / 2
    m = m * 2
  end
  return r
end
function bit32.bxor(...)
  local acc = 0
  for i = 1, select("#", ...) do acc = bxor2(acc, select(i, ...)) end
  return acc
end
`;

function newState({ withBit32 = false } = {}) {
  const L = lauxlib.luaL_newstate();
  lualib.luaL_openlibs(L);
  // fengari targets Lua 5.3: expose 5.1 style globals that Luau still has.
  run(L, PRELUDE + "\nloadstring = load\nunpack = table.unpack\n");
  if (withBit32) run(L, BIT32 + "\n");
  return L;
}

function topString(L) {
  if (lua.lua_gettop(L) < 1) return "(no message)";
  if (lua.lua_type(L, -1) !== lua.LUA_TSTRING && lua.lua_type(L, -1) !== lua.LUA_TNUMBER) {
    const t = lua.lua_type(L, -1);
    lua.lua_pop(L, 1);
    return "(error object, type " + t + ")";
  }
  const s = lua.lua_tojsstring(L, -1);
  lua.lua_pop(L, 1);
  return s === null ? "(unreadable message)" : s;
}

function run(L, src) {
  const status = lauxlib.luaL_loadstring(L, to_luastring(src));
  if (status !== lua.LUA_OK) return { ok: false, error: "load error: " + topString(L) };
  const call = lua.lua_pcall(L, 0, lua.LUA_MULTRET, 0);
  if (call !== lua.LUA_OK) return { ok: false, error: "runtime error: " + topString(L) };
  return { ok: true };
}

function output(L) {
  lua.lua_getglobal(L, to_luastring("__out"));
  if (lua.lua_type(L, -1) !== lua.LUA_TTABLE) { lua.lua_pop(L, 1); return ""; }
  const lines = [];
  const len = lauxlib.luaL_len(L, -1);
  for (let i = 1; i <= len; i++) {
    lua.lua_rawgeti(L, -1, i);
    lines.push(lua.lua_type(L, -1) === lua.LUA_TSTRING ? lua.lua_tojsstring(L, -1) : String(lua.lua_type(L, -1)));
    lua.lua_pop(L, 1);
  }
  lua.lua_pop(L, 1);
  return lines.join("\n");
}

/**
 * Check that Lua source parses, without running it. Used for builds that call
 * Roblox-only APIs (the executor runtime is not available in tests).
 */
export function syntaxCheck(source) {
  const L = newState({});
  const status = lauxlib.luaL_loadstring(L, to_luastring(source));
  const error = status === lua.LUA_OK ? null : topString(L);
  lua.lua_close(L);
  return { ok: status === lua.LUA_OK, error };
}

/**
 * Execute Lua source and return everything it printed.
 * @returns {{ok:boolean, output?:string, error?:string}}
 */
export function runLua(source, options = {}) {
  const L = newState(options);
  const res = run(L, source);
  const out = output(L);
  lua.lua_close(L);
  if (!res.ok) return { ok: false, error: res.error, output: out };
  return { ok: true, output: out };
}

export default { runLua };
