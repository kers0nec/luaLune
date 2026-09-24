/**
 * Lune Obfuscator engine (optional).
 *
 * LuaLune's own engines (payload / flow / vault) are always available. This
 * module adds an AST-level engine powered by **Prometheus** by Elias Oelschner
 * (https://github.com/prometheus-lua/Prometheus, MIT) running inside a WASM Lua
 * VM, which is how the deployment that this repository's `main` branch described
 * built its scripts.
 *
 * The upstream engine sources are not vendored here. To enable this engine:
 *
 *   npm install wasmoon
 *   git clone https://github.com/prometheus-lua/Prometheus vendor/prometheus
 *
 * When the bundle is missing, `available()` reports false and callers fall back
 * to LuaLune's own Vault engine with a warning instead of failing the build.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "vendor", "prometheus", "src");

/** Prometheus preset names. LuaLune exposes friendlier profile names. */
const PROFILE_MAP = {
  minify: "Minify",
  weak: "Weak",
  light: "Weak",
  medium: "Medium",
  balanced: "Medium",
  strong: "Strong",
  heavy: "Strong",
  maximum: "Strong",
};

export const ATTRIBUTION = "Based on Prometheus by Elias Oelschner (https://github.com/prometheus-lua/Prometheus, MIT)";

let factoryPromise = null;
let lastError = null;

function luaFiles(dir) {
  const found = [];
  for (const name of fs.readdirSync(dir)) {
    const file = path.join(dir, name);
    if (fs.statSync(file).isDirectory()) found.push(...luaFiles(file));
    else if (name.endsWith(".lua")) found.push(file);
  }
  return found;
}

async function factory() {
  if (!factoryPromise) {
    factoryPromise = (async () => {
      if (!fs.existsSync(ROOT)) throw new Error("Lune Obfuscator engine sources are not installed (vendor/prometheus).");
      let wasmoon;
      try {
        wasmoon = await import("wasmoon");
      } catch {
        throw new Error("The 'wasmoon' package is required to run the Lune Obfuscator engine.");
      }
      const instance = new wasmoon.LuaFactory();
      for (const file of luaFiles(ROOT)) {
        const relative = path.relative(ROOT, file).split(path.sep).join("/");
        await instance.mountFile(`/prometheus/${relative}`, fs.readFileSync(file));
      }
      return instance;
    })().catch((error) => {
      lastError = error.message;
      factoryPromise = null; // allow a retry after the operator installs the bundle
      throw error;
    });
  }
  return factoryPromise;
}

/** True when both the vendored engine and wasmoon are present. */
export async function available() {
  try {
    await factory();
    return true;
  } catch {
    return false;
  }
}

export function unavailableReason() {
  return lastError || "Lune Obfuscator engine bundle not installed";
}

/**
 * Wrap the script in the runtime self-check that the engine build was paired
 * with: capture the builtins, verify they still behave, run the script, verify
 * again. Adapted from the anti-tamper wrapper that shipped with this repository.
 */
export function wrapWithAntiTamper(source) {
  return `return (function(...)
local __ll_type,__ll_typeof,__ll_pcall,__ll_error,__ll_tostring=type,typeof,pcall,error,tostring
local __ll_game=game
local function __ll_verify()
  if type~=__ll_type or typeof~=__ll_typeof or pcall~=__ll_pcall or tostring~=__ll_tostring then return false end
  if __ll_type(__ll_type)~="function" or __ll_type(__ll_pcall)~="function" then return false end
  if __ll_game==nil or __ll_typeof(__ll_game)~="Instance" then return false end
  local marker="LL_"..__ll_tostring(math.random(100000,999999))
  local caught,message=__ll_pcall(function() __ll_error(marker,0) end)
  if caught or not message or not string.find(__ll_tostring(message),marker,1,true) then return false end
  local serviceOk,players=__ll_pcall(function() return __ll_game:GetService("Players") end)
  if not serviceOk or players==nil or __ll_typeof(players)~="Instance" then return false end
  return true
end
if not __ll_verify() then return end
local __ll_result=(function(...)
${source}
end)(...)
if not __ll_verify() then return end
return __ll_result
end)(...)`;
}

const DRIVER = `
  arg = {}
  math.log10 = math.log10 or function(value) return math.log(value, 10) end
  unpack = unpack or table.unpack
  loadstring = loadstring or load
  package.path = '/prometheus/?.lua;/prometheus/?/init.lua;' .. package.path
  local Prometheus = require('prometheus')
  Prometheus.Logger.logLevel = Prometheus.Logger.LogLevel.Error
  Prometheus.Logger.errorCallback = function(message) error(message, 0) end
  local config = Prometheus.Presets[LUALUNE_PROFILE]
  config.LuaVersion = 'LuaU'
  config.Seed = os.time() + math.random(1, 1000000)
  if LUALUNE_ANTITAMPER then
    local found = false
    for _, step in ipairs(config.Steps or {}) do if step.Name == 'AntiTamper' then found = true break end end
    if not found then table.insert(config.Steps, 1, {Name='AntiTamper',Settings={UseDebug=false}}) end
  else
    local filtered = {}
    for _, step in ipairs(config.Steps or {}) do if step.Name ~= 'AntiTamper' then filtered[#filtered+1]=step end end
    config.Steps = filtered
  end
  local pipeline = Prometheus.Pipeline:fromConfig(config)
  return pipeline:apply(LUALUNE_SOURCE, 'LuaLune')
`;

/**
 * Run the Lune Obfuscator engine.
 * @param {string} source Lua/Luau source
 * @param {{preset?:string, antiTamper?:boolean}} options
 * @returns {Promise<string>} protected source
 */
export async function obfuscate(source, { preset = "medium", antiTamper = true } = {}) {
  let text = String(source ?? "");
  if (!text.trim()) throw new Error("Lua source cannot be empty.");
  if (Buffer.byteLength(text) > 500_000) throw new Error("Source exceeds the 500 KB limit for the Lune Obfuscator engine.");
  const profile = PROFILE_MAP[String(preset).toLowerCase()] || "Medium";
  if (antiTamper) text = wrapWithAntiTamper(text);

  const lua = await (await factory()).createEngine();
  try {
    lua.global.set("LUALUNE_SOURCE", text);
    lua.global.set("LUALUNE_PROFILE", profile);
    lua.global.set("LUALUNE_ANTITAMPER", !!antiTamper);
    const result = await lua.doString(DRIVER);
    if (!result || !String(result).trim()) throw new Error("The engine returned an empty build.");
    return [
      "-- Protected by LuaLune | Lune Obfuscator engine",
      `-- ${ATTRIBUTION}`,
      String(result),
    ].join("\n");
  } catch (error) {
    throw new Error("Lune Obfuscator failed: " + (error?.message || error));
  } finally {
    lua.global.close();
  }
}

export default { obfuscate, available, unavailableReason, wrapWithAntiTamper, ATTRIBUTION };
