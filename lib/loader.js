/**
 * Loader generation.
 *
 * The loader is what an executor actually fetches: `/loader/:id`. Key checks,
 * HWID whitelist checks and execution logging all happen server side before a
 * single byte of protected source is handed out, so the protected build itself
 * never has to carry authentication logic.
 */

export function banner({ name, buildId, engine, scriptId }) {
  return [
    `-- LuaLune Obfuscator`,
    `-- script : ${sanitizeComment(name)}`,
    `-- build  : ${buildId}`,
    `-- engine : ${engine}`,
    `-- id     : ${scriptId}`,
  ].join("\n");
}

function sanitizeComment(value) {
  return String(value ?? "").replace(/[\r\n]+/g, " ").slice(0, 80);
}

/** Protected source as it is served to an executor. */
export function buildLoader({ code, name, buildId, engine, scriptId, engineName }) {
  return `${banner({ name, buildId, engine: engineName || engine, scriptId })}\n${code}\n`;
}

/** Served instead of the build when a key, HWID or status check fails. */
export function denialLoader({ reason, scriptId, code = "invalid_key" }) {
  return [
    banner({ name: "access denied", buildId: "0", engine: "none", scriptId }),
    `-- reason: ${sanitizeComment(reason)}`,
    `-- code  : ${code}`,
    `return error("LuaLune: ${sanitizeComment(reason).replace(/"/g, "'")}", 0)`,
    "",
  ].join("\n");
}

/** One-liner users paste into their executor. */
export function loaderSnippet({ origin, scriptId, key }) {
  const base = `${origin}/loader/${scriptId}`;
  return `loadstring(game:HttpGet(${JSON.stringify(key ? `${base}?key=${key}` : base)}))()`;
}

export default { buildLoader, denialLoader, loaderSnippet, banner };
