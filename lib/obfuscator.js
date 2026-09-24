/**
 * LuaLune Obfuscator
 * -------------------
 * Source-to-source protection for Lua / Luau.
 *
 * Engines:
 *   payload : "LuaLune Obfuscator"          encrypted payload + randomized runtime decoder
 *   flow    : "LuaLune Obfuscator - Flow"   control-flow flattening + identifier/string/number rewriting
 *   none    : "None"                        store the script untouched
 *
 * Every pass is conservative: when a construct cannot be transformed without a
 * chance of changing semantics the pass disables itself and reports a warning
 * instead of gambling with the user's script.
 */

import crypto from "node:crypto";

export const ENGINES = {
  payload: { id: "payload", name: "LuaLune Obfuscator", tagline: "Encrypted payload + randomized runtime decoder" },
  flow: { id: "flow", name: "LuaLune Obfuscator - Flow", tagline: "Control flow flattening, renaming, string + number encryption" },
  vault: { id: "vault", name: "LuaLune Obfuscator - Vault", tagline: "Layered cascade, per-segment keys, decoys and anti-tamper" },
  lune: { id: "lune", name: "Lune Obfuscator", tagline: "AST-level engine (Prometheus) — install the engine bundle to enable", external: true },
  none: { id: "none", name: "None", tagline: "Store the script exactly as written" },
};

const KEYWORDS = new Set([
  "and","break","do","else","elseif","end","false","for","function","goto","if","in",
  "local","nil","not","or","repeat","return","then","true","until","while","continue",
]);

const LONG_OPERATORS = ["...","..=","==","~=","<=",">=","+=","-=","*=","/=","%=","^=","..","::"];
const SINGLE_OPERATORS = new Set("+-*/%^#<>=(){}[];:,.");
const BLOCK_OPEN = new Set(["do", "then", "repeat", "function"]); // +1 depth, closed by `end` / `until`
const BLOCK_NEUTRAL = new Set(["else", "elseif"]);                 // closes one block, opens another
const BLOCK_CLOSE = new Set(["end", "until"]);

/* ------------------------------------------------------------------ lexer */

/** Split Lua/Luau source into tokens. Whitespace is dropped and re-added on serialize. */
export function tokenize(src) {
  const tokens = [];
  let i = 0;
  const n = src.length;
  const at = (k) => src[k];
  const longBracketLevel = (start) => {
    if (at(start) !== "[") return -1;
    let j = start + 1;
    let level = 0;
    while (at(j) === "=") { level++; j++; }
    return at(j) === "[" ? level : -1;
  };

  while (i < n) {
    const c = at(i);
    if (" \t\r\n\f\v".includes(c)) { i++; continue; }

    // comments
    if (c === "-" && at(i + 1) === "-") {
      const level = longBracketLevel(i + 2);
      if (level >= 0) {
        const close = "]" + "=".repeat(level) + "]";
        const end = src.indexOf(close, i + 3 + level);
        i = end < 0 ? n : end + close.length;
      } else {
        const end = src.indexOf("\n", i);
        i = end < 0 ? n : end;
      }
      continue;
    }

    // long strings
    if (c === "[") {
      const level = longBracketLevel(i);
      if (level >= 0) {
        const close = "]" + "=".repeat(level) + "]";
        const end = src.indexOf(close, i + level + 2);
        const stop = end < 0 ? n : end + close.length;
        tokens.push({ type: "string", value: src.slice(i, stop), long: true });
        i = stop;
        continue;
      }
    }

    // short strings
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === c) { j++; break; }
        if (src[j] === "\n") break;
        j++;
      }
      tokens.push({ type: "string", value: src.slice(i, j) });
      i = j;
      continue;
    }

    // numbers
    if (/[0-9]/.test(c) || (c === "." && /[0-9]/.test(at(i + 1) || ""))) {
      let j = i;
      if (c === "0" && (at(i + 1) === "x" || at(i + 1) === "X")) {
        j = i + 2;
        while (j < n && /[0-9a-fA-F._]/.test(at(j))) j++;
        if (/[pP]/.test(at(j))) { j++; if (/[+-]/.test(at(j))) j++; while (j < n && /[0-9]/.test(at(j))) j++; }
      } else {
        while (j < n) {
          const ch = at(j);
          if (/[0-9_]/.test(ch)) { j++; continue; }
          if (ch === ".") { if (at(j + 1) === ".") break; j++; continue; }
          if (/[eE]/.test(ch)) { j++; if (/[+-]/.test(at(j))) j++; continue; }
          break;
        }
      }
      tokens.push({ type: "number", value: src.slice(i, j) });
      i = j;
      continue;
    }

    // names / keywords
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < n && /[A-Za-z0-9_]/.test(at(j))) j++;
      const value = src.slice(i, j);
      tokens.push({ type: KEYWORDS.has(value) ? "keyword" : "name", value });
      i = j;
      continue;
    }

    // operators
    const op3 = src.slice(i, i + 3);
    const op2 = src.slice(i, i + 2);
    if (LONG_OPERATORS.includes(op3)) { tokens.push({ type: "op", value: op3 }); i += 3; continue; }
    if (LONG_OPERATORS.includes(op2)) { tokens.push({ type: "op", value: op2 }); i += 2; continue; }
    if (SINGLE_OPERATORS.has(c)) { tokens.push({ type: "op", value: c }); i += 1; continue; }

    tokens.push({ type: "unknown", value: c }); // never silently drop input
    i += 1;
  }
  return tokens;
}

const tok = (type, value) => ({ type, value });

/** Join tokens into valid Lua. A single space between every token is always safe. */
export function serialize(tokens) {
  return tokens.map((t) => t.value).join(" ");
}

const isKw = (t, v) => !!t && t.type === "keyword" && t.value === v;
const isOp = (t, v) => !!t && t.type === "op" && t.value === v;
const isName = (t) => !!t && t.type === "name";

/* --------------------------------------------------------------- analysis */

const STATEMENT_END = new Set([";", "end", ")", "}", "]"]);

/** Tokens after which a value is expected, so an `if` there is a Luau if-expression. */
const VALUE_EXPECTED = new Set([
  "=", ",", "(", "[", "{", "..", "+", "-", "*", "/", "%", "^", "#", "<", ">", "<=", ">=",
  "==", "~=", "+=", "-=", "*=", "/=", "%=", "^=", "..=", ":",
  "and", "or", "not", "return", "in",
]);

/**
 * Report constructs that make scope walking unreliable. Anything listed turns
 * identifier renaming off; the remaining passes still run.
 */
export function analyze(tokens) {
  const reasons = [];
  const seen = { repeat: false, goto: false, label: false, ifExpr: false, vararg: false, compound: false, typeDecl: false, unbalanced: false };

  // Every block opener must have a matching closer. If they do not balance the
  // script uses something exotic (if-expressions, macros, ...) and we stay out.
  let openers = 0;
  let closers = 0;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const prev = tokens[i - 1];
    if (isKw(t, "repeat")) seen.repeat = true;
    if (isKw(t, "goto")) seen.goto = true;
    if (isOp(t, "::")) seen.label = true;
    if (isOp(t, "...")) seen.vararg = true;
    if (t.type === "op" && ["+=", "-=", "*=", "/=", "%=", "^=", "..="].includes(t.value)) seen.compound = true;
    // `type Name = ...` / `export type Name = ...`
    if (t.value === "type" && isName(tokens[i + 1]) && isOp(tokens[i + 2], "=") &&
        (!prev || prev.value === "export" || STATEMENT_END.has(prev.value) || isOp(prev, ";") || isKw(prev, "do"))) {
      seen.typeDecl = true;
    }
    if (isKw(t, "if") && prev && VALUE_EXPECTED.has(prev.value)) seen.ifExpr = true;
    if (BLOCK_OPEN.has(t.value)) openers++;
    if (BLOCK_CLOSE.has(t.value)) closers++;
  }
  if (openers !== closers) seen.unbalanced = true;

  if (seen.repeat) reasons.push("repeat/until blocks");
  if (seen.goto) reasons.push("goto statements");
  if (seen.label) reasons.push("::labels::");
  if (seen.ifExpr) reasons.push("Luau if-expressions");
  if (seen.unbalanced) reasons.push("unbalanced block structure");
  return {
    safeToRename: reasons.length === 0,
    reasons,
    seen,
    counts: {
      tokens: tokens.length,
      strings: tokens.filter((t) => t.type === "string").length,
      numbers: tokens.filter((t) => t.type === "number").length,
      locals: tokens.filter((t, i) => isKw(t, "local") && isName(tokens[i + 1])).length,
    },
  };
}

/** Block depth after token index i (functions/blocks counted, expressions ignored). */
function depthTracker() {
  let depth = 0;
  return (t) => {
    if (BLOCK_OPEN.has(t.value)) depth++;
    else if (BLOCK_CLOSE.has(t.value)) depth = Math.max(0, depth - 1);
    return depth;
  };
}

/* --------------------------------------------------------- identifier pass */

function makeNameGenerator(tokens) {
  const taken = new Set(tokens.filter((t) => t.type === "name").map((t) => t.value));
  const alphabet = "abcdefghijklmnopqrstuvwxyz";
  let counter = 0;
  return () => {
    for (;;) {
      counter++;
      const name = "_" + alphabet[counter % alphabet.length] + counter.toString(36) + crypto.randomBytes(2).toString("hex");
      if (!taken.has(name) && !KEYWORDS.has(name)) { taken.add(name); return name; }
    }
  };
}

/** True when the innermost unclosed bracket seen so far is a table constructor. */
function insideTable(tokens, upto) {
  let pending = 0;
  for (let i = upto - 1; i >= 0; i--) {
    const v = tokens[i].value;
    if (v === "}" || v === ")" || v === "]") pending++;
    else if (v === "{" || v === "(" || v === "[") {
      if (pending > 0) pending--;
      else return v === "{";
    }
  }
  return false;
}

/**
 * Scope-aware local renaming. Only identifiers that are provably locals get a
 * new name; globals, table keys, method names and labels are untouched.
 */
export function renamePass(tokens) {
  const next = makeNameGenerator(tokens);
  const scopes = [new Map()];
  const top = () => scopes[scopes.length - 1];
  const declare = (name) => { const f = top(); if (!f.has(name)) f.set(name, next()); };
  const lookup = (name) => {
    for (let i = scopes.length - 1; i >= 0; i--) if (scopes[i].has(name)) return scopes[i].get(name);
    return null;
  };

  const out = [];
  let pendingFor = []; // {slot, name} -- control variables are renamed once the block opens
  let expectingParams = false;
  let renamedCount = 0;

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const n1 = tokens[i + 1];

    /* local a, b <const> = ...   |   local function f() */
    if (isKw(t, "local")) {
      if (isKw(n1, "function") && isName(tokens[i + 2])) {
        declare(tokens[i + 2].value);
        out.push(t, n1, { ...tokens[i + 2], value: lookup(tokens[i + 2].value) });
        renamedCount++;
        i += 2;
        expectingParams = true;
        continue;
      }
      out.push(t);
      let j = i + 1;
      // `local a, b` -- names must be comma separated, otherwise the next
      // statement's first token would be swallowed as another declaration
      if (isName(tokens[j])) {
        declare(tokens[j].value);
        out.push({ ...tokens[j], value: lookup(tokens[j].value) });
        renamedCount++;
        j++;
        while (isOp(tokens[j], ",") && isName(tokens[j + 1])) {
          out.push(tokens[j]);
          declare(tokens[j + 1].value);
          out.push({ ...tokens[j + 1], value: lookup(tokens[j + 1].value) });
          renamedCount++;
          j += 2;
        }
      }
      if (isOp(tokens[j], "<")) { // <const> / <close> attribute
        out.push(tokens[j]); j++;
        while (j < tokens.length && !isOp(tokens[j], ">")) { out.push(tokens[j]); j++; }
        if (j < tokens.length) { out.push(tokens[j]); j++; }
      }
      i = j - 1;
      continue;
    }

    /* function a.b.c:d(...) -- the dotted path is never renamed */
    if (isKw(t, "function")) {
      out.push(t);
      expectingParams = true;
      let j = i + 1;
      // `function obj:method()` -- the head is a variable reference, the rest are fields
      if (isName(tokens[j])) {
        const alias = lookup(tokens[j].value);
        out.push(alias ? { ...tokens[j], value: alias } : tokens[j]);
        j++;
      }
      while (j < tokens.length && (isName(tokens[j]) || isOp(tokens[j], ".") || isOp(tokens[j], ":"))) { out.push(tokens[j]); j++; }
      i = j - 1;
      continue;
    }

    /* for i = ... do   |   for k, v in ... do */
    if (isKw(t, "for")) {
      pendingFor = [];
      out.push(t);
      let j = i + 1;
      // Only the control variables are loop locals; everything from `=` / `in`
      // onwards belongs to the enclosing scope and is handled by the main loop.
      while (j < tokens.length && !isKw(tokens[j], "in") && !isOp(tokens[j], "=") && !isKw(tokens[j], "do")) {
        if (isName(tokens[j]) && !isOp(tokens[j - 1], ".") && !isOp(tokens[j - 1], ":")) {
          // remember the slot; the alias only exists once the loop block opens,
          // so the bounds expression still resolves against the outer scope
          pendingFor.push({ slot: out.length, name: tokens[j].value });
          out.push({ ...tokens[j] });
        } else {
          out.push(tokens[j]);
        }
        j++;
      }
      i = j - 1;
      continue;
    }

    /* block structure */
    if (isKw(t, "do") || isKw(t, "then")) {
      scopes.push(new Map());
      if (isKw(t, "do") && pendingFor.length) {
        for (const entry of pendingFor) {
          declare(entry.name);
          out[entry.slot].value = lookup(entry.name);
          renamedCount++;
        }
        pendingFor = [];
      }
      out.push(t);
      continue;
    }
    if (isKw(t, "else")) { if (scopes.length > 1) scopes.pop(); scopes.push(new Map()); out.push(t); continue; }
    if (isKw(t, "elseif")) { if (scopes.length > 1) scopes.pop(); out.push(t); continue; }
    if (isKw(t, "end") || isKw(t, "until")) { if (scopes.length > 1) scopes.pop(); out.push(t); continue; }

    /* parameter list */
    if (isOp(t, "(") && expectingParams) {
      expectingParams = false;
      scopes.push(new Map());
      out.push(t);
      let j = i + 1;
      let depth = 1;
      while (j < tokens.length) {
        const pt = tokens[j];
        if (isOp(pt, "(")) depth++;
        else if (isOp(pt, ")")) { depth--; if (depth === 0) break; }
        if (isName(pt) && depth === 1) { declare(pt.value); out.push({ ...pt, value: lookup(pt.value) }); renamedCount++; j++; continue; }
        out.push(pt);
        j++;
      }
      if (j < tokens.length) out.push(tokens[j]);
      i = j;
      continue;
    }
    if (isOp(t, "(")) expectingParams = false;

    /* names */
    if (isName(t)) {
      const prevRaw = tokens[i - 1];
      const afterDot = isOp(prevRaw, ".") || isOp(prevRaw, ":") || isOp(prevRaw, "::");
      const afterGoto = isKw(prevRaw, "goto");
      const keyPosition = insideTable(tokens, i) && (isOp(n1, "=") || isOp(n1, ":") || isOp(n1, "?") || isOp(n1, ","));
      if (!afterDot && !afterGoto && !keyPosition) {
        const alias = lookup(t.value);
        if (alias) { out.push({ ...t, value: alias }); continue; }
      }
      out.push(t);
      continue;
    }

    out.push(t);
  }

  return { tokens: out, renamed: renamedCount };
}

/* ------------------------------------------------------------- string pass */

/** Replace string literals with `dec(index)` lookups. Method-position strings are skipped. */
export function stringsPass(tokens, { decoderName = "__LLstr" } = {}) {
  const strings = [];
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const prev = tokens[i - 1];
    if (t.type === "string" && !isOp(prev, ":") && !isOp(prev, ".")) {
      strings.push(t.value);
      out.push(tok("name", decoderName), tok("op", "("), tok("number", String(strings.length - 1)), tok("op", ")"));
      continue;
    }
    out.push(t);
  }
  return { tokens: out, strings, decoderName };
}

/** Escape raw bytes into a Lua short-string literal using only \ddd escapes. */
export function luaStringLiteral(str) {
  let out = '"';
  const buf = Buffer.from(str, "binary");
  for (let i = 0; i < buf.length; i++) out += "\\" + String(buf[i]).padStart(3, "0");
  return out + '"';
}

/** Decode a Lua string literal token back to a binary string. */
export function readLuaStringLiteral(literal) {
  if (literal.startsWith("[")) {
    const level = (/^\[=*\[/).exec(literal)[0];
    const close = level.replace(/\[/g, "]");
    return literal.slice(level.length, literal.lastIndexOf(close));
  }
  const body = literal.slice(1, -1);
  const bytes = [];
  for (let i = 0; i < body.length; i++) {
    if (body[i] === "\\") {
      const m = /^\\(\d{1,3})/.exec(body.slice(i));
      if (m) { bytes.push(Number(m[1]) & 255); i += m[1].length; continue; }
      const c = body[++i];
      if (c === "x") { bytes.push(parseInt(body.substr(i + 1, 2), 16)); i += 2; continue; }
      const map = { n: 10, t: 9, r: 13, a: 7, b: 8, f: 12, v: 11, "\\": 92, '"': 34, "'": 39, "\n": 10, z: 0 };
      bytes.push(map[c] !== undefined ? map[c] : c.charCodeAt(0));
      continue;
    }
    bytes.push(body.charCodeAt(i) & 255);
  }
  return Buffer.from(bytes).toString("binary");
}

/* ------------------------------------------------------------- number pass */

/** Rewrite integer literals as `(a+b)` / `(a-b)` pairs. Floats and hex floats are left alone. */
export function numbersPass(tokens, { rng = Math.random } = {}) {
  let count = 0;
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const prev = tokens[i - 1];
    if (t.type === "number" && /^\d+$/.test(t.value) && !isOp(prev, ".")) {
      const value = Number(t.value);
      if (Number.isSafeInteger(value) && value >= 0 && value < 2 ** 31) {
        const delta = 1 + Math.floor(rng() * 4095);
        const useAdd = rng() < 0.5;
        const a = useAdd ? Math.max(0, value - delta) : value + delta;
        const b = useAdd ? value - a : delta;
        out.push(tok("op", "("), tok("number", String(a)), tok("op", useAdd ? "+" : "-"), tok("number", String(b)), tok("op", ")"));
        count++;
        continue;
      }
    }
    out.push(t);
  }
  return { tokens: out, count };
}

/* --------------------------------------------------------------- junk pass */

/**
 * Insert dead `local x=(a*b)` statements after unambiguous statement boundaries.
 * Nothing is inserted inside parentheses/braces, so table constructors and call
 * argument lists stay valid.
 */
export function junkPass(tokens, { prefix = "__LLjunk", rng = Math.random, density = 0.35 } = {}) {
  const out = [];
  let index = 0;
  let inserted = 0;
  let bracket = 0;
  const blocks = []; // true when the open block is a statement block (so `end` ends a statement)
  const junk = () => {
    index++;
    const a = 100 + Math.floor(rng() * 9000);
    const b = 100 + Math.floor(rng() * 9000);
    return [
      tok("keyword", "local"), tok("name", prefix + index.toString(36)), tok("op", "="),
      tok("op", "("), tok("number", String(a)), tok("op", "*"), tok("number", String(b)), tok("op", ")"),
    ];
  };
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    const prev = tokens[i - 1];
    if (t.value === "(" || t.value === "{" || t.value === "[") bracket++;
    else if (t.value === ")" || t.value === "}" || t.value === "]") bracket = Math.max(0, bracket - 1);

    if (isKw(t, "then") || isKw(t, "do") || isKw(t, "repeat")) blocks.push(true);
    else if (isKw(t, "function")) {
      // `function f()` at statement position vs `x = function()` inside an expression
      const statementPosition = !prev ||
        [";", "end", "then", "else", "do", "local", ")", "}", "]", "repeat", "until"].includes(prev.value);
      blocks.push(statementPosition);
    }

    out.push(t);

    let boundary = false;
    if (isKw(t, "end") || isKw(t, "until")) boundary = blocks.pop() === true;
    else if (isOp(t, ";")) boundary = true;
    if (boundary && bracket === 0 && rng() < density) { out.push(...junk()); inserted++; }
  }
  if (inserted === 0) { out.push(...junk()); inserted++; }
  return { tokens: out, inserted };
}

/* ------------------------------------------------------ control-flow pass */

/**
 * Split the top level of a chunk into blocks, hoist its locals into the shared
 * scope and run the blocks through a shuffled dispatcher. Returns null when the
 * script is not a candidate (top-level varargs, too many locals, attributes...).
 */
export function flattenPass(tokens, analysis) {
  if (analysis && !analysis.safeToRename) return { ok: false, reason: analysis.reasons.join(", ") };

  let depth = 0;
  let bracket = 0;
  const blocks = [];
  let current = [];
  const topLocals = [];
  let sawTopReturn = false;
  let sawTopVararg = false;
  let sawAttribute = false;
  const seenNames = new Set();   // every top level name reference
  const references = [];         // {name, index} of those references
  const declIndex = new Map();   // top level local name -> first declaration index
  const shadowed = [];           // names read before a later top level local captures them

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    current.push(t);
    const atTop = depth === 0 && bracket === 0;

    if (atTop) {
      if (isKw(t, "return")) sawTopReturn = true;
      if (isOp(t, "...")) sawTopVararg = true;
      if (isName(t) && !isOp(tokens[i - 1], ".") && !isOp(tokens[i - 1], ":") && !isOp(tokens[i - 1], "::")) {
        const declaredHere = isKw(tokens[i - 1], "local") || (isKw(tokens[i - 2], "local") && isKw(tokens[i - 1], "function"));
        if (declaredHere) {
          if (!declIndex.has(t.value)) declIndex.set(t.value, i);
        } else {
          seenNames.add(t.value);
          references.push({ name: t.value, index: i });
        }
      }
      if (isKw(t, "local")) {
        let j = i + 1;
        if (isKw(tokens[j], "function") && isName(tokens[j + 1])) {
          if (!topLocals.includes(tokens[j + 1].value)) topLocals.push(tokens[j + 1].value);
        } else {
          if (isName(tokens[j]) && !topLocals.includes(tokens[j].value)) topLocals.push(tokens[j].value);
          j++;
          while (isOp(tokens[j], ",") && isName(tokens[j + 1])) {
            if (!topLocals.includes(tokens[j + 1].value)) topLocals.push(tokens[j + 1].value);
            j += 2;
          }
          if (isOp(tokens[j], "<")) sawAttribute = true;
        }
      }
    }

    if (t.value === "(" || t.value === "{" || t.value === "[") bracket++;
    else if (t.value === ")" || t.value === "}" || t.value === "]") bracket = Math.max(0, bracket - 1);
    if (BLOCK_OPEN.has(t.value)) depth++;
    else if (BLOCK_CLOSE.has(t.value)) depth = Math.max(0, depth - 1);

    // Only a statement boundary at true top level may start a new block.
    if (depth === 0 && bracket === 0 && (isKw(t, "end") || isOp(t, ";"))) {
      blocks.push(current);
      current = [];
    }
  }
  if (current.length) blocks.push(current);

  // `print(x); local x = 1` reads a global that hoisting would hide.
  for (const ref of references) {
    const declared = declIndex.get(ref.name);
    if (declared !== undefined && declared > ref.index && !shadowed.includes(ref.name)) shadowed.push(ref.name);
  }

  if (sawTopVararg) return { ok: false, reason: "top-level varargs" };
  if (sawAttribute) return { ok: false, reason: "local attributes (<const>/<close>)" };
  if (shadowed.length) return { ok: false, reason: "a global is shadowed by a later top level local" };
  const usable = blocks.filter((b) => b.length > 0);
  if (usable.length < 3) return { ok: false, reason: "not enough top level blocks" };
  if (topLocals.length + usable.length + 8 > 180) return { ok: false, reason: "too many top level locals" };

  const rewritten = usable.map((block) => {
    const out = [];
    let d = 0;
    for (let i = 0; i < block.length; i++) {
      const t = block[i];
      const atTop = d === 0;
      if (BLOCK_OPEN.has(t.value)) d++;
      else if (BLOCK_CLOSE.has(t.value)) d = Math.max(0, d - 1);
      // top level declarations are hoisted into the dispatcher scope
      if (atTop && isKw(t, "local")) {
        if (isKw(block[i + 1], "function") && isName(block[i + 2])) {
          // `local function f(...)` -> assignment to the hoisted local, so
          // recursion and ordering behave exactly like the original
          out.push({ ...block[i + 2] }, tok("op", "="), block[i + 1]);
          i += 2;
          continue;
        }
        let j = i + 1;
        if (isName(block[j])) {
          j++;
          while (isOp(block[j], ",") && isName(block[j + 1])) j += 2;
        }
        if (isOp(block[j], "=")) {
          // `local a, b = expr` -> `a, b = expr`
          out.push(...block.slice(i + 1, j));
          i = j - 1;
          continue;
        }
        // `local a` with no value: the hoisted local is already nil
        i = j - 1;
        continue;
      }
      out.push(t);
    }
    // A top level `return` becomes "record values, stop the dispatcher".
    const retIdx = out.findIndex((x, k) => isKw(x, "return") && depthOf(out, k) === 0);
    if (retIdx >= 0) {
      const head = out.slice(0, retIdx);
      const values = out.slice(retIdx + 1);
      return [
        ...head,
        tok("name", "__LLret"), tok("op", "="), tok("op", "{"), ...values, tok("op", "}"), tok("op", ";"),
        tok("name", "__LLn"), tok("op", "="), tok("name", "select"), tok("op", "("), tok("string", '"#"'), tok("op", ","), ...values, tok("op", ")"), tok("op", ";"),
        tok("name", "__LLhalt"), tok("op", "="), tok("keyword", "true"), tok("op", ";"),
        tok("keyword", "return"),
      ];
    }
    return out;
  });

  return { ok: true, blocks: rewritten, hoisted: topLocals, count: rewritten.length };
}

function depthOf(tokens, k) {
  let d = 0;
  for (let i = 0; i < k; i++) {
    const v = tokens[i].value;
    if (BLOCK_OPEN.has(v)) d++;
    else if (BLOCK_CLOSE.has(v)) d = Math.max(0, d - 1);
  }
  return d;
}

/* ------------------------------------------------------- payload encryption */

/** Park-Miller LCG. Exact in IEEE doubles (< 2^53) and in Luau int64. */
export function keystream(seed, length) {
  let state = seed % 2147483647;
  if (state <= 0) state += 2147483646;
  const out = Buffer.alloc(length);
  for (let i = 0; i < length; i++) {
    state = (state * 48271) % 2147483647;
    let k = Math.floor(state / 8388608) % 256;
    k ^= ((i + 1) * 31 + 7) & 255;
    out[i] = k;
  }
  return out;
}

export function xorWith(buf, ks) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ ks[i];
  return out;
}

/** Rolling checksum (mod 65521) used by the runtime tamper check. */
export function checksum(buf) {
  let a = 1;
  let b = 0;
  for (let i = 0; i < buf.length; i++) {
    a = (a + buf[i]) % 65521;
    b = (b + a) % 65521;
  }
  return (b * 65536 + a) >>> 0;
}

export function shuffleOrder(n, rng = Math.random) {
  const order = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  return order;
}

const randomPrefix = () => "__LL" + crypto.randomBytes(3).toString("hex");

/* ------------------------------------------------- runtime helper emission */

/**
 * Generated builds must not depend on `bit32`: some executors ship it broken and
 * others do not ship it at all. Instead we embed a 256 byte xor table (nibble
 * against nibble) which is shifted by a per-build key, rebuilt at runtime and
 * used through arithmetic only. No bitwise operators, nothing wider than a byte.
 */
export function xorNibbleTable() {
  const table = Buffer.alloc(256);
  for (let a = 0; a < 16; a++) for (let b = 0; b < 16; b++) table[a * 16 + b] = a ^ b;
  return table;
}

/** One obfuscated xor table plus the Lua that rebuilds and uses it. */
function xorRuntime({ table, shift, fn }) {
  const real = xorNibbleTable();
  const shifts = crypto.randomBytes(16);
  const encoded = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) encoded[i] = (real[i] + shifts[i % 16]) & 255;
  return [
    `local ${shift}={${[...shifts].join(",")}}`,
    `local ${table}={}`,
    `local __xe=${luaStringLiteral(encoded.toString("binary"))}`,
    `for __xi=1,256 do ${table}[__xi]=(string.byte(__xe,__xi)-${shift}[((__xi-1)%16)+1])%256 end`,
    `local function ${fn}(a,b) return ${table}[math.floor(a/16)*16+math.floor(b/16)+1]*16+${table}[(a%16)*16+(b%16)+1] end`,
  ];
}

/** Environment self test: refuses to run when the builtins a build relies on are hooked. */
function envGuard(prefix, { needsLoad = true } = {}) {
  return [
    `local ${prefix}=function()`,
    `if string.char(65)~="A" or string.byte("A")~=65 then return false end`,
    `if table.concat({"a","b"})~="ab" then return false end`,
    `if math.fmod(7,3)~=1 or math.floor(2.5)~=2 then return false end`,
    needsLoad ? `if not (loadstring or load) then return false end` : "",
    `return true end`,
    `if not ${prefix}() then return error("LuaLune Obfuscator: unsupported or hooked environment",0) end`,
  ].filter(Boolean);
}

/** Build the protected Luau source for the payload engine. */
export function buildPayload(source, options = {}) {
  const seed = 1 + crypto.randomInt(1, 2147483645);
  const buf = Buffer.from(source, "utf8");
  const enc = xorWith(buf, keystream(seed, buf.length));
  const sum = checksum(enc);
  const parts = Math.max(2, Math.min(6, options.parts || 2 + crypto.randomInt(0, 4)));
  const size = Math.ceil(enc.length / parts) || 1;
  const chunks = [];
  for (let i = 0; i < parts; i++) {
    const slice = enc.subarray(i * size, (i + 1) * size);
    if (slice.length) chunks.push(slice);
  }
  const literal = (b) => luaStringLiteral(b.toString("binary"));
  // Table slots are shuffled; `order` maps original chunk index -> slot.
  const perm = shuffleOrder(chunks.length);
  const slots = perm.map((ci) => literal(chunks[ci]));
  const order = chunks.map((_, ci) => perm.indexOf(ci) + 1);
  const p = {
    tbl: randomPrefix(), order: randomPrefix(), dec: randomPrefix(), xor: randomPrefix(), xtab: randomPrefix(),
    xshift: randomPrefix(), guard: randomPrefix(), out: randomPrefix(), buf: randomPrefix(), fn: randomPrefix(),
    keys: randomPrefix(), i: randomPrefix(),
  };
  return [
    ...(options.harden === false ? [] : envGuard(p.guard, { needsLoad: true })),
    ...xorRuntime({ table: p.xtab, shift: p.xshift, fn: p.xor }),
    `local ${p.tbl}={${slots.join(",")}}`,
    `local ${p.order}={${order.join(",")}}`,
    `local ${p.buf}=""`,
    `for ${p.i}=1,#${p.order} do ${p.buf}=${p.buf}..${p.tbl}[${p.order}[${p.i}]] end`,
    `local __ca,__cb=1.0,0.0`,
    `for ${p.i}=1,#${p.buf} do __ca=math.fmod(__ca+string.byte(${p.buf},${p.i}),65521.0) __cb=math.fmod(__cb+__ca,65521.0) end`,
    // compared as two halves so it stays correct on Lua builds with 32 bit integers
    `if __ca~=${sum % 65536} or __cb~=${Math.floor(sum / 65536)} then return error("LuaLune Obfuscator: build integrity check failed",0) end`,
    `local ${p.dec}=function(s,seed)`,
    `local st=math.fmod(seed,2147483647.0) if st<=0 then st=st+2147483646 end`,
    `local o={}`,
    `for i=1,#s do`,
    `st=math.fmod(st*48271.0,2147483647.0)`,
    `local k=${p.xor}(math.floor(st/8388608)%256,((i*31)+7)%256)`,
    `o[i]=string.char(${p.xor}(string.byte(s,i),k))`,
    `end`,
    `return table.concat(o) end`,
    `local ${p.fn}=loadstring or load`,
    `local ${p.out}=${p.fn}(${p.dec}(${p.buf},${seed}))`,
    `if not ${p.out} then return error("LuaLune Obfuscator: unable to load protected build",0) end`,
    `return ${p.out}()`,
  ].join("\n");
}

/**
 * Vault engine: three cascaded transforms (keystream xor -> 3 bit rotate ->
 * additive stream), each segment carrying its own checksum, decoy records mixed
 * into the pool and a magic marker checked after decoding. Everything is plain
 * arithmetic, so it runs on any Lua or Luau build.
 */
export function buildVault(source, options = {}) {
  const magic = crypto.randomBytes(6);
  const plain = Buffer.concat([magic, Buffer.from(source, "utf8")]);
  const seedA = 1 + crypto.randomInt(1, 2147483645);
  const seedB = 1 + crypto.randomInt(1, 2147483645);
  const k1 = keystream(seedA, plain.length);
  const k2 = keystream(seedB, plain.length);
  const cipher = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) {
    const rotated = ((plain[i] ^ k1[i]) * 8 + ((plain[i] ^ k1[i]) >> 5)) & 255; // rotate left 3
    cipher[i] = (rotated + k2[i]) & 255;
  }

  const parts = Math.max(3, Math.min(8, options.parts || 3 + crypto.randomInt(0, 4)));
  const size = Math.ceil(cipher.length / parts) || 1;
  const segments = [];
  for (let i = 0; i < parts; i++) {
    const slice = cipher.subarray(i * size, (i + 1) * size);
    if (slice.length) segments.push(slice);
  }

  const sum = (buf) => {
    let a = 1;
    let b = 0;
    for (let i = 0; i < buf.length; i++) {
      a = (a + buf[i]) % 65521;
      b = (b + a) % 65521;
    }
    return [a, b];
  };

  // real records first, then decoys that are never referenced by `order`
  const records = segments.map((data) => ({ data, sum: sum(data) }));
  const decoys = 1 + crypto.randomInt(0, 2);
  for (let i = 0; i < decoys; i++) {
    const data = crypto.randomBytes(Math.max(8, Math.min(64, segments[0].length)));
    records.push({ data, sum: sum(data) });
  }
  const perm = shuffleOrder(records.length);
  const slots = perm.map((ri) => records[ri]);
  const order = segments.map((_, si) => perm.indexOf(si) + 1);
  const literal = (b) => luaStringLiteral(b.toString("binary"));

  const p = {
    xor: randomPrefix(), xtab: randomPrefix(), xshift: randomPrefix(), guard: randomPrefix(),
    rec: randomPrefix(), order: randomPrefix(), buf: randomPrefix(), i: randomPrefix(), j: randomPrefix(),
    fn: randomPrefix(), out: randomPrefix(),
  };

  return [
    ...(options.harden === false ? [] : envGuard(p.guard, { needsLoad: true })),
    ...xorRuntime({ table: p.xtab, shift: p.xshift, fn: p.xor }),
    `local ${p.rec}={${slots.map((r) => `{${literal(r.data)},${r.sum[0]},${r.sum[1]}}`).join(",")}}`,
    `local ${p.order}={${order.join(",")}}`,
    `local ${p.buf}=""`,
    `for ${p.i}=1,#${p.order} do`,
    `local __r=${p.rec}[${p.order}[${p.i}]] local __s=__r[1] local __a,__b=1.0,0.0`,
    `for ${p.j}=1,#__s do __a=math.fmod(__a+string.byte(__s,${p.j}),65521.0) __b=math.fmod(__b+__a,65521.0) end`,
    `if __a~=__r[2] or __b~=__r[3] then return error("LuaLune Obfuscator: build integrity check failed",0) end`,
    `${p.buf}=${p.buf}..__s`,
    `end`,
    `local __st1=math.fmod(${seedA},2147483647.0) if __st1<=0 then __st1=__st1+2147483646 end`,
    `local __st2=math.fmod(${seedB},2147483647.0) if __st2<=0 then __st2=__st2+2147483646 end`,
    `local __o={}`,
    `for i=1,#${p.buf} do`,
    `__st1=math.fmod(__st1*48271.0,2147483647.0)`,
    `local __k1=${p.xor}(math.floor(__st1/8388608)%256,((i*31)+7)%256)`,
    `__st2=math.fmod(__st2*48271.0,2147483647.0)`,
    `local __k2=${p.xor}(math.floor(__st2/8388608)%256,((i*31)+7)%256)`,
    `local __v=(string.byte(${p.buf},i)-__k2)%256`,
    `__v=math.floor(__v/8)+(__v%8)*32`,
    `__o[i]=string.char(${p.xor}(__v,__k1))`,
    `end`,
    `local __src=table.concat(__o)`,
    `if string.sub(__src,1,6)~=${literal(magic)} then return error("LuaLune Obfuscator: protected build failed to decode",0) end`,
    `local ${p.fn}=loadstring or load`,
    `local ${p.out}=${p.fn}(string.sub(__src,7))`,
    `if not ${p.out} then return error("LuaLune Obfuscator: unable to load protected build",0) end`,
    `return ${p.out}()`,
  ].join("\n");
}

/* ------------------------------------------------------------------- build */

export function buildId() {
  return crypto.randomBytes(6).toString("hex");
}

/**
 * Run the full pipeline.
 * @param {string} source Lua/Luau source
 * @param {object} options {engine, rename, strings, numbers, junk, flatten}
 */
export function obfuscate(source, options = {}) {
  const engine = ENGINES[options.engine] ? options.engine : "payload";
  const warnings = [];
  const stats = { engine, buildId: buildId(), sourceBytes: Buffer.byteLength(source, "utf8"), passes: [] };
  const finish = (code) => ({
    code,
    engine,
    warnings,
    stats: {
      ...stats,
      outputBytes: Buffer.byteLength(code, "utf8"),
      ratio: +(Buffer.byteLength(code, "utf8") / Math.max(1, stats.sourceBytes)).toFixed(2),
    },
  });

  if (engine === "none") return finish(source);

  if (engine === "payload") {
    stats.passes.push("payload-encryption", "shuffled-segments", "integrity-check", "runtime-decoder");
    if (options.harden !== false) stats.passes.push("environment-guard");
    return finish(buildPayload(source, options));
  }

  if (engine === "vault") {
    stats.passes.push("cascade-encryption", "per-segment-checksums", "decoy-records", "magic-marker", "runtime-decoder");
    if (options.harden !== false) stats.passes.push("environment-guard");
    return finish(buildVault(source, options));
  }

  /* ---- flow engine ---- */
  let tokens = tokenize(source);
  const info = analyze(tokens);
  stats.safeToRename = info.safeToRename;

  if (options.rename !== false && info.safeToRename) {
    const r = renamePass(tokens);
    tokens = r.tokens;
    stats.renamed = r.renamed;
    stats.passes.push("identifier-renaming");
  } else if (options.rename !== false) {
    warnings.push("Identifier renaming skipped (script uses " + info.reasons.join(", ") + "). Every other pass still ran.");
  }

  let originals = [];
  if (options.strings !== false) {
    const r = stringsPass(tokens);
    tokens = r.tokens;
    originals = r.strings.map(readLuaStringLiteral);
    stats.strings = originals.length;
    stats.passes.push("string-encryption");
  }

  if (options.numbers !== false) {
    const r = numbersPass(tokens);
    tokens = r.tokens;
    stats.numbers = r.count;
    stats.passes.push("number-encryption");
  }

  let prelude = "";
  if (originals.length) {
    const key = crypto.randomBytes(16);
    const encode = (s, i) => {
      const bytes = Buffer.from(s, "binary");
      const out = Buffer.alloc(bytes.length);
      for (let j = 0; j < bytes.length; j++) out[j] = bytes[j] ^ key[j % key.length] ^ ((i * 17 + j * 31) & 255);
      return luaStringLiteral(out.toString("binary"));
    };
    // Strings are split across two pools in shuffled order with decoy entries in
    // both, and `slots` records where each string actually lives (negative means
    // the second pool), so a reader cannot just index the table in order.
    const records = originals.map((s, i) => ({ encoded: encode(s, i), real: true }));
    const decoys = Math.min(6, Math.max(2, Math.round(originals.length / 2)));
    for (let i = 0; i < decoys; i++) {
      records.push({ encoded: luaStringLiteral(crypto.randomBytes(1 + crypto.randomInt(0, 12)).toString("binary")), real: false });
    }
    const perm = shuffleOrder(records.length);
    const poolA = [];
    const poolB = [];
    const slots = new Array(originals.length).fill(0);
    perm.forEach((recordIndex, slot) => {
      const record = records[recordIndex];
      if (slot % 2 === 0) poolA.push(record.encoded);
      else poolB.push(record.encoded);
      if (record.real && recordIndex < originals.length) {
        const absolute = slot % 2 === 0 ? poolA.length : poolB.length;
        slots[recordIndex] = slot % 2 === 0 ? absolute : -absolute;
      }
    });
    prelude = [
      ...(options.harden === false ? [] : envGuard("__LLenv", { needsLoad: false })),
      ...xorRuntime({ table: "__LLxt", shift: "__LLxs", fn: "__LLxor" }),
      `local __LLkey={${[...key].join(",")}}`,
      `local __LLt1={${poolA.join(",")}}`,
      `local __LLt2={${poolB.join(",")}}`,
      `local __LLslots={${slots.join(",")}}`,
      `local __LLcache={}`,
      `local function __LLstr(n)`,
      `local hit=__LLcache[n] if hit~=nil then return hit end`,
      `local __slot=__LLslots[n+1]`,
      `local __raw=__slot>0 and __LLt1[__slot] or __LLt2[-__slot]`,
      `local o={} local i=n`,
      `for p=1,#__raw do o[p]=string.char(__LLxor(__LLxor(string.byte(__raw,p),__LLkey[((p-1)%16)+1]),((i*17)+((p-1)*31))%256)) end`,
      `hit=table.concat(o) __LLcache[n]=hit return hit end`,
    ].join("\n");
    stats.passes.push("string-table", "string-pools");
  }

  let body = serialize(tokens);

  if (options.flatten !== false) {
    const flat = flattenPass(tokenize(body), info);
    if (flat.ok) {
      // Chunks still run in source order (hoisted locals create real
      // dependencies); only the table the functions live in is shuffled.
      const perm = shuffleOrder(flat.count);
      const slotOf = (chunkIndex) => perm.indexOf(chunkIndex);
      const order = flat.blocks.map((_, i) => slotOf(i) + 1);
      const chunks = flat.blocks.map((block, i) => `__LLc[${slotOf(i) + 1}]=function()\n${serialize(block)}\nend`);
      body = [
        `local __LLhalt=false local __LLret=nil local __LLn=0`,
        flat.hoisted.length ? `local ${flat.hoisted.join(", ")}` : "",
        `local __LLc={}`,
        chunks.join("\n"),
        `local __LLorder={${order.join(",")}}`,
        `for __LLi=1,${flat.count} do local __LLf=__LLc[__LLorder[__LLi]] if __LLf then __LLf() end if __LLhalt then break end end`,
        `if __LLret~=nil then local __LLu=table.unpack or unpack return __LLu(__LLret,1,__LLn) end`,
      ].filter(Boolean).join("\n");
      stats.chunks = flat.count;
      stats.hoisted = flat.hoisted.length;
      stats.passes.push("control-flow-flattening");
    } else if (flat.reason && flat.reason !== "not enough top level blocks") {
      warnings.push("Control flow flattening skipped (" + flat.reason + ").");
    }
  }

  // Dead code declares locals, which a `goto` is not allowed to jump into.
  if (options.junk !== false && !info.seen.goto && !info.seen.label) {
    const r = junkPass(tokenize(body), { density: options.junkDensity || 0.3 });
    body = serialize(r.tokens);
    stats.junk = r.inserted;
    stats.passes.push("dead-code-injection");
  } else if (options.junk !== false) {
    warnings.push("Dead code injection skipped (script uses goto/labels, which cannot jump over new locals).");
  }

  return finish((prelude ? prelude + "\n" : "") + body);
}

export default { obfuscate, ENGINES, tokenize, analyze, buildPayload };
