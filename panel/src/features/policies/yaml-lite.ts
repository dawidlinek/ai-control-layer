/**
 * A small YAML-subset parser for the policy files (no dependency: `yaml` is not a direct dependency of the panel).
 * Supports what the policy files use: block maps and sequences, flow collections (`[a, b]`, `{k: v}`), quoted and
 * plain scalars, comments, and `|` / `>` block scalars. It is used to read rules out of `controls.yaml` /
 * `groups.yaml` for display, and by the mock API to validate. The gateway remains the real validator.
 */

export type YamlValue = string | number | boolean | null | YamlValue[] | { [key: string]: YamlValue };
export type YamlMap = { [key: string]: YamlValue };

export class YamlError extends Error {
  readonly line: number;
  readonly column: number;
  constructor(message: string, line: number, column = 1) {
    super(message);
    this.name = "YamlError";
    this.line = line;
    this.column = column;
  }
}

interface Line {
  /** 1-based line number in the source. */
  no: number;
  indent: number;
  /** Content without indentation and comments, right-trimmed. */
  text: string;
  /** The raw line (for block scalars). */
  raw: string;
}

/** Remove a trailing `# comment` (a `#` at the start or after whitespace, outside quotes). */
export function stripComment(s: string): string {
  let quote: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (quote) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"') {
      // A quote only opens a quoted scalar at the start of a token.
      const prev = i === 0 ? " " : s[i - 1];
      if (/[\s[{,:-]/.test(prev)) quote = ch;
      continue;
    }
    if (ch === "#" && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i);
  }
  return s;
}

function toLines(src: string): Line[] {
  const out: Line[] = [];
  src.split(/\r?\n/).forEach((raw, i) => {
    const m = /^( *)(\t*)/.exec(raw)!;
    if (m[2] && raw.trim() !== "" && !raw.trim().startsWith("#")) {
      throw new YamlError("tabs are not allowed for indentation", i + 1, m[1].length + 1);
    }
    const text = stripComment(raw.slice(m[1].length)).trimEnd();
    if (text === "" || text === "---") return;
    out.push({ no: i + 1, indent: m[1].length, text, raw });
  });
  return out;
}

const NUM = /^[-+]?(\d+(\.\d*)?|\.\d+)([eE][-+]?\d+)?$/;

function plainScalar(s: string, line: number, col: number): YamlValue {
  const v = s.trim();
  if (v === "" || v === "~" || v === "null" || v === "Null" || v === "NULL") return null;
  if (v === "true" || v === "True" || v === "TRUE") return true;
  if (v === "false" || v === "False" || v === "FALSE") return false;
  if (NUM.test(v)) return Number(v);
  if (/:\s/.test(v) || v.endsWith(":")) throw new YamlError("mapping values are not allowed here", line, col);
  if (v.startsWith("&") || v.startsWith("*") || v.startsWith("!")) {
    throw new YamlError("anchors, aliases and tags are not supported in policy files", line, col);
  }
  return v;
}

function unquote(s: string, line: number, col: number): { value: string; end: number } {
  const q = s[0];
  let i = 1;
  let out = "";
  while (i < s.length) {
    const ch = s[i];
    if (q === "'" && ch === "'") {
      if (s[i + 1] === "'") {
        out += "'";
        i += 2;
        continue;
      }
      return { value: out, end: i + 1 };
    }
    if (q === '"' && ch === "\\") {
      const nx = s[i + 1];
      out += nx === "n" ? "\n" : nx === "t" ? "\t" : (nx ?? "");
      i += 2;
      continue;
    }
    if (q === '"' && ch === '"') return { value: out, end: i + 1 };
    out += ch;
    i++;
  }
  throw new YamlError("unterminated quoted string", line, col);
}

/** Flow collections and scalars on one line. */
class Flow {
  private i = 0;
  constructor(
    private readonly s: string,
    private readonly line: number,
    private readonly col: number,
  ) {}

  static parse(s: string, line: number, col: number): YamlValue {
    const f = new Flow(s, line, col);
    const v = f.value(false);
    f.ws();
    if (f.i < s.length) throw f.err(`unexpected "${s.slice(f.i, f.i + 10)}"`);
    return v;
  }

  private err(msg: string) {
    return new YamlError(msg, this.line, this.col + this.i);
  }

  private ws() {
    while (this.i < this.s.length && /\s/.test(this.s[this.i])) this.i++;
  }

  private value(inFlow: boolean): YamlValue {
    this.ws();
    const ch = this.s[this.i];
    if (ch === "[") return this.seq();
    if (ch === "{") return this.map();
    if (ch === "'" || ch === '"') {
      const { value, end } = unquote(this.s.slice(this.i), this.line, this.col + this.i);
      this.i += end;
      return value;
    }
    const start = this.i;
    if (!inFlow) {
      this.i = this.s.length;
      return plainScalar(this.s.slice(start), this.line, this.col + start);
    }
    while (this.i < this.s.length && !",]}".includes(this.s[this.i])) {
      if (this.s[this.i] === ":" && /[\s,\]}]/.test(this.s[this.i + 1] ?? " ")) break;
      this.i++;
    }
    return plainScalar(this.s.slice(start, this.i), this.line, this.col + start);
  }

  private seq(): YamlValue[] {
    this.i++; // [
    const out: YamlValue[] = [];
    for (;;) {
      this.ws();
      if (this.s[this.i] === "]") {
        this.i++;
        return out;
      }
      if (this.i >= this.s.length) throw this.err("unterminated flow sequence, expected ]");
      out.push(this.value(true));
      this.ws();
      if (this.s[this.i] === ",") this.i++;
      else if (this.s[this.i] !== "]") throw this.err("expected , or ] in flow sequence");
    }
  }

  private map(): YamlMap {
    this.i++; // {
    const out: YamlMap = {};
    for (;;) {
      this.ws();
      if (this.s[this.i] === "}") {
        this.i++;
        return out;
      }
      if (this.i >= this.s.length) throw this.err("unterminated flow mapping, expected }");
      const key = this.value(true);
      this.ws();
      if (this.s[this.i] !== ":") throw this.err("expected : in flow mapping");
      this.i++;
      this.ws();
      const val = ",}".includes(this.s[this.i] ?? "") ? null : this.value(true);
      const k = String(key);
      if (k in out) throw this.err(`duplicate key "${k}"`);
      out[k] = val;
      this.ws();
      if (this.s[this.i] === ",") this.i++;
      else if (this.s[this.i] !== "}") throw this.err("expected , or } in flow mapping");
    }
  }
}

/** Split `key: rest` (key may be quoted). `null` when the line is not a mapping entry. */
function splitKey(text: string, line: number, col: number): { key: string; rest: string; restCol: number } | null {
  if (text[0] === "'" || text[0] === '"') {
    const { value, end } = unquote(text, line, col);
    const after = text.slice(end);
    const m = /^\s*:(\s+|$)/.exec(after);
    if (!m) return null;
    return { key: value, rest: after.slice(m[0].length), restCol: col + end + m[0].length };
  }
  if (text[0] === "[" || text[0] === "{") return null;
  const m = /^([^\s:][^:]*?)\s*:(\s+|$)/.exec(text);
  if (!m) return null;
  return { key: m[1], rest: text.slice(m[0].length), restCol: col + m[0].length };
}

const isSeqItem = (text: string) => text === "-" || text.startsWith("- ");

class Block {
  private i = 0;
  /** JSON path (`controls.3.cost_tier`) → 1-based line of the key / item. */
  readonly paths = new Map<string, number>();
  constructor(private readonly lines: Line[]) {}

  private mark(path: string[], line: number) {
    const k = path.join(".");
    if (!this.paths.has(k)) this.paths.set(k, line);
  }

  parseDocument(): YamlValue {
    if (this.lines.length === 0) return null;
    const first = this.lines[0];
    const v = this.node(first.indent, []);
    if (this.i < this.lines.length) {
      const l = this.lines[this.i];
      throw new YamlError(l.indent > first.indent ? "bad indentation" : "unexpected content", l.no, l.indent + 1);
    }
    return v;
  }

  private node(indent: number, path: string[]): YamlValue {
    const l = this.lines[this.i];
    if (isSeqItem(l.text)) return this.seq(indent, path);
    if (splitKey(l.text, l.no, l.indent + 1)) return this.map(indent, path);
    this.i++;
    return Flow.parse(l.text, l.no, l.indent + 1);
  }

  private childOrNull(parentIndent: number, allowSeqAtSameIndent: boolean, path: string[]): YamlValue {
    const next = this.lines[this.i];
    if (!next) return null;
    if (next.indent > parentIndent) return this.node(next.indent, path);
    if (allowSeqAtSameIndent && next.indent === parentIndent && isSeqItem(next.text)) return this.seq(parentIndent, path);
    return null;
  }

  private blockScalar(header: string, parentIndent: number): string {
    const folded = header.startsWith(">");
    const parts: string[] = [];
    while (this.i < this.lines.length && this.lines[this.i].indent > parentIndent) {
      parts.push(this.lines[this.i].raw.trim());
      this.i++;
    }
    return parts.join(folded ? " " : "\n");
  }

  private map(indent: number, path: string[]): YamlMap {
    const out: YamlMap = {};
    while (this.i < this.lines.length) {
      const l = this.lines[this.i];
      if (l.indent < indent) break;
      if (l.indent > indent) throw new YamlError("bad indentation of a mapping entry", l.no, l.indent + 1);
      if (isSeqItem(l.text)) throw new YamlError("a sequence item cannot start here (expected key: value)", l.no, l.indent + 1);
      const kv = splitKey(l.text, l.no, l.indent + 1);
      if (!kv) throw new YamlError("expected key: value", l.no, l.indent + 1);
      if (kv.key in out) throw new YamlError(`duplicate key "${kv.key}"`, l.no, l.indent + 1);
      this.i++;
      this.mark([...path, kv.key], l.no);
      if (kv.rest === "") out[kv.key] = this.childOrNull(indent, true, [...path, kv.key]);
      else if (/^[|>][-+]?$/.test(kv.rest)) out[kv.key] = this.blockScalar(kv.rest, indent);
      else out[kv.key] = Flow.parse(kv.rest, l.no, kv.restCol);
    }
    return out;
  }

  private seq(indent: number, path: string[]): YamlValue[] {
    const out: YamlValue[] = [];
    while (this.i < this.lines.length) {
      const l = this.lines[this.i];
      if (l.indent < indent) break;
      if (l.indent > indent) throw new YamlError("bad indentation of a sequence item", l.no, l.indent + 1);
      if (!isSeqItem(l.text)) break;
      const rest = l.text.slice(1).trimStart();
      const itemPath = [...path, String(out.length)];
      this.mark(itemPath, l.no);
      if (rest === "") {
        this.i++;
        out.push(this.childOrNull(indent, false, itemPath));
        continue;
      }
      const restIndent = l.indent + (l.text.length - rest.length);
      if (splitKey(rest, l.no, restIndent + 1)) {
        // `- key: value` starts a mapping whose other keys are aligned with `key`.
        this.lines[this.i] = { ...l, indent: restIndent, text: rest };
        out.push(this.map(restIndent, itemPath));
      } else {
        this.i++;
        out.push(Flow.parse(rest, l.no, restIndent + 1));
      }
    }
    return out;
  }
}

/** Parse a YAML document (policy-file subset). Throws `YamlError` with a 1-based line. */
export function parseYaml(src: string): YamlValue {
  return new Block(toLines(src)).parseDocument();
}

/**
 * Parse and also return where each block key / item is: `controls.3.cost_tier` → line. Values inside flow
 * collections are not listed (use the nearest listed parent).
 */
export function parseYamlWithLines(src: string): { value: YamlValue; lines: Map<string, number> } {
  const b = new Block(toLines(src));
  const value = b.parseDocument();
  return { value, lines: b.paths };
}

/** The line of a JSON path, or of its nearest parent that has one. */
export function lineOfPath(lines: Map<string, number>, path: readonly (string | number)[]): number | null {
  for (let n = path.length; n > 0; n--) {
    const l = lines.get(path.slice(0, n).join("."));
    if (l) return l;
  }
  return null;
}

/** Parse and return the top-level mapping, or a `YamlError` (never throws). */
export function tryParseYamlMap(src: string): { ok: true; value: YamlMap } | { ok: false; error: YamlError } {
  try {
    const v = parseYaml(src);
    if (v === null) return { ok: true, value: {} };
    if (typeof v !== "object" || Array.isArray(v)) return { ok: false, error: new YamlError("a policy file must be a mapping", 1) };
    return { ok: true, value: v };
  } catch (e) {
    if (e instanceof YamlError) return { ok: false, error: e };
    return { ok: false, error: new YamlError(e instanceof Error ? e.message : "invalid YAML", 1) };
  }
}

export const isMap = (v: YamlValue | undefined): v is YamlMap => !!v && typeof v === "object" && !Array.isArray(v);
export const asList = (v: YamlValue | undefined): YamlValue[] => (Array.isArray(v) ? v : []);
export const asStr = (v: YamlValue | undefined): string | undefined =>
  typeof v === "string" ? v : typeof v === "number" || typeof v === "boolean" ? String(v) : undefined;
