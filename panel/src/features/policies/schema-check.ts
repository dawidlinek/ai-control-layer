/**
 * "Checked against the schema as you type": a small JSON Schema validator (the subset the policy schema uses:
 * $ref/$defs, anyOf/oneOf/allOf, type, enum, const, required, properties, patternProperties, additionalProperties,
 * propertyNames, items/prefixItems, min/max, pattern) run on the YAML parsed by `yaml-lite`. The gateway's
 * Validate stays authoritative; this gives instant feedback with line numbers.
 */
import { lineOfPath, parseYamlWithLines, YamlError, type YamlValue } from "./yaml-lite";

type Schema = Record<string, unknown> | boolean;
type Path = (string | number)[];

export interface SchemaProblem {
  path: Path;
  message: string;
}

export interface LineProblem {
  line: number;
  column?: number | null;
  path: string | null;
  message: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function typeOf(v: unknown): string {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

function typeMatches(v: unknown, t: unknown): boolean {
  const types = Array.isArray(t) ? t : [t];
  const actual = typeOf(v);
  return types.some((x) => x === actual || (x === "number" && actual === "integer"));
}

const TYPE_WORD: Record<string, string> = {
  object: "a mapping",
  array: "a list",
  string: "text",
  number: "a number",
  integer: "a whole number",
  boolean: "true or false",
  null: "empty",
};

class Checker {
  private readonly defs: Record<string, unknown>;
  constructor(private readonly root: Record<string, unknown>) {
    this.defs = (isObj(root.$defs) ? root.$defs : isObj(root.definitions) ? root.definitions : {}) as Record<string, unknown>;
  }

  private resolve(s: Schema, depth = 0): Schema {
    if (!isObj(s) || typeof s.$ref !== "string" || depth > 20) return s;
    const m = /^#\/(?:\$defs|definitions)\/(.+)$/.exec(s.$ref);
    const target = m ? this.defs[m[1]] : s.$ref === "#" ? this.root : undefined;
    return target === undefined ? true : this.resolve(target as Schema, depth + 1);
  }

  check(v: unknown, schema: Schema, path: Path, out: SchemaProblem[]): void {
    const s = this.resolve(schema);
    if (s === true || s === undefined) return;
    if (s === false) {
      out.push({ path, message: "not allowed here" });
      return;
    }
    const branches = (s.anyOf ?? s.oneOf) as Schema[] | undefined;
    if (Array.isArray(branches)) {
      const results = branches.map((b) => {
        const errs: SchemaProblem[] = [];
        this.check(v, b, path, errs);
        return { b: this.resolve(b), errs };
      });
      if (!results.some((r) => r.errs.length === 0)) {
        const typed = results.filter((r) => !isObj(r.b) || r.b.type === undefined || typeMatches(v, r.b.type));
        const best = (typed.length ? typed : results).sort((a, b) => a.errs.length - b.errs.length)[0];
        if (typed.length) out.push(...best.errs);
        else {
          const words = [...new Set(results.flatMap((r) => (isObj(r.b) && r.b.type ? [r.b.type].flat().map((t) => TYPE_WORD[String(t)] ?? String(t)) : [])))];
          out.push({ path, message: `must be ${words.join(" or ") || "something else"}` });
        }
      }
    }
    if (Array.isArray(s.allOf)) for (const b of s.allOf as Schema[]) this.check(v, b, path, out);

    if ("const" in s && v !== s.const) out.push({ path, message: `must be "${String(s.const)}"` });
    if (Array.isArray(s.enum) && !s.enum.includes(v as never)) {
      const opts = s.enum.slice(0, 9).map(String).join(", ");
      out.push({ path, message: `"${String(v)}" is not one of: ${opts}${s.enum.length > 9 ? ", …" : ""}` });
      return;
    }
    if (s.type !== undefined && !typeMatches(v, s.type)) {
      const t = [s.type].flat().map((x) => TYPE_WORD[String(x)] ?? String(x));
      out.push({ path, message: `must be ${t.join(" or ")}` });
      return;
    }

    if (typeof v === "number") {
      if (typeof s.minimum === "number" && v < s.minimum) out.push({ path, message: `must be at least ${s.minimum}` });
      if (typeof s.maximum === "number" && v > s.maximum) out.push({ path, message: `must be at most ${s.maximum}` });
      if (typeof s.exclusiveMinimum === "number" && v <= s.exclusiveMinimum) out.push({ path, message: `must be more than ${s.exclusiveMinimum}` });
      if (typeof s.exclusiveMaximum === "number" && v >= s.exclusiveMaximum) out.push({ path, message: `must be less than ${s.exclusiveMaximum}` });
    }
    if (typeof v === "string") {
      if (typeof s.pattern === "string") {
        try {
          if (!new RegExp(s.pattern, "u").test(v)) out.push({ path, message: `"${v}" does not match ${s.pattern}` });
        } catch {
          /* pattern not supported by JS: skip */
        }
      }
      if (typeof s.minLength === "number" && v.length < s.minLength) out.push({ path, message: `must have at least ${s.minLength} characters` });
      if (typeof s.maxLength === "number" && v.length > s.maxLength) out.push({ path, message: `must have at most ${s.maxLength} characters` });
    }
    if (Array.isArray(v)) {
      if (typeof s.minItems === "number" && v.length < s.minItems) out.push({ path, message: `must list at least ${s.minItems} item${s.minItems === 1 ? "" : "s"}` });
      if (typeof s.maxItems === "number" && v.length > s.maxItems) out.push({ path, message: `must list at most ${s.maxItems} items` });
      const prefix = (Array.isArray(s.prefixItems) ? s.prefixItems : Array.isArray(s.items) ? s.items : []) as Schema[];
      v.forEach((item, i) => {
        if (i < prefix.length) this.check(item, prefix[i], [...path, i], out);
        else if (s.items !== undefined && !Array.isArray(s.items)) this.check(item, s.items as Schema, [...path, i], out);
      });
    }
    if (isObj(v)) {
      const props = (isObj(s.properties) ? s.properties : {}) as Record<string, Schema>;
      const patterns = (isObj(s.patternProperties) ? s.patternProperties : {}) as Record<string, Schema>;
      for (const r of Array.isArray(s.required) ? (s.required as string[]) : []) {
        if (!(r in v)) out.push({ path, message: `missing required field "${r}"` });
      }
      for (const [k, val] of Object.entries(v)) {
        if (s.propertyNames !== undefined) {
          const errs: SchemaProblem[] = [];
          this.check(k, s.propertyNames as Schema, [...path, k], errs);
          if (errs.length) out.push({ path: [...path, k], message: `"${k}" is not allowed here` });
        }
        let matched = false;
        if (k in props) {
          matched = true;
          this.check(val, props[k], [...path, k], out);
        }
        for (const [p, ps] of Object.entries(patterns)) {
          let re: RegExp | null = null;
          try {
            re = new RegExp(p, "u");
          } catch {
            re = null;
          }
          if (re?.test(k)) {
            matched = true;
            this.check(val, ps, [...path, k], out);
          }
        }
        if (!matched) {
          if (s.additionalProperties === false) out.push({ path: [...path, k], message: `unknown field "${k}"` });
          else if (s.additionalProperties !== undefined && s.additionalProperties !== true) this.check(val, s.additionalProperties as Schema, [...path, k], out);
        }
      }
    }
  }
}

/** Validate a value against a JSON Schema (subset). */
export function checkSchema(value: unknown, schema: Record<string, unknown>): SchemaProblem[] {
  const out: SchemaProblem[] = [];
  new Checker(schema).check(value, schema, [], out);
  return out;
}

/**
 * Check a YAML policy file as you type: YAML syntax first, then the schema (when known).
 * Problems come back with 1-based lines.
 */
export function checkPolicyYaml(text: string, schema: Record<string, unknown> | undefined): LineProblem[] {
  let parsed: { value: YamlValue; lines: Map<string, number> };
  try {
    parsed = parseYamlWithLines(text);
  } catch (e) {
    if (e instanceof YamlError) return [{ line: e.line, column: e.column, path: null, message: e.message }];
    return [{ line: 1, path: null, message: e instanceof Error ? e.message : "invalid YAML" }];
  }
  if (!schema) return [];
  const value = parsed.value ?? {};
  return checkSchema(value, schema)
    .slice(0, 50)
    .map((p) => ({ line: lineOfPath(parsed.lines, p.path) ?? 1, path: p.path.length ? p.path.join(".") : null, message: p.message }));
}
