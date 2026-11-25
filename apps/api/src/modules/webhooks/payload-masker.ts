import crypto from "node:crypto";

/**
 * Webhook payload anonymization & field masking policy engine (#990).
 *
 * Subscribers attach declarative, per-webhook rules that rewrite sensitive
 * fields (memos, counterparty addresses, amounts) BEFORE the payload is
 * serialized and HMAC-signed, so third-party analytics endpoints never see
 * the raw values and the signature still covers exactly the bytes sent.
 */

export const MASK_ACTIONS = [
  "REDACT",
  "SHA256_SALTED",
  "TRUNCATE",
  "OMIT",
] as const;
export type MaskAction = (typeof MASK_ACTIONS)[number];

export interface MaskingRule {
  /** JSONPath subset: `$.memo`, `$.data.from`, `$.items[*].to`, `$..memo`, `$.a[0]`. */
  path: string;
  action: MaskAction;
  /** TRUNCATE: number of leading characters kept (default 4). */
  keep?: number;
  /** TRUNCATE: number of trailing characters kept (default 0). */
  keepEnd?: number;
  /** REDACT: replacement text (default `[REDACTED]`). */
  replacement?: string;
  /** SHA256_SALTED: hex digits of the digest to emit (default 64, min 8). */
  digestLength?: number;
}

export interface MaskingPolicy {
  rules: MaskingRule[];
  /**
   * Secret salt for SHA256_SALTED. Stable per webhook so the same input always
   * yields the same digest (deterministic correlation) without exposing it.
   */
  salt?: string;
}

export interface MaskingResult {
  payload: Record<string, unknown>;
  /** Number of values rewritten or removed. */
  maskedCount: number;
  /** Paths whose rules matched at least one field. */
  appliedPaths: string[];
}

export class MaskingPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MaskingPolicyError";
  }
}

type Segment =
  | { kind: "key"; name: string }
  | { kind: "index"; index: number }
  | { kind: "wildcard" }
  | { kind: "descend"; name: string };

const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
const DEFAULT_REDACTION = "[REDACTED]";
const MAX_RULES = 100;
const MAX_PATH_LENGTH = 256;
const MAX_DEPTH = 64;

/** Parses the supported JSONPath subset into segments. Throws on anything else. */
export function parseMaskPath(path: string): Segment[] {
  if (typeof path !== "string" || path.length === 0) {
    throw new MaskingPolicyError("Masking rule path must be a non-empty string");
  }
  if (path.length > MAX_PATH_LENGTH) {
    throw new MaskingPolicyError(
      `Masking rule path exceeds ${MAX_PATH_LENGTH} characters`,
    );
  }
  if (!path.startsWith("$")) {
    throw new MaskingPolicyError(`Masking path must start with '$': ${path}`);
  }

  const segments: Segment[] = [];
  let i = 1;
  while (i < path.length) {
    if (path.startsWith("..", i)) {
      i += 2;
      const match = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(path.slice(i));
      if (!match) {
        throw new MaskingPolicyError(`Invalid recursive descent in: ${path}`);
      }
      assertSafeKey(match[0]);
      segments.push({ kind: "descend", name: match[0] });
      i += match[0].length;
    } else if (path[i] === ".") {
      i += 1;
      const match = /^[A-Za-z_][A-Za-z0-9_-]*/.exec(path.slice(i));
      if (!match) {
        throw new MaskingPolicyError(`Invalid key segment in: ${path}`);
      }
      assertSafeKey(match[0]);
      segments.push({ kind: "key", name: match[0] });
      i += match[0].length;
    } else if (path[i] === "[") {
      const close = path.indexOf("]", i);
      if (close === -1) {
        throw new MaskingPolicyError(`Unclosed bracket in: ${path}`);
      }
      const inner = path.slice(i + 1, close).trim();
      if (inner === "*") {
        segments.push({ kind: "wildcard" });
      } else if (/^\d+$/.test(inner)) {
        segments.push({ kind: "index", index: Number(inner) });
      } else {
        const quoted = /^(['"])([^'"]+)\1$/.exec(inner);
        if (!quoted) {
          throw new MaskingPolicyError(`Unsupported bracket in: ${path}`);
        }
        assertSafeKey(quoted[2]);
        segments.push({ kind: "key", name: quoted[2] });
      }
      i = close + 1;
    } else {
      throw new MaskingPolicyError(`Unexpected character at ${i} in: ${path}`);
    }
  }

  if (segments.length === 0) {
    throw new MaskingPolicyError("Masking path must target at least one field");
  }
  return segments;
}

function assertSafeKey(name: string): void {
  if (FORBIDDEN_KEYS.has(name)) {
    throw new MaskingPolicyError(`Forbidden key in masking path: ${name}`);
  }
}

function isContainer(value: unknown): value is Record<string, unknown> | unknown[] {
  return typeof value === "object" && value !== null;
}

function hasOwn(obj: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

/** A resolved location: the parent container and the key/index within it. */
interface Slot {
  parent: Record<string, unknown> | unknown[];
  key: string | number;
}

function collectSlots(
  node: unknown,
  segments: Segment[],
  at: number,
  out: Slot[],
  depth: number,
): void {
  if (depth > MAX_DEPTH || !isContainer(node)) return;
  const seg = segments[at];
  const last = at === segments.length - 1;

  const visit = (parent: Record<string, unknown> | unknown[], key: string | number) => {
    if (last) out.push({ parent, key });
    else collectSlots((parent as any)[key], segments, at + 1, out, depth + 1);
  };

  switch (seg.kind) {
    case "key":
      if (!Array.isArray(node) && hasOwn(node, seg.name)) visit(node, seg.name);
      break;
    case "index":
      if (Array.isArray(node) && seg.index < node.length) visit(node, seg.index);
      break;
    case "wildcard":
      if (Array.isArray(node)) node.forEach((_, idx) => visit(node, idx));
      else Object.keys(node).forEach((k) => visit(node, k));
      break;
    case "descend": {
      // Match `name` at this level, then keep searching below.
      if (!Array.isArray(node) && hasOwn(node, seg.name)) visit(node, seg.name);
      const children = Array.isArray(node) ? node : Object.values(node);
      for (const child of children) {
        collectSlots(child, segments, at, out, depth + 1);
      }
      break;
    }
  }
}

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === undefined) return "";
  return JSON.stringify(value);
}

export class PayloadMaskingEngine {
  private readonly compiled: { rule: MaskingRule; segments: Segment[] }[];
  private readonly salt: string;

  constructor(policy: MaskingPolicy) {
    PayloadMaskingEngine.validatePolicy(policy);
    this.salt = policy.salt ?? "";
    this.compiled = policy.rules.map((rule) => ({
      rule,
      segments: parseMaskPath(rule.path),
    }));
  }

  /** Throws MaskingPolicyError describing the first problem found. */
  static validatePolicy(policy: MaskingPolicy): void {
    if (!policy || !Array.isArray(policy.rules)) {
      throw new MaskingPolicyError("Masking policy must contain a rules array");
    }
    if (policy.rules.length > MAX_RULES) {
      throw new MaskingPolicyError(`Masking policy exceeds ${MAX_RULES} rules`);
    }
    for (const rule of policy.rules) {
      if (!MASK_ACTIONS.includes(rule?.action)) {
        throw new MaskingPolicyError(
          `Unknown masking action '${String(rule?.action)}' for ${String(rule?.path)}`,
        );
      }
      parseMaskPath(rule.path);
      if (rule.action === "SHA256_SALTED" && !policy.salt) {
        throw new MaskingPolicyError(
          "SHA256_SALTED rules require a non-empty policy salt",
        );
      }
      if (rule.action === "SHA256_SALTED" && rule.digestLength !== undefined) {
        if (!Number.isInteger(rule.digestLength) || rule.digestLength < 8 || rule.digestLength > 64) {
          throw new MaskingPolicyError("digestLength must be an integer from 8 to 64");
        }
      }
      if (rule.action === "TRUNCATE") {
        for (const n of [rule.keep, rule.keepEnd]) {
          if (n !== undefined && (!Number.isInteger(n) || n < 0)) {
            throw new MaskingPolicyError("TRUNCATE keep/keepEnd must be non-negative integers");
          }
        }
      }
    }
  }

  /** Deterministic salted digest: same salt + input always gives the same output. */
  hash(value: unknown, digestLength = 64): string {
    const digest = crypto
      .createHmac("sha256", this.salt)
      .update(stringify(value), "utf8")
      .digest("hex");
    return digest.slice(0, digestLength);
  }

  private truncate(value: unknown, rule: MaskingRule): string {
    const text = stringify(value);
    const keep = rule.keep ?? 4;
    const keepEnd = rule.keepEnd ?? 0;
    if (text.length <= keep + keepEnd) return text.length === 0 ? text : "…";
    return `${text.slice(0, keep)}…${keepEnd > 0 ? text.slice(-keepEnd) : ""}`;
  }

  private apply(value: unknown, rule: MaskingRule): unknown {
    switch (rule.action) {
      case "REDACT":
        return rule.replacement ?? DEFAULT_REDACTION;
      case "SHA256_SALTED":
        return this.hash(value, rule.digestLength ?? 64);
      case "TRUNCATE":
        return this.truncate(value, rule);
      default:
        return value;
    }
  }

  /**
   * Returns a masked deep copy; the input is never mutated. Rules run in
   * declaration order, so an OMIT placed first wins over later rules.
   */
  mask(payload: Record<string, unknown>): MaskingResult {
    const copy = structuredClone(payload);
    const appliedPaths: string[] = [];
    let maskedCount = 0;

    for (const { rule, segments } of this.compiled) {
      const slots: Slot[] = [];
      collectSlots(copy, segments, 0, slots, 0);
      if (slots.length === 0) continue;
      appliedPaths.push(rule.path);

      if (rule.action === "OMIT") {
        // Delete array elements from the end so earlier indexes stay valid.
        const arraySlots = slots
          .filter((s) => Array.isArray(s.parent))
          .sort((a, b) => Number(b.key) - Number(a.key));
        for (const s of slots) {
          if (!Array.isArray(s.parent)) {
            delete (s.parent as Record<string, unknown>)[s.key as string];
            maskedCount++;
          }
        }
        for (const s of arraySlots) {
          (s.parent as unknown[]).splice(Number(s.key), 1);
          maskedCount++;
        }
        continue;
      }

      for (const { parent, key } of slots) {
        const current = (parent as any)[key];
        // Containers are masked as a whole value via their JSON form.
        (parent as any)[key] = this.apply(current, rule);
        maskedCount++;
      }
    }

    return { payload: copy, maskedCount, appliedPaths };
  }
}

/** Convenience wrapper; returns the payload untouched when no policy is set. */
export function applyMaskingPolicy(
  payload: Record<string, unknown>,
  policy?: MaskingPolicy | null,
): MaskingResult {
  if (!policy || policy.rules.length === 0) {
    return { payload, maskedCount: 0, appliedPaths: [] };
  }
  return new PayloadMaskingEngine(policy).mask(payload);
}
