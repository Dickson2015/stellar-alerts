import { describe, expect, it, vi } from "vitest";
import {
  MaskingPolicyError,
  PayloadMaskingEngine,
  applyMaskingPolicy,
  parseMaskPath,
  type MaskingPolicy,
} from "../payload-masker";
import { DispatcherWorker } from "../../../workers/dispatcher.worker";

const SALT = "per-webhook-salt";

const payload = () => ({
  id: "evt_1",
  memo: "invoice 4412 for ACME",
  from: "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVW",
  to: "GZYXWVUTSRQPONMLKJIHGFEDCBA765432ZYXWVUTSRQPONMLKJIHGFED",
  amount: "125.50",
  data: { counterparty: { address: "GCOUNTER", note: "secret" } },
  ops: [
    { to: "GOP0", amount: "1" },
    { to: "GOP1", amount: "2" },
  ],
});

const policy = (rules: MaskingPolicy["rules"]): MaskingPolicy => ({ rules, salt: SALT });

describe("PayloadMaskingEngine", () => {
  it("REDACT replaces the value and leaves other fields alone", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$.memo", action: "REDACT" }])).mask(payload());
    expect(r.payload.memo).toBe("[REDACTED]");
    expect(r.payload.amount).toBe("125.50");
    expect(r.maskedCount).toBe(1);
  });

  it("REDACT supports a custom replacement", () => {
    const r = new PayloadMaskingEngine(
      policy([{ path: "$.memo", action: "REDACT", replacement: "***" }]),
    ).mask(payload());
    expect(r.payload.memo).toBe("***");
  });

  it("TRUNCATE keeps a prefix and optional suffix", () => {
    const r = new PayloadMaskingEngine(
      policy([{ path: "$.from", action: "TRUNCATE", keep: 4, keepEnd: 4 }]),
    ).mask(payload());
    expect(r.payload.from).toBe("GABC…TUVW");
  });

  it("TRUNCATE never leaks a short value in full", () => {
    const r = new PayloadMaskingEngine(
      policy([{ path: "$.memo", action: "TRUNCATE", keep: 10 }]),
    ).mask({ memo: "short" });
    expect(r.payload.memo).toBe("…");
  });

  it("OMIT removes the key entirely", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$.memo", action: "OMIT" }])).mask(payload());
    expect("memo" in r.payload).toBe(false);
  });

  it("SHA256_SALTED is deterministic so repeat addresses correlate", () => {
    const engine = new PayloadMaskingEngine(policy([{ path: "$.from", action: "SHA256_SALTED" }]));
    const a = engine.mask(payload()).payload.from;
    const b = engine.mask({ ...payload(), id: "evt_2" }).payload.from;
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toContain("GABC");
  });

  it("SHA256_SALTED differs per salt and per input", () => {
    const e1 = new PayloadMaskingEngine(policy([{ path: "$.from", action: "SHA256_SALTED" }]));
    const e2 = new PayloadMaskingEngine({ salt: "other", rules: [{ path: "$.from", action: "SHA256_SALTED" }] });
    expect(e1.mask(payload()).payload.from).not.toBe(e2.mask(payload()).payload.from);
    expect(e1.mask(payload()).payload.from).not.toBe(e1.mask(payload()).payload.to);
  });

  it("SHA256_SALTED honours digestLength", () => {
    const r = new PayloadMaskingEngine(
      policy([{ path: "$.from", action: "SHA256_SALTED", digestLength: 16 }]),
    ).mask(payload());
    expect(r.payload.from).toMatch(/^[0-9a-f]{16}$/);
  });

  it("supports nested paths, array indexes and wildcards", () => {
    const r = new PayloadMaskingEngine(
      policy([
        { path: "$.data.counterparty.address", action: "REDACT" },
        { path: "$.ops[0].to", action: "OMIT" },
        { path: "$.ops[*].amount", action: "REDACT" },
      ]),
    ).mask(payload());
    const p = r.payload as any;
    expect(p.data.counterparty.address).toBe("[REDACTED]");
    expect(p.ops[0]).toEqual({ amount: "[REDACTED]" });
    expect(p.ops[1]).toEqual({ to: "GOP1", amount: "[REDACTED]" });
  });

  it("recursive descent masks the field at any depth", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$..to", action: "REDACT" }])).mask(payload());
    const p = r.payload as any;
    expect(p.to).toBe("[REDACTED]");
    expect(p.ops[0].to).toBe("[REDACTED]");
    expect(p.ops[1].to).toBe("[REDACTED]");
  });

  it("OMIT on array elements removes them without shifting errors", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$.ops[*]", action: "OMIT" }])).mask(payload());
    expect((r.payload as any).ops).toEqual([]);
  });

  it("does not mutate the input payload", () => {
    const input = payload();
    new PayloadMaskingEngine(policy([{ path: "$.memo", action: "REDACT" }])).mask(input);
    expect(input.memo).toBe("invoice 4412 for ACME");
  });

  it("ignores rules whose path does not exist", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$.nope.deeper", action: "REDACT" }])).mask(payload());
    expect(r.maskedCount).toBe(0);
    expect(r.appliedPaths).toEqual([]);
  });

  it("never walks the prototype chain", () => {
    const r = new PayloadMaskingEngine(policy([{ path: "$.toString", action: "REDACT" }])).mask(payload());
    expect(r.maskedCount).toBe(0);
  });

  it("applyMaskingPolicy is a no-op without a policy", () => {
    const input = payload();
    expect(applyMaskingPolicy(input, null).payload).toBe(input);
    expect(applyMaskingPolicy(input, { rules: [] }).payload).toBe(input);
  });
});

describe("masking policy validation", () => {
  it.each([
    ["", "non-empty"],
    ["memo", "must start with"],
    ["$", "at least one field"],
    ["$.__proto__.x", "Forbidden"],
    ["$.a[", "Unclosed"],
    ["$.a[?(@.x)]", "Unsupported"],
  ])("rejects path %j", (path, message) => {
    expect(() => parseMaskPath(path)).toThrow(new RegExp(message));
  });

  it("rejects unknown actions", () => {
    expect(() => new PayloadMaskingEngine({ rules: [{ path: "$.a", action: "NUKE" as any }] })).toThrow(
      MaskingPolicyError,
    );
  });

  it("requires a salt for SHA256_SALTED", () => {
    expect(
      () => new PayloadMaskingEngine({ rules: [{ path: "$.a", action: "SHA256_SALTED" }] }),
    ).toThrow(/salt/);
  });

  it("rejects bad digestLength and truncate bounds", () => {
    expect(
      () => new PayloadMaskingEngine(policy([{ path: "$.a", action: "SHA256_SALTED", digestLength: 4 }])),
    ).toThrow(/digestLength/);
    expect(
      () => new PayloadMaskingEngine(policy([{ path: "$.a", action: "TRUNCATE", keep: -1 }])),
    ).toThrow(/non-negative/);
  });
});

describe("DispatcherWorker masking before signing", () => {
  const fakeBreaker: any = {
    canExecute: async () => true,
    execute: async (_id: string, fn: () => Promise<unknown>) => fn(),
  };
  const fakeFilter: any = {
    validateAndResolve: async (url: string) => ({
      parsedUrl: new URL(url),
      pinnedUrl: url,
      pinnedIp: "93.184.216.34",
      hostHeader: new URL(url).host,
    }),
  };

  const run = async (opts: {
    signer?: (id: string, body: string) => Promise<Record<string, string>>;
    headers?: Record<string, string>;
    maskingPolicy?: MaskingPolicy | null;
  }) => {
    const transport = vi.fn(async () => ({ status: 200 }));
    const worker = new DispatcherWorker(fakeBreaker, transport, fakeFilter, undefined, opts.signer);
    const result = await worker.processJob({
      data: {
        webhookId: "wh_1",
        url: "https://hooks.example.com/in",
        payload: payload(),
        headers: opts.headers,
        maskingPolicy: opts.maskingPolicy,
      },
    });
    return { result, transport };
  };

  it("signs the masked body, not the original", async () => {
    const signer = vi.fn(async (_id: string, body: string) => ({ "X-Stellar-Signature": `sig:${body.length}` }));
    const { result, transport } = await run({
      signer,
      headers: { "X-Stellar-Signature": "stale" },
      maskingPolicy: policy([{ path: "$.memo", action: "REDACT" }]),
    });
    expect(result.status).toBe("delivered");
    const [, body, headers] = transport.mock.calls[0] as unknown as [string, string, Record<string, string>];
    expect(body).not.toContain("invoice 4412");
    expect(signer).toHaveBeenCalledWith("wh_1", body);
    expect(headers["X-Stellar-Signature"]).toBe(`sig:${body.length}`);
  });

  it("fails closed rather than sending a stale signature", async () => {
    const { result, transport } = await run({
      headers: { "X-Stellar-Signature": "stale" },
      maskingPolicy: policy([{ path: "$.memo", action: "REDACT" }]),
    });
    expect(result.status).toBe("failed");
    expect(transport).not.toHaveBeenCalled();
  });

  it("leaves unmasked jobs and their signatures untouched", async () => {
    const { result, transport } = await run({ headers: { "X-Stellar-Signature": "orig" } });
    expect(result.status).toBe("delivered");
    const [, body, headers] = transport.mock.calls[0] as unknown as [string, string, Record<string, string>];
    expect(body).toContain("invoice 4412");
    expect(headers["X-Stellar-Signature"]).toBe("orig");
  });
});
