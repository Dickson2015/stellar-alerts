import { describe, expect, it, vi } from 'vitest';
import {
  Account,
  Networks,
  Operation,
  SorobanDataBuilder,
  StrKey,
  TransactionBuilder,
  nativeToScVal,
  xdr,
} from 'stellar-sdk';

vi.mock('../../../lib/prisma', () => ({ prisma: { wallet: { findMany: vi.fn() } } }));
vi.mock('../../stellar/alert-delivery', () => ({
  deliverUserAlert: vi.fn(),
  escapeTelegramHtml: (v: string) => v,
}));

import {
  DEFAULT_SOROBAN_LIMITS,
  ResourceSaturationProfiler,
  buildResourceSaturationTelegramMessage,
  buildResourceSaturationWebhookPayload,
  extractDeclaredUsage,
  extractInvocationTarget,
  extractUsageFromMeta,
  type ResourceSaturationReport,
} from '../resource-profiler';

const CONTRACT = StrKey.encodeContract(Buffer.alloc(32, 7));
const SOURCE = StrKey.encodeEd25519PublicKey(Buffer.alloc(32, 1));

function coreMetric(name: string, value: bigint): xdr.DiagnosticEvent {
  return new xdr.DiagnosticEvent({
    inSuccessfulContractCall: true,
    event: new xdr.ContractEvent({
      ext: new xdr.ExtensionPoint(0),
      contractId: null,
      type: xdr.ContractEventType.diagnostic(),
      body: new xdr.ContractEventBody(
        0,
        new xdr.ContractEventV0({
          topics: [xdr.ScVal.scvSymbol('core_metrics'), xdr.ScVal.scvSymbol(name)],
          data: nativeToScVal(value, { type: 'u64' }),
        }),
      ),
    }),
  });
}

function metaXdr(diagnosticEvents: xdr.DiagnosticEvent[], withSoroban = true): string {
  const v3 = new xdr.TransactionMetaV3({
    ext: new xdr.ExtensionPoint(0),
    txChangesBefore: [],
    operations: [],
    txChangesAfter: [],
    sorobanMeta: withSoroban
      ? new xdr.SorobanTransactionMeta({
          ext: new xdr.SorobanTransactionMetaExt(0),
          events: [],
          returnValue: xdr.ScVal.scvVoid(),
          diagnosticEvents,
        })
      : null,
  });
  return new xdr.TransactionMeta(3, v3).toXDR('base64');
}

const metrics = (cpu: bigint, mem: bigint, read: bigint, write: bigint) => [
  coreMetric('cpu_insn', cpu),
  coreMetric('mem_byte', mem),
  coreMetric('ledger_read_byte', read),
  coreMetric('ledger_write_byte', write),
];

function envelopeXdr(fn = 'swap', declared?: { cpu: number; read: number; write: number }): string {
  const builder = new TransactionBuilder(new Account(SOURCE, '1'), { fee: '100', networkPassphrase: Networks.TESTNET })
    .addOperation(Operation.invokeContractFunction({ contract: CONTRACT, function: fn, args: [] }))
    .setTimeout(30);
  if (declared) {
    builder.setSorobanData(new SorobanDataBuilder().setResources(declared.cpu, declared.read, declared.write).build());
  }
  return builder.build().toEnvelope().toXDR('base64');
}

describe('extractUsageFromMeta', () => {
  it('reads CPU, memory, read and write bytes from core_metrics diagnostics', () => {
    const usage = extractUsageFromMeta(metaXdr(metrics(85_000_000n, 30_000_000n, 150_000n, 100_000n)));
    expect(usage).toEqual({
      cpuInstructions: 85_000_000,
      memoryBytes: 30_000_000,
      readBytes: 150_000,
      writeBytes: 100_000,
    });
  });

  it('sums metrics emitted more than once in a transaction', () => {
    const usage = extractUsageFromMeta(
      metaXdr([coreMetric('cpu_insn', 10n), coreMetric('cpu_insn', 15n), coreMetric('mem_byte', 5n)]),
    );
    expect(usage?.cpuInstructions).toBe(25);
  });

  it('ignores unrelated and malformed diagnostic events', () => {
    const noise = new xdr.DiagnosticEvent({
      inSuccessfulContractCall: true,
      event: new xdr.ContractEvent({
        ext: new xdr.ExtensionPoint(0),
        contractId: null,
        type: xdr.ContractEventType.diagnostic(),
        body: new xdr.ContractEventBody(
          0,
          new xdr.ContractEventV0({ topics: [xdr.ScVal.scvSymbol('fn_call')], data: xdr.ScVal.scvVoid() }),
        ),
      }),
    });
    const usage = extractUsageFromMeta(metaXdr([noise, coreMetric('cpu_insn', 7n), coreMetric('read_entry', 99n)]));
    expect(usage).toEqual({ cpuInstructions: 7, memoryBytes: 0, readBytes: 0, writeBytes: 0 });
  });

  it('returns null for non-soroban meta, empty diagnostics and garbage', () => {
    expect(extractUsageFromMeta(metaXdr([], false))).toBeNull();
    expect(extractUsageFromMeta(metaXdr([]))).toBeNull();
    expect(extractUsageFromMeta('not-xdr')).toBeNull();
  });

  it('accepts a raw Buffer', () => {
    const buf = Buffer.from(metaXdr([coreMetric('cpu_insn', 42n)]), 'base64');
    expect(extractUsageFromMeta(buf)?.cpuInstructions).toBe(42);
  });
});

describe('envelope decoding', () => {
  it('names the contract and function being invoked', () => {
    expect(extractInvocationTarget(envelopeXdr('deposit'))).toEqual({ contractId: CONTRACT, functionName: 'deposit' });
  });

  it('reads declared resources as a fallback', () => {
    const declared = extractDeclaredUsage(envelopeXdr('swap', { cpu: 90_000_000, read: 150_000, write: 100_000 }));
    expect(declared?.cpuInstructions).toBe(90_000_000);
    expect(declared?.writeBytes).toBe(100_000);
  });

  it('returns null for envelopes without soroban data or invalid input', () => {
    expect(extractDeclaredUsage(envelopeXdr())).toBeNull();
    expect(extractInvocationTarget('garbage')).toBeNull();
  });
});

describe('ResourceSaturationProfiler', () => {
  const make = (over: ConstructorParameters<typeof ResourceSaturationProfiler>[0] = {}) => {
    let now = 1_000_000;
    const handler = vi.fn();
    const profiler = new ResourceSaturationProfiler({ handlers: [handler], now: () => now, ...over });
    return { profiler, handler, advance: (ms: number) => (now += ms) };
  };

  it('computes utilization against network maximums', async () => {
    const { profiler } = make();
    const report = (await profiler.profile({
      txHash: 'tx1',
      resultMetaXdr: metaXdr(metrics(50_000_000n, 20_971_520n, 100_000n, 66_048n)),
      envelopeXdr: envelopeXdr('swap'),
    }))!;
    expect(report.utilizationPct.cpuInstructions).toBeCloseTo(50);
    expect(report.utilizationPct.memoryBytes).toBeCloseTo(50);
    expect(report.utilizationPct.readBytes).toBeCloseTo(50);
    expect(report.utilizationPct.writeBytes).toBeCloseTo(50);
    expect(report.contractId).toBe(CONTRACT);
    expect(report.functionName).toBe('swap');
    expect(report.severity).toBeNull();
    expect(report.saturated).toEqual([]);
  });

  it('warns at 80% and names every saturated resource', async () => {
    const { profiler, handler } = make();
    const report = (await profiler.profile({
      txHash: 'tx2',
      resultMetaXdr: metaXdr(metrics(85_000_000n, 1_000n, 180_000n, 1_000n)),
      envelopeXdr: envelopeXdr('swap'),
    }))!;
    expect(report.severity).toBe('WARNING');
    expect(report.saturated).toEqual(['cpuInstructions', 'readBytes']);
    expect(report.worst.metric).toBe('readBytes');
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(1));
  });

  it('does not alert just below the threshold but does at exactly 80%', async () => {
    const { profiler } = make();
    const below = await profiler.profile({ txHash: 'a', usage: { cpuInstructions: 79_999_999 }, contractId: 'C', functionName: 'f' });
    const at = await profiler.profile({ txHash: 'b', usage: { cpuInstructions: 80_000_000 }, contractId: 'C', functionName: 'g' });
    expect(below?.severity).toBeNull();
    expect(at?.severity).toBe('WARNING');
  });

  it('escalates to CRITICAL at 95%', async () => {
    const { profiler } = make();
    const report = await profiler.profile({ txHash: 'c', usage: { writeBytes: 130_000 }, contractId: 'C', functionName: 'f' });
    expect(report?.severity).toBe('CRITICAL');
  });

  it('falls back to declared resources when no diagnostics exist', async () => {
    const { profiler } = make();
    const report = (await profiler.profile({
      txHash: 'd',
      envelopeXdr: envelopeXdr('swap', { cpu: 90_000_000, read: 1_000, write: 1_000 }),
    }))!;
    expect(report.source).toBe('declared');
    expect(report.severity).toBe('WARNING');
  });

  it('returns null when there is nothing to measure', async () => {
    const { profiler, handler } = make();
    expect(await profiler.profile({ txHash: 'e' })).toBeNull();
    expect(await profiler.profile({ txHash: 'f', resultMetaXdr: metaXdr([]) })).toBeNull();
    expect(handler).not.toHaveBeenCalled();
  });

  it('applies the per-function cooldown, but not across functions', async () => {
    const { profiler, handler, advance } = make();
    const hot = (fn: string) => profiler.profile({ txHash: fn, usage: { cpuInstructions: 90_000_000 }, contractId: 'C', functionName: fn });
    await hot('swap');
    await hot('swap');
    await hot('withdraw');
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(2));

    advance(11 * 60 * 1000);
    await hot('swap');
    await vi.waitFor(() => expect(handler).toHaveBeenCalledTimes(3));
  });

  it('uses live network limits from a provider and survives its failure', async () => {
    const live = make({ limitsProvider: async () => ({ cpuInstructions: 200_000_000 }) });
    const r1 = await live.profiler.profile({ txHash: 'g', usage: { cpuInstructions: 100_000_000 }, contractId: 'C', functionName: 'f' });
    expect(r1?.utilizationPct.cpuInstructions).toBeCloseTo(50);
    expect(r1?.limits.memoryBytes).toBe(DEFAULT_SOROBAN_LIMITS.memoryBytes);

    const broken = make({ limitsProvider: async () => { throw new Error('rpc down'); } });
    const r2 = await broken.profiler.profile({ txHash: 'h', usage: { cpuInstructions: 100_000_000 }, contractId: 'C', functionName: 'f' });
    expect(r2?.utilizationPct.cpuInstructions).toBeCloseTo(100);
  });

  it('flags a function whose usage keeps climbing and tracks its peak', async () => {
    const { profiler } = make();
    let last: ResourceSaturationReport | null = null;
    for (let i = 0; i < 12; i++) {
      last = await profiler.profile({
        txHash: `t${i}`,
        usage: { cpuInstructions: 20_000_000 + i * 4_000_000 },
        contractId: 'C',
        functionName: 'grow',
      });
    }
    expect(last?.trendingUp).toBe(true);
    const stats = profiler.getFunctionStats('C', 'grow')!;
    expect(stats.invocations).toBe(12);
    expect(stats.peak.cpuInstructions).toBe(64_000_000);
    expect(stats.peakUtilizationPct.cpuInstructions).toBeCloseTo(64);
  });

  it('does not flag a steady function as trending', async () => {
    const { profiler } = make();
    let last: ResourceSaturationReport | null = null;
    for (let i = 0; i < 12; i++) {
      last = await profiler.profile({ txHash: `s${i}`, usage: { cpuInstructions: 30_000_000 }, contractId: 'C', functionName: 'steady' });
    }
    expect(last?.trendingUp).toBe(false);
  });

  it('keeps going when a handler throws', async () => {
    const bad = vi.fn().mockRejectedValue(new Error('boom'));
    const good = vi.fn();
    const { profiler } = make({ handlers: [bad, good] });
    await profiler.profile({ txHash: 'x', usage: { cpuInstructions: 90_000_000 }, contractId: 'C', functionName: 'f' });
    await vi.waitFor(() => expect(good).toHaveBeenCalled());
  });

  it('rejects an invalid threshold', () => {
    expect(() => new ResourceSaturationProfiler({ threshold: 0 })).toThrow(RangeError);
    expect(() => new ResourceSaturationProfiler({ threshold: 1.5 })).toThrow(RangeError);
  });

  it('formats alerts for webhooks and Telegram', async () => {
    const { profiler } = make();
    const report = (await profiler.profile({
      txHash: 'tx9',
      usage: { cpuInstructions: 90_000_000, readBytes: 10 },
      contractId: CONTRACT,
      functionName: 'swap',
    }))!;
    const payload = buildResourceSaturationWebhookPayload(report);
    expect(payload.event).toBe('soroban.resource_saturation');
    expect(payload.saturated).toEqual(['cpuInstructions']);
    const text = buildResourceSaturationTelegramMessage(report);
    expect(text).toContain(CONTRACT);
    expect(text).toContain('90.0%');
  });
});
