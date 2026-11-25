import { describe, expect, it, vi } from 'vitest';

// Any of these being invoked during a replay would be a side effect.
const sideEffects = vi.hoisted(() => ({
  enqueue: vi.fn(),
  fetch: vi.fn(),
}));
vi.mock('../../../lib/queue', () => ({ enqueue: sideEffects.enqueue, addJob: sideEffects.enqueue }));
vi.stubGlobal('fetch', sideEffects.fetch);

import {
  BacktestReplayEngine,
  type BacktestPaymentSource,
  type BacktestRange,
  type HistoricalPayment,
} from '../backtest-engine';

const USER = 'user-1';
const WALLET = 'wallet-1';

function payment(i: number, overrides: Partial<HistoricalPayment>): HistoricalPayment {
  return {
    paymentId: `pay-${i}`,
    txHash: `tx-${i}`,
    walletId: WALLET,
    userId: USER,
    amount: '10',
    asset: 'XLM',
    fromAddress: `GSENDER${i}`,
    memo: null,
    receivedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  };
}

// Seeded, fixed fixture spanning 3 days. Ordered by (receivedAt, paymentId).
const FIXTURE: HistoricalPayment[] = [
  payment(1, { amount: '5', receivedAt: '2026-01-01T02:10:00.000Z' }),
  payment(2, { amount: '150', receivedAt: '2026-01-01T02:40:00.000Z' }),
  payment(3, { amount: '500', asset: 'USDC', receivedAt: '2026-01-01T14:00:00.000Z' }),
  payment(4, { amount: '250', receivedAt: '2026-01-02T02:05:00.000Z', memo: 'invoice-77' }),
  payment(5, { amount: '99.9999999', receivedAt: '2026-01-02T09:30:00.000Z' }),
  payment(6, { amount: '100', receivedAt: '2026-01-02T23:59:00.000Z' }),
  payment(7, { amount: '1000', receivedAt: '2026-01-03T14:15:00.000Z', walletId: 'other-wallet' }),
  payment(8, { amount: '300', receivedAt: '2026-01-04T02:00:00.000Z' }),
];

class FixtureSource implements BacktestPaymentSource {
  calls: BacktestRange[] = [];
  async *stream(range: BacktestRange) {
    this.calls.push(range);
    for (const p of FIXTURE) yield p;
  }
}

const RANGE = { from: new Date('2026-01-01T00:00:00Z'), to: new Date('2026-01-04T23:59:59Z') };

const baseRule = {
  assets: ['XLM'],
  minAmount: 100,
  maxAmount: null,
  memo: null,
  conditions: null,
  walletId: WALLET,
};

describe('BacktestReplayEngine (integration over seeded ledger fixture)', () => {
  it('produces the exact expected report', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const report = await engine.run(baseRule, RANGE, { userId: USER, walletId: WALLET });

    // XLM, >= 100, wallet-1 only: pay-2 (150), pay-4 (250), pay-6 (100, inclusive), pay-8 (300).
    const hourly = new Array(24).fill(0);
    hourly[2] = 3; // pay-2, pay-4, pay-8
    hourly[23] = 1; // pay-6

    expect(report).toEqual({
      dryRun: true,
      range: {
        startLedger: null,
        endLedger: null,
        from: '2026-01-01T00:00:00.000Z',
        to: '2026-01-04T23:59:59.000Z',
      },
      totalEvaluated: 8,
      totalMatches: 4,
      matchRate: 0.5,
      evaluationErrors: 0,
      // observed span: 02:10 on Jan 1 -> 02:00 on Jan 4 = 2.9931 days; 4 / 2.9931 = 1.3364
      averageMatchesPerDay: 1.3364,
      sampleMatches: [
        expect.objectContaining({ paymentId: 'pay-2', txHash: 'tx-2', amount: '150', ledger: null }),
        expect.objectContaining({ paymentId: 'pay-4', memo: 'invoice-77' }),
        expect.objectContaining({ paymentId: 'pay-6', amount: '100' }),
        expect.objectContaining({ paymentId: 'pay-8', amount: '300' }),
      ],
      hourlyDistribution: hourly,
      peakHour: { hour: 2, count: 3 },
      accuracy: null,
    });
  });

  it('is deterministic across repeated runs', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const a = await engine.run(baseRule, RANGE, { userId: USER, walletId: WALLET });
    const b = await engine.run(baseRule, RANGE, { userId: USER, walletId: WALLET });
    expect(b).toEqual(a);
  });

  it('caps sample matches but still counts every match and histogram bucket', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const report = await engine.run(baseRule, RANGE, { userId: USER, walletId: WALLET }, { sampleSize: 2 });
    expect(report.sampleMatches.map((s) => s.paymentId)).toEqual(['pay-2', 'pay-4']);
    expect(report.totalMatches).toBe(4);
    expect(report.hourlyDistribution.reduce((a, b) => a + b, 0)).toBe(4);
  });

  it('evaluates AST conditions and memo filters', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const report = await engine.run(
      {
        ...baseRule,
        minAmount: null,
        conditions: {
          operator: 'AND',
          rules: [
            { field: 'amount', operator: 'gt', value: 200 },
            { field: 'memo', operator: 'contains', value: 'invoice' },
          ],
        },
      },
      RANGE,
      { userId: USER, walletId: WALLET },
    );
    expect(report.sampleMatches.map((s) => s.paymentId)).toEqual(['pay-4']);
  });

  it('backtests a draft regardless of isActive and never matches other wallets', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const report = await engine.run(
      { ...baseRule, minAmount: 900, assets: [] },
      RANGE,
      { userId: USER, walletId: WALLET },
    );
    // pay-7 (1000) belongs to another wallet, and the rule is wallet-scoped.
    expect(report.totalMatches).toBe(0);
    expect(report.peakHour).toBeNull();
  });

  it('reports false positives and precision when a labeller is supplied', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    const report = await engine.run(
      baseRule,
      RANGE,
      { userId: USER, walletId: WALLET },
      { isExpectedMatch: (p) => Number(p.amount) >= 200 && p.asset === 'XLM' },
    );
    // matched: 2,4,6,8; expected: 4,7(other wallet, XLM 1000),8
    expect(report.accuracy).toEqual({
      truePositives: 2,
      falsePositives: 2,
      falseNegatives: 1,
      precision: 0.5,
      falsePositiveRate: 0.5,
      recall: 0.6667,
    });
  });

  it('forwards ledger ranges to the source and rejects invalid ranges', async () => {
    const source = new FixtureSource();
    const engine = new BacktestReplayEngine(source);
    await engine.run(baseRule, { startLedger: 100, endLedger: 200 }, { userId: USER });
    expect(source.calls[0]).toEqual({ startLedger: 100, endLedger: 200 });

    await expect(engine.run(baseRule, {}, { userId: USER })).rejects.toThrow(/required/);
    await expect(
      engine.run(baseRule, { startLedger: 5, endLedger: 1 }, { userId: USER }),
    ).rejects.toThrow(/startLedger/);
  });

  it('aborts when the range exceeds maxEvents', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    await expect(
      engine.run(baseRule, RANGE, { userId: USER }, { maxEvents: 3 }),
    ).rejects.toMatchObject({ code: 'BACKTEST_RANGE_TOO_LARGE' });
  });

  it('has zero side effects: no queueing or outbound network calls', async () => {
    const engine = new BacktestReplayEngine(new FixtureSource());
    await engine.run(baseRule, RANGE, { userId: USER, walletId: WALLET });
    expect(sideEffects.enqueue).not.toHaveBeenCalled();
    expect(sideEffects.fetch).not.toHaveBeenCalled();
  });
});
