import { describe, expect, it, vi } from 'vitest';
import {
  computeClaimWindow,
  evaluateClaimPredicate,
  type ClaimPredicate,
} from '@stellar-alerts/shared';
import {
  pollClaimableBalances,
  processClaimableBalance,
  type ClaimableBalanceEntry,
} from '../claimable-balance.worker';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

function balance(overrides: Partial<ClaimableBalanceEntry> = {}): ClaimableBalanceEntry {
  return {
    id: 'bal-1',
    asset: 'USDC:GISSUER',
    amount: '250.0000000',
    sponsor: 'GSPONSOR',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    claimants: [{ destination: 'GCLAIMANT', predicate: { unconditional: true } }],
    ...overrides,
  };
}

describe('claim predicate evaluation (#913)', () => {
  const createdAt = new Date('2026-01-01T00:00:00.000Z');

  it('treats an unconditional predicate as claimable forever', () => {
    const window = computeClaimWindow({ unconditional: true }, createdAt, '2026-06-01T00:00:00.000Z');
    expect(window.claimableNow).toBe(true);
    expect(window.becomesClaimableAt?.toISOString()).toBe(createdAt.toISOString());
    expect(window.expiresAt).toBeNull();
    expect(window.neverClaimable).toBe(false);
  });

  it('treats abs_before as an exclusive expiry deadline, not an unlock time', () => {
    const deadline = '2026-02-01T00:00:00.000Z';
    const predicate: ClaimPredicate = { abs_before: deadline };

    expect(evaluateClaimPredicate(predicate, '2026-01-15T00:00:00.000Z', createdAt)).toBe(true);
    expect(evaluateClaimPredicate(predicate, deadline, createdAt)).toBe(false);

    const window = computeClaimWindow(predicate, createdAt, '2026-01-15T00:00:00.000Z');
    expect(window.claimableNow).toBe(true);
    expect(window.expiresAt?.toISOString()).toBe(deadline);
  });

  it('anchors rel_before to the balance creation time', () => {
    const predicate: ClaimPredicate = { rel_before: '3600' };
    expect(evaluateClaimPredicate(predicate, new Date(createdAt.getTime() + 3599_000), createdAt)).toBe(true);
    expect(evaluateClaimPredicate(predicate, new Date(createdAt.getTime() + 3600_000), createdAt)).toBe(false);

    const window = computeClaimWindow(predicate, createdAt, new Date(createdAt.getTime() + 60_000));
    expect(window.claimableNow).toBe(true);
    expect(window.expiresAt?.toISOString()).toBe(new Date(createdAt.getTime() + 3_600_000).toISOString());
  });

  it('computes a delayed claim window for not(abs_before(...))', () => {
    const predicate: ClaimPredicate = { not: { abs_before: '2026-03-01T00:00:00.000Z' } };

    const before = computeClaimWindow(predicate, createdAt, '2026-02-01T00:00:00.000Z');
    expect(before.claimableNow).toBe(false);
    expect(before.becomesClaimableAt?.toISOString()).toBe('2026-03-01T00:00:00.000Z');
    expect(before.expiresAt).toBeNull();

    const after = computeClaimWindow(predicate, createdAt, '2026-03-01T00:00:00.001Z');
    expect(after.claimableNow).toBe(true);
  });

  it('evaluates nested AND/OR predicate trees', () => {
    const predicate: ClaimPredicate = {
      and: [
        { not: { abs_before: '2026-02-01T00:00:00.000Z' } },
        {
          or: [
            { abs_before: '2026-05-01T00:00:00.000Z' },
            { rel_before: String(30 * 24 * 3600) },
          ],
        },
      ],
    };

    // Before Feb 1: the NOT fails, so the AND cannot hold.
    expect(evaluateClaimPredicate(predicate, '2026-01-15T00:00:00.000Z', createdAt)).toBe(false);
    // Between Feb 1 and the OR bounds: claimable.
    expect(evaluateClaimPredicate(predicate, '2026-03-01T00:00:00.000Z', createdAt)).toBe(true);
    // The OR is satisfied by the later abs_before, so the window runs to May 1.
    const window = computeClaimWindow(predicate, createdAt, '2026-03-01T00:00:00.000Z');
    expect(window.becomesClaimableAt?.toISOString()).toBe('2026-02-01T00:00:00.000Z');
    expect(window.expiresAt?.toISOString()).toBe('2026-05-01T00:00:00.000Z');
  });

  it('marks a predicate that can never hold as never claimable', () => {
    const window = computeClaimWindow({ and: [{ unconditional: true }, { not: { unconditional: true } }] }, createdAt);
    expect(window.neverClaimable).toBe(true);
    expect(window.claimableNow).toBe(false);
  });
});

describe('processClaimableBalance (#913)', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');

  it('emits CREATED, NOW_CLAIMABLE and EXPIRING_SOON for a balance inside its claim window', () => {
    const alerts = processClaimableBalance(
      balance({ claimants: [{ destination: 'GCLAIMANT', predicate: { abs_before: new Date(now.getTime() + 2 * HOUR).toISOString() } }] }),
      new Set(['GCLAIMANT']),
      { now },
    );

    expect(alerts.map((a) => a.type)).toEqual(['CREATED', 'NOW_CLAIMABLE', 'EXPIRING_SOON']);
    expect(alerts.every((a) => a.claimantAddress === 'GCLAIMANT')).toBe(true);
    expect(alerts[1]!.claimableAt).toBe(now.toISOString());
    expect(new Date(alerts[1]!.expiresAt!).getTime()).toBe(now.getTime() + 2 * HOUR);
  });

  it('emits EXPIRED after the upper bound passes', () => {
    const alerts = processClaimableBalance(
      balance({
        createdAt: new Date(now.getTime() - 2 * DAY),
        claimants: [{ destination: 'GCLAIMANT', predicate: { abs_before: new Date(now.getTime() - DAY).toISOString() } }],
      }),
      new Set(['GCLAIMANT']),
      { now },
    );

    expect(alerts.map((a) => a.type)).toEqual(['CREATED', 'EXPIRED']);
  });

  it('ignores claimants that are not monitored', () => {
    const alerts = processClaimableBalance(
      balance({ claimants: [{ destination: 'GSOMEONE_ELSE', predicate: { unconditional: true } }] }),
      new Set(['GCLAIMANT']),
      { now },
    );
    expect(alerts).toEqual([]);
  });

  it('does not alert for a balance whose window has not opened yet', () => {
    const alerts = processClaimableBalance(
      balance({ claimants: [{ destination: 'GCLAIMANT', predicate: { not: { abs_before: new Date(now.getTime() + DAY).toISOString() } } }] }),
      new Set(['GCLAIMANT']),
      { now },
    );
    expect(alerts.map((a) => a.type)).toEqual(['CREATED']);
  });
});

describe('pollClaimableBalances (#913)', () => {
  it('fetches each monitored claimant once and dispatches every alert through the notifier', async () => {
    const fetchBalances = vi.fn(async (claimant: string) => [
      balance({
        id: `bal-${claimant}`,
        claimants: [{ destination: claimant, predicate: { unconditional: true } }],
      }),
    ]);
    const notify = vi.fn();

    const alerts = await pollClaimableBalances({
      monitoredAddresses: ['GA', 'GB'],
      fetchBalances,
      notify,
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });

    expect(fetchBalances.mock.calls.map(([claimant]) => claimant)).toEqual(['GA', 'GB']);
    expect(alerts.length).toBe(4); // CREATED + NOW_CLAIMABLE per balance
    expect(notify).toHaveBeenCalledTimes(4);
  });

  it('continues past a claimant whose Horizon fetch fails', async () => {
    const fetchBalances = vi.fn(async (claimant: string) => {
      if (claimant === 'GA') throw new Error('horizon timeout');
      return [balance({ claimants: [{ destination: claimant, predicate: { unconditional: true } }] })];
    });
    const notify = vi.fn();

    const alerts = await pollClaimableBalances({
      monitoredAddresses: ['GA', 'GB'],
      fetchBalances,
      notify,
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });

    expect(alerts.every((a) => a.claimantAddress === 'GB')).toBe(true);
    expect(notify).toHaveBeenCalledTimes(2);
  });
});
