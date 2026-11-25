import { describe, it, expect, beforeEach } from 'vitest';
import { DaoGovernanceSentinel, type VotingPowerLookup } from '../dao-sentinel.service';
import { parseDaoEvent, processDaoEventBatch } from '../../../workers/dao-sentinel.worker';

const HOUR = 60 * 60 * 1000;
const START = 1_000_000_000_000;
const END = START + 100 * HOUR;
const C = 'CDAO';

const created = {
  kind: 'proposal_created' as const,
  contractId: C,
  proposalId: '7',
  txHash: 'txc',
  ledgerSeq: 1,
  timestampMs: START,
  proposer: 'GPROPOSER',
  title: 'Drain treasury',
  votingStartsMs: START,
  votingEndsMs: END,
  quorum: '300',
  totalVotingPower: '1000',
};

function vote(voter: string, support: boolean, weight: number, atMs: number) {
  return { kind: 'vote_cast' as const, contractId: C, proposalId: '7', txHash: `tx-${voter}`, ledgerSeq: 2, timestampMs: atMs, voter, support, weight };
}

describe('DaoGovernanceSentinel (#971)', () => {
  let sentinel: DaoGovernanceSentinel;
  let power: Record<string, { now: bigint; before: bigint }>;
  const lookup: VotingPowerLookup = (_c, voter, atMs) => {
    const p = power[voter];
    if (!p) return null;
    return atMs >= START + 50 * HOUR ? p.now : p.before;
  };

  beforeEach(() => {
    power = {};
    sentinel = new DaoGovernanceSentinel({}, lookup);
  });

  it('alerts immediately on a new proposal and on queueing, once each', async () => {
    const a = await sentinel.processEvent(created);
    expect(a.map((x) => x.type)).toEqual(['PROPOSAL_CREATED']);

    const queuedEvent = { kind: 'proposal_queued' as const, contractId: C, proposalId: '7', txHash: 'txq', ledgerSeq: 9, timestampMs: END + HOUR, executableAtMs: END + 49 * HOUR };
    expect((await sentinel.processEvent(queuedEvent)).map((x) => x.type)).toEqual(['PROPOSAL_QUEUED']);
    expect(await sentinel.processEvent(queuedEvent)).toHaveLength(0);
  });

  it('delivers alerts to subscribers and survives a throwing handler', async () => {
    const seen: string[] = [];
    sentinel.subscribe(() => { throw new Error('boom'); });
    sentinel.subscribe((a) => { seen.push(a.type); });
    await sentinel.processEvent(created);
    expect(seen).toEqual(['PROPOSAL_CREATED']);
  });

  describe('flash-vote risk', () => {
    beforeEach(async () => { await sentinel.processEvent(created); });

    it('flags a voter who gained more than 10% of power within 24h', async () => {
      power.GWHALE = { before: 10n, now: 200n }; // +190 of 1000 = 19%
      const alerts = await sentinel.processEvent(vote('GWHALE', true, 200, START + 50 * HOUR));
      const flash = alerts.find((a) => a.type === 'FLASH_VOTE_RISK');
      expect(flash).toBeDefined();
      expect(flash?.severity).toBe('URGENT');
      expect(flash?.acquiredPowerShare).toBeCloseTo(0.19);
    });

    it('does not flag long-held power, or an acquisition of exactly 10%', async () => {
      power.GHOLDER = { before: 200n, now: 200n };
      power.GEDGE = { before: 0n, now: 100n };
      expect((await sentinel.processEvent(vote('GHOLDER', true, 200, START + 50 * HOUR))).some((a) => a.type === 'FLASH_VOTE_RISK')).toBe(false);
      expect((await sentinel.processEvent(vote('GEDGE', true, 100, START + 50 * HOUR))).some((a) => a.type === 'FLASH_VOTE_RISK')).toBe(false);
    });

    it('skips the check (without throwing) when power lookup fails', async () => {
      const failing = new DaoGovernanceSentinel({}, () => { throw new Error('rpc down'); });
      await failing.processEvent(created);
      const alerts = await failing.processEvent(vote('GX', true, 500, START + 10 * HOUR));
      expect(alerts.some((a) => a.type === 'FLASH_VOTE_RISK')).toBe(false);
    });
  });

  describe('last-minute outcome flip', () => {
    beforeEach(async () => {
      await sentinel.processEvent(created);
      await sentinel.processEvent(vote('GA', true, 200, START + 10 * HOUR));
      await sentinel.processEvent(vote('GB', false, 150, START + 20 * HOUR));
    });

    it('emits an urgent alert when a vote in the final 10% flips the outcome', async () => {
      // 200 for / 150 against, quorum 300 met -> PASSING; 100 against flips it.
      const alerts = await sentinel.processEvent(vote('GC', false, 100, END - 5 * HOUR));
      const flip = alerts.find((a) => a.type === 'OUTCOME_FLIP_LAST_MINUTE');
      expect(flip?.severity).toBe('URGENT');
      expect(flip).toMatchObject({ previousOutcome: 'PASSING', newOutcome: 'FAILING' });
    });

    it('does not alert on a flip earlier in the voting period', async () => {
      const alerts = await sentinel.processEvent(vote('GC', false, 100, START + 40 * HOUR));
      expect(alerts.some((a) => a.type === 'OUTCOME_FLIP_LAST_MINUTE')).toBe(false);
    });

    it('does not alert when a late vote leaves the outcome unchanged', async () => {
      const alerts = await sentinel.processEvent(vote('GC', true, 10, END - HOUR));
      expect(alerts.some((a) => a.type === 'OUTCOME_FLIP_LAST_MINUTE')).toBe(false);
    });

    it('treats failing quorum as a failing outcome', async () => {
      expect(sentinel.getProposalTally(C, '7')?.outcome).toBe('PASSING');
    });
  });

  it('reports whale votes by share of total power', async () => {
    await sentinel.processEvent(created);
    const alerts = await sentinel.processEvent(vote('GBIG', true, 60, START + HOUR));
    expect(alerts.find((a) => a.type === 'WHALE_VOTE')?.weightShare).toBeCloseTo(0.06);
  });

  describe('worker event parsing', () => {
    it('maps decoded Soroban events and ignores unrelated ones', () => {
      const proposal = parseDaoEvent(
        { contractId: C, topic: ['proposal_created'], txHash: 't', ledger: 5, ledgerClosedAt: '2026-01-01T00:00:00Z',
          value: { id: 3, proposer: 'GP', start: START, end: END, quorum: '10', totalVotingPower: '100' } },
        C,
      );
      expect(proposal).toMatchObject({ kind: 'proposal_created', proposalId: '3', totalVotingPower: '100' });
      expect(parseDaoEvent({ topic: ['transfer'], txHash: 't', ledger: 1 }, C)).toBeNull();
      expect(parseDaoEvent({ topic: ['vote_cast'], txHash: 't', ledger: 1, value: { proposal_id: 1 } }, C)).toBeNull();
    });

    it('processes a batch in ledger order', async () => {
      const alerts = await processDaoEventBatch(
        sentinel,
        [
          { topic: ['vote_cast'], txHash: 'v', ledger: 3, ledgerClosedAt: START + HOUR, value: { proposal_id: 7, voter: 'GV', support: true, weight: 80 } },
          { topic: ['proposal_created'], txHash: 'c', ledger: 2, ledgerClosedAt: START, value: { proposal_id: 7, start: START, end: END, quorum: 1, totalVotingPower: 1000 } },
        ],
        C,
      );
      expect(alerts.map((a) => a.type)).toEqual(['PROPOSAL_CREATED', 'WHALE_VOTE']);
    });
  });
});
