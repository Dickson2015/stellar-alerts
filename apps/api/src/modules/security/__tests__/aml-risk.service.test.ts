/**
 * Unit tests for the graph-based AML risk scorer (#928).
 *
 * The fixtures model a classic laundering chain: a sanctioned wallet sells
 * funds to a transit wallet, which forwards them to the wallet under
 * evaluation. The scorer must find the taint within the configured two-hop
 * window, decay it per hop, and escalate a payment source above 70 points.
 */
import { describe, it, expect, vi } from 'vitest';
import {
  AmlRiskScorer,
  createAmlRiskScorerFromEnv,
} from '../aml-risk.service';
import {
  AML_CRITICAL_RISK_THRESHOLD,
  amlRiskAssessmentSchema,
  amlRiskLevelFromScore,
  isCriticalAmlRisk,
  type AmlTransactionEdge,
} from '@stellar-alerts/shared';

const SANCTIONED = 'GSANCTIONEDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const EXPLOITER = 'GEXPLOITERXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const MIXER = 'GMIXERXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const TRANSIT = 'GTRANSITXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const CUSTOMER = 'GCUSTOMERXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
const MERCHANT = 'GMERCHANTXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

function buildScorer(options: ConstructorParameters<typeof AmlRiskScorer>[0] = {}) {
  return new AmlRiskScorer({
    flaggedAddresses: [
      { address: SANCTIONED, category: 'sanctioned', label: 'OFAC SDN' },
      { address: EXPLOITER, category: 'exploiter', label: 'Drainer' },
      { address: MIXER, category: 'mixer', label: 'Tumbler' },
    ],
    ...options,
  });
}

describe('AmlRiskScorer direct matches (#928)', () => {
  it('scores a direct sanctioned match at 100 and marks it critical', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(SANCTIONED);

    expect(assessment.score).toBe(100);
    expect(assessment.level).toBe('critical');
    expect(assessment.hops).toBe(0);
    expect(assessment.matches).toHaveLength(1);
    expect(assessment.matches[0]).toMatchObject({
      address: SANCTIONED,
      category: 'sanctioned',
      hops: 0,
    });
    expect(scorer.shouldTriggerCritical(assessment)).toBe(true);
    expect(amlRiskAssessmentSchema.safeParse(assessment).success).toBe(true);
  });

  it('returns a low-risk assessment when an address is clean', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(CUSTOMER, [
      { from: CUSTOMER, to: MERCHANT },
    ]);

    expect(assessment).toMatchObject({
      address: CUSTOMER,
      score: 0,
      level: 'low',
      hops: null,
      matches: [],
    });
    expect(scorer.shouldTriggerCritical(assessment)).toBe(false);
  });
});

describe('AmlRiskScorer taint propagation (#928)', () => {
  it('decays a one-hop exploiter link but still escalates above 70', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, [
      { from: EXPLOITER, to: MERCHANT },
    ]);

    // 85 (hop 1 base) * 0.85 (exploiter severity) = 72.25
    expect(assessment.score).toBeCloseTo(72.25, 2);
    expect(assessment.hops).toBe(1);
    expect(assessment.level).toBe('critical');
    expect(scorer.shouldTriggerCritical(assessment)).toBe(true);
  });

  it('propagates two-hop mixer taint below the critical threshold', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, [
      { from: MIXER, to: TRANSIT },
      { from: TRANSIT, to: MERCHANT },
    ]);

    // 65 (hop 2 base) * 0.9 (mixer severity) = 58.5
    expect(assessment.score).toBeCloseTo(58.5, 2);
    expect(assessment.hops).toBe(2);
    expect(assessment.level).toBe('high');
    expect(scorer.shouldTriggerCritical(assessment)).toBe(false);
  });

  it('does not propagate taint beyond the configured two hops', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, [
      { from: SANCTIONED, to: CUSTOMER },
      { from: CUSTOMER, to: TRANSIT },
      { from: TRANSIT, to: MERCHANT },
    ]);

    expect(assessment.score).toBe(0);
    expect(assessment.matches).toEqual([]);
  });

  it('applies edge weights to the propagated contribution', () => {
    const graph: AmlTransactionEdge[] = [
      { from: EXPLOITER, to: MERCHANT, weight: 0.5 },
    ];
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, graph);

    // 85 * 0.85 * 0.5 = 36.125, rounded to two decimals
    expect(assessment.score).toBe(36.13);
    expect(assessment.level).toBe('medium');
  });

  it('keeps the strongest path when several routes reach the same flagged address', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, [
      { from: EXPLOITER, to: MERCHANT },
      { from: EXPLOITER, to: TRANSIT, weight: 0.2 },
      { from: TRANSIT, to: MERCHANT, weight: 0.2 },
    ]);

    expect(assessment.score).toBeCloseTo(72.25, 2);
    expect(assessment.matches).toHaveLength(1);
    expect(assessment.matches[0].hops).toBe(1);
  });

  it('reports every flagged counterparty, strongest first', () => {
    const scorer = buildScorer();
    const assessment = scorer.evaluateAddress(MERCHANT, [
      { from: MIXER, to: TRANSIT },
      { from: TRANSIT, to: MERCHANT },
      { from: EXPLOITER, to: MERCHANT },
    ]);

    expect(assessment.score).toBeCloseTo(72.25, 2);
    expect(assessment.matches.map((match) => match.address)).toEqual([
      EXPLOITER,
      MIXER,
    ]);
    expect(assessment.hops).toBe(1);
  });

  it('terminates on cycles without expanding a node twice', () => {
    const scorer = buildScorer();
    const graph: AmlTransactionEdge[] = [
      { from: TRANSIT, to: MERCHANT },
      { from: MERCHANT, to: TRANSIT },
      { from: EXPLOITER, to: TRANSIT },
    ];

    const assessment = scorer.evaluateAddress(MERCHANT, graph);
    // EXPLOITER reaches the target through TRANSIT (two hops): 65 * 0.85.
    expect(assessment.score).toBeCloseTo(55.25, 2);
    expect(assessment.matches).toHaveLength(1);
    expect(assessment.hops).toBe(2);
  });

  it('honours a caller-supplied critical threshold', () => {
    const scorer = buildScorer({ criticalThreshold: 90 });
    const oneHop = scorer.evaluateAddress(MERCHANT, [
      { from: EXPLOITER, to: MERCHANT },
    ]);

    expect(oneHop.score).toBeCloseTo(72.25, 2);
    expect(scorer.shouldTriggerCritical(oneHop)).toBe(false);
    expect(oneHop.level).toBe('critical'); // band is a fixed shared contract
  });
});

describe('AmlRiskScorer flagged-address registry', () => {
  it('registers, replaces and removes entries', () => {
    const scorer = new AmlRiskScorer();
    expect(scorer.hasFlaggedAddresses()).toBe(false);

    scorer.registerFlaggedAddress({ address: MIXER, category: 'mixer' });
    expect(scorer.isFlagged(MIXER)).toBe(true);
    expect(scorer.getFlaggedAddress(MIXER)).toMatchObject({ severity: 0.9 });

    scorer.registerFlaggedAddress({
      address: MIXER,
      category: 'sanctioned',
      severity: 2, // out of range: clamped to 1
    });
    expect(scorer.getFlaggedAddress(MIXER)).toMatchObject({
      category: 'sanctioned',
      severity: 1,
    });

    expect(scorer.removeFlaggedAddress(MIXER)).toBe(true);
    expect(scorer.removeFlaggedAddress(MIXER)).toBe(false);
    expect(scorer.listFlaggedAddresses()).toEqual([]);
  });

  it('rejects empty addresses', () => {
    const scorer = new AmlRiskScorer();
    expect(() =>
      scorer.registerFlaggedAddress({ address: '   ', category: 'other' }),
    ).toThrow(/must not be empty/i);
  });

  it('builds a graph from payment rows', () => {
    const scorer = new AmlRiskScorer();
    const graph = scorer.buildGraphFromPayments([
      { fromAddress: EXPLOITER, toAddress: MERCHANT },
      { fromAddress: TRANSIT, toAddress: MERCHANT, weight: 0.4 },
    ]);

    expect(graph).toEqual([
      { from: EXPLOITER, to: MERCHANT },
      { from: TRANSIT, to: MERCHANT, weight: 0.4 },
    ]);
  });
});

describe('AmlRiskScorer edge loader', () => {
  it('fetches the target and non-flagged first-hop edges only', async () => {
    const scorer = buildScorer();
    const loader = vi.fn(async (address: string) => {
      if (address === MERCHANT) {
        return [
          { from: EXPLOITER, to: MERCHANT },
          { from: TRANSIT, to: MERCHANT },
        ];
      }
      if (address === TRANSIT) {
        return [{ from: MIXER, to: TRANSIT }];
      }
      return [];
    });

    const assessment = await scorer.evaluateWithEdgeLoader(MERCHANT, loader);

    expect(loader).toHaveBeenCalledTimes(2);
    expect(loader).toHaveBeenNthCalledWith(1, MERCHANT);
    expect(loader).toHaveBeenNthCalledWith(2, TRANSIT);
    expect(assessment.score).toBeCloseTo(72.25, 2);
    expect(assessment.matches.map((match) => match.address)).toEqual([
      EXPLOITER,
      MIXER,
    ]);
  });

  it('skips all I/O when no addresses are flagged', async () => {
    const scorer = new AmlRiskScorer();
    const loader = vi.fn(async () => []);
    const assessment = await scorer.evaluateWithEdgeLoader(MERCHANT, loader);

    expect(loader).not.toHaveBeenCalled();
    expect(assessment.score).toBe(0);
    expect(scorer.getStats()).toMatchObject({ evaluations: 1 });
  });

  it('does not query the graph for a direct match', async () => {
    const scorer = buildScorer();
    const loader = vi.fn(async () => []);
    const assessment = await scorer.evaluateWithEdgeLoader(SANCTIONED, loader);

    expect(loader).not.toHaveBeenCalled();
    expect(assessment.score).toBe(100);
  });

  it('caps the number of second-hop lookups', async () => {
    const scorer = buildScorer({ maxSecondHopLookups: 2 });
    const senders = [CUSTOMER, TRANSIT, 'GTHIRDXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'];
    const loader = vi.fn(async (address: string) =>
      address === MERCHANT
        ? senders.map((from, index) => ({
            from,
            to: MERCHANT,
            weight: 1 - index * 0.1,
          }))
        : [],
    );

    await scorer.evaluateWithEdgeLoader(MERCHANT, loader);

    // One query for the target plus two capped first-hop senders.
    expect(loader).toHaveBeenCalledTimes(3);
    expect(loader).toHaveBeenNthCalledWith(2, CUSTOMER);
    expect(loader).toHaveBeenNthCalledWith(3, TRANSIT);
  });
});

describe('AmlRiskScorer statistics and env bootstrap', () => {
  it('tracks evaluations and critical hits', () => {
    const scorer = buildScorer();
    scorer.evaluateAddress(MERCHANT, [{ from: EXPLOITER, to: MERCHANT }]);
    scorer.evaluateAddress(MERCHANT, []);

    expect(scorer.getStats()).toEqual({
      flaggedAddresses: 3,
      evaluations: 2,
      criticalHits: 1,
    });
  });

  it('seeds the local list from the comma-separated environment config', () => {
    const scorer = createAmlRiskScorerFromEnv({
      AML_SANCTIONED_ADDRESSES: `${SANCTIONED}, ${CUSTOMER}`,
      AML_EXPLOITER_ADDRESSES: EXPLOITER,
      AML_MIXER_ADDRESSES: MIXER,
    } as NodeJS.ProcessEnv);

    expect(scorer.listFlaggedAddresses()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ address: SANCTIONED, category: 'sanctioned' }),
        expect.objectContaining({ address: CUSTOMER, category: 'sanctioned' }),
        expect.objectContaining({ address: EXPLOITER, category: 'exploiter' }),
        expect.objectContaining({ address: MIXER, category: 'mixer' }),
      ]),
    );
  });

  it('parses structured AML_FLAGGED_ADDRESSES and ignores malformed entries', () => {
    const scorer = createAmlRiskScorerFromEnv({
      AML_FLAGGED_ADDRESSES: JSON.stringify([
        { address: MIXER, category: 'mixer', label: 'Tumbler', severity: 0.5 },
        { address: TRANSIT, category: 'not-a-category' },
        { category: 'sanctioned' },
      ]),
    } as NodeJS.ProcessEnv);

    expect(scorer.listFlaggedAddresses()).toEqual([
      expect.objectContaining({ address: MIXER, severity: 0.5 }),
    ]);
  });

  it('survives malformed JSON without losing the comma-separated lists', () => {
    const scorer = createAmlRiskScorerFromEnv({
      AML_SANCTIONED_ADDRESSES: SANCTIONED,
      AML_FLAGGED_ADDRESSES: '{not-json',
    } as NodeJS.ProcessEnv);

    expect(scorer.isFlagged(SANCTIONED)).toBe(true);
  });
});

describe('Shared AML score contract', () => {
  it('maps scores to the documented risk bands', () => {
    expect(amlRiskLevelFromScore(0)).toBe('low');
    expect(amlRiskLevelFromScore(24.99)).toBe('low');
    expect(amlRiskLevelFromScore(25)).toBe('medium');
    expect(amlRiskLevelFromScore(49.99)).toBe('medium');
    expect(amlRiskLevelFromScore(50)).toBe('high');
    expect(amlRiskLevelFromScore(70)).toBe('high');
    expect(amlRiskLevelFromScore(70.01)).toBe('critical');
    expect(amlRiskLevelFromScore(100)).toBe('critical');
  });

  it('escalates strictly above the shared 70-point threshold', () => {
    expect(AML_CRITICAL_RISK_THRESHOLD).toBe(70);
    expect(isCriticalAmlRisk(70)).toBe(false);
    expect(isCriticalAmlRisk(70.01)).toBe(true);
    expect(isCriticalAmlRisk(100)).toBe(true);
  });
});
