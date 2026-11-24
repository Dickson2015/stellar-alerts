import { describe, expect, it } from 'vitest';
import {
  WashTradingDetector,
  buildTransferGraph,
  classifyWashVolume,
  findStronglyConnectedComponents,
  scoreReciprocity,
  type TransferRecord,
} from '../wash-trading-detector';

const AS_OF = 1_700_000_000_000;
const HOUR = 3_600_000;
const ORG_WALLET = 'ORG2';

function transfer(from: string, to: string, amount: number, overrides: Partial<TransferRecord> = {}): TransferRecord {
  return { from, to, amount, asset: 'USDC', timestamp: AS_OF - 1_000, ...overrides };
}

describe('buildTransferGraph (#1046)', () => {
  it('aggregates parallel transfers and ignores invalid records', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 4),
      transfer('A', 'B', 6),
      transfer('A', 'C', 0),
      transfer('A', 'C', -5),
      transfer('A', 'C', Number.NaN),
      transfer('A', 'C', Number.POSITIVE_INFINITY),
      transfer('A', 'C', 7, { timestamp: 'not-a-date' }),
      transfer('A', 'C', 8, { asset: 'XLM' }),
    ], 'usdc', AS_OF - HOUR, AS_OF);

    expect(graph.nodes.has('A')).toBe(true);
    expect(graph.nodes.has('C')).toBe(false);
    expect(graph.edges.get('A')?.get('B')).toBe(10);
    expect(graph.grossVolume).toBe(10);
  });

  it('honors the window bounds and asset filter', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 1, { timestamp: AS_OF - 2 * HOUR }),
      transfer('A', 'B', 2, { timestamp: AS_OF - HOUR - 1 }),
      transfer('A', 'B', 3, { timestamp: AS_OF - HOUR }),
    ], 'USDC', AS_OF - HOUR, AS_OF);

    expect(graph.grossVolume).toBe(3);
  });
});

describe('findStronglyConnectedComponents and scoreReciprocity (#1046)', () => {
  it('finds a 3-node circular component but never clusters an organic tree', () => {
    const ring = buildTransferGraph([
      transfer('A', 'B', 10), transfer('B', 'C', 10), transfer('C', 'A', 10),
    ], 'USDC', AS_OF - HOUR, AS_OF);
    const tree = buildTransferGraph([
      transfer('A', 'B', 10), transfer('B', 'C', 5), transfer('B', 'D', 5),
    ], 'USDC', AS_OF - HOUR, AS_OF);

    expect(findStronglyConnectedComponents(ring)).toHaveLength(1);
    expect(findStronglyConnectedComponents(ring)[0].sort()).toEqual(['A', 'B', 'C']);
    expect(findStronglyConnectedComponents(tree).every((component) => component.length === 1)).toBe(true);
  });

  it('scores one-way edges as zero and balanced pairs as one', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 10), transfer('B', 'A', 10), transfer('B', 'C', 5),
    ], 'USDC', AS_OF - HOUR, AS_OF);
    const scores = scoreReciprocity(graph);

    expect(scores.get('A|B')).toBe(1);
    expect(scores.get('B|C')).toBe(0);
  });
});

describe('classifyWashVolume (#1046)', () => {
  it('reports no clusters for an organic star/tree topology', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 10), transfer('A', 'C', 20), transfer('C', 'D', 30),
    ], 'USDC', AS_OF - HOUR, AS_OF);

    expect(classifyWashVolume(graph)).toEqual([]);
  });

  it('flags a bidirectional ping-pong loop above the 80% return threshold', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 100), transfer('B', 'A', 90),
    ], 'USDC', AS_OF - HOUR, AS_OF);
    const clusters = classifyWashVolume(graph);

    expect(clusters).toHaveLength(1);
    expect(clusters[0]).toMatchObject({ addresses: ['A', 'B'], pattern: 'ping-pong', volume: 190 });
    expect(clusters[0].returnRatio).toBeCloseTo(0.9, 9);
  });

  it('flags a 3-node A->B->C->A ring with its full circulating volume', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 10), transfer('B', 'C', 10), transfer('C', 'A', 10),
    ], 'USDC', AS_OF - HOUR, AS_OF);
    const clusters = classifyWashVolume(graph);

    expect(clusters).toHaveLength(1);
    expect(clusters[0]).toMatchObject({ addresses: ['A', 'B', 'C'], pattern: 'ring', volume: 30 });
    expect(clusters[0].returnRatio).toBe(1);
  });

  it('flags a self-transfer loop even though the component has one address', () => {
    const graph = buildTransferGraph([transfer('A', 'A', 7)], 'USDC', AS_OF - HOUR, AS_OF);
    expect(classifyWashVolume(graph)).toMatchObject([{ addresses: ['A'], pattern: 'self', volume: 7 }]);
  });

  it('treats 79% return as organic but excludes exactly 80% as not above threshold', () => {
    const below = buildTransferGraph([
      transfer('A', 'B', 100), transfer('B', 'A', 79),
    ], 'USDC', AS_OF - HOUR, AS_OF);
    const exact = buildTransferGraph([
      transfer('A', 'B', 100), transfer('B', 'A', 80),
    ], 'USDC', AS_OF - HOUR, AS_OF);

    expect(classifyWashVolume(below)).toEqual([]);
    expect(classifyWashVolume(exact)).toEqual([]);
  });

  it('respects a custom return threshold', () => {
    const graph = buildTransferGraph([
      transfer('A', 'B', 100), transfer('B', 'A', 40),
    ], 'USDC', AS_OF - HOUR, AS_OF);

    expect(classifyWashVolume(graph, 30)).toHaveLength(1);
    expect(classifyWashVolume(graph, 50)).toEqual([]);
  });
});

describe('WashTradingDetector.detect (#1046)', () => {
  it('reports gross, wash and organic volume with flagged cluster addresses', () => {
    const transfers = [
      transfer('ORG', 'BUYER', 50),
      transfer('A', 'B', 100), transfer('B', 'A', 90),
      transfer(ORG_WALLET, 'BUYER', 25),
    ];
    const [report] = new WashTradingDetector().detect(transfers, AS_OF)
      .filter((candidate) => candidate.windowMs === HOUR);

    expect(report.grossVolume).toBe(265);
    expect(report.washVolume).toBe(190);
    expect(report.organicVolume).toBe(75);
    expect(report.organicRatio).toBeCloseTo(75 / 265, 9);
    expect(report.clusters[0].addresses).toEqual(['A', 'B']);
    expect(report.windowStart).toBe(AS_OF - HOUR);
    expect(report.windowEnd).toBe(AS_OF);
  });

  it('separates 1-hour and 24-hour windows', () => {
    const transfers = [
      transfer('A', 'B', 10, { timestamp: AS_OF - 2 * HOUR }),
      transfer('A', 'B', 5),
    ];
    const reports = new WashTradingDetector().detect(transfers, AS_OF);

    expect(reports.find((report) => report.windowMs === HOUR)?.grossVolume).toBe(5);
    expect(reports.find((report) => report.windowMs === 86_400_000)?.grossVolume).toBe(15);
  });

  it('analyzes each asset independently', () => {
    const transfers = [
      transfer('A', 'B', 100, { asset: 'USDC' }),
      transfer('B', 'A', 90, { asset: 'USDC' }),
      transfer('A', 'B', 100, { asset: 'XLM' }),
    ];
    const reports = new WashTradingDetector().detect(transfers, AS_OF)
      .filter((report) => report.windowMs === HOUR);

    expect(reports).toHaveLength(2);
    expect(reports.find((report) => report.asset === 'USDC')?.washVolume).toBe(190);
    expect(reports.find((report) => report.asset === 'XLM')?.clusters).toEqual([]);
  });

  it('returns no reports for empty input', () => {
    expect(new WashTradingDetector().detect([], AS_OF)).toEqual([]);
  });
});
