/**
 * Wash-trading and circular-volume detection (#1046).
 *
 * Builds a directed, weighted transfer graph per asset over rolling time
 * windows, then uses Tarjan's strongly connected components plus a bottleneck
 * reciprocity score to distinguish circular "wash" volume from organic volume.
 *
 * The module is deliberately pure: callers supply the transfer records (from
 * payments, Soroban transfer events, or both) and the detector performs no I/O.
 */

export interface TransferRecord {
  from: string;
  to: string;
  amount: number;
  asset: string;
  timestamp: Date | number | string;
  txHash?: string;
}

export interface WashTradingDetectorOptions {
  /** Rolling window lengths in milliseconds. Defaults to 1 hour and 24 hours. */
  windowMs?: number[];
  /** Minimum share of circulating volume that must return to origin. Default 80. */
  returnThresholdPct?: number;
  /** Minimum component size to flag, except for explicit self-loops. Default 2. */
  minClusterSize?: number;
}

export type WashPattern = 'ping-pong' | 'ring' | 'self';

export interface WashCluster {
  addresses: string[];
  /** Volume circulating inside the cluster (counted once per directed edge). */
  volume: number;
  /** Fraction 0..1 of the weakest node's outgoing volume that flows back to it. */
  returnRatio: number;
  pattern: WashPattern;
}

export interface WashTradingReport {
  asset: string;
  windowMs: number;
  windowStart: number;
  windowEnd: number;
  grossVolume: number;
  washVolume: number;
  organicVolume: number;
  organicRatio: number;
  clusters: WashCluster[];
}

export interface TransferGraph {
  asset: string;
  nodes: Set<string>;
  /** edges.get(from)?.get(to) is the total amount transferred from `from` to `to`. */
  edges: Map<string, Map<string, number>>;
  grossVolume: number;
}

export const DEFAULT_WINDOWS_MS = [3_600_000, 86_400_000] as const;
const DEFAULT_RETURN_THRESHOLD_PCT = 80;
const DEFAULT_MIN_CLUSTER_SIZE = 2;

function timestampMs(value: TransferRecord['timestamp']): number {
  return value instanceof Date ? value.getTime() : typeof value === 'number' ? value : new Date(value).getTime();
}

function assetKey(asset: string): string {
  return asset.trim().toUpperCase();
}

/**
 * Builds a weighted graph for one asset inside `[windowStart, windowEnd)`.
 * Invalid amounts, unparseable timestamps, blank addresses and out-of-window
 * transfers are ignored rather than aborting the analysis.
 */
export function buildTransferGraph(
  transfers: readonly TransferRecord[],
  asset: string,
  windowStart: number,
  windowEnd: number
): TransferGraph {
  const target = assetKey(asset);
  const nodes = new Set<string>();
  const edges = new Map<string, Map<string, number>>();
  let grossVolume = 0;

  for (const transfer of transfers) {
    if (assetKey(transfer.asset) !== target) continue;

    const amount = Number(transfer.amount);
    if (!Number.isFinite(amount) || amount <= 0) continue;
    if (!transfer.from || !transfer.to) continue;

    const at = timestampMs(transfer.timestamp);
    if (!Number.isFinite(at) || at < windowStart || at >= windowEnd) continue;

    nodes.add(transfer.from);
    nodes.add(transfer.to);

    let outgoing = edges.get(transfer.from);
    if (!outgoing) {
      outgoing = new Map<string, number>();
      edges.set(transfer.from, outgoing);
    }
    outgoing.set(transfer.to, (outgoing.get(transfer.to) ?? 0) + amount);
    grossVolume += amount;
  }

  return { asset: target, nodes, edges, grossVolume };
}

interface TarjanFrame {
  node: string;
  neighbors: string[];
  next: number;
}

/** Iterative Tarjan SCC so deep transfer chains cannot overflow the JS stack. */
export function findStronglyConnectedComponents(graph: TransferGraph): string[][] {
  const indices = new Map<string, number>();
  const lowLinks = new Map<string, number>();
  const onStack = new Set<string>();
  const pending: string[] = [];
  const components: string[][] = [];
  let nextIndex = 0;

  for (const start of graph.nodes) {
    if (indices.has(start)) continue;

    indices.set(start, nextIndex);
    lowLinks.set(start, nextIndex);
    nextIndex += 1;
    pending.push(start);
    onStack.add(start);

    const frames: TarjanFrame[] = [{
      node: start,
      neighbors: Array.from(graph.edges.get(start)?.keys() ?? []),
      next: 0,
    }];

    while (frames.length > 0) {
      const frame = frames[frames.length - 1];

      if (frame.next < frame.neighbors.length) {
        const neighbor = frame.neighbors[frame.next];
        frame.next += 1;
        if (!graph.nodes.has(neighbor)) continue;

        if (!indices.has(neighbor)) {
          indices.set(neighbor, nextIndex);
          lowLinks.set(neighbor, nextIndex);
          nextIndex += 1;
          pending.push(neighbor);
          onStack.add(neighbor);
          frames.push({
            node: neighbor,
            neighbors: Array.from(graph.edges.get(neighbor)?.keys() ?? []),
            next: 0,
          });
        } else if (onStack.has(neighbor)) {
          lowLinks.set(frame.node, Math.min(lowLinks.get(frame.node)!, indices.get(neighbor)!));
        }
        continue;
      }

      frames.pop();
      if (lowLinks.get(frame.node) === indices.get(frame.node)) {
        const component: string[] = [];
        let popped: string;
        do {
          popped = pending.pop()!;
          onStack.delete(popped);
          component.push(popped);
        } while (popped !== frame.node);
        components.push(component);
      }

      const parent = frames[frames.length - 1];
      if (parent) {
        lowLinks.set(parent.node, Math.min(lowLinks.get(parent.node)!, lowLinks.get(frame.node)!));
      }
    }
  }

  return components;
}

/** Pairwise reciprocity: `min(a→b, b→a) / max(a→b, b→a)`, or 0 when one way. */
export function scoreReciprocity(graph: TransferGraph): Map<string, number> {
  const scores = new Map<string, number>();
  for (const [from, outgoing] of graph.edges) {
    for (const [to, forward] of outgoing) {
      const backward = graph.edges.get(to)?.get(from) ?? 0;
      const key = `${from}|${to}`;
      if (scores.has(key)) continue;
      const max = Math.max(forward, backward);
      scores.set(key, max > 0 ? Math.min(forward, backward) / max : 0);
    }
  }
  return scores;
}

function classifyComponent(
  graph: TransferGraph,
  component: string[],
  threshold: number,
  minClusterSize: number
): WashCluster | null {
  const members = new Set(component);
  const selfLoopVolume = component.length === 1
    ? (graph.edges.get(component[0])?.get(component[0]) ?? 0)
    : 0;
  if (component.length < minClusterSize && selfLoopVolume <= 0) return null;

  const incoming = new Map<string, number>();
  const outgoing = new Map<string, number>();
  let volume = 0;

  for (const from of component) {
    for (const [to, weight] of graph.edges.get(from) ?? []) {
      if (!members.has(to)) continue;
      outgoing.set(from, (outgoing.get(from) ?? 0) + weight);
      incoming.set(to, (incoming.get(to) ?? 0) + weight);
      volume += weight;
    }
  }

  if (volume <= 0) return null;

  // The weakest node's return ratio is the share of circulating volume that
  // comes back for every participant. A 100-out/79-in node scores 0.79, so a
  // 79% return is not misclassified as a >80% wash ring.
  let returnRatio = 1;
  for (const address of component) {
    const out = outgoing.get(address) ?? 0;
    if (out <= 0) continue;
    const back = incoming.get(address) ?? 0;
    returnRatio = Math.min(returnRatio, Math.min(1, back / out));
  }

  if (returnRatio <= threshold) return null;

  const pattern: WashPattern = component.length === 1
    ? 'self'
    : component.length === 2
      ? 'ping-pong'
      : 'ring';

  return {
    addresses: [...component].sort(),
    volume,
    returnRatio,
    pattern,
  };
}

/** Extracts the wash clusters from a graph; SCCs are disjoint, so volumes do not double-count. */
export function classifyWashVolume(
  graph: TransferGraph,
  returnThresholdPct: number = DEFAULT_RETURN_THRESHOLD_PCT,
  minClusterSize: number = DEFAULT_MIN_CLUSTER_SIZE
): WashCluster[] {
  const threshold = returnThresholdPct / 100;
  return findStronglyConnectedComponents(graph)
    .map((component) => classifyComponent(graph, component, threshold, minClusterSize))
    .filter((cluster): cluster is WashCluster => cluster !== null)
    .sort((left, right) => right.volume - left.volume);
}

function analyzeWindow(
  transfers: readonly TransferRecord[],
  asset: string,
  windowMs: number,
  asOf: number,
  thresholdPct: number,
  minClusterSize: number
): WashTradingReport {
  const windowStart = asOf - windowMs;
  const graph = buildTransferGraph(transfers, asset, windowStart, asOf);
  const clusters = classifyWashVolume(graph, thresholdPct, minClusterSize);
  const washVolume = clusters.reduce((sum, cluster) => sum + cluster.volume, 0);
  const organicVolume = Math.max(0, graph.grossVolume - washVolume);

  return {
    asset: graph.asset,
    windowMs,
    windowStart,
    windowEnd: asOf,
    grossVolume: graph.grossVolume,
    washVolume,
    organicVolume,
    organicRatio: graph.grossVolume > 0 ? organicVolume / graph.grossVolume : 1,
    clusters,
  };
}

export class WashTradingDetector {
  private readonly options: WashTradingDetectorOptions;

  constructor(options: WashTradingDetectorOptions = {}) {
    this.options = options;
  }

  /** Returns one report per asset per configured rolling window. */
  detect(transfers: readonly TransferRecord[], asOf: number = Date.now()): WashTradingReport[] {
    const windows = this.options.windowMs?.length
      ? this.options.windowMs
      : DEFAULT_WINDOWS_MS;
    const thresholdPct = this.options.returnThresholdPct ?? DEFAULT_RETURN_THRESHOLD_PCT;
    const minClusterSize = this.options.minClusterSize ?? DEFAULT_MIN_CLUSTER_SIZE;
    const assets = new Set(
      transfers
        .map((transfer) => (transfer.asset ?? '').trim().toUpperCase())
        .filter((asset) => asset.length > 0)
    );

    const reports: WashTradingReport[] = [];
    for (const asset of assets) {
      for (const windowMs of windows) {
        if (!Number.isFinite(windowMs) || windowMs <= 0) continue;
        reports.push(analyzeWindow(transfers, asset, windowMs, asOf, thresholdPct, minClusterSize));
      }
    }
    return reports;
  }
}

export const washTradingDetector = new WashTradingDetector();
