import {
  AML_CRITICAL_RISK_THRESHOLD,
  AML_MAX_HOPS,
  amlRiskLevelFromScore,
  type AmlPaymentInput,
  type AmlRiskAssessment,
  type AmlRiskCategory,
  type AmlRiskMatch,
  type AmlTransactionEdge,
  type FlaggedAddress,
} from '@stellar-alerts/shared';

/**
 * Heuristic AML risk scorer for incoming payments (#928).
 *
 * The scorer holds a *local* list of sanctioned / exploiter / mixer addresses
 * (no third-party network call is made at evaluation time) and propagates
 * taint backwards through a directed transaction graph, up to
 * `AML_MAX_HOPS` hops. A direct match scores highest; each hop decays the
 * contribution so an indirect link is still actionable but lower-confidence.
 *
 * The class is intentionally free of database imports: callers supply the
 * graph (in unit tests, a fixture; in the watcher, a loader that reads recent
 * payments). That keeps the scoring algorithm pure and testable while still
 * letting a worker plug in its own persistence.
 */

const HOP_BASE_SCORE: Readonly<Record<number, number>> = {
  0: 100,
  1: 85,
  2: 65,
};

/** Default severity multiplier per category when none is supplied. */
const CATEGORY_SEVERITY: Readonly<Record<AmlRiskCategory, number>> = {
  sanctioned: 1,
  mixer: 0.9,
  darknet: 0.9,
  exploiter: 0.85,
  other: 0.7,
};

export interface AmlRiskScorerOptions {
  /** Pre-populated local flagged-address list. */
  flaggedAddresses?: FlaggedAddress[];
  /** Critical-escalation threshold; defaults to the shared 70. */
  criticalThreshold?: number;
  /**
   * Upper bound on hop-1 addresses whose incoming edges are fetched by
   * {@link AmlRiskScorer.evaluateWithEdgeLoader}. A busy wallet can have
   * thousands of distinct senders; without a cap a single evaluation would
   * fan out into an unbounded number of database queries.
   */
  maxSecondHopLookups?: number;
  /** Injectable clock used for deterministic tests. */
  now?: () => number;
}

const DEFAULT_MAX_SECOND_HOP_LOOKUPS = 25;

export interface AmlRiskScorerStats {
  flaggedAddresses: number;
  evaluations: number;
  criticalHits: number;
}

interface CompiledFlag {
  address: string;
  category: AmlRiskCategory;
  label?: string;
  severity: number;
}

function normalizeAddress(address: string): string {
  return address.trim();
}

function clampScore(score: number): number {
  return Math.round(Math.min(100, Math.max(0, score)) * 100) / 100;
}

function clampSeverity(severity: number): number {
  if (!Number.isFinite(severity)) return 0;
  return Math.min(1, Math.max(0, severity));
}

export class AmlRiskScorer {
  private readonly flagged = new Map<string, CompiledFlag>();
  private readonly criticalThreshold: number;
  private readonly maxSecondHopLookups: number;
  private evaluations = 0;
  private criticalHits = 0;

  constructor(options: AmlRiskScorerOptions = {}) {
    this.criticalThreshold = options.criticalThreshold ?? AML_CRITICAL_RISK_THRESHOLD;
    this.maxSecondHopLookups =
      options.maxSecondHopLookups ?? DEFAULT_MAX_SECOND_HOP_LOOKUPS;
    if (options.flaggedAddresses) {
      this.registerFlaggedAddresses(options.flaggedAddresses);
    }
  }

  /** Adds or replaces a flagged address in the local database. */
  registerFlaggedAddress(entry: FlaggedAddress): CompiledFlag {
    const address = normalizeAddress(entry.address);
    if (!address) {
      throw new Error('Flagged address must not be empty');
    }

    const compiled: CompiledFlag = {
      address,
      category: entry.category,
      label: entry.label,
      severity: clampSeverity(entry.severity ?? CATEGORY_SEVERITY[entry.category]),
    };
    this.flagged.set(address, compiled);
    return compiled;
  }

  registerFlaggedAddresses(entries: FlaggedAddress[]): void {
    for (const entry of entries) {
      this.registerFlaggedAddress(entry);
    }
  }

  removeFlaggedAddress(address: string): boolean {
    return this.flagged.delete(normalizeAddress(address));
  }

  isFlagged(address: string): boolean {
    return this.flagged.has(normalizeAddress(address));
  }

  getFlaggedAddress(address: string): FlaggedAddress | undefined {
    return this.flagged.get(normalizeAddress(address));
  }

  listFlaggedAddresses(): FlaggedAddress[] {
    return [...this.flagged.values()].map((entry) => ({ ...entry }));
  }

  hasFlaggedAddresses(): boolean {
    return this.flagged.size > 0;
  }

  getStats(): AmlRiskScorerStats {
    return {
      flaggedAddresses: this.flagged.size,
      evaluations: this.evaluations,
      criticalHits: this.criticalHits,
    };
  }

  /**
   * Scores `address` against the local flagged list by walking the
   * transaction graph backwards from it (i.e. following edges whose `to` is
   * the address under evaluation).
   */
  evaluateAddress(
    address: string,
    graph: AmlTransactionEdge[] = [],
  ): AmlRiskAssessment {
    const target = normalizeAddress(address);
    this.evaluations += 1;

    if (!target) {
      return this.emptyAssessment(target);
    }

    const direct = this.flagged.get(target);
    if (direct) {
      return this.assembleAssessment(target, [
        {
          address: direct.address,
          category: direct.category,
          label: direct.label,
          hops: 0,
          contribution: clampScore(HOP_BASE_SCORE[0] * direct.severity),
        },
      ]);
    }

    const matches = this.findPropagatedMatches(target, graph);
    return matches.length > 0
      ? this.assembleAssessment(target, matches)
      : this.emptyAssessment(target);
  }

  /** Convenience wrapper for incoming payments: scores the sender. */
  evaluateIncomingPayment(
    payment: Pick<AmlPaymentInput, 'fromAddress' | 'txHash'>,
    graph: AmlTransactionEdge[] = [],
  ): AmlRiskAssessment {
    return this.evaluateAddress(payment.fromAddress, graph);
  }

  /**
   * Scores an address using a caller-supplied loader, fetching the target's
   * incoming edges and then the incoming edges of the strongest hop-1 senders.
   * I/O is skipped entirely when the flagged-address list is empty or the
   * target is a direct match, and the hop-1 fan-out is capped by
   * `maxSecondHopLookups` (25 by default).
   */
  async evaluateWithEdgeLoader(
    address: string,
    loadIncomingEdges: (address: string) => Promise<AmlTransactionEdge[]>,
  ): Promise<AmlRiskAssessment> {
    const target = normalizeAddress(address);
    if (!target || this.flagged.size === 0) {
      this.evaluations += 1;
      return this.emptyAssessment(target);
    }

    if (this.flagged.has(target)) {
      return this.evaluateAddress(target, []);
    }

    const edges: AmlTransactionEdge[] = [];
    const firstHop = await loadIncomingEdges(target);
    edges.push(...firstHop);

    // Keep the strongest-looking first-hop senders first, then cap the fan-out
    // so a single evaluation stays within a bounded number of queries.
    const secondHopWeights = new Map<string, number>();
    for (const edge of firstHop) {
      const source = normalizeAddress(edge.from);
      if (!source || this.flagged.has(source)) continue;
      const weight = edge.weight ?? 1;
      const current = secondHopWeights.get(source) ?? 0;
      if (weight > current) secondHopWeights.set(source, weight);
    }

    const secondHopSources = [...secondHopWeights.entries()]
      .sort((left, right) => right[1] - left[1])
      .slice(0, this.maxSecondHopLookups)
      .map(([source]) => source);

    const fetched = await Promise.all(
      secondHopSources.map((source) => loadIncomingEdges(source)),
    );
    for (const list of fetched) {
      edges.push(...list);
    }

    return this.evaluateAddress(target, edges);
  }

  buildGraphFromPayments(
    payments: Array<{ fromAddress: string; toAddress: string; weight?: number }>,
  ): AmlTransactionEdge[] {
    return payments.map((payment) => ({
      from: payment.fromAddress,
      to: payment.toAddress,
      ...(payment.weight !== undefined ? { weight: payment.weight } : {}),
    }));
  }

  /**
   * True when the assessment's score crosses *this scorer's* threshold. A
   * custom `criticalThreshold` is authoritative — the shared default constant
   * must not override a stricter or looser instance configuration.
   */
  shouldTriggerCritical(
    assessment: AmlRiskAssessment | number,
  ): boolean {
    const score = typeof assessment === 'number' ? assessment : assessment.score;
    return score > this.criticalThreshold;
  }

  /**
   * Walks incoming edges backwards from `target` (up to `AML_MAX_HOPS`) and
   * returns one match per flagged address, keeping the highest contributing
   * path when several routes reach the same address.
   *
   * A node is expanded at most once. Edge weights are in (0, 1], so the first
   * (shortest) arrival is always at least as strong as a longer route; this
   * also makes cycles (`A -> B -> A`) terminate without repeated work.
   */
  private findPropagatedMatches(
    target: string,
    graph: AmlTransactionEdge[],
  ): AmlRiskMatch[] {
    if (graph.length === 0) return [];

    const incoming = new Map<string, AmlTransactionEdge[]>();
    for (const edge of graph) {
      const to = normalizeAddress(edge.to);
      const from = normalizeAddress(edge.from);
      if (!to || !from) continue;
      const list = incoming.get(to) ?? [];
      list.push({ ...edge, from, to });
      incoming.set(to, list);
    }

    let frontier = new Map<string, number>([[target, 1]]);
    const expanded = new Set<string>([target]);
    const best = new Map<string, AmlRiskMatch>();

    for (let hop = 1; hop <= AML_MAX_HOPS; hop += 1) {
      const next = new Map<string, number>();

      for (const [node, pathWeight] of frontier) {
        for (const edge of incoming.get(node) ?? []) {
          if (edge.from === target) continue;

          const weight = pathWeight * (edge.weight ?? 1);
          if (weight <= 0) continue;

          const flagged = this.flagged.get(edge.from);
          if (flagged) {
            const contribution = clampScore(
              HOP_BASE_SCORE[hop] * flagged.severity * weight,
            );
            const existing = best.get(flagged.address);
            if (!existing || contribution > existing.contribution) {
              best.set(flagged.address, {
                address: flagged.address,
                category: flagged.category,
                label: flagged.label,
                hops: hop,
                contribution,
              });
            }
          }

          if (!expanded.has(edge.from)) {
            const currentWeight = next.get(edge.from) ?? 0;
            if (weight > currentWeight) {
              next.set(edge.from, weight);
            }
          }
        }
      }

      for (const node of next.keys()) {
        expanded.add(node);
      }
      frontier = next;
      if (frontier.size === 0) break;
    }

    return [...best.values()].sort(
      (left, right) =>
        right.contribution - left.contribution || left.hops - right.hops,
    );
  }

  private emptyAssessment(address: string): AmlRiskAssessment {
    return {
      address,
      score: 0,
      level: amlRiskLevelFromScore(0),
      hops: null,
      matches: [],
    };
  }

  private assembleAssessment(
    address: string,
    matches: AmlRiskMatch[],
  ): AmlRiskAssessment {
    const score = clampScore(Math.max(...matches.map((match) => match.contribution), 0));
    const assessment: AmlRiskAssessment = {
      address,
      score,
      level: amlRiskLevelFromScore(score),
      hops: matches.length > 0 ? Math.min(...matches.map((match) => match.hops)) : null,
      matches,
    };

    if (this.shouldTriggerCritical(assessment)) {
      this.criticalHits += 1;
    }
    return assessment;
  }
}

function splitAddressList(value: string | undefined): string[] {
  if (!value) return [];
  return value
    .split(',')
    .map((address) => address.trim())
    .filter(Boolean);
}

function parseFlaggedAddressEnv(
  env: NodeJS.ProcessEnv,
): FlaggedAddress[] {
  const entries: FlaggedAddress[] = [];

  for (const address of splitAddressList(env.AML_SANCTIONED_ADDRESSES)) {
    entries.push({ address, category: 'sanctioned' });
  }
  for (const address of splitAddressList(env.AML_EXPLOITER_ADDRESSES)) {
    entries.push({ address, category: 'exploiter' });
  }
  for (const address of splitAddressList(env.AML_MIXER_ADDRESSES)) {
    entries.push({ address, category: 'mixer' });
  }

  if (env.AML_FLAGGED_ADDRESSES) {
    try {
      const parsed: unknown = JSON.parse(env.AML_FLAGGED_ADDRESSES);
      if (Array.isArray(parsed)) {
        for (const entry of parsed) {
          if (
            entry &&
            typeof entry === 'object' &&
            typeof (entry as { address?: unknown }).address === 'string' &&
            typeof (entry as { category?: unknown }).category === 'string'
          ) {
            const candidate = entry as {
              address: string;
              category: AmlRiskCategory;
              label?: string;
              severity?: number;
            };
            if (
              ['sanctioned', 'exploiter', 'mixer', 'darknet', 'other'].includes(
                candidate.category,
              )
            ) {
              entries.push({
                address: candidate.address,
                category: candidate.category,
                label: candidate.label,
                severity: candidate.severity,
              });
            }
          }
        }
      }
    } catch {
      // A malformed AML_FLAGGED_ADDRESSES must not stop the worker from
      // booting; the comma-separated lists above remain active.
    }
  }

  return entries;
}

/** Builds a scorer seeded from the local flagged-address environment config. */
export function createAmlRiskScorerFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): AmlRiskScorer {
  return new AmlRiskScorer({ flaggedAddresses: parseFlaggedAddressEnv(env) });
}

/** Process-wide scorer used by the watcher worker. */
export const amlRiskScorer = createAmlRiskScorerFromEnv();
