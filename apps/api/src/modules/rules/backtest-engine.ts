import {
  compileAlertRule,
  matchesAlertRule,
  type AlertRuleRecord,
  type NormalizedPaymentEvent,
} from '../../lib/alert-rule-evaluator';
import { ValidationError } from '../../lib/errors';

/**
 * Deterministic historical replay ("time-travel") engine for draft alert rules.
 *
 * The engine is a pure, in-memory evaluator: it only depends on the pure rule
 * matcher in `lib/alert-rule-evaluator` and on an injected read-only
 * {@link BacktestPaymentSource}. It deliberately imports nothing that can
 * enqueue webhooks, emails, Telegram/Slack messages, outbox rows or
 * dead-letters, so a replay cannot produce external side effects.
 */

/** A historical payment, optionally tagged with the ledger it closed in. */
export interface HistoricalPayment extends NormalizedPaymentEvent {
  ledger?: number;
}

/** Inclusive range to replay. Provide a ledger range, a time range, or both. */
export interface BacktestRange {
  startLedger?: number;
  endLedger?: number;
  from?: Date;
  to?: Date;
}

/** Read-only source of historical payments, ordered by (receivedAt, paymentId). */
export interface BacktestPaymentSource {
  stream(range: BacktestRange, scope: BacktestScope): AsyncIterable<HistoricalPayment>;
}

export interface BacktestScope {
  userId: string;
  walletId?: string | null;
}

/** Candidate rule; identity fields are assigned by the engine. */
export type CandidateRule = Omit<AlertRuleRecord, 'id' | 'userId' | 'isActive' | 'walletId'> & {
  walletId?: string | null;
};

export interface BacktestOptions {
  /** Max number of matched transactions returned in the report. Default 10. */
  sampleSize?: number;
  /** Hard cap on events scanned; the run aborts with a ValidationError beyond it. */
  maxEvents?: number;
  /**
   * Optional ground-truth labeller. When provided, matches for which it returns
   * `false` are counted as false positives and precision/recall are reported.
   */
  isExpectedMatch?: (payment: HistoricalPayment) => boolean;
}

export interface BacktestSampleMatch {
  paymentId: string;
  txHash: string;
  walletId: string;
  asset: string;
  amount: string;
  fromAddress: string;
  memo: string | null;
  receivedAt: string;
  ledger: number | null;
}

export interface BacktestAccuracy {
  truePositives: number;
  falsePositives: number;
  falseNegatives: number;
  /** TP / (TP + FP); null when nothing matched. */
  precision: number | null;
  /** FP / (TP + FP); null when nothing matched. */
  falsePositiveRate: number | null;
  /** TP / (TP + FN); null when there are no expected matches. */
  recall: number | null;
}

export interface BacktestReport {
  /** Always true: a replay never dispatches notifications. */
  dryRun: true;
  range: {
    startLedger: number | null;
    endLedger: number | null;
    from: string | null;
    to: string | null;
  };
  totalEvaluated: number;
  totalMatches: number;
  /** totalMatches / totalEvaluated, 0 when nothing was evaluated. */
  matchRate: number;
  /** Events whose evaluation threw; they are never counted as matches. */
  evaluationErrors: number;
  /** Matches per day over the observed span (min. 1 day). */
  averageMatchesPerDay: number;
  sampleMatches: BacktestSampleMatch[];
  /** Matches bucketed by UTC hour of day; index 0 = 00:00-00:59. Always 24 entries. */
  hourlyDistribution: number[];
  peakHour: { hour: number; count: number } | null;
  accuracy: BacktestAccuracy | null;
}

export const BACKTEST_DEFAULT_SAMPLE_SIZE = 10;
export const BACKTEST_MAX_SAMPLE_SIZE = 100;
export const BACKTEST_DEFAULT_MAX_EVENTS = 250_000;

const DAY_MS = 86_400_000;
const DRAFT_RULE_ID = 'backtest-draft';

export class BacktestReplayEngine {
  constructor(private readonly source: BacktestPaymentSource) {}

  async run(
    candidate: CandidateRule,
    range: BacktestRange,
    scope: BacktestScope,
    options: BacktestOptions = {},
  ): Promise<BacktestReport> {
    validateRange(range);

    const sampleSize = Math.min(
      Math.max(0, Math.floor(options.sampleSize ?? BACKTEST_DEFAULT_SAMPLE_SIZE)),
      BACKTEST_MAX_SAMPLE_SIZE,
    );
    const maxEvents = options.maxEvents ?? BACKTEST_DEFAULT_MAX_EVENTS;

    // Always evaluate as an active, throwaway rule so `isActive: false` drafts
    // can still be backtested. It is never persisted.
    const rule = compileAlertRule({
      ...candidate,
      id: DRAFT_RULE_ID,
      userId: scope.userId,
      walletId: candidate.walletId ?? null,
      isActive: true,
    });

    const hourly = new Array<number>(24).fill(0);
    const samples: BacktestSampleMatch[] = [];
    let evaluated = 0;
    let matches = 0;
    let errors = 0;
    let truePositives = 0;
    let falsePositives = 0;
    let falseNegatives = 0;
    let firstAt: number | null = null;
    let lastAt: number | null = null;

    for await (const payment of this.source.stream(range, scope)) {
      evaluated += 1;
      if (evaluated > maxEvents) {
        throw new ValidationError(
          `Backtest range exceeds ${maxEvents} events; narrow the ledger or date range`,
          { maxEvents },
          'BACKTEST_RANGE_TOO_LARGE',
        );
      }

      const at = Date.parse(payment.receivedAt);
      if (!Number.isNaN(at)) {
        firstAt = firstAt === null ? at : Math.min(firstAt, at);
        lastAt = lastAt === null ? at : Math.max(lastAt, at);
      }

      let matched = false;
      try {
        matched = matchesAlertRule(rule, payment);
      } catch {
        errors += 1;
      }

      const expected = options.isExpectedMatch?.(payment);
      if (expected !== undefined) {
        if (matched && expected) truePositives += 1;
        else if (matched && !expected) falsePositives += 1;
        else if (!matched && expected) falseNegatives += 1;
      }

      if (!matched) continue;
      matches += 1;

      if (!Number.isNaN(at)) hourly[new Date(at).getUTCHours()] += 1;
      if (samples.length < sampleSize) samples.push(toSample(payment));
    }

    const spanDays =
      firstAt !== null && lastAt !== null ? Math.max(1, (lastAt - firstAt) / DAY_MS) : 1;

    let peakHour: BacktestReport['peakHour'] = null;
    if (matches > 0) {
      const hour = hourly.indexOf(Math.max(...hourly));
      peakHour = { hour, count: hourly[hour] };
    }

    return {
      dryRun: true,
      range: {
        startLedger: range.startLedger ?? null,
        endLedger: range.endLedger ?? null,
        from: range.from?.toISOString() ?? null,
        to: range.to?.toISOString() ?? null,
      },
      totalEvaluated: evaluated,
      totalMatches: matches,
      matchRate: evaluated === 0 ? 0 : round(matches / evaluated),
      evaluationErrors: errors,
      averageMatchesPerDay: round(matches / spanDays),
      sampleMatches: samples,
      hourlyDistribution: hourly,
      peakHour,
      accuracy: options.isExpectedMatch
        ? buildAccuracy(truePositives, falsePositives, falseNegatives)
        : null,
    };
  }
}

function validateRange(range: BacktestRange): void {
  const { startLedger, endLedger, from, to } = range;
  const hasLedger = startLedger !== undefined || endLedger !== undefined;
  const hasTime = from !== undefined || to !== undefined;

  if (!hasLedger && !hasTime) {
    throw new ValidationError('A ledger range (startLedger/endLedger) or date range (from/to) is required');
  }
  for (const [name, value] of [['startLedger', startLedger], ['endLedger', endLedger]] as const) {
    if (value !== undefined && (!Number.isInteger(value) || value < 0)) {
      throw new ValidationError(`${name} must be a non-negative integer`);
    }
  }
  if (startLedger !== undefined && endLedger !== undefined && startLedger > endLedger) {
    throw new ValidationError('startLedger must be <= endLedger');
  }
  for (const [name, value] of [['from', from], ['to', to]] as const) {
    if (value !== undefined && Number.isNaN(value.getTime())) {
      throw new ValidationError(`${name} must be a valid date`);
    }
  }
  if (from && to && from.getTime() > to.getTime()) {
    throw new ValidationError('from must be <= to');
  }
}

function toSample(p: HistoricalPayment): BacktestSampleMatch {
  return {
    paymentId: p.paymentId,
    txHash: p.txHash,
    walletId: p.walletId,
    asset: p.asset,
    amount: String(p.amount),
    fromAddress: p.fromAddress,
    memo: p.memo ?? null,
    receivedAt: p.receivedAt,
    ledger: p.ledger ?? null,
  };
}

function buildAccuracy(tp: number, fp: number, fn: number): BacktestAccuracy {
  const matched = tp + fp;
  const expected = tp + fn;
  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    precision: matched === 0 ? null : round(tp / matched),
    falsePositiveRate: matched === 0 ? null : round(fp / matched),
    recall: expected === 0 ? null : round(tp / expected),
  };
}

function round(n: number): number {
  return Math.round(n * 10_000) / 10_000;
}
