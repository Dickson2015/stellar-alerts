import * as StellarSdk from 'stellar-sdk';
import { createLogger } from '../../lib/logger';

const logger = createLogger({ module: 'FeeBumpSentinel' });

const STROOPS_PER_XLM = 10_000_000;

export const FEE_BUMP_DEFAULTS = {
  /** Rolling window used for burn-rate accounting. */
  windowMs: 60 * 60 * 1000,
  /** Average fee per operation (stroops) above which surge pricing is flagged. */
  maxAvgFeePerOpStroops: 10_000,
  /** Failed inner-transaction ratio above which the sponsor is flagged. */
  maxFailedInnerRatio: 0.15,
  /** Minimum transactions in the window before the failure ratio can alert. */
  minTxForFailureRatio: 5,
  /** Minimum time between repeated alerts of the same kind for one sponsor. */
  alertCooldownMs: 10 * 60 * 1000,
} as const;

export interface FeeBumpSentinelConfig {
  windowMs: number;
  maxAvgFeePerOpStroops: number;
  maxFailedInnerRatio: number;
  minTxForFailureRatio: number;
  alertCooldownMs: number;
}

/** The two accounts and fee data extracted from a Fee-Bump (CAP-0015) envelope. */
export interface FeeBumpEnvelopeInfo {
  /** Outer account that pays the fee (the sponsor / fee-payer hot wallet). */
  feeSource: string;
  /** Source account of the wrapped inner transaction. */
  innerSource: string;
  innerTxHash: string;
  /** Operations inside the inner transaction (the fee bump itself is not counted). */
  operationCount: number;
  /** Maximum total fee the outer envelope is willing to pay, in stroops. */
  maxFeeStroops: bigint;
}

/** Subset of a Horizon transaction record the sentinel needs. */
export interface HorizonFeeBumpRecord {
  hash: string;
  successful?: boolean;
  fee_account?: string;
  fee_charged?: string | number;
  max_fee?: string | number;
  operation_count?: number;
  created_at?: string;
  fee_bump_transaction?: { hash?: string; signatures?: string[] };
  inner_transaction?: { hash?: string; max_fee?: string | number; signatures?: string[] };
  /** Not part of Horizon; the sentinel itself recovers it from `envelope_xdr`. */
  envelope_xdr?: string;
}

export interface FeeBumpObservation {
  txHash: string;
  innerTxHash: string;
  feeSource: string;
  innerSource: string;
  feeChargedStroops: bigint;
  operationCount: number;
  innerSucceeded: boolean;
  observedAt: number;
}

export type FeeBumpAlertType = 'FEE_SURGE' | 'INNER_FAILURE_RATIO';

export interface FeeBumpAlert {
  type: FeeBumpAlertType;
  severity: 'WARNING' | 'CRITICAL';
  feeSource: string;
  windowMs: number;
  /** XLM spent by this sponsor over the rolling window. */
  feeBurnXlm: number;
  avgFeePerOpStroops: number;
  failedInnerRatio: number;
  txCount: number;
  failedTxCount: number;
  txHash: string;
  summary: string;
  timestamp: string;
}

export interface SponsorStats {
  feeSource: string;
  txCount: number;
  failedTxCount: number;
  operationCount: number;
  feeBurnStroops: bigint;
  feeBurnXlm: number;
  avgFeePerOpStroops: number;
  failedInnerRatio: number;
}

export type FeeBumpAlertHandler = (alert: FeeBumpAlert) => void | Promise<void>;

function toBigInt(value: string | number | undefined, fallback = 0n): bigint {
  if (value === undefined || value === null || value === '') return fallback;
  try {
    return BigInt(value);
  } catch {
    return fallback;
  }
}

/**
 * Unwraps a base64 transaction envelope. Returns null when the envelope is not
 * a Fee-Bump transaction or cannot be decoded, so callers can pass any envelope.
 */
export function extractFeeBumpEnvelope(
  envelopeXdr: string,
  networkPassphrase: string,
): FeeBumpEnvelopeInfo | null {
  let parsed: ReturnType<typeof StellarSdk.TransactionBuilder.fromXDR>;
  try {
    parsed = StellarSdk.TransactionBuilder.fromXDR(envelopeXdr, networkPassphrase);
  } catch {
    return null;
  }
  if (!('innerTransaction' in parsed)) return null;

  const inner = parsed.innerTransaction;
  return {
    feeSource: parsed.feeSource,
    innerSource: inner.source,
    innerTxHash: inner.hash().toString('hex'),
    operationCount: inner.operations.length,
    maxFeeStroops: toBigInt(parsed.fee),
  };
}

export class FeeBumpSentinel {
  private readonly config: FeeBumpSentinelConfig;
  private readonly observations = new Map<string, FeeBumpObservation[]>();
  private readonly lastAlertAt = new Map<string, number>();
  private readonly handlers = new Set<FeeBumpAlertHandler>();
  private readonly now: () => number;

  constructor(config: Partial<FeeBumpSentinelConfig> = {}, now: () => number = Date.now) {
    this.config = { ...FEE_BUMP_DEFAULTS, ...config };
    this.now = now;
  }

  public subscribe(handler: FeeBumpAlertHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  public clear(): void {
    this.observations.clear();
    this.lastAlertAt.clear();
    this.handlers.clear();
  }

  /**
   * Turns a Horizon transaction record into an observation. Returns null for
   * ordinary (non fee-bump) transactions. Accounts come from the Horizon fields
   * when present and otherwise from the unwrapped envelope XDR.
   */
  public observationFromHorizon(
    record: HorizonFeeBumpRecord,
    networkPassphrase: string,
  ): FeeBumpObservation | null {
    const envelope = record.envelope_xdr
      ? extractFeeBumpEnvelope(record.envelope_xdr, networkPassphrase)
      : null;
    const isFeeBump = Boolean(record.fee_bump_transaction || record.inner_transaction || envelope);
    if (!isFeeBump) return null;

    const feeSource = record.fee_account ?? envelope?.feeSource;
    if (!feeSource) return null;

    const operationCount = envelope?.operationCount ?? record.operation_count ?? 0;
    const charged = toBigInt(record.fee_charged, envelope?.maxFeeStroops ?? toBigInt(record.max_fee));

    return {
      txHash: record.hash,
      innerTxHash: record.inner_transaction?.hash ?? envelope?.innerTxHash ?? '',
      feeSource,
      innerSource: envelope?.innerSource ?? '',
      feeChargedStroops: charged,
      operationCount,
      innerSucceeded: record.successful !== false,
      observedAt: record.created_at ? Date.parse(record.created_at) || this.now() : this.now(),
    };
  }

  /** Records one fee-bump transaction and returns any alerts it triggers. */
  public record(observation: FeeBumpObservation): FeeBumpAlert[] {
    const list = this.observations.get(observation.feeSource) ?? [];
    list.push(observation);
    this.observations.set(observation.feeSource, list);

    const stats = this.getStats(observation.feeSource);
    const alerts: FeeBumpAlert[] = [];

    if (stats.avgFeePerOpStroops > this.config.maxAvgFeePerOpStroops) {
      alerts.push(
        this.buildAlert('FEE_SURGE', 'CRITICAL', stats, observation.txHash,
          `Fee sponsor ${stats.feeSource} is paying ${Math.round(stats.avgFeePerOpStroops)} stroops/op ` +
            `(limit ${this.config.maxAvgFeePerOpStroops}); ${stats.feeBurnXlm.toFixed(4)} XLM burned in the last hour.`),
      );
    }

    if (
      stats.txCount >= this.config.minTxForFailureRatio &&
      stats.failedInnerRatio > this.config.maxFailedInnerRatio
    ) {
      alerts.push(
        this.buildAlert('INNER_FAILURE_RATIO', 'WARNING', stats, observation.txHash,
          `${(stats.failedInnerRatio * 100).toFixed(1)}% of inner transactions sponsored by ${stats.feeSource} ` +
            `failed in the last hour (limit ${(this.config.maxFailedInnerRatio * 100).toFixed(0)}%); ` +
            `${stats.feeBurnXlm.toFixed(4)} XLM burned.`),
      );
    }

    const emitted = alerts.filter((alert) => this.passesCooldown(alert));
    for (const alert of emitted) this.dispatch(alert);
    return emitted;
  }

  /** Convenience wrapper for the watcher: decode, record and alert in one call. */
  public inspectHorizonTransaction(
    record: HorizonFeeBumpRecord,
    networkPassphrase: string,
  ): FeeBumpAlert[] {
    const observation = this.observationFromHorizon(record, networkPassphrase);
    return observation ? this.record(observation) : [];
  }

  /** Rolling-window statistics for one fee sponsor. */
  public getStats(feeSource: string): SponsorStats {
    const cutoff = this.now() - this.config.windowMs;
    const live = (this.observations.get(feeSource) ?? []).filter((o) => o.observedAt >= cutoff);
    if (live.length > 0) this.observations.set(feeSource, live);
    else this.observations.delete(feeSource);

    let feeBurnStroops = 0n;
    let operationCount = 0;
    let failedTxCount = 0;
    for (const o of live) {
      feeBurnStroops += o.feeChargedStroops;
      operationCount += o.operationCount;
      if (!o.innerSucceeded) failedTxCount++;
    }

    return {
      feeSource,
      txCount: live.length,
      failedTxCount,
      operationCount,
      feeBurnStroops,
      feeBurnXlm: Number(feeBurnStroops) / STROOPS_PER_XLM,
      avgFeePerOpStroops: operationCount > 0 ? Number(feeBurnStroops) / operationCount : 0,
      failedInnerRatio: live.length > 0 ? failedTxCount / live.length : 0,
    };
  }

  private buildAlert(
    type: FeeBumpAlertType,
    severity: FeeBumpAlert['severity'],
    stats: SponsorStats,
    txHash: string,
    summary: string,
  ): FeeBumpAlert {
    return {
      type,
      severity,
      feeSource: stats.feeSource,
      windowMs: this.config.windowMs,
      feeBurnXlm: stats.feeBurnXlm,
      avgFeePerOpStroops: stats.avgFeePerOpStroops,
      failedInnerRatio: stats.failedInnerRatio,
      txCount: stats.txCount,
      failedTxCount: stats.failedTxCount,
      txHash,
      summary,
      timestamp: new Date(this.now()).toISOString(),
    };
  }

  private passesCooldown(alert: FeeBumpAlert): boolean {
    const key = `${alert.feeSource}:${alert.type}`;
    const last = this.lastAlertAt.get(key);
    const now = this.now();
    if (last !== undefined && now - last < this.config.alertCooldownMs) return false;
    this.lastAlertAt.set(key, now);
    return true;
  }

  private dispatch(alert: FeeBumpAlert): void {
    for (const handler of this.handlers) {
      Promise.resolve()
        .then(() => handler(alert))
        .catch((err: unknown) => {
          logger.warn(
            { feeSource: alert.feeSource, err: err instanceof Error ? err.message : String(err) },
            'Fee-bump alert handler failed',
          );
        });
    }
  }
}

export const feeBumpSentinel = new FeeBumpSentinel();
