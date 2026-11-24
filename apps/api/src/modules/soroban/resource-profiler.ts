import { Address, scValToNative, xdr } from 'stellar-sdk';
import { prisma } from '../../lib/prisma';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from '../stellar/alert-delivery';

/**
 * Soroban resource saturation profiler (#972).
 *
 * Decodes the real `TransactionMetaV3` of an invocation, reads the metered
 * CPU / memory / ledger read / ledger write consumption from its
 * `core_metrics` diagnostic events, and compares each against the network's
 * per-transaction maximums. Crossing 80% warns the contract owner before the
 * transaction starts failing with `ResourceLimitExceeded`.
 *
 * Unlike the generic usage sentinel (#720) this reads the actual XDR, covers
 * ledger read/write bytes, and tracks each contract function over time.
 */

const log = createLogger({ module: 'ResourceSaturationProfiler' });

export const RESOURCE_METRICS = ['cpuInstructions', 'memoryBytes', 'readBytes', 'writeBytes'] as const;
export type ResourceMetric = (typeof RESOURCE_METRICS)[number];

export type ResourceUsage = Record<ResourceMetric, number>;
export type SorobanNetworkLimits = Record<ResourceMetric, number>;

/**
 * Per-transaction maximums from the Soroban network config settings
 * (CONFIG_SETTING_CONTRACT_COMPUTE_V0 / LEDGER_COST_V0). These are the pubnet
 * values; pass `limits` or a `limitsProvider` when the network is re-tuned.
 */
export const DEFAULT_SOROBAN_LIMITS: SorobanNetworkLimits = {
  cpuInstructions: 100_000_000,
  memoryBytes: 41_943_040,
  readBytes: 200_000,
  writeBytes: 132_096,
};

export const RESOURCE_SATURATION_DEFAULTS = {
  /** Fraction of a network maximum at which a warning fires. */
  threshold: 0.8,
  /** Fraction at which the alert becomes critical. */
  criticalThreshold: 0.95,
  alertCooldownMs: 10 * 60 * 1000,
  /** Invocations remembered per contract function for trend analysis. */
  historySize: 20,
} as const;

/** Diagnostic `core_metrics` names (stellar-core / soroban-env-host) mapped to our metrics. */
const CORE_METRIC_NAMES: Record<string, ResourceMetric> = {
  cpu_insn: 'cpuInstructions',
  mem_byte: 'memoryBytes',
  ledger_read_byte: 'readBytes',
  ledger_write_byte: 'writeBytes',
};

export interface InvocationTarget {
  contractId: string;
  functionName: string;
}

export type UsageSource = 'metered' | 'declared';

export interface ExtractedUsage {
  usage: ResourceUsage;
  /** `declared` means diagnostics were absent and the signer's reserved resources were used. */
  source: UsageSource;
}

export interface ProfileInput {
  txHash: string;
  ledgerSeq?: number;
  /** Base64 `TransactionMeta` XDR. */
  resultMetaXdr?: string | null;
  /** Base64 `TransactionEnvelope` XDR; used to name the contract/function and as a declared-resource fallback. */
  envelopeXdr?: string | null;
  /** Overrides what is decoded from the envelope. */
  contractId?: string;
  functionName?: string;
  /** Already-decoded usage (e.g. from simulation); skips XDR decoding. */
  usage?: Partial<ResourceUsage>;
}

export type SaturationSeverity = 'WARNING' | 'CRITICAL';

export interface ResourceSaturationReport {
  txHash: string;
  ledgerSeq?: number;
  contractId: string | null;
  functionName: string | null;
  source: UsageSource;
  usage: ResourceUsage;
  limits: SorobanNetworkLimits;
  /** Utilization of each network maximum, in percent. */
  utilizationPct: Record<ResourceMetric, number>;
  /** Metrics at or above the warning threshold. */
  saturated: ResourceMetric[];
  worst: { metric: ResourceMetric; pct: number };
  severity: SaturationSeverity | null;
  /** True when this function's peak utilization has been climbing across recent invocations. */
  trendingUp: boolean;
  summary: string;
  timestamp: string;
}

export interface FunctionStats {
  key: string;
  invocations: number;
  peak: ResourceUsage;
  peakUtilizationPct: Record<ResourceMetric, number>;
  trendingUp: boolean;
}

export interface ResourceProfilerConfig {
  threshold: number;
  criticalThreshold: number;
  alertCooldownMs: number;
  historySize: number;
  limits: SorobanNetworkLimits;
}

export type SaturationHandler = (report: ResourceSaturationReport) => Promise<void> | void;
export type LimitsProvider = () => Promise<Partial<SorobanNetworkLimits> | null | undefined>;

const emptyUsage = (): ResourceUsage => ({ cpuInstructions: 0, memoryBytes: 0, readBytes: 0, writeBytes: 0 });

function toSafeNumber(value: unknown): number | null {
  if (typeof value === 'bigint') return Number(value);
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  return null;
}

// ── XDR extraction ──────────────────────────────────────────────────────────

/**
 * Reads CPU / memory / ledger read / ledger write consumption from the
 * `core_metrics` diagnostic events of a TransactionMetaV3. Returns null when
 * the meta is not a Soroban v3 meta or carries no core metrics.
 */
export function extractUsageFromMeta(resultMetaXdr: string | Buffer): ResourceUsage | null {
  let meta: xdr.TransactionMeta;
  try {
    meta = Buffer.isBuffer(resultMetaXdr)
      ? xdr.TransactionMeta.fromXDR(resultMetaXdr)
      : xdr.TransactionMeta.fromXDR(resultMetaXdr, 'base64');
  } catch {
    return null;
  }
  if (meta.switch() !== 3) return null;

  const sorobanMeta = meta.v3().sorobanMeta();
  if (!sorobanMeta) return null;

  const usage = emptyUsage();
  let found = false;

  for (const diagnostic of sorobanMeta.diagnosticEvents()) {
    const body = diagnostic.event().body();
    if (body.switch() !== 0) continue;
    const v0 = body.v0();
    const topics = v0.topics();
    if (topics.length < 2) continue;

    let group: unknown;
    let name: unknown;
    try {
      group = scValToNative(topics[0]);
      name = scValToNative(topics[1]);
    } catch {
      continue;
    }
    if (group !== 'core_metrics' || typeof name !== 'string') continue;

    const metric = CORE_METRIC_NAMES[name];
    if (!metric) continue;
    let value: number | null = null;
    try {
      value = toSafeNumber(scValToNative(v0.data()));
    } catch {
      value = null;
    }
    if (value === null || value < 0) continue;
    // Metrics may be emitted once per host-function call; the transaction total is the sum.
    usage[metric] += value;
    found = true;
  }

  return found ? usage : null;
}

function innerTransaction(envelope: xdr.TransactionEnvelope): xdr.Transaction | null {
  switch (envelope.switch().value) {
    case 2:
      return envelope.v1().tx();
    case 5:
      return envelope.feeBump().tx().innerTx().v1().tx();
    default:
      return null;
  }
}

function decodeEnvelope(envelopeXdr: string): xdr.Transaction | null {
  try {
    return innerTransaction(xdr.TransactionEnvelope.fromXDR(envelopeXdr, 'base64'));
  } catch {
    return null;
  }
}

/** Contract and function being invoked by the envelope's first `invokeHostFunction` operation. */
export function extractInvocationTarget(envelopeXdr: string): InvocationTarget | null {
  const tx = decodeEnvelope(envelopeXdr);
  if (!tx) return null;
  try {
    for (const op of tx.operations()) {
      const body = op.body();
      if (body.switch().name !== 'invokeHostFunction') continue;
      const hostFunction = body.invokeHostFunctionOp().hostFunction();
      if (hostFunction.switch().name !== 'hostFunctionTypeInvokeContract') continue;
      const invoke = hostFunction.invokeContract();
      return {
        contractId: Address.fromScAddress(invoke.contractAddress()).toString(),
        functionName: invoke.functionName().toString(),
      };
    }
  } catch {
    return null;
  }
  return null;
}

/** Resources the signer reserved (`SorobanTransactionData.resources`), used when no metering is available. */
export function extractDeclaredUsage(envelopeXdr: string): ResourceUsage | null {
  const tx = decodeEnvelope(envelopeXdr);
  if (!tx) return null;
  try {
    const ext = tx.ext();
    if (ext.switch() !== 1) return null;
    const resources = ext.sorobanData().resources();
    return {
      cpuInstructions: resources.instructions(),
      memoryBytes: 0,
      readBytes: resources.readBytes(),
      writeBytes: resources.writeBytes(),
    };
  } catch {
    return null;
  }
}

// ── Profiler ────────────────────────────────────────────────────────────────

interface Sample {
  worstPct: number;
}

export class ResourceSaturationProfiler {
  private readonly config: ResourceProfilerConfig;
  private readonly limitsProvider?: LimitsProvider;
  private readonly handlers: SaturationHandler[] = [];
  private readonly history = new Map<string, Sample[]>();
  private readonly peaks = new Map<string, ResourceUsage>();
  private readonly invocations = new Map<string, number>();
  private readonly lastAlertAt = new Map<string, number>();
  private readonly now: () => number;

  constructor(
    options: Partial<ResourceProfilerConfig> & {
      limitsProvider?: LimitsProvider;
      handlers?: SaturationHandler[];
      now?: () => number;
    } = {},
  ) {
    const threshold = options.threshold ?? RESOURCE_SATURATION_DEFAULTS.threshold;
    if (!(threshold > 0 && threshold <= 1)) {
      throw new RangeError('threshold must be greater than 0 and at most 1');
    }
    this.config = {
      threshold,
      criticalThreshold: options.criticalThreshold ?? RESOURCE_SATURATION_DEFAULTS.criticalThreshold,
      alertCooldownMs: options.alertCooldownMs ?? RESOURCE_SATURATION_DEFAULTS.alertCooldownMs,
      historySize: options.historySize ?? RESOURCE_SATURATION_DEFAULTS.historySize,
      limits: { ...DEFAULT_SOROBAN_LIMITS, ...options.limits },
    };
    this.limitsProvider = options.limitsProvider;
    this.handlers.push(...(options.handlers ?? []));
    this.now = options.now ?? Date.now;
  }

  onAlert(handler: SaturationHandler): void {
    this.handlers.push(handler);
  }

  /**
   * Builds a utilization report for one invocation, records it for trend
   * tracking and, when a limit is near, notifies handlers (subject to a
   * per-function cooldown). Returns null when no resource data is available.
   */
  async profile(input: ProfileInput): Promise<ResourceSaturationReport | null> {
    const extracted = this.resolveUsage(input);
    if (!extracted) return null;

    const limits = await this.resolveLimits();
    const target = this.resolveTarget(input);
    const report = this.buildReport(input, extracted, limits, target);

    const key = target ? `${target.contractId}:${target.functionName}` : null;
    if (key) {
      report.trendingUp = this.record(key, extracted.usage, report.worst.pct);
    }

    if (report.severity && this.passesCooldown(key ?? input.txHash, report.worst.metric)) {
      this.dispatch(report);
    }
    return report;
  }

  getFunctionStats(contractId: string, functionName: string): FunctionStats | null {
    const key = `${contractId}:${functionName}`;
    const peak = this.peaks.get(key);
    if (!peak) return null;
    const limits = this.config.limits;
    return {
      key,
      invocations: this.invocations.get(key) ?? 0,
      peak: { ...peak },
      peakUtilizationPct: this.utilization(peak, limits),
      trendingUp: this.isTrendingUp(this.history.get(key) ?? []),
    };
  }

  // ── internals ─────────────────────────────────────────────────────────

  private resolveUsage(input: ProfileInput): ExtractedUsage | null {
    if (input.usage) {
      const usage = { ...emptyUsage() };
      let any = false;
      for (const metric of RESOURCE_METRICS) {
        const value = toSafeNumber(input.usage[metric]);
        if (value !== null && value >= 0) {
          usage[metric] = value;
          any = true;
        }
      }
      if (any) return { usage, source: 'metered' };
    }

    if (input.resultMetaXdr) {
      const metered = extractUsageFromMeta(input.resultMetaXdr);
      if (metered) return { usage: metered, source: 'metered' };
    }
    if (input.envelopeXdr) {
      const declared = extractDeclaredUsage(input.envelopeXdr);
      if (declared) return { usage: declared, source: 'declared' };
    }
    return null;
  }

  private resolveTarget(input: ProfileInput): InvocationTarget | null {
    if (input.contractId && input.functionName) {
      return { contractId: input.contractId, functionName: input.functionName };
    }
    const decoded = input.envelopeXdr ? extractInvocationTarget(input.envelopeXdr) : null;
    if (!decoded && !input.contractId) return null;
    return {
      contractId: input.contractId ?? decoded?.contractId ?? '',
      functionName: input.functionName ?? decoded?.functionName ?? 'unknown',
    };
  }

  private async resolveLimits(): Promise<SorobanNetworkLimits> {
    if (!this.limitsProvider) return this.config.limits;
    try {
      const live = await this.limitsProvider();
      if (!live) return this.config.limits;
      const merged = { ...this.config.limits };
      for (const metric of RESOURCE_METRICS) {
        const value = live[metric];
        if (typeof value === 'number' && Number.isFinite(value) && value > 0) merged[metric] = value;
      }
      return merged;
    } catch (err) {
      log.warn({ err: err instanceof Error ? err.message : String(err) }, 'Network limits lookup failed; using configured limits');
      return this.config.limits;
    }
  }

  private utilization(usage: ResourceUsage, limits: SorobanNetworkLimits): Record<ResourceMetric, number> {
    const out = {} as Record<ResourceMetric, number>;
    for (const metric of RESOURCE_METRICS) {
      out[metric] = limits[metric] > 0 ? (usage[metric] / limits[metric]) * 100 : 0;
    }
    return out;
  }

  private buildReport(
    input: ProfileInput,
    extracted: ExtractedUsage,
    limits: SorobanNetworkLimits,
    target: InvocationTarget | null,
  ): ResourceSaturationReport {
    const utilizationPct = this.utilization(extracted.usage, limits);
    const saturated = RESOURCE_METRICS.filter((m) => utilizationPct[m] >= this.config.threshold * 100);
    const worstMetric = RESOURCE_METRICS.reduce((a, b) => (utilizationPct[b] > utilizationPct[a] ? b : a));
    const worst = { metric: worstMetric, pct: utilizationPct[worstMetric] };

    let severity: SaturationSeverity | null = null;
    if (saturated.length > 0) {
      severity = worst.pct >= this.config.criticalThreshold * 100 ? 'CRITICAL' : 'WARNING';
    }

    const where = target ? `${target.contractId}.${target.functionName}` : 'transaction';
    const summary =
      saturated.length > 0
        ? `${where} is using ${worst.pct.toFixed(1)}% of the network ${LABELS[worst.metric]} limit` +
          (saturated.length > 1 ? ` (${saturated.length} resources above ${(this.config.threshold * 100).toFixed(0)}%)` : '') +
          '; it may soon fail with ResourceLimitExceeded.'
        : `${where} resource usage is within limits (peak ${worst.pct.toFixed(1)}% of ${LABELS[worst.metric]}).`;

    return {
      txHash: input.txHash,
      ledgerSeq: input.ledgerSeq,
      contractId: target?.contractId ?? null,
      functionName: target?.functionName ?? null,
      source: extracted.source,
      usage: extracted.usage,
      limits,
      utilizationPct,
      saturated,
      worst,
      severity,
      trendingUp: false,
      summary,
      timestamp: new Date(this.now()).toISOString(),
    };
  }

  private record(key: string, usage: ResourceUsage, worstPct: number): boolean {
    const samples = this.history.get(key) ?? [];
    samples.push({ worstPct });
    if (samples.length > this.config.historySize) samples.shift();
    this.history.set(key, samples);
    this.invocations.set(key, (this.invocations.get(key) ?? 0) + 1);

    const peak = this.peaks.get(key) ?? emptyUsage();
    for (const metric of RESOURCE_METRICS) peak[metric] = Math.max(peak[metric], usage[metric]);
    this.peaks.set(key, peak);

    // Bound memory: forget the least recently touched functions.
    if (this.history.size > 5000) {
      const oldest = this.history.keys().next().value as string;
      this.history.delete(oldest);
      this.peaks.delete(oldest);
      this.invocations.delete(oldest);
    }
    return this.isTrendingUp(samples);
  }

  /** Rising when the recent half averages at least 5 points above the earlier half. */
  private isTrendingUp(samples: Sample[]): boolean {
    if (samples.length < 6) return false;
    const mid = Math.floor(samples.length / 2);
    const avg = (xs: Sample[]) => xs.reduce((n, s) => n + s.worstPct, 0) / xs.length;
    return avg(samples.slice(mid)) - avg(samples.slice(0, mid)) >= 5;
  }

  private passesCooldown(key: string, metric: ResourceMetric): boolean {
    const id = `${key}:${metric}`;
    const last = this.lastAlertAt.get(id);
    const now = this.now();
    if (last !== undefined && now - last < this.config.alertCooldownMs) return false;
    this.lastAlertAt.set(id, now);
    return true;
  }

  private dispatch(report: ResourceSaturationReport): void {
    for (const handler of this.handlers) {
      Promise.resolve()
        .then(() => handler(report))
        .catch((err: unknown) => {
          log.warn(
            { contractId: report.contractId, err: err instanceof Error ? err.message : String(err) },
            'Resource saturation handler failed',
          );
        });
    }
  }
}

const LABELS: Record<ResourceMetric, string> = {
  cpuInstructions: 'CPU instruction',
  memoryBytes: 'memory',
  readBytes: 'ledger read byte',
  writeBytes: 'ledger write byte',
};

// ── Delivery ────────────────────────────────────────────────────────────────

export function buildResourceSaturationWebhookPayload(report: ResourceSaturationReport): Record<string, unknown> {
  return {
    event: 'soroban.resource_saturation',
    severity: report.severity ?? 'WARNING',
    contractId: report.contractId,
    functionName: report.functionName,
    transactionHash: report.txHash,
    ledgerSeq: report.ledgerSeq,
    usage: report.usage,
    limits: report.limits,
    utilizationPct: report.utilizationPct,
    saturated: report.saturated,
    worst: report.worst,
    trendingUp: report.trendingUp,
    source: report.source,
    summary: report.summary,
    timestamp: report.timestamp,
  };
}

export function buildResourceSaturationTelegramMessage(report: ResourceSaturationReport): string {
  const rows = RESOURCE_METRICS.map((m) => {
    const flag = report.saturated.includes(m) ? '⚠️ ' : '';
    return `${flag}${LABELS[m]}: ${report.usage[m].toLocaleString('en-US')} / ${report.limits[m].toLocaleString('en-US')} (${report.utilizationPct[m].toFixed(1)}%)`;
  });
  return [
    `<b>Soroban resource limit warning</b> (${report.severity ?? 'WARNING'})`,
    report.contractId ? `<b>Contract:</b> <code>${escapeTelegramHtml(report.contractId)}</code>` : '',
    report.functionName ? `<b>Function:</b> <code>${escapeTelegramHtml(report.functionName)}</code>` : '',
    ...rows.map((r) => escapeTelegramHtml(r)),
    report.trendingUp ? '📈 Usage has been climbing across recent invocations.' : '',
    `<b>Transaction:</b> <code>${escapeTelegramHtml(report.txHash)}</code>`,
  ]
    .filter(Boolean)
    .join('\n');
}

/** Notifies users watching the contract id (registered as a monitored identifier). */
export const deliverResourceSaturationAlert: SaturationHandler = async (report) => {
  if (!report.contractId) return;
  const wallets = await prisma.wallet.findMany({
    where: { publicKey: report.contractId, deletedAt: null },
    select: { userId: true },
  });
  const payload = buildResourceSaturationWebhookPayload(report);
  const text = buildResourceSaturationTelegramMessage(report);
  for (const userId of new Set(wallets.map((w) => w.userId))) {
    await deliverUserAlert(userId, payload, text);
  }
};

export const resourceSaturationProfiler = new ResourceSaturationProfiler({
  handlers: [deliverResourceSaturationAlert],
});
