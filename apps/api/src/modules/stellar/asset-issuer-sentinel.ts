import { prisma } from '../../lib/prisma';
import { stellar } from '../../lib/stellar';
import { redisCache } from '../../lib/redis';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from './alert-delivery';

const log = createLogger({ module: 'AssetIssuerSentinel' });

/** Stellar account flag bits relevant to asset risk (#1035). */
export const AUTH_REQUIRED = 1;
export const AUTH_REVOCABLE = 2;
export const AUTH_IMMUTABLE = 4;
export const AUTH_CLAWBACK_ENABLED = 8;

export interface DecodedIssuerFlags {
  mask: number;
  authRequired: boolean;
  authRevocable: boolean;
  authImmutable: boolean;
  authClawbackEnabled: boolean;
  unknownBits: number[];
}

const NAMED_FLAGS: Record<string, number> = {
  auth_required: AUTH_REQUIRED,
  auth_required_flag: AUTH_REQUIRED,
  auth_revocable: AUTH_REVOCABLE,
  auth_revocable_flag: AUTH_REVOCABLE,
  auth_immutable: AUTH_IMMUTABLE,
  auth_immutable_flag: AUTH_IMMUTABLE,
  auth_clawback_enabled: AUTH_CLAWBACK_ENABLED,
  auth_clawback_enabled_flag: AUTH_CLAWBACK_ENABLED,
  auth_clawback: AUTH_CLAWBACK_ENABLED,
};

const FLAG_LABELS: Array<[number, string]> = [
  [AUTH_REQUIRED, 'AUTH_REQUIRED'],
  [AUTH_REVOCABLE, 'AUTH_REVOCABLE'],
  [AUTH_IMMUTABLE, 'AUTH_IMMUTABLE'],
  [AUTH_CLAWBACK_ENABLED, 'AUTH_CLAWBACK_ENABLED'],
];

function toBit(value: number | string): number | undefined {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  }
  const key = value.trim().toLowerCase();
  if (NAMED_FLAGS[key] !== undefined) return NAMED_FLAGS[key];
  if (/^\d+$/.test(key)) return Number(key);
  if (/^0x[0-9a-f]+$/i.test(key)) return Number.parseInt(key, 16);
  return undefined;
}

/**
 * Decodes Horizon's mixed numeric/named flag arrays. `AUTH_CLAWBACK_ENABLED`
 * is bit 8; the bundled SDK's numeric union omits it, so this decoder is
 * deliberately independent of that type.
 */
export function decodeIssuerFlags(
  flags: readonly (number | string)[] | number | string | null | undefined,
): DecodedIssuerFlags {
  const values = flags === null || flags === undefined
    ? []
    : Array.isArray(flags) ? flags : [flags];
  let mask = 0;
  const unknown = new Set<number>();

  for (const value of values) {
    const bit = toBit(value);
    if (bit === undefined || bit === 0) continue;
    if (FLAG_LABELS.some(([known]) => known === bit)) mask |= bit;
    else unknown.add(bit);
  }

  return {
    mask,
    authRequired: (mask & AUTH_REQUIRED) !== 0,
    authRevocable: (mask & AUTH_REVOCABLE) !== 0,
    authImmutable: (mask & AUTH_IMMUTABLE) !== 0,
    authClawbackEnabled: (mask & AUTH_CLAWBACK_ENABLED) !== 0,
    unknownBits: [...unknown].sort((a, b) => a - b),
  };
}

export function describeIssuerFlags(flags: DecodedIssuerFlags): string {
  const labels = FLAG_LABELS.filter(([bit]) => (flags.mask & bit) !== 0).map(([, label]) => label);
  if (flags.unknownBits.length > 0) labels.push(`UNKNOWN(${flags.unknownBits.join(',')})`);
  return labels.length > 0 ? labels.join(', ') : 'none';
}

export interface IssuerOperation {
  id?: string;
  paging_token?: string;
  type: string;
  created_at?: string;
  transaction_hash?: string;
  transaction_successful?: boolean;
  source_account?: string;
  from?: string;
  to?: string;
  asset_code?: string;
  asset_issuer?: string;
  amount?: string;
  home_domain?: string;
  set_flags?: readonly (number | string)[];
  clear_flags?: readonly (number | string)[];
  set_flags_s?: readonly string[];
  clear_flags_s?: readonly string[];
}

export interface RegisteredAssetIssuer {
  issuer: string;
  /** When set, only payments of this asset code count toward supply. */
  assetCode?: string;
  /** Known-good baseline; the first differing `home_domain` op is a drift alert. */
  homeDomain?: string;
  /** Known-good flag baseline, e.g. `[AUTH_REQUIRED, AUTH_IMMUTABLE]`. */
  flags?: readonly (number | string)[];
  /** Absolute circulating-supply ceiling; exceeding it emits a critical alert. */
  supplyCap?: number;
}

export type AssetIssuerEventType =
  | 'ISSUER_FLAG_MUTATION'
  | 'HOME_DOMAIN_DRIFT'
  | 'ISSUANCE'
  | 'REDEMPTION'
  | 'SUPPLY_CAP_EXCEEDED';

export type AssetIssuerAlertSeverity = 'CRITICAL' | 'WARNING';

export interface AssetIssuerAlert {
  eventType: AssetIssuerEventType;
  severity: AssetIssuerAlertSeverity;
  issuer: string;
  assetCode: string;
  operationId: string;
  transactionHash?: string;
  amount?: number;
  setFlags?: string;
  clearedFlags?: string;
  homeDomain?: string;
  previousHomeDomain?: string;
  circulatingSupply?: number;
  supplyCap?: number;
  message: string;
  occurredAt: string;
}

interface IssuerState {
  flags: number;
  homeDomain?: string;
  circulatingSupply: number;
}

function short(address: string | undefined): string {
  return address ? `${address.slice(0, 6)}…${address.slice(-4)}` : 'unknown';
}

/**
 * Pure per-issuer analysis. Callers supply raw Horizon operations; all state
 * (current flags, home domain and circulating supply) lives in memory so the
 * decoder and mint/burn logic can be unit tested without I/O.
 */
export class AssetIssuerSentinel {
  private issuers = new Map<string, RegisteredAssetIssuer>();
  private readonly state = new Map<string, IssuerState>();

  constructor(issuers: Iterable<RegisteredAssetIssuer> = []) {
    this.setIssuers(issuers);
  }

  /** Replaces the registry while preserving accumulated state for existing issuers. */
  setIssuers(issuers: Iterable<RegisteredAssetIssuer>): void {
    const next = new Map<string, RegisteredAssetIssuer>();
    for (const issuer of issuers) {
      if (!issuer.issuer) continue;
      next.set(issuer.issuer, issuer);
      if (!this.state.has(issuer.issuer)) {
        this.state.set(issuer.issuer, {
          flags: decodeIssuerFlags(issuer.flags).mask,
          homeDomain: issuer.homeDomain,
          circulatingSupply: 0,
        });
      }
    }
    for (const key of this.state.keys()) {
      if (!next.has(key)) this.state.delete(key);
    }
    this.issuers = next;
  }

  isIssuer(address: string | undefined): boolean {
    return Boolean(address && this.issuers.has(address));
  }

  /** Returns a snapshot mainly useful for tests and operational diagnostics. */
  stateFor(issuer: string): IssuerState | undefined {
    const state = this.state.get(issuer);
    return state ? { ...state } : undefined;
  }

  assess(op: IssuerOperation): AssetIssuerAlert[] {
    if (op.transaction_successful === false) return [];
    if (op.type !== 'set_options' && op.type !== 'payment') return [];

    const candidates = op.type === 'set_options'
      ? [op.source_account]
      : [op.from, op.to];
    const matched = [...new Set(candidates.filter((address): address is string => this.isIssuer(address)))];

    return matched.flatMap((issuer) => this.assessForIssuer(issuer, this.issuers.get(issuer)!, op));
  }

  private base(issuer: string, op: IssuerOperation, assetCode: string) {
    return {
      issuer,
      assetCode,
      operationId: op.id ?? op.paging_token ?? op.transaction_hash ?? `${op.type}:${op.created_at ?? 'unknown'}`,
      transactionHash: op.transaction_hash,
      occurredAt: op.created_at ?? new Date(0).toISOString(),
    };
  }

  private assessForIssuer(
    issuer: string,
    registered: RegisteredAssetIssuer,
    op: IssuerOperation,
  ): AssetIssuerAlert[] {
    const assetCode = registered.assetCode ?? op.asset_code ?? '';
    const alerts: AssetIssuerAlert[] = [];

    if (op.type === 'set_options') {
      const set = decodeIssuerFlags([...(op.set_flags ?? []), ...(op.set_flags_s ?? [])]);
      const clear = decodeIssuerFlags([...(op.clear_flags ?? []), ...(op.clear_flags_s ?? [])]);
      if (set.mask !== 0 || clear.mask !== 0) {
        const state = this.state.get(issuer)!;
        const before = state.flags;
        state.flags = (before | set.mask) & ~clear.mask;
        if (state.flags !== before) {
          alerts.push({
            ...this.base(issuer, op, assetCode),
            eventType: 'ISSUER_FLAG_MUTATION',
            severity: 'CRITICAL',
            setFlags: describeIssuerFlags(set),
            clearedFlags: describeIssuerFlags(clear),
            message:
              `Issuer ${short(issuer)} changed account flags from ` +
              `${describeIssuerFlags({ ...set, mask: before })} to ${describeIssuerFlags({
                ...set,
                mask: state.flags,
                unknownBits: [],
              })}.`,
          });
        }
      }

      if (Object.prototype.hasOwnProperty.call(op, 'home_domain')) {
        const state = this.state.get(issuer)!;
        const next = op.home_domain || undefined;
        if (next !== state.homeDomain) {
          const previous = state.homeDomain;
          state.homeDomain = next;
          alerts.push({
            ...this.base(issuer, op, assetCode),
            eventType: 'HOME_DOMAIN_DRIFT',
            severity: 'CRITICAL',
            homeDomain: next,
            previousHomeDomain: previous,
            message:
              `Issuer ${short(issuer)} changed home_domain from ` +
              `${previous ?? '(unset)'} to ${next ?? '(unset)'}.`,
          });
        }
      }

      return alerts;
    }

    if (op.asset_issuer && op.asset_issuer !== issuer) return alerts;
    if (registered.assetCode && op.asset_code && op.asset_code !== registered.assetCode) return alerts;

    const amount = Number(op.amount);
    if (!Number.isFinite(amount) || amount <= 0) return alerts;
    const state = this.state.get(issuer)!;
    const base = this.base(issuer, op, op.asset_code ?? assetCode);

    if (op.from === issuer) {
      state.circulatingSupply += amount;
      alerts.push({
        ...base,
        eventType: 'ISSUANCE',
        severity: 'WARNING',
        amount,
        circulatingSupply: state.circulatingSupply,
        message: `Issuer ${short(issuer)} issued ${amount} ${base.assetCode || 'tokens'}.`,
      });
      if (registered.supplyCap !== undefined && state.circulatingSupply > registered.supplyCap) {
        alerts.push({
          ...base,
          eventType: 'SUPPLY_CAP_EXCEEDED',
          severity: 'CRITICAL',
          amount,
          circulatingSupply: state.circulatingSupply,
          supplyCap: registered.supplyCap,
          message:
            `Circulating supply of ${base.assetCode || 'tokens'} from ${short(issuer)} ` +
            `reached ${state.circulatingSupply}, above the ${registered.supplyCap} cap.`,
        });
      }
    }

    if (op.to === issuer) {
      state.circulatingSupply = Math.max(0, state.circulatingSupply - amount);
      alerts.push({
        ...base,
        eventType: 'REDEMPTION',
        severity: 'WARNING',
        amount,
        circulatingSupply: state.circulatingSupply,
        message: `Issuer ${short(issuer)} redeemed ${amount} ${base.assetCode || 'tokens'}.`,
      });
    }

    return alerts;
  }
}

export function buildAssetIssuerWebhookPayload(alert: AssetIssuerAlert) {
  return { event: 'asset_issuer.alert', ...alert };
}

export function buildAssetIssuerTelegramMessage(alert: AssetIssuerAlert): string {
  const tag = alert.severity === 'CRITICAL' ? '🚨 <b>CRITICAL</b>' : '⚠️ <b>WARNING</b>';
  return [
    `${tag} — Stellar asset issuer alert`,
    `<b>Event:</b> ${escapeTelegramHtml(alert.eventType)}`,
    `<b>Issuer:</b> <code>${escapeTelegramHtml(alert.issuer)}</code>`,
    alert.assetCode ? `<b>Asset:</b> ${escapeTelegramHtml(alert.assetCode)}` : '',
    escapeTelegramHtml(alert.message),
    alert.transactionHash ? `<b>Transaction:</b> <code>${escapeTelegramHtml(alert.transactionHash)}</code>` : '',
  ].filter(Boolean).join('\n');
}

export type AssetIssuerAlertNotifier = (alert: AssetIssuerAlert) => Promise<void> | void;

/** Routes an issuer alert to the issuer's wallet owner and known asset holders. */
export const deliverAssetIssuerAlert: AssetIssuerAlertNotifier = async (alert) => {
  const wallets = await prisma.wallet.findMany({
    where: {
      OR: [
        { publicKey: alert.issuer },
        { payments: { some: { assetIssuer: alert.issuer } } },
      ],
    },
    select: { userId: true },
    take: 500,
  });

  const payload = buildAssetIssuerWebhookPayload(alert);
  const text = buildAssetIssuerTelegramMessage(alert);
  for (const userId of new Set(wallets.map((wallet) => wallet.userId))) {
    await deliverUserAlert(userId, payload, text);
  }
};

// ── Registry loading and polling pass (called from the watcher worker) ──────

const CURSOR_KEY_PREFIX = 'asset-issuer-sentinel:cursor:';
const ALERT_KEY_PREFIX = 'asset-issuer-sentinel:alert:';
const ALERT_DEDUPE_TTL_SECONDS = 30 * 24 * 60 * 60;
const OPERATIONS_PAGE_SIZE = 100;
const MONITORED_OPERATION_TYPES = new Set(['set_options', 'payment']);

export type IssuerRegistryLoader = (
  walletPublicKeys: string[],
) => Promise<RegisteredAssetIssuer[]>;

/** Combines monitored wallet keys with issuers seen in stored payments. */
export const loadRegisteredIssuers: IssuerRegistryLoader = async (walletPublicKeys) => {
  const payments = await prisma.payment.findMany({
    where: { assetIssuer: { not: null } },
    select: { asset: true, assetIssuer: true },
    distinct: ['asset', 'assetIssuer'],
    take: 500,
  });

  const issuers = new Map<string, RegisteredAssetIssuer>();
  for (const publicKey of walletPublicKeys) {
    if (publicKey) issuers.set(publicKey, { issuer: publicKey });
  }
  for (const payment of payments) {
    if (!payment.assetIssuer) continue;
    issuers.set(payment.assetIssuer, { issuer: payment.assetIssuer, assetCode: payment.asset });
  }
  return [...issuers.values()];
};

export const assetIssuerSentinel = new AssetIssuerSentinel();

async function emitOnce(alert: AssetIssuerAlert, notify: AssetIssuerAlertNotifier): Promise<boolean> {
  const first = await redisCache.setNx(
    `${ALERT_KEY_PREFIX}${alert.operationId}:${alert.issuer}:${alert.eventType}`,
    '1',
    ALERT_DEDUPE_TTL_SECONDS,
  );
  if (!first) return false;

  log.warn(`[${alert.severity}] ${alert.eventType}: ${alert.message}`);
  await notify(alert);
  return true;
}

async function scanIssuer(
  issuer: RegisteredAssetIssuer,
  sentinel: AssetIssuerSentinel,
  notify: AssetIssuerAlertNotifier,
): Promise<number> {
  const cursorKey = `${CURSOR_KEY_PREFIX}${issuer.issuer}`;
  let cursor = await redisCache.get(cursorKey);

  if (!cursor) {
    // First sight of this issuer: start from "now" so history is not replayed.
    const latest = await stellar.getLatestOperationPagingToken(issuer.issuer);
    await redisCache.set(cursorKey, latest.ok ? latest.token ?? '0' : '0');
    return 0;
  }

  const result = await stellar.getAccountOperationsSince(issuer.issuer, cursor, OPERATIONS_PAGE_SIZE);
  if (!result.ok) return 0;

  let emitted = 0;
  for (const record of result.records as IssuerOperation[]) {
    if (MONITORED_OPERATION_TYPES.has(record.type)) {
      for (const alert of sentinel.assess(record)) {
        if (await emitOnce(alert, notify)) emitted += 1;
      }
    }
    if (record.paging_token) cursor = record.paging_token;
  }

  await redisCache.set(cursorKey, cursor);
  return emitted;
}

export interface AssetIssuerPassOptions {
  sentinel?: AssetIssuerSentinel;
  loadIssuers?: IssuerRegistryLoader;
}

/**
 * One sentinel pass over registered issuers. Each issuer's failure is isolated
 * so an unreachable Horizon account never stalls the rest of the pass.
 */
export async function runAssetIssuerSentinelPass(
  walletPublicKeys: string[],
  notify: AssetIssuerAlertNotifier = deliverAssetIssuerAlert,
  options: AssetIssuerPassOptions = {},
): Promise<number> {
  const issuers = await (options.loadIssuers ?? loadRegisteredIssuers)(walletPublicKeys);
  if (issuers.length === 0) return 0;

  const sentinel = options.sentinel ?? assetIssuerSentinel;
  sentinel.setIssuers(issuers);

  let emitted = 0;
  for (const issuer of issuers) {
    try {
      emitted += await scanIssuer(issuer, sentinel, notify);
    } catch (err: unknown) {
      log.warn(`Issuer scan failed for ${short(issuer.issuer)}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return emitted;
}
