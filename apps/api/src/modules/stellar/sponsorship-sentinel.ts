import { prisma } from '../../lib/prisma';
import { stellar } from '../../lib/stellar';
import { redisCache } from '../../lib/redis';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from './alert-delivery';

const log = createLogger({ module: 'SponsorshipSentinel' });

export const SPONSORSHIP_SENTINEL_DEFAULTS = {
  baseReserveXlm: 0.5,
  safetyThresholdXlm: 1,
  alertCooldownMs: 10 * 60 * 1000,
  operationPageSize: 100,
} as const;

export type SponsorshipEntryType =
  | 'account'
  | 'signer'
  | 'trustline'
  | 'offer'
  | 'data'
  | 'claimable_balance'
  | 'liquidity_pool';

export interface SponsorshipOperation {
  id?: string;
  paging_token?: string;
  type: string;
  created_at?: string;
  transaction_hash?: string;
  transaction_successful?: boolean;
  source_account?: string;
  sponsored_id?: string;
  sponsor?: string;
  sponsor_account?: string;
  sponsoring_account?: string;
  account?: string;
  account_id?: string;
  signer_account_id?: string;
  signer_key?: string;
  trustline_account?: string;
  trustline_asset?: string;
  offer_id?: string | number;
  data_account?: string;
  data_name?: string;
  claimable_balance_id?: string;
  liquidity_pool_id?: string;
  [key: string]: unknown;
}

export interface SponsorshipOperationEvent {
  type:
    | 'SPONSORSHIP_GRANTED'
    | 'SPONSORSHIP_ENDED'
    | 'SPONSORSHIP_REVOKED'
    | 'RESERVE_HEADROOM_LOW';
  entryType?: SponsorshipEntryType;
  /** Account whose reserve is being sponsored, or whose entry sponsorship changed. */
  account: string;
  sponsor?: string;
  operationId: string;
  transactionHash?: string;
  occurredAt: string;
}

export interface SponsorshipAccountSnapshot {
  account: string;
  /** Native XLM balance in XLM, not stroops. */
  balanceXlm: number;
  subentryCount: number;
  numSponsoring: number;
  numSponsored: number;
  baseReserveXlm?: number;
}

export interface SponsorshipLiability {
  sponsoredEntryCount: number;
  liabilityXlm: number;
  availableXlm: number;
  headroomXlm: number;
  safetyThresholdXlm: number;
  belowThreshold: boolean;
}

export interface SponsorshipAlert extends SponsorshipOperationEvent {
  severity: 'WARNING' | 'CRITICAL';
  message: string;
  liability?: SponsorshipLiability;
}

export interface SponsorshipSentinelConfig {
  baseReserveXlm: number;
  safetyThresholdXlm: number;
  alertCooldownMs: number;
}

const ENTRY_FIELDS: Array<[SponsorshipEntryType, string[]]> = [
  ['account', ['account_id']],
  ['signer', ['signer_account_id', 'signer_key']],
  ['trustline', ['trustline_account', 'trustline_asset']],
  ['offer', ['offer_id']],
  ['data', ['data_account', 'data_name']],
  ['claimable_balance', ['claimable_balance_id']],
  ['liquidity_pool', ['liquidity_pool_id']],
];

const GRANT_OPERATION_TYPES: Record<string, SponsorshipEntryType> = {
  create_account: 'account',
  change_trust: 'trustline',
  allow_trust: 'trustline',
  manage_sell_offer: 'offer',
  manage_buy_offer: 'offer',
  create_passive_sell_offer: 'offer',
  manage_data: 'data',
  create_claimable_balance: 'claimable_balance',
  liquidity_pool_deposit: 'liquidity_pool',
};

export function sponsorshipEntryType(op: SponsorshipOperation): SponsorshipEntryType | undefined {
  for (const [type, fields] of ENTRY_FIELDS) {
    if (fields.some((field) => op[field] !== undefined && op[field] !== null)) return type;
  }
  if (op.type === 'set_options' && op.signer_key) return 'signer';
  return GRANT_OPERATION_TYPES[op.type];
}

/**
 * Parses the Horizon operation shapes for the sponsorship lifecycle. Revoke
 * sponsorship records identify their target using one of the ledger-entry
 * fields; accepting both snake_case and camelCase accommodates SDK records.
 */
export function parseSponsorshipOperation(
  op: SponsorshipOperation,
): SponsorshipOperationEvent | null {
  if (op.transaction_successful === false) return null;

  const sponsor = op.sponsor ?? op.sponsor_account ?? op.sponsoring_account;
  const base = {
    operationId: op.id ?? op.paging_token ?? `${op.type}:${op.created_at ?? 'unknown'}`,
    transactionHash: op.transaction_hash,
    occurredAt: op.created_at ?? new Date().toISOString(),
  };

  if (op.type === 'begin_sponsoring_future_reserves') {
    const account = op.sponsored_id ?? op.sponsoredId;
    if (typeof account !== 'string' || !account) return null;
    return { ...base, type: 'SPONSORSHIP_GRANTED', account, sponsor: sponsor ?? op.source_account };
  }

  if (op.type === 'end_sponsoring_future_reserves') {
    const account = op.source_account ?? op.sponsored_id ?? op.sponsoredId;
    if (typeof account !== 'string' || !account) return null;
    return { ...base, type: 'SPONSORSHIP_ENDED', account, sponsor };
  }

  if (op.type !== 'revoke_sponsorship') {
    const entryType = sponsorshipEntryType(op);
    if (!entryType || !sponsor) return null;
    const account =
      (entryType === 'account' ? op.account ?? op.destination ?? op.account_id : undefined) ??
      op.trustline_account ?? op.trustor ?? op.data_account ?? op.source_account ?? op.seller;
    if (typeof account !== 'string' || !account) return null;
    return { ...base, type: 'SPONSORSHIP_GRANTED', account, sponsor, entryType };
  }

  const normalized: SponsorshipOperation = { ...op };
  for (const [type, fields] of ENTRY_FIELDS) {
    for (const field of fields) {
      const camel = field.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
      if (normalized[field] === undefined && normalized[camel] !== undefined) {
        normalized[field] = normalized[camel];
      }
    }
    if (fields.some((field) => normalized[field] !== undefined && normalized[field] !== null)) {
      const account =
        (type === 'account' ? normalized.account_id : undefined) ??
        normalized.trustline_account ??
        normalized.data_account ??
        normalized.signer_account_id ??
        op.source_account;
      if (typeof account !== 'string' || !account) return null;
      return { ...base, type: 'SPONSORSHIP_REVOKED', account, sponsor, entryType: type };
    }
  }
  return null;
}

/**
 * Reserve cost per sponsored ledger entry. Claimable balances consume two
 * base reserves; accounts, signers, trustlines, offers, data and pool shares
 * consume one each.
 */
export function sponsorshipReserveUnits(entryType: SponsorshipEntryType): number {
  return entryType === 'claimable_balance' ? 2 : 1;
}

export function calculateSponsorshipLiability(
  numSponsoring: number,
  baseReserveXlm: number = SPONSORSHIP_SENTINEL_DEFAULTS.baseReserveXlm,
): number {
  if (!Number.isFinite(numSponsoring) || numSponsoring < 0 ||
      !Number.isFinite(baseReserveXlm) || baseReserveXlm < 0) return 0;
  return numSponsoring * baseReserveXlm;
}

export function calculateSponsorshipHeadroom(
  snapshot: SponsorshipAccountSnapshot,
  safetyThresholdXlm: number = SPONSORSHIP_SENTINEL_DEFAULTS.safetyThresholdXlm,
): SponsorshipLiability {
  const baseReserveXlm = snapshot.baseReserveXlm ?? SPONSORSHIP_SENTINEL_DEFAULTS.baseReserveXlm;
  const liabilityXlm = calculateSponsorshipLiability(snapshot.numSponsoring, baseReserveXlm);
  // Keep the account's own minimum balance separate from reserve liabilities:
  // num_sponsoring is then subtracted exactly once, as the liability.
  const ownReserveXlm = Math.max(
    0,
    2 + snapshot.subentryCount - snapshot.numSponsored,
  ) * baseReserveXlm;
  const availableXlm = snapshot.balanceXlm - ownReserveXlm;
  const headroomXlm = availableXlm - liabilityXlm;
  return {
    sponsoredEntryCount: snapshot.numSponsoring,
    liabilityXlm,
    availableXlm,
    headroomXlm,
    safetyThresholdXlm,
    belowThreshold: headroomXlm < safetyThresholdXlm,
  };
}

export function buildSponsorshipWebhookPayload(alert: SponsorshipAlert): Record<string, unknown> {
  return {
    event: 'stellar.sponsorship',
    timestamp: alert.occurredAt,
    severity: alert.severity,
    data: { ...alert },
  };
}

export function buildSponsorshipTelegramMessage(alert: SponsorshipAlert): string {
  return [
    `<b>${alert.severity}: Stellar sponsorship ${alert.type.replace('SPONSORSHIP_', '').toLowerCase()}</b>`,
    `<b>Account:</b> <code>${escapeTelegramHtml(alert.account)}</code>`,
    alert.sponsor ? `<b>Sponsor:</b> <code>${escapeTelegramHtml(alert.sponsor)}</code>` : '',
    alert.entryType ? `<b>Entry:</b> ${escapeTelegramHtml(alert.entryType)}` : '',
    alert.liability
      ? `<b>Reserve liability:</b> ${alert.liability.liabilityXlm.toFixed(4)} XLM; ` +
        `<b>headroom:</b> ${alert.liability.headroomXlm.toFixed(4)} XLM`
      : '',
    escapeTelegramHtml(alert.message),
    alert.transactionHash ? `<b>Transaction:</b> <code>${escapeTelegramHtml(alert.transactionHash)}</code>` : '',
  ].filter(Boolean).join('\n');
}

export type SponsorshipNotifier = (alert: SponsorshipAlert) => Promise<void>;

export const deliverSponsorshipAlert: SponsorshipNotifier = async (alert) => {
  const addresses = [...new Set([alert.account, alert.sponsor].filter((v): v is string => Boolean(v)))];
  if (addresses.length === 0) return;
  const wallets = await prisma.wallet.findMany({
    where: { publicKey: { in: addresses }, deletedAt: null },
    select: { userId: true },
  });
  const payload = buildSponsorshipWebhookPayload(alert);
  const text = buildSponsorshipTelegramMessage(alert);
  for (const userId of new Set(wallets.map((wallet) => wallet.userId))) {
    await deliverUserAlert(userId, payload, text);
  }
};

const CURSOR_PREFIX = 'sponsorship-sentinel:cursor:';
const ALERT_PREFIX = 'sponsorship-sentinel:alert:';
const ALERT_DEDUPE_TTL_SECONDS = 30 * 24 * 60 * 60;

export class SponsorshipSentinel {
  private readonly config: SponsorshipSentinelConfig;
  private readonly lastThresholdAlert = new Map<string, number>();

  constructor(
    config: Partial<SponsorshipSentinelConfig> = {},
    private readonly now: () => number = Date.now,
  ) {
    this.config = { ...SPONSORSHIP_SENTINEL_DEFAULTS, ...config };
  }

  assessOperation(op: SponsorshipOperation): SponsorshipAlert | null {
    const event = parseSponsorshipOperation(op);
    if (!event) return null;
    const isRevocation = event.type === 'SPONSORSHIP_REVOKED';
    return {
      ...event,
      severity: isRevocation ? 'CRITICAL' : 'WARNING',
      message: isRevocation
        ? `Sponsorship for ${event.entryType ?? 'ledger'} entry on ${event.account.slice(0, 8)}… was revoked.`
        : `${event.type === 'SPONSORSHIP_GRANTED' ? 'Reserve sponsorship started' : 'Reserve sponsorship ended'} ` +
          `for ${event.account.slice(0, 8)}….`,
    };
  }

  assessAccount(snapshot: SponsorshipAccountSnapshot): SponsorshipAlert | null {
    const liability = calculateSponsorshipHeadroom(snapshot, this.config.safetyThresholdXlm);
    if (liability.sponsoredEntryCount <= 0 || !liability.belowThreshold) return null;
    const previous = this.lastThresholdAlert.get(snapshot.account);
    if (previous !== undefined && this.now() - previous < this.config.alertCooldownMs) return null;
    this.lastThresholdAlert.set(snapshot.account, this.now());
    const event: SponsorshipOperationEvent = {
      type: 'RESERVE_HEADROOM_LOW',
      account: snapshot.account,
      operationId: `reserve-threshold:${snapshot.account}`,
      occurredAt: new Date(this.now()).toISOString(),
    };
    return {
      ...event,
      severity: 'CRITICAL',
      liability,
      message:
        `Transferable headroom for ${snapshot.account.slice(0, 8)}… is ` +
        `${liability.headroomXlm.toFixed(4)} XLM, below the ` +
        `${liability.safetyThresholdXlm.toFixed(4)} XLM safety threshold ` +
        `(${liability.liabilityXlm.toFixed(4)} XLM sponsored reserve liability).`,
    };
  }

  getAlertCooldownMs(): number {
    return this.config.alertCooldownMs;
  }

  clear(): void {
    this.lastThresholdAlert.clear();
  }
}

export const sponsorshipSentinel = new SponsorshipSentinel();

async function loadAccountSnapshot(account: string): Promise<SponsorshipAccountSnapshot | null> {
  try {
    const record = await stellar.server.accounts().accountId(account).call() as {
      balances?: Array<{ asset_type?: string; balance?: string }>;
      subentry_count?: number;
      num_sponsoring?: number;
      num_sponsored?: number;
      base_reserve_in_stroops?: string | number;
    };
    const balanceXlm = Number(record.balances?.find((balance) => balance.asset_type === 'native')?.balance);
    if (!Number.isFinite(balanceXlm)) return null;
    const rawBaseReserve = Number(record.base_reserve_in_stroops);
    return {
      account,
      balanceXlm,
      subentryCount: Number(record.subentry_count ?? 0),
      numSponsoring: Number(record.num_sponsoring ?? 0),
      numSponsored: Number(record.num_sponsored ?? 0),
      baseReserveXlm: Number.isFinite(rawBaseReserve) && rawBaseReserve > 0
        ? rawBaseReserve / 10_000_000
        : undefined,
    };
  } catch (err: unknown) {
    log.warn(`Account snapshot failed for ${account.slice(0, 8)}…: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}

async function scanAccount(
  account: string,
  sentinel: SponsorshipSentinel,
  notify: SponsorshipNotifier,
): Promise<number> {
  const cursorKey = `${CURSOR_PREFIX}${account}`;
  let emitted = 0;
  let cursor = await redisCache.get(cursorKey);
  if (!cursor) {
    const latest = await stellar.getLatestOperationPagingToken(account);
    if (!latest.ok) return 0;
    cursor = latest.token ?? '0';
    await redisCache.set(cursorKey, cursor);
  } else {
    const result = await stellar.getAccountOperationsSince(
      account,
      cursor,
      SPONSORSHIP_SENTINEL_DEFAULTS.operationPageSize,
    );
    if (result.ok) {
      for (const op of result.records as SponsorshipOperation[]) {
        const alert = sentinel.assessOperation(op);
        if (alert) {
          const dedupeKey = `${ALERT_PREFIX}${alert.operationId}:${alert.account}:${alert.type}`;
          if (await redisCache.setNx(dedupeKey, '1', ALERT_DEDUPE_TTL_SECONDS)) {
            try {
              await notify(alert);
              emitted += 1;
            } catch (err: unknown) {
              await redisCache.del(dedupeKey);
              throw err;
            }
          }
        }
        if (op.paging_token) {
          cursor = op.paging_token;
          await redisCache.set(cursorKey, cursor);
        }
      }
    }
  }

  const snapshot = await loadAccountSnapshot(account);
  if (!snapshot) return emitted;
  const thresholdAlert = sentinel.assessAccount(snapshot);
  if (!thresholdAlert) return emitted;
  const key = `${ALERT_PREFIX}${thresholdAlert.operationId}`;
  const cooldownSeconds = Math.max(1, Math.ceil(sentinel.getAlertCooldownMs() / 1000));
  if (!(await redisCache.setNx(key, '1', cooldownSeconds))) return emitted;
  try {
    await notify(thresholdAlert);
    return emitted + 1;
  } catch (err: unknown) {
    await redisCache.del(key);
    throw err;
  }
}

/** Polls wallet operation feeds and current Horizon account state for reserve risk. */
export async function runSponsorshipSentinelPass(
  accounts: string[],
  notify: SponsorshipNotifier = deliverSponsorshipAlert,
  sentinel: SponsorshipSentinel = sponsorshipSentinel,
): Promise<number> {
  let emitted = 0;
  for (const account of new Set(accounts)) {
    try {
      emitted += await scanAccount(account, sentinel, notify);
    } catch (err: unknown) {
      log.warn(`Sponsorship scan failed for ${account.slice(0, 8)}…: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return emitted;
}
