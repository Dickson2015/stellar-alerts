import { prisma } from '../../lib/prisma';
import { createLogger } from '../../lib/logger';
import { deliverUserAlert, escapeTelegramHtml } from './alert-delivery';

/**
 * Classic (protocol-18) constant-product liquidity pool watcher (#982).
 *
 * Decodes `liquidity_pool_deposit` / `liquidity_pool_withdraw` Horizon
 * operations, values the LP shares against the pool reserves, derives price
 * bounds and slippage, and notifies subscribers watching either the acting
 * wallet or the 64-hex pool ID.
 */

const log = createLogger({ module: 'ClassicAmmWatcher' });

export const POOL_ID_PATTERN = /^[0-9a-f]{64}$/i;

export type ClassicAmmOperationType = 'liquidity_pool_deposit' | 'liquidity_pool_withdraw';

export interface HorizonPoolAmount {
  /** `native` or `CODE:ISSUER`. */
  asset: string;
  amount: string;
}

interface HorizonRatio {
  n: number;
  d: number;
}

/** Subset of a Horizon liquidity pool operation record. */
export interface HorizonLiquidityPoolOperation {
  id?: string;
  type: string;
  transaction_hash?: string;
  source_account?: string;
  created_at?: string;
  liquidity_pool_id?: string;
  // deposit
  reserves_max?: HorizonPoolAmount[];
  min_price?: string;
  min_price_r?: HorizonRatio;
  max_price?: string;
  max_price_r?: HorizonRatio;
  reserves_deposited?: HorizonPoolAmount[];
  shares_received?: string;
  // withdraw
  reserves_min?: HorizonPoolAmount[];
  shares?: string;
  reserves_received?: HorizonPoolAmount[];
}

/** Subset of Horizon's `/liquidity_pools/{id}` record. */
export interface HorizonLiquidityPool {
  id: string;
  fee_bp?: number;
  total_shares: string;
  total_trustlines?: string;
  reserves: HorizonPoolAmount[];
}

export interface PoolLeg {
  asset: string;
  /** Amount moved by the operation (deposited or withdrawn). */
  amount: number;
  /** Limit the submitter set (reserves_max on deposit, reserves_min on withdraw). */
  limit: number;
}

export interface ClassicAmmEvent {
  kind: 'DEPOSIT' | 'WITHDRAW';
  poolId: string;
  account: string;
  transactionHash?: string;
  operationId?: string;
  timestamp: string;
  assetA: PoolLeg;
  assetB: PoolLeg;
  /** LP shares minted (deposit) or burned (withdraw). */
  shares: number;
  /** Price bounds the submitter accepted, as B per A. Deposit only. */
  minPrice?: number;
  maxPrice?: number;
  /** Pool spot price at inspection time (B per A), when pool state is known. */
  poolPrice?: number;
  /**
   * Width of the accepted price band relative to its midpoint, in percent.
   * This is the slippage the submitter was willing to tolerate (deposit).
   */
  slippageTolerancePct?: number;
  /**
   * Actual shortfall versus the submitter's limits, in percent. Negative means
   * the operation executed better than its limit (withdraw receives more than
   * reserves_min; deposit uses less than reserves_max).
   */
  executedSlippagePct?: number;
  /** Value of the moved shares in each pool asset, from current reserves. */
  shareValue?: { assetA: number; assetB: number; sharePct: number };
}

export class ClassicAmmDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ClassicAmmDecodeError';
  }
}

export function isClassicAmmOperation(op: { type?: string }): boolean {
  return op.type === 'liquidity_pool_deposit' || op.type === 'liquidity_pool_withdraw';
}

function num(value: string | undefined, label: string): number {
  const parsed = Number(value);
  if (value === undefined || !Number.isFinite(parsed)) {
    throw new ClassicAmmDecodeError(`Missing or invalid ${label}`);
  }
  return parsed;
}

function ratio(r: HorizonRatio | undefined, fallback: string | undefined, label: string): number {
  if (r && r.d !== 0) return r.n / r.d;
  return num(fallback, label);
}

function pair(
  moved: HorizonPoolAmount[] | undefined,
  limits: HorizonPoolAmount[] | undefined,
  label: string,
): [PoolLeg, PoolLeg] {
  if (!moved || moved.length !== 2 || !limits || limits.length !== 2) {
    throw new ClassicAmmDecodeError(`${label} must list exactly two pool assets`);
  }
  const leg = (i: 0 | 1): PoolLeg => ({
    asset: moved[i].asset,
    amount: num(moved[i].amount, `${label}[${i}].amount`),
    limit: num(limits[i].amount, `${label} limit[${i}]`),
  });
  return [leg(0), leg(1)];
}

/** Percentage by which `actual` falls short of `limit`; negative when it beats it. */
function shortfallPct(actual: number, limit: number): number {
  if (limit === 0) return 0;
  return ((limit - actual) / limit) * 100;
}

/**
 * Decodes one Horizon operation into a typed event. Throws
 * ClassicAmmDecodeError for malformed records; non-pool operations are rejected.
 */
export function decodeClassicAmmOperation(
  op: HorizonLiquidityPoolOperation,
  pool?: HorizonLiquidityPool | null,
): ClassicAmmEvent {
  if (!isClassicAmmOperation(op)) {
    throw new ClassicAmmDecodeError(`Unsupported operation type: ${String(op.type)}`);
  }
  if (!op.liquidity_pool_id || !POOL_ID_PATTERN.test(op.liquidity_pool_id)) {
    throw new ClassicAmmDecodeError('Missing or malformed 64-character liquidity pool id');
  }
  if (!op.source_account) {
    throw new ClassicAmmDecodeError('Operation is missing source_account');
  }

  const base = {
    poolId: op.liquidity_pool_id.toLowerCase(),
    account: op.source_account,
    transactionHash: op.transaction_hash,
    operationId: op.id,
    timestamp: op.created_at ?? new Date().toISOString(),
  };

  let event: ClassicAmmEvent;
  if (op.type === 'liquidity_pool_deposit') {
    const [assetA, assetB] = pair(op.reserves_deposited, op.reserves_max, 'reserves_deposited');
    const minPrice = ratio(op.min_price_r, op.min_price, 'min_price');
    const maxPrice = ratio(op.max_price_r, op.max_price, 'max_price');
    if (minPrice <= 0 || maxPrice < minPrice) {
      throw new ClassicAmmDecodeError('Price bounds must satisfy 0 < min_price <= max_price');
    }
    const mid = (minPrice + maxPrice) / 2;
    // Slippage is measured on the more heavily consumed side of the deposit.
    const used = Math.max(
      assetA.limit ? assetA.amount / assetA.limit : 0,
      assetB.limit ? assetB.amount / assetB.limit : 0,
    );
    event = {
      kind: 'DEPOSIT',
      ...base,
      assetA,
      assetB,
      shares: num(op.shares_received, 'shares_received'),
      minPrice,
      maxPrice,
      slippageTolerancePct: ((maxPrice - minPrice) / mid) * 100,
      executedSlippagePct: (1 - used) * 100,
    };
  } else {
    const [assetA, assetB] = pair(op.reserves_received, op.reserves_min, 'reserves_received');
    event = {
      kind: 'WITHDRAW',
      ...base,
      assetA,
      assetB,
      shares: num(op.shares, 'shares'),
      // Worst-case shortfall across both legs versus the minimum the user set.
      executedSlippagePct: Math.max(
        shortfallPct(assetA.amount, assetA.limit),
        shortfallPct(assetB.amount, assetB.limit),
      ),
    };
  }

  return pool ? enrichWithPool(event, pool) : event;
}

/** Adds spot price and LP share valuation from current pool reserves. */
export function enrichWithPool(event: ClassicAmmEvent, pool: HorizonLiquidityPool): ClassicAmmEvent {
  if (pool.reserves.length !== 2) return event;
  const reserveOf = (asset: string) => pool.reserves.find((r) => r.asset === asset);
  const a = reserveOf(event.assetA.asset);
  const b = reserveOf(event.assetB.asset);
  const totalShares = Number(pool.total_shares);
  if (!a || !b || !Number.isFinite(totalShares) || totalShares <= 0) return event;

  const reserveA = Number(a.amount);
  const reserveB = Number(b.amount);
  if (!(reserveA > 0) || !(reserveB > 0)) return event;

  const fraction = event.shares / totalShares;
  return {
    ...event,
    poolPrice: reserveB / reserveA,
    shareValue: {
      assetA: reserveA * fraction,
      assetB: reserveB * fraction,
      sharePct: fraction * 100,
    },
  };
}

/** True when the pool's spot price currently sits outside the accepted band. */
export function isPriceOutsideBounds(event: ClassicAmmEvent): boolean {
  if (event.poolPrice === undefined || event.minPrice === undefined || event.maxPrice === undefined) {
    return false;
  }
  return event.poolPrice < event.minPrice || event.poolPrice > event.maxPrice;
}

export interface SubscriberLookup {
  /** User IDs watching either the acting wallet or the pool ID. */
  (keys: { account: string; poolId: string }): Promise<string[]>;
}

/**
 * Default matcher: a subscriber watches a pool by registering the 64-hex pool
 * ID as a monitored identifier alongside their normal wallet addresses.
 */
export const defaultSubscriberLookup: SubscriberLookup = async ({ account, poolId }) => {
  const rows = await prisma.wallet.findMany({
    where: { publicKey: { in: [account, poolId, poolId.toUpperCase()] }, deletedAt: null },
    select: { userId: true },
  });
  return [...new Set(rows.map((r) => r.userId))];
};

export type PoolFetcher = (poolId: string) => Promise<HorizonLiquidityPool | null>;
export type AmmNotifier = (userId: string, event: ClassicAmmEvent) => Promise<void>;

export function buildClassicAmmWebhookPayload(event: ClassicAmmEvent): Record<string, unknown> {
  return {
    event: event.kind === 'DEPOSIT' ? 'stellar.lp_deposit' : 'stellar.lp_withdraw',
    severity: isPriceOutsideBounds(event) ? 'HIGH' : 'MEDIUM',
    poolId: event.poolId,
    account: event.account,
    transactionHash: event.transactionHash,
    assetA: event.assetA,
    assetB: event.assetB,
    shares: event.shares,
    minPrice: event.minPrice,
    maxPrice: event.maxPrice,
    poolPrice: event.poolPrice,
    slippageTolerancePct: event.slippageTolerancePct,
    executedSlippagePct: event.executedSlippagePct,
    shareValue: event.shareValue,
    priceOutsideBounds: isPriceOutsideBounds(event),
    timestamp: event.timestamp,
  };
}

const fmt = (n: number, digits = 4) => n.toFixed(digits).replace(/\.?0+$/, '') || '0';

export function buildClassicAmmTelegramMessage(event: ClassicAmmEvent): string {
  const verb = event.kind === 'DEPOSIT' ? 'deposited into' : 'withdrawn from';
  const lines = [
    `<b>Liquidity pool ${event.kind.toLowerCase()}</b>`,
    `<b>Pool:</b> <code>${escapeTelegramHtml(event.poolId)}</code>`,
    `<b>Account:</b> <code>${escapeTelegramHtml(event.account)}</code>`,
    `${fmt(event.assetA.amount)} ${escapeTelegramHtml(event.assetA.asset)} + ` +
      `${fmt(event.assetB.amount)} ${escapeTelegramHtml(event.assetB.asset)} ${verb} the pool`,
    `<b>LP shares:</b> ${fmt(event.shares)}`,
  ];
  if (event.minPrice !== undefined && event.maxPrice !== undefined) {
    lines.push(`<b>Price bounds:</b> ${fmt(event.minPrice, 6)} – ${fmt(event.maxPrice, 6)}`);
  }
  if (event.slippageTolerancePct !== undefined) {
    lines.push(`<b>Slippage tolerance:</b> ${fmt(event.slippageTolerancePct, 2)}%`);
  }
  if (isPriceOutsideBounds(event)) lines.push('⚠️ Pool price is outside the accepted bounds.');
  if (event.transactionHash) lines.push(`<b>Transaction:</b> <code>${escapeTelegramHtml(event.transactionHash)}</code>`);
  return lines.join('\n');
}

const defaultNotifier: AmmNotifier = (userId, event) =>
  deliverUserAlert(userId, buildClassicAmmWebhookPayload(event), buildClassicAmmTelegramMessage(event));

export interface ClassicAmmWatcherDeps {
  lookupSubscribers?: SubscriberLookup;
  fetchPool?: PoolFetcher;
  notify?: AmmNotifier;
}

export class ClassicAmmWatcher {
  private readonly lookupSubscribers: SubscriberLookup;
  private readonly fetchPool?: PoolFetcher;
  private readonly notify: AmmNotifier;

  constructor(deps: ClassicAmmWatcherDeps = {}) {
    this.lookupSubscribers = deps.lookupSubscribers ?? defaultSubscriberLookup;
    this.fetchPool = deps.fetchPool;
    this.notify = deps.notify ?? defaultNotifier;
  }

  /**
   * Decodes, enriches and delivers one operation. Returns null for operations
   * that are not classic pool deposits/withdrawals or that fail to decode, so
   * one bad record can never stall the ingest loop.
   */
  async inspectOperation(op: HorizonLiquidityPoolOperation): Promise<ClassicAmmEvent | null> {
    if (!isClassicAmmOperation(op)) return null;

    let pool: HorizonLiquidityPool | null = null;
    if (this.fetchPool && op.liquidity_pool_id && POOL_ID_PATTERN.test(op.liquidity_pool_id)) {
      try {
        pool = await this.fetchPool(op.liquidity_pool_id.toLowerCase());
      } catch (err) {
        log.warn(
          { poolId: op.liquidity_pool_id, err: err instanceof Error ? err.message : String(err) },
          'Pool state fetch failed; continuing without share valuation',
        );
      }
    }

    let event: ClassicAmmEvent;
    try {
      event = decodeClassicAmmOperation(op, pool);
    } catch (err) {
      log.warn(
        { operationId: op.id, err: err instanceof Error ? err.message : String(err) },
        'Skipping undecodable liquidity pool operation',
      );
      return null;
    }

    const userIds = await this.lookupSubscribers({ account: event.account, poolId: event.poolId });
    for (const userId of userIds) {
      try {
        await this.notify(userId, event);
      } catch (err) {
        log.warn(
          { userId, poolId: event.poolId, err: err instanceof Error ? err.message : String(err) },
          'Classic AMM alert delivery failed',
        );
      }
    }
    return event;
  }

  /** Inspects a page of operations, ignoring everything that is not a pool operation. */
  async inspectOperations(ops: readonly HorizonLiquidityPoolOperation[]): Promise<ClassicAmmEvent[]> {
    const events: ClassicAmmEvent[] = [];
    for (const op of ops) {
      const event = await this.inspectOperation(op);
      if (event) events.push(event);
    }
    return events;
  }
}

export const classicAmmWatcher = new ClassicAmmWatcher();
