import { createLogger } from '../../lib/logger';

const logger = createLogger({ module: 'MevArbitrageDetector' });

const STROOP_SCALE = 10_000_000;

/** One swap event from a single closed ledger. Amounts are integer base units (7 decimals). */
export interface LedgerSwap {
  txHash: string;
  /** Application order of the transaction inside the ledger. */
  txIndex: number;
  /** Order of the swap inside its transaction. */
  opIndex?: number;
  ledgerSeq: number;
  poolId: string;
  trader: string;
  tokenIn: string;
  tokenOut: string;
  amountIn: string | bigint | number;
  amountOut: string | bigint | number;
}

export interface ProfitQuote {
  asset: string;
  /** Profit in whole units of `asset`. */
  amount: number;
  usdc: number | null;
  xlm: number | null;
}

export interface ArbitrageCycleAlert {
  type: 'CYCLIC_ARBITRAGE';
  ledgerSeq: number;
  trader: string;
  /** Asset path, first and last entries are the same asset (A -> B -> C -> A). */
  path: string[];
  pools: string[];
  txHashes: string[];
  profit: ProfitQuote;
  summary: string;
}

export interface SandwichAlert {
  type: 'SANDWICH';
  ledgerSeq: number;
  attacker: string;
  victim: string;
  poolId: string;
  frontRunTxHash: string;
  victimTxHash: string;
  backRunTxHash: string;
  profit: ProfitQuote;
  /** Victim execution price vs. the attacker's front-run price, in percent (0 when unknown). */
  victimPriceImpactPct: number;
  summary: string;
}

export type MevAlert = ArbitrageCycleAlert | SandwichAlert;

export interface MevAlertWithPool {
  alert: MevAlert;
  /** Pools whose subscribers should hear about this alert. */
  affectedPools: string[];
}

export type MevAlertHandler = (alert: MevAlert) => void | Promise<void>;

/** Prices one whole unit of `asset` in USDC; null when unknown. */
export type PriceResolver = (asset: string) => number | null;

export interface MevDetectorOptions {
  priceResolver?: PriceResolver;
  /** USDC price of 1 XLM, used to express profit in XLM. */
  xlmPriceUsdc?: number;
  /** Profits below this USDC value are ignored; only applies when a price is known. */
  minProfitUsdc?: number;
  /** Longest arbitrage cycle (in swaps) to look for. */
  maxCycleLength?: number;
}

function toBigInt(value: string | bigint | number): bigint {
  try {
    return BigInt(value);
  } catch {
    return 0n;
  }
}

function isNativeXlm(asset: string): boolean {
  const upper = asset.toUpperCase();
  return upper === 'XLM' || upper === 'NATIVE';
}

function isUsdc(asset: string): boolean {
  return asset.toUpperCase().startsWith('USDC');
}

function compareSwaps(a: LedgerSwap, b: LedgerSwap): number {
  return a.txIndex - b.txIndex || (a.opIndex ?? 0) - (b.opIndex ?? 0);
}

/**
 * Scans the swaps of one closed ledger for cyclic arbitrage (A->B->C->A at a net
 * profit across at least two pools) and sandwich extraction (attacker buys before
 * and sells after a victim swap on the same pool).
 *
 * Detection is pure: it never touches the network or the database, so a whole
 * ledger can be replayed deterministically.
 */
export class MevArbitrageDetector {
  private readonly priceResolver: PriceResolver;
  private readonly xlmPriceUsdc: number | null;
  private readonly minProfitUsdc: number;
  private readonly maxCycleLength: number;
  private readonly poolSubscribers = new Map<string, Set<MevAlertHandler>>();

  constructor(options: MevDetectorOptions = {}) {
    this.xlmPriceUsdc = options.xlmPriceUsdc ?? null;
    this.priceResolver = options.priceResolver ?? this.defaultPriceResolver.bind(this);
    this.minProfitUsdc = options.minProfitUsdc ?? 0;
    this.maxCycleLength = options.maxCycleLength ?? 6;
  }

  /** Subscribes to alerts that affect `poolId`. Returns an unsubscribe function. */
  public subscribePool(poolId: string, handler: MevAlertHandler): () => void {
    const set = this.poolSubscribers.get(poolId) ?? new Set<MevAlertHandler>();
    set.add(handler);
    this.poolSubscribers.set(poolId, set);
    return () => set.delete(handler);
  }

  public clearSubscriptions(): void {
    this.poolSubscribers.clear();
  }

  /** Detects MEV in one ledger's swaps. Swaps from other ledgers are rejected, not mixed in. */
  public analyzeLedger(swaps: readonly LedgerSwap[]): MevAlertWithPool[] {
    if (swaps.length === 0) return [];
    const ledgerSeq = swaps[0].ledgerSeq;
    const ordered = swaps.filter((s) => s.ledgerSeq === ledgerSeq).sort(compareSwaps);

    const results: MevAlertWithPool[] = [];
    for (const alert of this.detectArbitrageCycles(ordered)) {
      results.push({ alert, affectedPools: [...new Set(alert.pools)] });
    }
    for (const alert of this.detectSandwiches(ordered)) {
      results.push({ alert, affectedPools: [alert.poolId] });
    }
    return results;
  }

  /** Analyzes a ledger and notifies the subscribers of every affected pool. */
  public async analyzeAndNotify(swaps: readonly LedgerSwap[]): Promise<MevAlertWithPool[]> {
    const results = this.analyzeLedger(swaps);
    for (const { alert, affectedPools } of results) {
      for (const poolId of affectedPools) {
        for (const handler of this.poolSubscribers.get(poolId) ?? []) {
          try {
            await handler(alert);
          } catch (err) {
            logger.warn(
              { poolId, err: err instanceof Error ? err.message : String(err) },
              'MEV alert handler failed',
            );
          }
        }
      }
    }
    return results;
  }

  public detectArbitrageCycles(ordered: readonly LedgerSwap[]): ArbitrageCycleAlert[] {
    const byTrader = new Map<string, LedgerSwap[]>();
    for (const swap of ordered) {
      const list = byTrader.get(swap.trader) ?? [];
      list.push(swap);
      byTrader.set(swap.trader, list);
    }

    const alerts: ArbitrageCycleAlert[] = [];
    for (const [trader, swaps] of byTrader) {
      let i = 0;
      while (i < swaps.length) {
        const cycleEnd = this.findCycleFrom(swaps, i);
        if (cycleEnd === -1) {
          i++;
          continue;
        }
        const chain = swaps.slice(i, cycleEnd + 1);
        const startAsset = chain[0].tokenIn;
        const profit = toBigInt(chain[chain.length - 1].amountOut) - toBigInt(chain[0].amountIn);
        const quote = this.quote(startAsset, profit);
        if (this.meetsMinimum(quote)) {
          alerts.push({
            type: 'CYCLIC_ARBITRAGE',
            ledgerSeq: chain[0].ledgerSeq,
            trader,
            path: [startAsset, ...chain.map((s) => s.tokenOut)],
            pools: chain.map((s) => s.poolId),
            txHashes: [...new Set(chain.map((s) => s.txHash))],
            profit: quote,
            summary:
              `Cyclic arbitrage by ${trader}: ${[startAsset, ...chain.map((s) => s.tokenOut)].join(' -> ')} ` +
              `netted ${quote.amount.toFixed(7)} ${startAsset}${this.usdcSuffix(quote)}.`,
          });
        }
        i = cycleEnd + 1;
      }
    }
    return alerts;
  }

  /**
   * Returns the index of the swap that closes a profitable cycle starting at `start`,
   * or -1. Each hop must spend the asset the previous hop produced, and the cycle
   * must touch at least two distinct pools (a same-pool round trip is not arbitrage).
   */
  private findCycleFrom(swaps: readonly LedgerSwap[], start: number): number {
    const first = swaps[start];
    const startAsset = first.tokenIn;
    const spent = toBigInt(first.amountIn);
    let carriedAsset = first.tokenOut;
    let carriedAmount = toBigInt(first.amountOut);
    const pools = new Set([first.poolId]);

    for (let j = start + 1; j < swaps.length && j - start < this.maxCycleLength; j++) {
      const swap = swaps[j];
      if (swap.tokenIn !== carriedAsset || toBigInt(swap.amountIn) > carriedAmount) break;

      pools.add(swap.poolId);
      carriedAsset = swap.tokenOut;
      carriedAmount = toBigInt(swap.amountOut);

      if (carriedAsset === startAsset) {
        return pools.size >= 2 && carriedAmount > spent ? j : -1;
      }
    }
    return -1;
  }

  public detectSandwiches(ordered: readonly LedgerSwap[]): SandwichAlert[] {
    const alerts: SandwichAlert[] = [];
    const used = new Set<LedgerSwap>();

    for (let v = 0; v < ordered.length; v++) {
      const victim = ordered[v];

      for (let f = 0; f < v; f++) {
        const front = ordered[f];
        if (used.has(front) || front.poolId !== victim.poolId || front.trader === victim.trader) continue;
        // Attacker buys the same asset the victim is about to buy, pushing its price up.
        if (front.tokenIn !== victim.tokenIn || front.tokenOut !== victim.tokenOut) continue;

        const back = this.findBackRun(ordered, v, front);
        if (!back) continue;

        const profit = toBigInt(back.amountOut) - toBigInt(front.amountIn);
        if (profit <= 0n) continue;

        const quote = this.quote(front.tokenIn, profit);
        if (!this.meetsMinimum(quote)) continue;

        used.add(front);
        alerts.push({
          type: 'SANDWICH',
          ledgerSeq: victim.ledgerSeq,
          attacker: front.trader,
          victim: victim.trader,
          poolId: victim.poolId,
          frontRunTxHash: front.txHash,
          victimTxHash: victim.txHash,
          backRunTxHash: back.txHash,
          profit: quote,
          victimPriceImpactPct: this.priceImpactPct(front, victim),
          summary:
            `Sandwich on pool ${victim.poolId}: ${front.trader} front- and back-ran ${victim.trader} ` +
            `for ${quote.amount.toFixed(7)} ${front.tokenIn}${this.usdcSuffix(quote)}.`,
        });
        break;
      }
    }
    return alerts;
  }

  /** The attacker's closing swap: after the victim, same pool, selling back what the front-run bought. */
  private findBackRun(
    ordered: readonly LedgerSwap[],
    victimIndex: number,
    front: LedgerSwap,
  ): LedgerSwap | null {
    for (let b = victimIndex + 1; b < ordered.length; b++) {
      const back = ordered[b];
      if (
        back.trader === front.trader &&
        back.poolId === front.poolId &&
        back.tokenIn === front.tokenOut &&
        back.tokenOut === front.tokenIn
      ) {
        return back;
      }
    }
    return null;
  }

  /** How much worse the victim's price was than the attacker's front-run price. */
  private priceImpactPct(front: LedgerSwap, victim: LedgerSwap): number {
    const frontOut = Number(toBigInt(front.amountOut));
    const victimOut = Number(toBigInt(victim.amountOut));
    const frontIn = Number(toBigInt(front.amountIn));
    const victimIn = Number(toBigInt(victim.amountIn));
    if (frontIn <= 0 || victimIn <= 0 || frontOut <= 0) return 0;

    const frontPrice = frontOut / frontIn;
    const victimPrice = victimOut / victimIn;
    return Math.max(0, ((frontPrice - victimPrice) / frontPrice) * 100);
  }

  private quote(asset: string, profitBaseUnits: bigint): ProfitQuote {
    const amount = Number(profitBaseUnits) / STROOP_SCALE;
    const price = this.priceResolver(asset);
    const usdc = price === null ? null : amount * price;
    const xlm = usdc !== null && this.xlmPriceUsdc ? usdc / this.xlmPriceUsdc : isNativeXlm(asset) ? amount : null;
    return { asset, amount, usdc, xlm };
  }

  private meetsMinimum(quote: ProfitQuote): boolean {
    return quote.amount > 0 && (quote.usdc === null || quote.usdc >= this.minProfitUsdc);
  }

  private usdcSuffix(quote: ProfitQuote): string {
    return quote.usdc === null ? '' : ` (~${quote.usdc.toFixed(2)} USDC)`;
  }

  private defaultPriceResolver(asset: string): number | null {
    if (isUsdc(asset)) return 1;
    if (isNativeXlm(asset)) return this.xlmPriceUsdc;
    return null;
  }
}

export const mevArbitrageDetector = new MevArbitrageDetector();
