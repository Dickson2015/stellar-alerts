import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../lib/prisma', () => ({ prisma: { wallet: { findMany: vi.fn() } } }));
vi.mock('../alert-delivery', () => ({
  deliverUserAlert: vi.fn(),
  escapeTelegramHtml: (v: string) => v,
}));

import {
  ClassicAmmDecodeError,
  ClassicAmmWatcher,
  buildClassicAmmTelegramMessage,
  buildClassicAmmWebhookPayload,
  decodeClassicAmmOperation,
  isPriceOutsideBounds,
  type HorizonLiquidityPool,
  type HorizonLiquidityPoolOperation,
} from '../classic-amm.service';

const POOL_ID = 'a'.repeat(64);
const USDC = 'USDC:GISSUER';
const WALLET = 'GWALLET';

const deposit = (over: Partial<HorizonLiquidityPoolOperation> = {}): HorizonLiquidityPoolOperation => ({
  id: 'op1',
  type: 'liquidity_pool_deposit',
  transaction_hash: 'tx1',
  source_account: WALLET,
  created_at: '2026-11-24T10:00:00Z',
  liquidity_pool_id: POOL_ID,
  reserves_max: [
    { asset: 'native', amount: '1000.0000000' },
    { asset: USDC, amount: '200.0000000' },
  ],
  min_price: '0.1900000',
  max_price: '0.2100000',
  min_price_r: { n: 19, d: 100 },
  max_price_r: { n: 21, d: 100 },
  reserves_deposited: [
    { asset: 'native', amount: '950.0000000' },
    { asset: USDC, amount: '190.0000000' },
  ],
  shares_received: '420.0000000',
  ...over,
});

const withdraw = (over: Partial<HorizonLiquidityPoolOperation> = {}): HorizonLiquidityPoolOperation => ({
  id: 'op2',
  type: 'liquidity_pool_withdraw',
  transaction_hash: 'tx2',
  source_account: WALLET,
  created_at: '2026-11-24T11:00:00Z',
  liquidity_pool_id: POOL_ID,
  shares: '100.0000000',
  reserves_min: [
    { asset: 'native', amount: '90.0000000' },
    { asset: USDC, amount: '18.0000000' },
  ],
  reserves_received: [
    { asset: 'native', amount: '100.0000000' },
    { asset: USDC, amount: '20.0000000' },
  ],
  ...over,
});

const pool = (over: Partial<HorizonLiquidityPool> = {}): HorizonLiquidityPool => ({
  id: POOL_ID,
  total_shares: '10000.0000000',
  reserves: [
    { asset: 'native', amount: '50000.0000000' },
    { asset: USDC, amount: '10000.0000000' },
  ],
  ...over,
});

describe('decodeClassicAmmOperation', () => {
  it('decodes a deposit: pool id, both assets, shares, price bounds', () => {
    const e = decodeClassicAmmOperation(deposit());
    expect(e.kind).toBe('DEPOSIT');
    expect(e.poolId).toBe(POOL_ID);
    expect(e.account).toBe(WALLET);
    expect(e.assetA).toEqual({ asset: 'native', amount: 950, limit: 1000 });
    expect(e.assetB).toEqual({ asset: USDC, amount: 190, limit: 200 });
    expect(e.shares).toBe(420);
    expect(e.minPrice).toBeCloseTo(0.19);
    expect(e.maxPrice).toBeCloseTo(0.21);
  });

  it('computes slippage tolerance from the price band', () => {
    // (0.21 - 0.19) / 0.20 = 10%
    expect(decodeClassicAmmOperation(deposit()).slippageTolerancePct).toBeCloseTo(10);
  });

  it('reports deposit headroom against reserves_max', () => {
    // Largest consumption ratio is 0.95, so 5% headroom.
    expect(decodeClassicAmmOperation(deposit()).executedSlippagePct).toBeCloseTo(5);
  });

  it('prefers exact rational prices over rounded decimal strings', () => {
    const e = decodeClassicAmmOperation(
      deposit({ min_price: '0.3333333', min_price_r: { n: 1, d: 3 }, max_price: '0.5', max_price_r: { n: 1, d: 2 } }),
    );
    expect(e.minPrice).toBeCloseTo(1 / 3, 12);
  });

  it('decodes a withdraw: shares burned and assets received', () => {
    const e = decodeClassicAmmOperation(withdraw());
    expect(e.kind).toBe('WITHDRAW');
    expect(e.shares).toBe(100);
    expect(e.assetA.amount).toBe(100);
    expect(e.assetB.limit).toBe(18);
    expect(e.minPrice).toBeUndefined();
  });

  it('withdraw receiving more than the minimum has negative shortfall', () => {
    // 100 vs min 90 = -11.1%; 20 vs 18 = -11.1%
    expect(decodeClassicAmmOperation(withdraw()).executedSlippagePct).toBeCloseTo(-11.11, 1);
  });

  it('withdraw exactly at the minimum has zero shortfall', () => {
    const e = decodeClassicAmmOperation(
      withdraw({
        reserves_received: [
          { asset: 'native', amount: '90.0000000' },
          { asset: USDC, amount: '18.0000000' },
        ],
      }),
    );
    expect(e.executedSlippagePct).toBeCloseTo(0);
  });

  it('lowercases the pool id', () => {
    expect(decodeClassicAmmOperation(deposit({ liquidity_pool_id: 'A'.repeat(64) })).poolId).toBe(POOL_ID);
  });

  it.each([
    ['bad pool id', deposit({ liquidity_pool_id: 'xyz' })],
    ['missing pool id', deposit({ liquidity_pool_id: undefined })],
    ['missing source', deposit({ source_account: undefined })],
    ['one-sided reserves', deposit({ reserves_deposited: [{ asset: 'native', amount: '1' }] })],
    ['missing shares', deposit({ shares_received: undefined })],
    ['inverted bounds', deposit({ min_price_r: { n: 3, d: 10 }, max_price_r: { n: 1, d: 10 } })],
    ['unsupported type', { ...deposit(), type: 'payment' }],
  ])('throws on %s', (_label, op) => {
    expect(() => decodeClassicAmmOperation(op as HorizonLiquidityPoolOperation)).toThrow(ClassicAmmDecodeError);
  });
});

describe('LP share valuation', () => {
  it('values shares against current reserves', () => {
    // 420 / 10000 = 4.2% of each reserve.
    const e = decodeClassicAmmOperation(deposit(), pool());
    expect(e.shareValue!.sharePct).toBeCloseTo(4.2);
    expect(e.shareValue!.assetA).toBeCloseTo(2100);
    expect(e.shareValue!.assetB).toBeCloseTo(420);
    expect(e.poolPrice).toBeCloseTo(0.2);
  });

  it('matches reserves by asset regardless of order', () => {
    const swapped = pool({ reserves: [...pool().reserves].reverse() });
    expect(decodeClassicAmmOperation(deposit(), swapped).shareValue!.assetA).toBeCloseTo(2100);
  });

  it.each([
    ['zero total shares', pool({ total_shares: '0' })],
    ['empty reserve', pool({ reserves: [{ asset: 'native', amount: '0' }, { asset: USDC, amount: '1' }] })],
    ['unknown asset', pool({ reserves: [{ asset: 'native', amount: '1' }, { asset: 'EURC:GX', amount: '1' }] })],
  ])('skips valuation for %s', (_l, p) => {
    expect(decodeClassicAmmOperation(deposit(), p).shareValue).toBeUndefined();
  });

  it('flags a pool price outside the accepted bounds', () => {
    const inside = decodeClassicAmmOperation(deposit(), pool());
    const outside = decodeClassicAmmOperation(
      deposit(),
      pool({ reserves: [{ asset: 'native', amount: '10000' }, { asset: USDC, amount: '5000' }] }),
    );
    expect(isPriceOutsideBounds(inside)).toBe(false);
    expect(isPriceOutsideBounds(outside)).toBe(true);
    expect(buildClassicAmmWebhookPayload(outside).severity).toBe('HIGH');
    expect(buildClassicAmmWebhookPayload(inside).severity).toBe('MEDIUM');
  });
});

describe('ClassicAmmWatcher', () => {
  const make = (over: Partial<ConstructorParameters<typeof ClassicAmmWatcher>[0]> = {}) => {
    const notify = vi.fn(async () => {});
    const lookupSubscribers = vi.fn(async () => ['u1', 'u2']);
    const watcher = new ClassicAmmWatcher({ notify, lookupSubscribers, fetchPool: async () => pool(), ...over });
    return { watcher, notify, lookupSubscribers };
  };

  it('looks up subscribers by both wallet address and pool id', async () => {
    const { watcher, lookupSubscribers, notify } = make();
    await watcher.inspectOperation(deposit());
    expect(lookupSubscribers).toHaveBeenCalledWith({ account: WALLET, poolId: POOL_ID });
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('ignores non-pool operations without touching subscribers', async () => {
    const { watcher, lookupSubscribers } = make();
    expect(await watcher.inspectOperation({ type: 'payment' } as any)).toBeNull();
    expect(lookupSubscribers).not.toHaveBeenCalled();
  });

  it('skips malformed operations instead of throwing', async () => {
    const { watcher, notify } = make();
    expect(await watcher.inspectOperation(deposit({ liquidity_pool_id: 'bad' }))).toBeNull();
    expect(notify).not.toHaveBeenCalled();
  });

  it('still alerts when pool state cannot be fetched', async () => {
    const { watcher, notify } = make({ fetchPool: async () => { throw new Error('horizon down'); } });
    const event = await watcher.inspectOperation(deposit());
    expect(event?.shareValue).toBeUndefined();
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('one failing subscriber does not block the rest', async () => {
    const notify = vi.fn().mockRejectedValueOnce(new Error('boom')).mockResolvedValue(undefined);
    const { watcher } = make({ notify });
    await watcher.inspectOperation(deposit());
    expect(notify).toHaveBeenCalledTimes(2);
  });

  it('inspectOperations returns only decoded pool events', async () => {
    const { watcher } = make();
    const events = await watcher.inspectOperations([deposit(), { type: 'payment' } as any, withdraw()]);
    expect(events.map((e) => e.kind)).toEqual(['DEPOSIT', 'WITHDRAW']);
  });
});

describe('alert formatting', () => {
  it('includes pool id, shares and bounds in the message', () => {
    const msg = buildClassicAmmTelegramMessage(decodeClassicAmmOperation(deposit(), pool()));
    expect(msg).toContain(POOL_ID);
    expect(msg).toContain('420');
    expect(msg).toContain('Price bounds');
    expect(msg).toContain('Slippage tolerance');
  });

  it('webhook payload uses stable event names', () => {
    expect(buildClassicAmmWebhookPayload(decodeClassicAmmOperation(deposit())).event).toBe('stellar.lp_deposit');
    expect(buildClassicAmmWebhookPayload(decodeClassicAmmOperation(withdraw())).event).toBe('stellar.lp_withdraw');
  });
});
