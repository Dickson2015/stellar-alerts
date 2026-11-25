import { describe, it, expect } from 'vitest';
import { MevArbitrageDetector, type LedgerSwap } from '../mev-detector';

const U = 10_000_000n; // 1 whole unit

let seq = 0;
function swap(over: Partial<LedgerSwap> & Pick<LedgerSwap, 'trader' | 'poolId' | 'tokenIn' | 'tokenOut'>, amountIn: bigint, amountOut: bigint): LedgerSwap {
  seq++;
  return { txHash: `tx${seq}`, txIndex: seq, ledgerSeq: 500, amountIn, amountOut, ...over };
}

const detector = () => new MevArbitrageDetector({ xlmPriceUsdc: 0.1 });

describe('MevArbitrageDetector (#970)', () => {
  describe('cyclic arbitrage', () => {
    it('finds a profitable A->B->C->A cycle across pools', () => {
      seq = 0;
      const swaps = [
        swap({ trader: 'GBOT', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 100n * U, 1000n * U),
        swap({ trader: 'GBOT', poolId: 'P2', tokenIn: 'XLM', tokenOut: 'AQUA' }, 1000n * U, 50_000n * U),
        swap({ trader: 'GBOT', poolId: 'P3', tokenIn: 'AQUA', tokenOut: 'USDC' }, 50_000n * U, 103n * U),
      ];
      const results = detector().analyzeLedger(swaps);
      expect(results).toHaveLength(1);
      const alert = results[0].alert;
      expect(alert.type).toBe('CYCLIC_ARBITRAGE');
      if (alert.type !== 'CYCLIC_ARBITRAGE') return;
      expect(alert.path).toEqual(['USDC', 'XLM', 'AQUA', 'USDC']);
      expect(alert.profit.amount).toBe(3);
      expect(alert.profit.usdc).toBe(3);
      expect(alert.profit.xlm).toBeCloseTo(30);
      expect(results[0].affectedPools.sort()).toEqual(['P1', 'P2', 'P3']);
    });

    it('ignores a cycle that loses money', () => {
      seq = 0;
      const swaps = [
        swap({ trader: 'GBOT', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 100n * U, 1000n * U),
        swap({ trader: 'GBOT', poolId: 'P2', tokenIn: 'XLM', tokenOut: 'USDC' }, 1000n * U, 99n * U),
      ];
      expect(detector().analyzeLedger(swaps)).toHaveLength(0);
    });

    it('ignores a same-pool round trip', () => {
      seq = 0;
      const swaps = [
        swap({ trader: 'GBOT', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 100n * U, 1000n * U),
        swap({ trader: 'GBOT', poolId: 'P1', tokenIn: 'XLM', tokenOut: 'USDC' }, 1000n * U, 101n * U),
      ];
      expect(detector().analyzeLedger(swaps)).toHaveLength(0);
    });

    it('does not join swaps from different traders into one cycle', () => {
      seq = 0;
      const swaps = [
        swap({ trader: 'GA', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 100n * U, 1000n * U),
        swap({ trader: 'GB', poolId: 'P2', tokenIn: 'XLM', tokenOut: 'USDC' }, 1000n * U, 120n * U),
      ];
      expect(detector().analyzeLedger(swaps)).toHaveLength(0);
    });
  });

  describe('sandwich extraction', () => {
    function sandwich(backOut: bigint) {
      seq = 0;
      return [
        swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 1000n * U, 10_000n * U),
        swap({ trader: 'GVICTIM', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 500n * U, 4_500n * U),
        swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'XLM', tokenOut: 'USDC' }, 10_000n * U, backOut),
      ];
    }

    it('detects buy-before / sell-after around a victim and quantifies profit', () => {
      const results = detector().analyzeLedger(sandwich(1060n * U));
      expect(results).toHaveLength(1);
      const alert = results[0].alert;
      expect(alert.type).toBe('SANDWICH');
      if (alert.type !== 'SANDWICH') return;
      expect(alert.attacker).toBe('GATTACKER');
      expect(alert.victim).toBe('GVICTIM');
      expect(alert.profit.amount).toBe(60);
      expect(alert.profit.usdc).toBe(60);
      expect(alert.victimPriceImpactPct).toBeCloseTo(10);
      expect(results[0].affectedPools).toEqual(['P1']);
    });

    it('ignores an unprofitable round trip', () => {
      expect(detector().analyzeLedger(sandwich(990n * U))).toHaveLength(0);
    });

    it('requires the victim to sit between the attacker legs', () => {
      seq = 0;
      const swaps = [
        swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 1000n * U, 10_000n * U),
        swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'XLM', tokenOut: 'USDC' }, 10_000n * U, 1060n * U),
        swap({ trader: 'GVICTIM', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 500n * U, 4_500n * U),
      ];
      expect(detector().analyzeLedger(swaps).filter((r) => r.alert.type === 'SANDWICH')).toHaveLength(0);
    });

    it('orders swaps by tx index even when input is shuffled', () => {
      const [a, v, b] = sandwich(1060n * U);
      const results = detector().analyzeLedger([b, a, v]);
      expect(results.map((r) => r.alert.type)).toEqual(['SANDWICH']);
    });
  });

  it('notifies subscribers of every affected pool only', async () => {
    const d = detector();
    const hits: string[] = [];
    d.subscribePool('P1', (a) => { hits.push(`P1:${a.type}`); });
    d.subscribePool('PX', (a) => { hits.push(`PX:${a.type}`); });
    seq = 0;
    await d.analyzeAndNotify([
      swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 1000n * U, 10_000n * U),
      swap({ trader: 'GVICTIM', poolId: 'P1', tokenIn: 'USDC', tokenOut: 'XLM' }, 500n * U, 4_500n * U),
      swap({ trader: 'GATTACKER', poolId: 'P1', tokenIn: 'XLM', tokenOut: 'USDC' }, 10_000n * U, 1060n * U),
    ]);
    expect(hits).toEqual(['P1:SANDWICH']);
  });
});
