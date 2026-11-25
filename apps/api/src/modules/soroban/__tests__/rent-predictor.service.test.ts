import { describe, expect, it } from 'vitest';
import {
  estimateRentCostStroops,
  formatStroopsAsXlm,
  projectRentExhaustion,
  type RentNetworkConfig,
} from '../rent-predictor.service';

const config: RentNetworkConfig = {
  ledgerCloseTimeSeconds: 5,
  persistentRentRateDenominator: 100_000n,
  temporaryRentRateDenominator: 200_000n,
};

describe('Soroban rent predictor', () => {
  it('prices persistent and temporary storage from their network rent denominators', () => {
    expect(estimateRentCostStroops(1024, 100, 'PERSISTENT', config)).toBe(10_240_000n);
    expect(estimateRentCostStroops(1024, 100, 'TEMPORARY', config)).toBe(5_120_000n);
    expect(formatStroopsAsXlm(10_240_000n)).toBe('1.0240000');
  });

  it('rounds a fractional stroop upward and rejects invalid input', () => {
    expect(estimateRentCostStroops(1, 1, 'PERSISTENT', {
      ...config,
      persistentRentRateDenominator: 20_000_000n,
    })).toBe(1n);
    expect(() => estimateRentCostStroops(-1, 1, 'PERSISTENT', config)).toThrow(RangeError);
    expect(() => estimateRentCostStroops(1, 1, 'PERSISTENT', {
      ...config,
      persistentRentRateDenominator: 0n,
    })).toThrow(RangeError);
  });

  it('projects growth, archival time, tiered warnings, and renewal options', () => {
    const now = new Date('2026-01-01T00:00:00.000Z');
    const result = projectRentExhaustion(
      {
        currentLedger: 1000,
        liveUntilLedgerSeq: 242_920,
        currentByteSize: 2000,
        previousByteSize: 1000,
        ledgersBetweenSamples: 100_000,
        now,
      },
      'PERSISTENT',
      config,
    );

    expect(result.daysUntilArchival).toBe(14);
    expect(result.archivalAt).toEqual(new Date(now.getTime() + 14 * 86_400_000));
    expect(result.byteGrowthPerDay).toBe(172.8);
    expect(result.projectedBytesAtArchival).toBe(4420);
    expect(result.warningTier).toBe('14_DAYS');
    expect(BigInt(result.extensionCostsXlm[30].replace('.', ''))).toBeGreaterThan(0n);
    expect(BigInt(result.extensionCostsXlm[90].replace('.', ''))).toBeGreaterThan(
      BigInt(result.extensionCostsXlm[30].replace('.', '')),
    );
    expect(BigInt(result.extensionCostsXlm[180].replace('.', ''))).toBeGreaterThan(
      BigInt(result.extensionCostsXlm[90].replace('.', '')),
    );
  });

  it.each([
    [2, '48_HOURS'],
    [7, '7_DAYS'],
    [14, '14_DAYS'],
    [15, null],
  ] as const)('uses the correct warning tier at %i days', (days, warningTier) => {
    const projected = projectRentExhaustion(
      {
        currentLedger: 10,
        liveUntilLedgerSeq: 10 + (days * 86_400) / config.ledgerCloseTimeSeconds,
        currentByteSize: 1,
        previousByteSize: 1,
        ledgersBetweenSamples: 1,
        now: new Date(0),
      },
      'INSTANCE',
      config,
    );
    expect(projected.warningTier).toBe(warningTier);
  });
});
