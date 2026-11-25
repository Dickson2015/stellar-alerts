const STROOPS_PER_XLM = 10_000_000n;
const SECONDS_PER_DAY = 86_400;

export type RentDurability = 'PERSISTENT' | 'INSTANCE' | 'TEMPORARY';
export type RentWarningTier = '14_DAYS' | '7_DAYS' | '48_HOURS';

export interface RentObservation {
  key: string;
  durability: RentDurability;
  byteSize: number;
  liveUntilLedgerSeq: number;
}

export interface RentNetworkConfig {
  ledgerCloseTimeSeconds: number;
  persistentRentRateDenominator: bigint;
  temporaryRentRateDenominator: bigint;
}

export interface RentProjection {
  archivalAt: Date;
  daysUntilArchival: number;
  byteGrowthPerDay: number;
  projectedBytesAtArchival: number;
  extensionCostsXlm: Record<30 | 90 | 180, string>;
  warningTier: RentWarningTier | null;
}

export function formatStroopsAsXlm(stroops: bigint): string {
  const whole = stroops / STROOPS_PER_XLM;
  const fraction = (stroops % STROOPS_PER_XLM).toString().padStart(7, '0');
  return `${whole}.${fraction}`;
}

export function estimateRentCostStroops(
  byteSize: number,
  ledgers: number,
  durability: RentDurability,
  config: RentNetworkConfig,
): bigint {
  if (!Number.isSafeInteger(byteSize) || byteSize < 0 || !Number.isSafeInteger(ledgers) || ledgers < 0) {
    throw new RangeError('byteSize and ledgers must be non-negative safe integers');
  }

  const feeRateDenominator =
    durability === 'TEMPORARY'
      ? config.temporaryRentRateDenominator
      : config.persistentRentRateDenominator;
  if (feeRateDenominator <= 0n) throw new RangeError('rent fee denominator must be positive');
  const rentFeeNumerator = BigInt(byteSize) * BigInt(ledgers) * STROOPS_PER_XLM;
  return (rentFeeNumerator + feeRateDenominator - 1n) / feeRateDenominator;
}

export function projectRentExhaustion(
  input: {
    currentLedger: number;
    liveUntilLedgerSeq: number;
    currentByteSize: number;
    previousByteSize: number;
    ledgersBetweenSamples: number;
    now?: Date;
  },
  durability: RentDurability,
  config: RentNetworkConfig,
): RentProjection {
  const values = [
    input.currentLedger,
    input.liveUntilLedgerSeq,
    input.currentByteSize,
    input.previousByteSize,
    input.ledgersBetweenSamples,
  ];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new RangeError('ledger and byte measurements must be non-negative safe integers');
  }
  if (!Number.isFinite(config.ledgerCloseTimeSeconds) || config.ledgerCloseTimeSeconds <= 0) {
    throw new RangeError('ledgerCloseTimeSeconds must be positive');
  }
  if (input.ledgersBetweenSamples === 0) {
    throw new RangeError('ledgersBetweenSamples must be positive');
  }

  const growthPerLedger = Math.max(0, input.currentByteSize - input.previousByteSize) / input.ledgersBetweenSamples;
  const remainingLedgers = Math.max(0, input.liveUntilLedgerSeq - input.currentLedger);
  const daysUntilArchival =
    (remainingLedgers * config.ledgerCloseTimeSeconds) / SECONDS_PER_DAY;
  const projectedBytesAtArchival = Math.ceil(input.currentByteSize + growthPerLedger * remainingLedgers);
  const now = input.now ?? new Date();
  const archivalAt = new Date(now.getTime() + remainingLedgers * config.ledgerCloseTimeSeconds * 1000);

  const extensionCostsXlm = {
    30: formatStroopsAsXlm(
      estimateRentCostStroops(
        projectedBytesAtArchival,
        Math.ceil((30 * SECONDS_PER_DAY) / config.ledgerCloseTimeSeconds),
        durability,
        config,
      ),
    ),
    90: formatStroopsAsXlm(
      estimateRentCostStroops(
        projectedBytesAtArchival,
        Math.ceil((90 * SECONDS_PER_DAY) / config.ledgerCloseTimeSeconds),
        durability,
        config,
      ),
    ),
    180: formatStroopsAsXlm(
      estimateRentCostStroops(
        projectedBytesAtArchival,
        Math.ceil((180 * SECONDS_PER_DAY) / config.ledgerCloseTimeSeconds),
        durability,
        config,
      ),
    ),
  };

  return {
    archivalAt,
    daysUntilArchival,
    byteGrowthPerDay: growthPerLedger * (SECONDS_PER_DAY / config.ledgerCloseTimeSeconds),
    projectedBytesAtArchival,
    extensionCostsXlm,
    warningTier:
      daysUntilArchival <= 2 ? '48_HOURS' : daysUntilArchival <= 7 ? '7_DAYS' : daysUntilArchival <= 14 ? '14_DAYS' : null,
  };
}
