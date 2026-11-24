import { describe, it, expect } from 'vitest';
import type { TailEvent } from './stream-printer.js';
import {
  matchesTailFilter,
  serializeNdjson,
  formatHumanEvent,
  formatSessionSummary,
  paymentToTailEvent,
  sorobanEventToTailEvent,
} from './stream-printer.js';
import type { PaymentDTO, SorobanEventDTO } from '../lib/types.js';

const payment: PaymentDTO = {
  id: 'p1',
  walletId: 'wallet-1',
  txHash: 'tx-1',
  fromAddress: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  amount: '12.5',
  asset: 'USDC',
  memo: 'invoice-7',
  receivedAt: '2026-11-24T10:20:30.000Z',
};

const sorobanEvent: SorobanEventDTO = {
  id: 's1',
  contractId: 'CBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
  topic: ['transfer', 'from', 'to'],
  amount: 3,
  asset: 'USDC',
  from: 'GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  to: 'GCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC',
  txHash: 'tx-2',
  ledger: 12345,
  createdAt: '2026-11-24T10:21:00.000Z',
};

function events(): TailEvent[] {
  return [paymentToTailEvent(payment), sorobanEventToTailEvent(sorobanEvent)];
}

describe('matchesTailFilter', () => {
  it('matches every event when no filters are set', () => {
    for (const event of events()) expect(matchesTailFilter(event, {})).toBe(true);
  });

  it('matches a wallet address case-insensitively across payment and Soroban events', () => {
    const filter = { wallet: 'gaaaaaaaaaaaa' };
    expect(matchesTailFilter(paymentToTailEvent(payment), filter)).toBe(true);
    expect(matchesTailFilter(sorobanEventToTailEvent(sorobanEvent), filter)).toBe(true);
  });

  it('matches a wallet id and rejects an unrelated wallet', () => {
    expect(matchesTailFilter(paymentToTailEvent(payment), { wallet: 'wallet-1' })).toBe(true);
    expect(matchesTailFilter(paymentToTailEvent(payment), { wallet: 'wallet-9' })).toBe(false);
  });

  it('matches contract ids on both event kinds and rejects mismatches', () => {
    const filter = { contract: 'cbbbbbbbbb' };
    expect(matchesTailFilter(sorobanEventToTailEvent(sorobanEvent), filter)).toBe(true);
    expect(matchesTailFilter(paymentToTailEvent(payment), filter)).toBe(false);
  });

  it('matches asset codes exactly but case-insensitively', () => {
    expect(matchesTailFilter(paymentToTailEvent(payment), { asset: 'usdc' })).toBe(true);
    expect(matchesTailFilter(paymentToTailEvent(payment), { asset: 'USD' })).toBe(false);
  });

  it('applies the inclusive minimum amount threshold to numeric strings and numbers', () => {
    expect(matchesTailFilter(paymentToTailEvent(payment), { minAmount: 12.5 })).toBe(true);
    expect(matchesTailFilter(paymentToTailEvent(payment), { minAmount: 12.51 })).toBe(false);
    expect(matchesTailFilter(sorobanEventToTailEvent(sorobanEvent), { minAmount: 3 })).toBe(true);
  });

  it('rejects events with missing or non-finite amounts when a minimum is required', () => {
    const noAmount: TailEvent = { kind: 'soroban', id: 's2', asset: 'XLM' };
    const badAmount: TailEvent = { kind: 'soroban', id: 's3', amount: 'not-a-number' };
    expect(matchesTailFilter(noAmount, { minAmount: 1 })).toBe(false);
    expect(matchesTailFilter(badAmount, { minAmount: 1 })).toBe(false);
  });

  it('ANDs multiple filters together', () => {
    const filter = { wallet: 'gAAAAAAAA', asset: 'usdc', minAmount: 10 };
    expect(matchesTailFilter(paymentToTailEvent(payment), filter)).toBe(true);
    expect(matchesTailFilter(sorobanEventToTailEvent(sorobanEvent), { ...filter, minAmount: 10 })).toBe(false);
  });
});

describe('serializeNdjson', () => {
  it('produces one parseable line with normalized fields for each event kind', () => {
    for (const event of events()) {
      const line = serializeNdjson(event);
      expect(line).not.toContain('\n');
      const parsed = JSON.parse(line) as Record<string, unknown>;
      expect(parsed.id).toBe(event.id);
      expect(parsed.type).toBe(event.kind);
      expect(parsed.asset).toBe('USDC');
      expect(parsed.amount).toBe(event.kind === 'payment' ? 12.5 : 3);
      expect(parsed.timestamp).toBe(event.kind === 'payment'
        ? '2026-11-24T10:20:30.000Z'
        : '2026-11-24T10:21:00.000Z');
    }
  });

  it('escapes newlines inside string values so stdout stays line-delimited', () => {
    const event: TailEvent = {
      ...paymentToTailEvent(payment),
      memo: 'line one\nline two',
    };
    const line = serializeNdjson(event);
    expect(line).not.toContain('\n');
    expect((JSON.parse(line) as { memo: string }).memo).toBe('line one\nline two');
  });

  it('omits optional fields instead of emitting nulls', () => {
    const parsed = JSON.parse(serializeNdjson({ kind: 'soroban', id: 's9' })) as Record<string, unknown>;
    expect(parsed).toEqual({ type: 'soroban', id: 's9' });
  });
});

describe('formatHumanEvent', () => {
  it('renders a readable line containing the kind, amount, asset and address', () => {
    const line = formatHumanEvent(paymentToTailEvent(payment));
    expect(line).toContain('PAYMENT');
    expect(line).toContain('12.5');
    expect(line).toContain('USDC');
    expect(line).toContain('invoice-7');
  });

  it('renders Soroban events with their contract topic', () => {
    const line = formatHumanEvent(sorobanEventToTailEvent(sorobanEvent));
    expect(line).toContain('SOROBAN');
    expect(line).toContain('transfer,from,to');
  });
});

describe('formatSessionSummary', () => {
  it('reports duration, inspected/matched counts and the per-second match rate', () => {
    const summary = formatSessionSummary({
      startedAt: 1_000,
      endedAt: 4_000,
      inspected: 40,
      matched: 6,
    });
    expect(summary).toContain('Duration:         3.0s');
    expect(summary).toContain('Events inspected: 40');
    expect(summary).toContain('Matched:          6');
    expect(summary).toContain('Match rate:       2.00/sec');
  });

  it('does not divide by zero for an instantaneous session', () => {
    const summary = formatSessionSummary({
      startedAt: 1_000,
      endedAt: 1_000,
      inspected: 0,
      matched: 0,
    });
    expect(summary).toContain('Duration:         0.0s');
    expect(summary).toContain('Match rate:       0.00/sec');
  });
});
