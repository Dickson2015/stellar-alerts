import { describe, it, expect, vi, beforeEach } from 'vitest';

const queueMocks = vi.hoisted(() => ({
  enqueuePaymentAlert: vi.fn().mockResolvedValue(undefined),
}));

const realtimeMocks = vi.hoisted(() => ({
  publishAlertEvent: vi.fn().mockResolvedValue(undefined),
}));

const prismaMocks = vi.hoisted(() => ({
  payment: {
    findMany: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('../../../lib/queue', () => queueMocks);
vi.mock('../../../lib/realtime', () => realtimeMocks);
vi.mock('../../../lib/prisma', () => ({ prisma: prismaMocks }));

import {
  AddressPoisoningDetector,
  PHISHING_WARNING_BANNER,
  compareVanitySimilarity,
  findVanityLookalikeMatch,
} from '../address-poisoning.service';

// 56-character Stellar-shaped public keys for testing
const TRUSTED_COUNTERPARTY =
  'GDQP2KPQGKIHYJGXNUIYOMHARUARCA7DJT5FO2FFOOKY3B2WSFMG4BVI';
const SECOND_COUNTERPARTY =
  'GBPDX2DPUHABCGNHXQRNK5A6NGV5R7T244HJ5CXAWSWVRTZR4WMADE72';
// Crafted vanity lookalike: matches first 4 ("GDQP") and last 4 ("4BVI") with different middle chars
const VANITY_LOOKALIKE_4X4 =
  'GDQPXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX4BVI';
// Crafted stronger vanity lookalike: matches first 6 ("GDQP2K") and last 6 ("MG4BVI")
const VANITY_LOOKALIKE_6X6 =
  'GDQP2KYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYMG4BVI';
// Random unrelated address
const RANDOM_ADDRESS =
  'GC3C4AKRBQLHOJ45U4XG35ESVWRDECWO5XLDGYADO6DPR3L7KIDVUMML';
// Matches only prefix (>=4), different suffix
const PREFIX_ONLY_ADDRESS =
  'GDQP2KZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ9999';
// Matches only suffix (>=4), different prefix
const SUFFIX_ONLY_ADDRESS =
  'GAAA99ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ4BVI';
// Matches only 3 prefix chars + 4 suffix chars (below >=4 prefix threshold)
const SHORT_PREFIX_ADDRESS =
  'GDQ9XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX4BVI';

function createMockRedis() {
  const sets = new Map<string, Set<string>>();
  const kv = new Map<string, string>();
  const published: Array<{ channel: string; message: string }> = [];

  return {
    sets,
    kv,
    published,
    sadd: vi.fn(async (key: string, ...members: string[]) => {
      let set = sets.get(key);
      if (!set) {
        set = new Set<string>();
        sets.set(key, set);
      }
      let added = 0;
      for (const m of members) {
        if (!set.has(m)) {
          set.add(m);
          added++;
        }
      }
      return added;
    }),
    smembers: vi.fn(async (key: string) => Array.from(sets.get(key) ?? [])),
    set: vi.fn(async (key: string, value: string) => {
      kv.set(key, value);
      return 'OK';
    }),
    mget: vi.fn(async (...keys: string[]) => keys.map((k) => kv.get(k) ?? null)),
    publish: vi.fn(async (channel: string, message: string) => {
      published.push({ channel, message });
      return 1;
    }),
  };
}

describe('Vanity Prefix/Suffix Similarity Matcher (#994)', () => {
  it('does NOT flag a genuine exact counterparty address as a lookalike', () => {
    const result = compareVanitySimilarity(TRUSTED_COUNTERPARTY, TRUSTED_COUNTERPARTY);
    expect(result.isLookalike).toBe(false);
    expect(result.isExactMatch).toBe(true);
    expect(result.similarityScore).toBe(1);

    const bookMatch = findVanityLookalikeMatch(TRUSTED_COUNTERPARTY, [
      TRUSTED_COUNTERPARTY,
      SECOND_COUNTERPARTY,
    ]);
    expect(bookMatch).toBeNull();
  });

  it('does NOT flag random unrelated addresses', () => {
    const result = compareVanitySimilarity(RANDOM_ADDRESS, TRUSTED_COUNTERPARTY);
    expect(result.isLookalike).toBe(false);
    expect(result.isExactMatch).toBe(false);

    const bookMatch = findVanityLookalikeMatch(RANDOM_ADDRESS, [
      TRUSTED_COUNTERPARTY,
      SECOND_COUNTERPARTY,
    ]);
    expect(bookMatch).toBeNull();
  });

  it('does NOT flag addresses matching only prefix, only suffix, or <4 prefix chars', () => {
    expect(compareVanitySimilarity(PREFIX_ONLY_ADDRESS, TRUSTED_COUNTERPARTY).isLookalike).toBe(false);
    expect(compareVanitySimilarity(SUFFIX_ONLY_ADDRESS, TRUSTED_COUNTERPARTY).isLookalike).toBe(false);
    expect(compareVanitySimilarity(SHORT_PREFIX_ADDRESS, TRUSTED_COUNTERPARTY).isLookalike).toBe(false);
  });

  it('detects a crafted 4-char prefix + 4-char suffix lookalike with different middle characters', () => {
    const result = compareVanitySimilarity(VANITY_LOOKALIKE_4X4, TRUSTED_COUNTERPARTY);
    expect(result.isLookalike).toBe(true);
    expect(result.isExactMatch).toBe(false);
    expect(result.prefixMatchLength).toBe(4);
    expect(result.suffixMatchLength).toBe(4);
    expect(result.matchedPrefix).toBe('GDQP');
    expect(result.matchedSuffix).toBe('4BVI');
  });

  it('detects stronger vanity lookalikes (>=6 prefix and >=6 suffix) case-insensitively', () => {
    const match = findVanityLookalikeMatch(VANITY_LOOKALIKE_6X6.toLowerCase(), [
      SECOND_COUNTERPARTY,
      TRUSTED_COUNTERPARTY,
    ]);
    expect(match).not.toBeNull();
    expect(match?.isLookalike).toBe(true);
    expect(match?.spoofedCounterparty).toBe(TRUSTED_COUNTERPARTY);
    expect(match?.prefixMatchLength).toBe(6);
    expect(match?.suffixMatchLength).toBe(6);
    expect(match?.matchedPrefix).toBe('GDQP2K');
    expect(match?.matchedSuffix).toBe('MG4BVI');
  });
});

describe('AddressPoisoningDetector (#994)', () => {
  let mockRedis: ReturnType<typeof createMockRedis>;
  let detector: AddressPoisoningDetector;

  beforeEach(() => {
    vi.clearAllMocks();
    mockRedis = createMockRedis();
    detector = new AddressPoisoningDetector(
      mockRedis as unknown as ConstructorParameters<typeof AddressPoisoningDetector>[0],
    );
  });

  it('detects, quarantines, and emits a high-priority security alert for <0.01 XLM lookalike dust from a first-time sender', async () => {
    // Seed counterparty book via a genuine non-dust payment
    const genuineResult = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      walletPublicKey: SECOND_COUNTERPARTY,
      userId: 'user-1',
      paymentId: 'pay-genuine',
      txHash: 'tx-genuine-1',
      fromAddress: TRUSTED_COUNTERPARTY,
      amount: 25,
      asset: 'XLM',
    });
    expect(genuineResult.isPoisoning).toBe(false);
    expect(genuineResult.isDust).toBe(false);

    // Now attacker sends 0.00001 XLM dust from a 4x4 vanity lookalike
    const attackResult = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      walletPublicKey: SECOND_COUNTERPARTY,
      userId: 'user-1',
      paymentId: 'pay-dust',
      txHash: 'tx-poison-1',
      fromAddress: VANITY_LOOKALIKE_4X4,
      amount: 0.00001,
      asset: 'XLM',
    });

    expect(attackResult.isPoisoning).toBe(true);
    expect(attackResult.isDust).toBe(true);
    expect(attackResult.isFirstTimeSender).toBe(true);
    expect(attackResult.match?.spoofedCounterparty).toBe(TRUSTED_COUNTERPARTY);
    expect(attackResult.alert?.warningBanner).toBe(PHISHING_WARNING_BANNER);
    expect(attackResult.alert?.warningMessage).toContain('DO NOT copy the sender address from your transaction history');
    expect(attackResult.securityWarning).toEqual({
      type: 'ADDRESS_POISONING',
      banner: 'PHISHING / ADDRESS POISONING WARNING',
      message: expect.stringContaining('DO NOT copy the sender address'),
      spoofedCounterparty: TRUSTED_COUNTERPARTY,
      matchedPrefix: 'GDQP',
      matchedSuffix: '4BVI',
    });

    // Transaction is quarantined in Redis and retrievable
    const quarantined = await detector.getQuarantinedTransactions(['tx-poison-1', 'tx-genuine-1']);
    expect(quarantined.size).toBe(1);
    expect(quarantined.get('tx-poison-1')?.banner).toBe(PHISHING_WARNING_BANNER);

    // High-priority security alerts emitted across queue, SSE stream, and Redis security channel
    expect(queueMocks.enqueuePaymentAlert).toHaveBeenCalledWith(
      expect.objectContaining({
        paymentId: 'sec-poisoning-tx-poison-1',
        txHash: 'tx-poison-1',
        walletId: 'wallet-1',
        fromAddress: VANITY_LOOKALIKE_4X4,
        severity: 'critical',
      }),
    );
    expect(realtimeMocks.publishAlertEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'user-1',
        event: 'security.address_poisoning',
        severity: 'critical',
        walletId: 'wallet-1',
      }),
    );
    expect(mockRedis.publish).toHaveBeenCalledWith(
      'security:alerts',
      expect.stringContaining('ADDRESS_POISONING_PHISHING'),
    );
  });

  it('does NOT flag micro-payments from an existing trusted counterparty', async () => {
    await detector.recordTrustedCounterparty('wallet-1', TRUSTED_COUNTERPARTY);

    const result = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      userId: 'user-1',
      txHash: 'tx-trusted-dust',
      fromAddress: TRUSTED_COUNTERPARTY,
      amount: 0.0001,
      asset: 'XLM',
    });

    expect(result.isPoisoning).toBe(false);
    expect(result.isFirstTimeSender).toBe(false);
    expect(queueMocks.enqueuePaymentAlert).not.toHaveBeenCalled();
  });

  it('does NOT flag payments at or above the 0.01 XLM threshold or non-XLM assets', async () => {
    await detector.recordTrustedCounterparty('wallet-1', TRUSTED_COUNTERPARTY);

    const thresholdPayment = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      userId: 'user-1',
      txHash: 'tx-001-xlm',
      fromAddress: VANITY_LOOKALIKE_4X4,
      amount: 0.01,
      asset: 'XLM',
    });
    expect(thresholdPayment.isPoisoning).toBe(false);
    expect(thresholdPayment.isDust).toBe(false);

    const nonXlmDust = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      userId: 'user-1',
      txHash: 'tx-usdc-dust',
      fromAddress: VANITY_LOOKALIKE_6X6,
      amount: 0.0001,
      asset: 'USDC',
    });
    expect(nonXlmDust.isPoisoning).toBe(false);
    expect(nonXlmDust.isDust).toBe(false);
    expect(queueMocks.enqueuePaymentAlert).not.toHaveBeenCalled();
  });

  it('does NOT flag dust from a random first-time sender that is not a lookalike', async () => {
    await detector.recordTrustedCounterparty('wallet-1', TRUSTED_COUNTERPARTY);

    const result = await detector.evaluateIncomingPayment({
      walletId: 'wallet-1',
      userId: 'user-1',
      txHash: 'tx-random-dust',
      fromAddress: RANDOM_ADDRESS,
      amount: 0.00001,
      asset: 'XLM',
    });

    expect(result.isPoisoning).toBe(false);
    expect(result.isDust).toBe(true);
    expect(result.isFirstTimeSender).toBe(true);
    expect(queueMocks.enqueuePaymentAlert).not.toHaveBeenCalled();
  });
});
