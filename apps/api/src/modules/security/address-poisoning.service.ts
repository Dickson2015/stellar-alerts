import type { PaymentSecurityWarningDTO } from '@stellar-alerts/shared';
import { redis } from '../../lib/redis';
import { prisma } from '../../lib/prisma';
import { createLogger } from '../../lib/logger';
import { enqueuePaymentAlert, type AlertJobData } from '../../lib/queue';
import { publishAlertEvent } from '../../lib/realtime';

const log = createLogger({ module: 'AddressPoisoningDetector' });

export const PHISHING_WARNING_BANNER = 'PHISHING / ADDRESS POISONING WARNING' as const;
export const DEFAULT_DUST_THRESHOLD_XLM = 0.01;
export const DEFAULT_MIN_PREFIX_CHARS = 4;
export const DEFAULT_MIN_SUFFIX_CHARS = 4;
const DEFAULT_QUARANTINE_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days

export interface VanitySimilarityOptions {
  minPrefixChars?: number;
  minSuffixChars?: number;
}

export interface VanitySimilarityResult {
  isLookalike: boolean;
  isExactMatch: boolean;
  prefixMatchLength: number;
  suffixMatchLength: number;
  matchedPrefix: string;
  matchedSuffix: string;
  similarityScore: number;
}

export interface VanityLookalikeMatch extends VanitySimilarityResult {
  spoofedCounterparty: string;
}

export interface IncomingPaymentCheckParams {
  walletId: string;
  walletPublicKey?: string;
  userId?: string;
  paymentId?: string;
  txHash: string;
  fromAddress: string;
  amount: number;
  asset: string;
  timestamp?: number;
  /** Optional explicit counterparty book override (useful for deterministic unit tests). */
  knownCounterparties?: ReadonlyArray<string>;
}

export interface AddressPoisoningAlert {
  type: 'ADDRESS_POISONING';
  txHash: string;
  paymentId?: string;
  walletId: string;
  userId?: string;
  fromAddress: string;
  spoofedCounterparty: string;
  matchedPrefix: string;
  matchedSuffix: string;
  prefixMatchLength: number;
  suffixMatchLength: number;
  amount: number;
  asset: string;
  warningBanner: typeof PHISHING_WARNING_BANNER;
  warningMessage: string;
  detectedAt: string;
}

export interface AddressPoisoningCheckResult {
  isPoisoning: boolean;
  isDust: boolean;
  isFirstTimeSender: boolean;
  match: VanityLookalikeMatch | null;
  alert?: AddressPoisoningAlert;
  securityWarning?: PaymentSecurityWarningDTO;
}

export interface AddressPoisoningDetectorOptions extends VanitySimilarityOptions {
  dustThresholdXlm?: number;
  quarantineTtlSeconds?: number;
}

function normalizeAddress(address: string): string {
  return address.trim().toUpperCase();
}

/**
 * Pure vanity prefix/suffix similarity matcher.
 *
 * Compares a candidate sender address against a trusted counterparty address.
 * A lookalike matches at least `minPrefixChars` (default 4) leading characters
 * AND at least `minSuffixChars` (default 4) trailing characters while having
 * different middle characters (i.e. not the exact same address).
 */
export function compareVanitySimilarity(
  senderAddress: string,
  counterpartyAddress: string,
  options: VanitySimilarityOptions = {},
): VanitySimilarityResult {
  const minPrefixChars = options.minPrefixChars ?? DEFAULT_MIN_PREFIX_CHARS;
  const minSuffixChars = options.minSuffixChars ?? DEFAULT_MIN_SUFFIX_CHARS;

  const sender = normalizeAddress(senderAddress);
  const counterparty = normalizeAddress(counterpartyAddress);

  if (!sender || !counterparty) {
    return {
      isLookalike: false,
      isExactMatch: false,
      prefixMatchLength: 0,
      suffixMatchLength: 0,
      matchedPrefix: '',
      matchedSuffix: '',
      similarityScore: 0,
    };
  }

  if (sender === counterparty) {
    return {
      isLookalike: false,
      isExactMatch: true,
      prefixMatchLength: sender.length,
      suffixMatchLength: sender.length,
      matchedPrefix: sender.slice(0, minPrefixChars),
      matchedSuffix: sender.slice(-minSuffixChars),
      similarityScore: 1,
    };
  }

  const minLen = Math.min(sender.length, counterparty.length);
  const maxLen = Math.max(sender.length, counterparty.length);

  if (minLen < minPrefixChars + minSuffixChars) {
    return {
      isLookalike: false,
      isExactMatch: false,
      prefixMatchLength: 0,
      suffixMatchLength: 0,
      matchedPrefix: '',
      matchedSuffix: '',
      similarityScore: 0,
    };
  }

  let prefixMatchLength = 0;
  while (prefixMatchLength < minLen && sender[prefixMatchLength] === counterparty[prefixMatchLength]) {
    prefixMatchLength++;
  }

  let suffixMatchLength = 0;
  const maxRemainingForSuffix = minLen - prefixMatchLength;
  while (
    suffixMatchLength < maxRemainingForSuffix &&
    sender[sender.length - 1 - suffixMatchLength] ===
      counterparty[counterparty.length - 1 - suffixMatchLength]
  ) {
    suffixMatchLength++;
  }

  const isLookalike =
    prefixMatchLength >= minPrefixChars && suffixMatchLength >= minSuffixChars;

  const similarityScore = Number(((prefixMatchLength + suffixMatchLength) / maxLen).toFixed(4));

  return {
    isLookalike,
    isExactMatch: false,
    prefixMatchLength,
    suffixMatchLength,
    matchedPrefix: sender.slice(0, prefixMatchLength),
    matchedSuffix: suffixMatchLength > 0 ? sender.slice(sender.length - suffixMatchLength) : '',
    similarityScore,
  };
}

/**
 * Searches a wallet's trusted counterparty book for a vanity prefix/suffix lookalike.
 *
 * Returns `null` if the sender is already an exact trusted counterparty or if no
 * counterparty matches both the prefix and suffix thresholds.
 */
export function findVanityLookalikeMatch(
  senderAddress: string,
  trustedCounterparties: ReadonlyArray<string>,
  options: VanitySimilarityOptions = {},
): VanityLookalikeMatch | null {
  const normalizedSender = normalizeAddress(senderAddress);
  if (!normalizedSender || trustedCounterparties.length === 0) {
    return null;
  }

  // Exact match against any trusted counterparty means this is a genuine sender, not a spoof.
  for (const counterparty of trustedCounterparties) {
    if (normalizeAddress(counterparty) === normalizedSender) {
      return null;
    }
  }

  let bestMatch: VanityLookalikeMatch | null = null;

  for (const counterparty of trustedCounterparties) {
    const similarity = compareVanitySimilarity(normalizedSender, counterparty, options);
    if (!similarity.isLookalike) {
      continue;
    }

    const combinedChars = similarity.prefixMatchLength + similarity.suffixMatchLength;
    const bestCombinedChars = bestMatch
      ? bestMatch.prefixMatchLength + bestMatch.suffixMatchLength
      : -1;

    if (combinedChars > bestCombinedChars) {
      bestMatch = {
        ...similarity,
        spoofedCounterparty: normalizeAddress(counterparty),
      };
    }
  }

  return bestMatch;
}

export class AddressPoisoningDetector {
  private readonly redisClient: typeof redis;
  private readonly dustThresholdXlm: number;
  private readonly minPrefixChars: number;
  private readonly minSuffixChars: number;
  private readonly quarantineTtlSeconds: number;

  constructor(
    customRedis?: typeof redis,
    options: AddressPoisoningDetectorOptions = {},
  ) {
    this.redisClient = customRedis ?? redis;
    this.dustThresholdXlm = options.dustThresholdXlm ?? DEFAULT_DUST_THRESHOLD_XLM;
    this.minPrefixChars = options.minPrefixChars ?? DEFAULT_MIN_PREFIX_CHARS;
    this.minSuffixChars = options.minSuffixChars ?? DEFAULT_MIN_SUFFIX_CHARS;
    this.quarantineTtlSeconds = options.quarantineTtlSeconds ?? DEFAULT_QUARANTINE_TTL_SECONDS;
  }

  /**
   * Returns true if the incoming payment is an XLM micro-payment below the dust threshold (< 0.01 XLM).
   */
  public isDustMicroPayment(amount: number, asset: string): boolean {
    const normalizedAsset = asset.trim().toUpperCase();
    const isNativeXlm = normalizedAsset === 'XLM' || normalizedAsset === 'NATIVE';
    return isNativeXlm && Number.isFinite(amount) && amount > 0 && amount < this.dustThresholdXlm;
  }

  /**
   * Builds a user-facing security warning DTO from a detected poisoning alert.
   */
  public buildSecurityWarning(alert: AddressPoisoningAlert): PaymentSecurityWarningDTO {
    return {
      type: 'ADDRESS_POISONING',
      banner: PHISHING_WARNING_BANNER,
      message: alert.warningMessage,
      spoofedCounterparty: alert.spoofedCounterparty,
      matchedPrefix: alert.matchedPrefix,
      matchedSuffix: alert.matchedSuffix,
    };
  }

  /**
   * Records a genuine (non-dust) sender into the wallet's historical counterparty book.
   */
  public async recordTrustedCounterparty(walletId: string, address: string): Promise<void> {
    const normalized = normalizeAddress(address);
    if (!walletId || !normalized) return;

    const bookKey = this.counterpartyBookKey(walletId);
    try {
      await this.redisClient.sadd(bookKey, normalized);
    } catch (err: unknown) {
      log.warn(
        { err: err instanceof Error ? err.message : String(err), walletId },
        'Failed to record trusted counterparty in Redis',
      );
    }
  }

  /**
   * Loads the wallet's historical trusted counterparties from Redis, falling back
   * to historical non-dust payments in PostgreSQL on a cold cache.
   */
  public async getTrustedCounterparties(walletId: string): Promise<string[]> {
    const bookKey = this.counterpartyBookKey(walletId);
    try {
      const cached = await this.redisClient.smembers(bookKey);
      if (cached && cached.length > 0) {
        return cached;
      }
    } catch (err: unknown) {
      log.warn(
        { err: err instanceof Error ? err.message : String(err), walletId },
        'Failed to read counterparty book from Redis',
      );
    }

    // Cold-cache seed from historical non-dust payments in Prisma
    try {
      if (typeof prisma?.payment?.findMany !== 'function') {
        return [];
      }
      const historicalPayments = await prisma.payment.findMany({
        where: {
          walletId,
          amount: { gte: this.dustThresholdXlm },
        },
        select: { fromAddress: true },
        distinct: ['fromAddress'],
        take: 500,
      });

      const addresses = historicalPayments
        .map((p) => normalizeAddress(p.fromAddress))
        .filter((addr) => addr.length > 0);

      if (addresses.length > 0) {
        try {
          await this.redisClient.sadd(bookKey, ...addresses);
        } catch {
          // Best-effort cache warm
        }
      }

      return addresses;
    } catch (err: unknown) {
      log.warn(
        { err: err instanceof Error ? err.message : String(err), walletId },
        'Failed to load historical counterparties from database',
      );
      return [];
    }
  }

  /**
   * Evaluates an incoming payment for address-poisoning dust attacks.
   *
   * - Known counterparties and self-transfers are never flagged.
   * - Non-dust incoming payments (>= 0.01 XLM or non-XLM) are added to the
   *   wallet's historical counterparty book.
   * - Incoming micro-payments (< 0.01 XLM) from first-time senders are compared
   *   against the counterparty book for >=4 prefix and >=4 suffix similarity.
   * - Detected poisoning transactions are quarantined and emit a high-priority
   *   security alert warning the user not to copy the sender address.
   */
  public async evaluateIncomingPayment(
    params: IncomingPaymentCheckParams,
  ): Promise<AddressPoisoningCheckResult> {
    const normalizedSender = normalizeAddress(params.fromAddress);
    const normalizedWallet = params.walletPublicKey
      ? normalizeAddress(params.walletPublicKey)
      : '';

    const isDust = this.isDustMicroPayment(params.amount, params.asset);

    if (!normalizedSender || (normalizedWallet && normalizedSender === normalizedWallet)) {
      return {
        isPoisoning: false,
        isDust,
        isFirstTimeSender: false,
        match: null,
      };
    }

    const counterparties =
      params.knownCounterparties !== undefined
        ? params.knownCounterparties.map(normalizeAddress).filter(Boolean)
        : await this.getTrustedCounterparties(params.walletId);

    const isKnownCounterparty = counterparties.includes(normalizedSender);
    const isFirstTimeSender = !isKnownCounterparty;

    // Non-dust payment: learn this counterparty and return clean.
    if (!isDust) {
      if (isFirstTimeSender && params.knownCounterparties === undefined) {
        await this.recordTrustedCounterparty(params.walletId, normalizedSender);
      }
      return {
        isPoisoning: false,
        isDust: false,
        isFirstTimeSender,
        match: null,
      };
    }

    // Known counterparty sending a small payment is not a first-time poisoning attack.
    if (!isFirstTimeSender) {
      return {
        isPoisoning: false,
        isDust: true,
        isFirstTimeSender: false,
        match: null,
      };
    }

    const match = findVanityLookalikeMatch(normalizedSender, counterparties, {
      minPrefixChars: this.minPrefixChars,
      minSuffixChars: this.minSuffixChars,
    });

    if (!match) {
      return {
        isPoisoning: false,
        isDust: true,
        isFirstTimeSender: true,
        match: null,
      };
    }

    const detectedAt = new Date(params.timestamp ?? Date.now()).toISOString();
    const warningMessage =
      `${PHISHING_WARNING_BANNER}: Incoming micro-payment (${params.amount} ${params.asset}) ` +
      `from first-time sender ${normalizedSender} mimics trusted counterparty ${match.spoofedCounterparty} ` +
      `(matching prefix "${match.matchedPrefix}" and suffix "${match.matchedSuffix}"). ` +
      `DO NOT copy the sender address from your transaction history.`;

    const alert: AddressPoisoningAlert = {
      type: 'ADDRESS_POISONING',
      txHash: params.txHash,
      paymentId: params.paymentId,
      walletId: params.walletId,
      userId: params.userId,
      fromAddress: normalizedSender,
      spoofedCounterparty: match.spoofedCounterparty,
      matchedPrefix: match.matchedPrefix,
      matchedSuffix: match.matchedSuffix,
      prefixMatchLength: match.prefixMatchLength,
      suffixMatchLength: match.suffixMatchLength,
      amount: params.amount,
      asset: params.asset,
      warningBanner: PHISHING_WARNING_BANNER,
      warningMessage,
      detectedAt,
    };

    const securityWarning = this.buildSecurityWarning(alert);

    log.warn(
      {
        walletId: params.walletId,
        txHash: params.txHash,
        fromAddress: normalizedSender,
        spoofedCounterparty: match.spoofedCounterparty,
        prefixMatchLength: match.prefixMatchLength,
        suffixMatchLength: match.suffixMatchLength,
        amount: params.amount,
        asset: params.asset,
      },
      '🚨 [SECURITY] Address-poisoning lookalike dust transaction detected and quarantined!',
    );

    await this.quarantineTransaction(alert);
    await this.dispatchSecurityAlert(alert);

    return {
      isPoisoning: true,
      isDust: true,
      isFirstTimeSender: true,
      match,
      alert,
      securityWarning,
    };
  }

  /**
   * Stores quarantine metadata for a suspected poisoning transaction in Redis.
   */
  public async quarantineTransaction(alert: AddressPoisoningAlert): Promise<void> {
    const key = this.quarantineKey(alert.txHash);
    try {
      await this.redisClient.set(
        key,
        JSON.stringify(this.buildSecurityWarning(alert)),
        'EX',
        this.quarantineTtlSeconds,
      );
    } catch (err: unknown) {
      log.error(
        { err: err instanceof Error ? err.message : String(err), txHash: alert.txHash },
        'Failed to store address-poisoning quarantine record in Redis',
      );
    }
  }

  /**
   * Fetches quarantine warning metadata for a batch of transaction hashes.
   * Fails gracefully (returns an empty map) if Redis is unavailable.
   */
  public async getQuarantinedTransactions(
    txHashes: ReadonlyArray<string>,
  ): Promise<Map<string, PaymentSecurityWarningDTO>> {
    const result = new Map<string, PaymentSecurityWarningDTO>();
    if (txHashes.length === 0) return result;

    try {
      const keys = txHashes.map((hash) => this.quarantineKey(hash));
      const values = await this.redisClient.mget(...keys);
      for (let i = 0; i < txHashes.length; i++) {
        const raw = values[i];
        if (!raw) continue;
        try {
          const parsed = JSON.parse(raw) as PaymentSecurityWarningDTO;
          if (parsed && parsed.type === 'ADDRESS_POISONING') {
            result.set(txHashes[i], parsed);
          }
        } catch {
          // Ignore malformed quarantine cache entry
        }
      }
    } catch (err: unknown) {
      log.warn(
        { err: err instanceof Error ? err.message : String(err) },
        'Failed to fetch quarantined transactions from Redis',
      );
    }

    return result;
  }

  /**
   * Emits a high-priority security alert warning the user not to copy the
   * poisoned sender address from their transaction history.
   */
  public async dispatchSecurityAlert(alert: AddressPoisoningAlert): Promise<void> {
    try {
      const jobPayload: AlertJobData = {
        paymentId: `sec-poisoning-${alert.txHash}`,
        txHash: alert.txHash,
        walletId: alert.walletId,
        amount: String(alert.amount),
        asset: alert.asset,
        fromAddress: alert.fromAddress,
        receivedAt: alert.detectedAt,
        severity: 'critical',
      };

      await enqueuePaymentAlert(jobPayload);

      if (alert.userId) {
        await publishAlertEvent({
          userId: alert.userId,
          event: 'security.address_poisoning',
          severity: 'critical',
          walletId: alert.walletId,
          payload: alert,
        });
      }

      const { type: _type, ...alertRest } = alert;
      await this.redisClient.publish(
        'security:alerts',
        JSON.stringify({
          ...alertRest,
          type: 'ADDRESS_POISONING_PHISHING',
          severity: 'CRITICAL',
        }),
      );
    } catch (err: unknown) {
      log.error(
        { err: err instanceof Error ? err.message : String(err), txHash: alert.txHash },
        'Failed to dispatch address-poisoning security alert',
      );
    }
  }

  private counterpartyBookKey(walletId: string): string {
    return `security:counterparties:${walletId}`;
  }

  private quarantineKey(txHash: string): string {
    return `security:poisoning:tx:${txHash}`;
  }
}

export const addressPoisoningDetector = new AddressPoisoningDetector();
