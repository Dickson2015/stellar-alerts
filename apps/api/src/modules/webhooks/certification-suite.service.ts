import { validateUrlForSsrf, ssrfSafeFetch, SsrfValidationError } from '../../utils/ssrf';
import { generateWebhookSignature } from '../../utils/webhook-signer';
import { RateLimitError, ValidationError } from '../../lib/errors';
import { redis } from '../../lib/redis';

/**
 * Webhook certification harness (#1039). Runs ten deterministic probes against
 * a subscriber-controlled receiver and reports PASS/FAIL with the raw HTTP
 * status and latency of every request. No signing secret is ever echoed back.
 */

export const CERTIFICATION_PROBE_HEADER = 'x-certification-probe';
export const CERTIFICATION_RUN_HEADER = 'x-certification-run-id';
export const CERTIFICATION_DELIVERY_HEADER = 'x-certification-delivery-id';
export const CERTIFICATION_SEQUENCE_HEADER = 'x-certification-sequence';
/** Matches the header emitted by webhooks.service.ts during secret rotation. */
export const SECONDARY_SIGNATURE_HEADER = 'X-Stellar-Signature-Secondary';
export const PRIMARY_SIGNATURE_HEADER = 'X-Stellar-Signature';

const PROBE_TIMEOUT_MS = 5_000;
const EXPIRED_TIMESTAMP_MS = 11 * 60 * 1000;
const FUTURE_SKEW_MS = 2 * 60 * 1000;

export type CertificationProbeId =
  | 'valid_signature'
  | 'tampered_body'
  | 'expired_timestamp'
  | 'future_clock_skew'
  | 'missing_signature'
  | 'corrupted_hmac'
  | 'replayed_nonce'
  | 'duplicate_delivery_id'
  | 'out_of_order_ledger'
  | 'rotated_secondary_signature';

export interface CertificationRequest {
  userId: string;
  targetUrl: string;
  secret: string;
  previousSecret?: string;
}

export interface CertificationCheck {
  id: CertificationProbeId;
  name: string;
  description: string;
  expected: string;
  status: 'PASS' | 'FAIL';
  /** Last observed status; null when the probe could not be sent. */
  httpStatus: number | null;
  httpStatuses: number[];
  latencyMs: number;
  message: string;
}

export interface CertificationReport {
  runId: string;
  targetUrl: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  checks: CertificationCheck[];
  passed: number;
  failed: number;
  score: number;
  certified: boolean;
}

export interface CertificationRateLimitDecision {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
}

export interface CertificationRateLimiter {
  consume(userId: string): Promise<CertificationRateLimitDecision>;
}

/**
 * Fixed-window Redis limiter: certification runs are expensive (ten outbound
 * requests each), so the limit is per user rather than per IP and shared across
 * API pods. Failing to increment fails closed instead of allowing unlimited runs.
 */
export class RedisCertificationRateLimiter implements CertificationRateLimiter {
  constructor(
    private readonly maxRuns = 5,
    private readonly windowMs = 10 * 60 * 1000,
    private readonly client: Pick<typeof redis, 'incr' | 'expire'> = redis,
    private readonly now: () => number = Date.now,
  ) {}

  async consume(userId: string): Promise<CertificationRateLimitDecision> {
    const bucket = Math.floor(this.now() / this.windowMs);
    const key = `stellar-alerts:certification:${userId}:${bucket}`;
    const count = await this.client.incr(key);
    if (count === 1) {
      await this.client.expire(key, Math.ceil(this.windowMs / 1000) + 5);
    }

    const retryAfterMs = Math.max(0, (bucket + 1) * this.windowMs - this.now());
    return {
      allowed: count <= this.maxRuns,
      remaining: Math.max(0, this.maxRuns - count),
      retryAfterMs,
    };
  }
}

export const certificationRateLimiter: CertificationRateLimiter = new RedisCertificationRateLimiter();

export interface ResponseLike {
  status: number;
  text?: () => Promise<string> | string;
  headers?: { get?: (name: string) => string | null } | Record<string, string>;
}

export type CertificationFetch = (url: string, init: RequestInit) => Promise<ResponseLike>;

type UrlValidator = (url: string) => Promise<{ url: URL; resolvedIps: string[] }>;

export interface CertificationSuiteOptions {
  fetchImpl?: CertificationFetch;
  validateUrl?: UrlValidator;
  rateLimiter?: CertificationRateLimiter;
  now?: () => number;
  probeTimeoutMs?: number;
}

interface SendResult {
  status: number;
  latencyMs: number;
  body: string;
  headers: Record<string, string>;
}

interface ProbeContext {
  url: string;
  secret: string;
  previousSecret?: string;
  runId: string;
  deliveryId: string;
  nowMs: number;
}

interface ProbeResult {
  pass: boolean;
  httpStatuses: number[];
  latencyMs: number;
  message: string;
}

type ProbeRunner = (context: ProbeContext) => Promise<ProbeResult>;

interface ProbeDefinition {
  id: CertificationProbeId;
  name: string;
  description: string;
  expected: string;
  run: ProbeRunner;
}

function is2xx(status: number): boolean {
  return status >= 200 && status < 300;
}

function isRejected(status: number): boolean {
  return status === 400 || status === 401 || status === 403;
}

function responseHeader(response: ResponseLike, name: string): string | undefined {
  const headers = response.headers;
  if (!headers) return undefined;
  if (typeof (headers as { get?: unknown }).get === 'function') {
    return (headers as { get: (key: string) => string | null }).get(name) ?? undefined;
  }
  const record = headers as Record<string, string>;
  const key = Object.keys(record).find((entry) => entry.toLowerCase() === name.toLowerCase());
  return key ? record[key] : undefined;
}

async function readBody(response: ResponseLike): Promise<string> {
  if (typeof response.text !== 'function') return '';
  try {
    return await response.text();
  } catch {
    return '';
  }
}

/**
 * Executes the certification suite. Dependencies are injectable so tests can
 * drive mock receivers and deterministic clocks without any network access.
 */
export class WebhookCertificationSuite {
  private readonly fetchImpl: CertificationFetch;
  private readonly validateUrl: UrlValidator;
  private readonly rateLimiter: CertificationRateLimiter;
  private readonly now: () => number;
  private readonly probeTimeoutMs: number;

  constructor(options: CertificationSuiteOptions = {}) {
    this.fetchImpl = options.fetchImpl ?? ((url, init) => ssrfSafeFetch(url, init));
    this.validateUrl = options.validateUrl ?? validateUrlForSsrf;
    this.rateLimiter = options.rateLimiter ?? certificationRateLimiter;
    this.now = options.now ?? Date.now;
    this.probeTimeoutMs = options.probeTimeoutMs ?? PROBE_TIMEOUT_MS;
  }

  async run(input: CertificationRequest): Promise<CertificationReport> {
    const limit = await this.rateLimiter.consume(input.userId);
    if (!limit.allowed) {
      throw new RateLimitError(
        `Certification rate limit exceeded. Try again in ${Math.ceil(limit.retryAfterMs / 1000)}s.`,
      );
    }

    try {
      await this.validateUrl(input.targetUrl);
    } catch (error: unknown) {
      if (error instanceof SsrfValidationError) {
        throw new ValidationError('Unsafe certification target URL', { code: error.code });
      }
      throw new ValidationError('Invalid certification target URL');
    }

    const startedAtMs = this.now();
    const runId = `cert-${startedAtMs.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    const context: ProbeContext = {
      url: input.targetUrl,
      secret: input.secret,
      previousSecret: input.previousSecret,
      runId,
      deliveryId: `delivery-${runId}`,
      nowMs: startedAtMs,
    };

    const checks: CertificationCheck[] = [];
    for (const probe of this.probes()) {
      let result: ProbeResult;
      try {
        result = await probe.run(context);
      } catch (error: unknown) {
        result = {
          pass: false,
          httpStatuses: [],
          latencyMs: 0,
          message: `Probe could not be delivered: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
      checks.push({
        id: probe.id,
        name: probe.name,
        description: probe.description,
        expected: probe.expected,
        status: result.pass ? 'PASS' : 'FAIL',
        httpStatus: result.httpStatuses[result.httpStatuses.length - 1] ?? null,
        httpStatuses: result.httpStatuses,
        latencyMs: result.latencyMs,
        message: result.message,
      });
    }

    const completedAtMs = this.now();
    const passed = checks.filter((check) => check.status === 'PASS').length;
    return {
      runId,
      targetUrl: input.targetUrl,
      startedAt: new Date(startedAtMs).toISOString(),
      completedAt: new Date(completedAtMs).toISOString(),
      durationMs: completedAtMs - startedAtMs,
      checks,
      passed,
      failed: checks.length - passed,
      score: passed / checks.length,
      certified: passed === checks.length,
    };
  }

  private async send(
    context: ProbeContext,
    options: {
      probe: CertificationProbeId;
      body: string;
      headers: Record<string, string>;
      deliveryId?: string;
      sequence?: number;
    },
  ): Promise<SendResult> {
    const started = this.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.probeTimeoutMs);
    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'StellarAlerts-Certification/1.0',
        [CERTIFICATION_RUN_HEADER]: context.runId,
        [CERTIFICATION_PROBE_HEADER]: options.probe,
        [CERTIFICATION_DELIVERY_HEADER]: options.deliveryId ?? context.deliveryId,
        [CERTIFICATION_SEQUENCE_HEADER]: String(options.sequence ?? 1),
        ...options.headers,
      };
      const response = await this.fetchImpl(context.url, {
        method: 'POST',
        headers,
        body: options.body,
        signal: controller.signal,
      });
      return {
        status: response.status,
        latencyMs: Math.max(0, this.now() - started),
        body: await readBody(response),
        headers: responseHeader(response, 'x-certification-duplicate')
          ? { duplicate: responseHeader(response, 'x-certification-duplicate')! }
          : {},
      };
    } finally {
      clearTimeout(timer);
    }
  }

  private signedHeaders(
    body: string,
    secret: string,
    timestamp: number,
    nonce: string,
  ): Record<string, string> {
    const signature = generateWebhookSignature(body, secret, timestamp, nonce);
    return {
      [PRIMARY_SIGNATURE_HEADER]: signature.headerValue,
      'X-Stellar-Alerts-Timestamp': String(timestamp),
      'X-Stellar-Alerts-Nonce': nonce,
    };
  }

  private payload(probe: CertificationProbeId, extra: Record<string, unknown> = {}): string {
    return JSON.stringify({
      event: 'certification.probe',
      probe,
      ...extra,
    });
  }

  private probes(): ProbeDefinition[] {
    const single = (
      id: CertificationProbeId,
      name: string,
      description: string,
      expected: string,
      build: (context: ProbeContext) => Promise<{ body: string; headers: Record<string, string> }>,
      accept: (response: SendResult) => boolean,
      successMessage: string,
      failureMessage: string,
    ): ProbeDefinition => ({
      id,
      name,
      description,
      expected,
      run: async (context) => {
        const { body, headers } = await build(context);
        const response = await this.send(context, { probe: id, body, headers });
        const pass = accept(response);
        return {
          pass,
          httpStatuses: [response.status],
          latencyMs: response.latencyMs,
          message: pass
            ? successMessage
            : `${failureMessage} (received ${response.status}${response.body ? `: ${response.body.slice(0, 240)}` : ''})`,
        };
      },
    });

    return [
      single(
        'valid_signature',
        'Valid signed payload',
        'Sends a correctly signed payload with current timestamp and nonce.',
        '2xx success',
        (context) => {
          const timestamp = context.nowMs;
          const nonce = `nonce-valid-${context.runId}`;
          const body = this.payload('valid_signature', { deliveredAt: timestamp });
          return Promise.resolve({ body, headers: this.signedHeaders(body, context.secret, timestamp, nonce) });
        },
        (response) => is2xx(response.status),
        'Receiver accepted the valid signature.',
        'Receiver rejected a correctly signed payload.',
      ),
      single(
        'tampered_body',
        'Tampered body with valid header',
        'Reuses a valid signature header after modifying the signed body.',
        '400/401/403 rejection',
        (context) => {
          const timestamp = context.nowMs;
          const nonce = `nonce-tamper-${context.runId}`;
          const original = this.payload('tampered_body', { amount: '1' });
          const body = original.replace('"1"', '"2"');
          return Promise.resolve({ body, headers: this.signedHeaders(original, context.secret, timestamp, nonce) });
        },
        (response) => isRejected(response.status),
        'Receiver rejected the tampered body.',
        'Receiver accepted a body that does not match its signature.',
      ),
      single(
        'expired_timestamp',
        'Expired timestamp',
        'Signs a payload with a timestamp more than ten minutes in the past.',
        '400/401 rejection',
        (context) => {
          const timestamp = context.nowMs - EXPIRED_TIMESTAMP_MS;
          const nonce = `nonce-expired-${context.runId}`;
          const body = this.payload('expired_timestamp', { timestamp });
          return Promise.resolve({ body, headers: this.signedHeaders(body, context.secret, timestamp, nonce) });
        },
        (response) => response.status === 400 || response.status === 401,
        'Receiver rejected the stale timestamp.',
        'Receiver accepted a timestamp beyond the freshness window.',
      ),
      single(
        'future_clock_skew',
        'Future clock skew',
        'Signs a payload two minutes ahead of server time to test skew tolerance.',
        '400/401 rejection',
        (context) => {
          const timestamp = context.nowMs + FUTURE_SKEW_MS;
          const nonce = `nonce-future-${context.runId}`;
          const body = this.payload('future_clock_skew', { timestamp });
          return Promise.resolve({ body, headers: this.signedHeaders(body, context.secret, timestamp, nonce) });
        },
        (response) => response.status === 400 || response.status === 401,
        'Receiver rejected the future timestamp.',
        'Receiver accepted a timestamp too far ahead of server time.',
      ),
      single(
        'missing_signature',
        'Missing signature header',
        'Sends a well-formed payload without any signature header.',
        '401/403 rejection',
        (context) => Promise.resolve({
          body: this.payload('missing_signature'),
          headers: {
            'X-Stellar-Alerts-Timestamp': String(context.nowMs),
            'X-Stellar-Alerts-Nonce': `nonce-missing-${context.runId}`,
          },
        }),
        (response) => response.status === 401 || response.status === 403,
        'Receiver rejected the unsigned request.',
        'Receiver accepted an unsigned payload.',
      ),
      single(
        'corrupted_hmac',
        'Corrupted HMAC',
        'Flips the final hex character of an otherwise valid signature.',
        '401/403 rejection',
        (context) => {
          const timestamp = context.nowMs;
          const nonce = `nonce-corrupt-${context.runId}`;
          const body = this.payload('corrupted_hmac');
          const signed = this.signedHeaders(body, context.secret, timestamp, nonce);
          const header = signed[PRIMARY_SIGNATURE_HEADER];
          const last = header.slice(-1);
          signed[PRIMARY_SIGNATURE_HEADER] = `${header.slice(0, -1)}${last === '0' ? '1' : '0'}`;
          return Promise.resolve({ body, headers: signed });
        },
        (response) => response.status === 401 || response.status === 403,
        'Receiver rejected the corrupted HMAC.',
        'Receiver accepted an invalid HMAC.',
      ),
      {
        id: 'replayed_nonce',
        name: 'Replayed nonce',
        description: 'Sends the same signed request twice to test one-time nonce enforcement.',
        expected: 'first 2xx, then 401/403',
        run: async (context) => {
          const timestamp = context.nowMs;
          const nonce = `nonce-replay-${context.runId}`;
          const body = this.payload('replayed_nonce', { deliveryId: context.deliveryId });
          const headers = this.signedHeaders(body, context.secret, timestamp, nonce);
          const first = await this.send(context, { probe: 'replayed_nonce', body, headers });
          const second = await this.send(context, { probe: 'replayed_nonce', body, headers });
          const pass = is2xx(first.status) && isRejected(second.status);
          return {
            pass,
            httpStatuses: [first.status, second.status],
            latencyMs: first.latencyMs + second.latencyMs,
            message: pass
              ? 'Receiver accepted the first delivery and rejected the replayed nonce.'
              : `Replay defense failed: first ${first.status}, replay ${second.status}.`,
          };
        },
      },
      {
        id: 'duplicate_delivery_id',
        name: 'Duplicate delivery ID',
        description: 'Delivers the same delivery ID twice with distinct nonces (retries).',
        expected: 'both 2xx (idempotent handling)',
        run: async (context) => {
          const deliveryId = `duplicate-${context.runId}`;
          const body = this.payload('duplicate_delivery_id', { deliveryId });
          const firstHeaders = this.signedHeaders(
            body,
            context.secret,
            context.nowMs,
            `nonce-dup-1-${context.runId}`,
          );
          const secondHeaders = this.signedHeaders(
            body,
            context.secret,
            context.nowMs + 1,
            `nonce-dup-2-${context.runId}`,
          );
          const first = await this.send(context, {
            probe: 'duplicate_delivery_id', body, headers: firstHeaders, deliveryId,
          });
          const second = await this.send(context, {
            probe: 'duplicate_delivery_id', body, headers: secondHeaders, deliveryId,
          });
          const pass = is2xx(first.status) && is2xx(second.status);
          const duplicateMarker = second.headers.duplicate;
          return {
            pass,
            httpStatuses: [first.status, second.status],
            latencyMs: first.latencyMs + second.latencyMs,
            message: pass
              ? `Receiver tolerated the retry.${duplicateMarker ? ` Duplicate marker: ${duplicateMarker}.` : ''}`
              : `Receiver failed retry handling: ${first.status}, ${second.status}.`,
          };
        },
      },
      {
        id: 'out_of_order_ledger',
        name: 'Out-of-order ledger',
        description: 'Delivers sequence 2 before sequence 1 with valid signatures.',
        expected: 'both 2xx (no strict ordering assumption)',
        run: async (context) => {
          const later = this.payload('out_of_order_ledger', { sequence: 2 });
          const earlier = this.payload('out_of_order_ledger', { sequence: 1 });
          const second = await this.send(context, {
            probe: 'out_of_order_ledger',
            body: later,
            headers: this.signedHeaders(later, context.secret, context.nowMs, `nonce-seq2-${context.runId}`),
            deliveryId: `seq-2-${context.runId}`,
            sequence: 2,
          });
          const first = await this.send(context, {
            probe: 'out_of_order_ledger',
            body: earlier,
            headers: this.signedHeaders(earlier, context.secret, context.nowMs + 1, `nonce-seq1-${context.runId}`),
            deliveryId: `seq-1-${context.runId}`,
            sequence: 1,
          });
          const pass = is2xx(second.status) && is2xx(first.status);
          return {
            pass,
            httpStatuses: [second.status, first.status],
            latencyMs: second.latencyMs + first.latencyMs,
            message: pass
              ? 'Receiver tolerated out-of-order ledger events.'
              : `Receiver rejected out-of-order delivery: ${second.status}, ${first.status}.`,
          };
        },
      },
      {
        id: 'rotated_secondary_signature',
        name: 'Rotated secondary signature',
        description: 'Signs with the previous secret in the secondary header during rotation.',
        expected: '2xx success',
        run: async (context) => {
          if (!context.previousSecret) {
            return {
              pass: false,
              httpStatuses: [],
              latencyMs: 0,
              message: 'No previousSecret was supplied, so rotation compliance could not be tested.',
            };
          }
          const timestamp = context.nowMs;
          const nonce = `nonce-rotate-${context.runId}`;
          const body = this.payload('rotated_secondary_signature', { rotation: true });
          const headers = this.signedHeaders(body, context.secret, timestamp, nonce);
          const secondary = generateWebhookSignature(body, context.previousSecret, timestamp, nonce);
          headers[SECONDARY_SIGNATURE_HEADER] = secondary.headerValue;
          const response = await this.send(context, { probe: 'rotated_secondary_signature', body, headers });
          return {
            pass: is2xx(response.status),
            httpStatuses: [response.status],
            latencyMs: response.latencyMs,
            message: is2xx(response.status)
              ? 'Receiver verified the rotated secondary signature.'
              : `Receiver rejected the rotated secondary signature (received ${response.status}).`,
          };
        },
      },
    ];
  }
}

export const webhookCertificationSuite = new WebhookCertificationSuite();
