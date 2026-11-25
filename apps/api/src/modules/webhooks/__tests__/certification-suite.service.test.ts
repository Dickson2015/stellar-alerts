import crypto from 'crypto';
import { describe, expect, it, vi } from 'vitest';
import { RateLimitError, ValidationError } from '../../../lib/errors';
import {
  CERTIFICATION_PROBE_HEADER,
  SECONDARY_SIGNATURE_HEADER,
  WebhookCertificationSuite,
  type CertificationFetch,
  type CertificationRateLimiter,
  type CertificationReport,
} from '../certification-suite.service';

const TARGET = 'https://hooks.example.com/certify';
const SECRET = 'primary-secret-long-enough';
const PREVIOUS_SECRET = 'previous-secret-long-enough';
const NOW = Date.parse('2026-11-24T10:00:00.000Z');

interface ParsedSignature {
  timestamp: number;
  nonce: string;
  signature: string;
}

function parseSignature(header: string | undefined): ParsedSignature | null {
  if (!header) return null;
  const fields = new Map(
    header.split(',').map((part) => {
      const index = part.indexOf('=');
      return [part.slice(0, index), part.slice(index + 1)] as const;
    }),
  );
  const timestamp = Number(fields.get('t'));
  const nonce = fields.get('n');
  const signature = fields.get('v1');
  if (!Number.isFinite(timestamp) || !nonce || !signature) return null;
  return { timestamp, nonce, signature };
}

function sign(body: string, secret: string, timestamp: number, nonce: string): string {
  const data = `${timestamp}.${nonce}.${body}`;
  const signature = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return `t=${timestamp},n=${nonce},v1=${signature}`;
}

interface ReceiverOptions {
  compliant: boolean;
  rejectSecondary?: boolean;
}

interface Receiver {
  fetchImpl: CertificationFetch;
  requests: Array<{ probe: string; headers: Record<string, string>; body: string }>;
}

/** In-process webhook receiver implementing the certification contract. */
function createReceiver(options: ReceiverOptions): Receiver {
  const requests: Receiver['requests'] = [];
  const usedNonces = new Set<string>();
  const deliveries = new Map<string, number>();

  const fetchImpl: CertificationFetch = async (_url, init) => {
    const headers: Record<string, string> = {};
    const raw = (init.headers ?? {}) as Record<string, string>;
    for (const [key, value] of Object.entries(raw)) headers[key.toLowerCase()] = String(value);
    const body = String(init.body ?? '');
    const probe = headers[CERTIFICATION_PROBE_HEADER] ?? 'unknown';
    requests.push({ probe, headers, body });

    if (!options.compliant) {
      // Insecure receiver: accepts everything, ignores replay and ordering.
      return { status: 200, text: () => '', headers: {} };
    }

    const parsed = parseSignature(headers['x-stellar-signature']);
    if (!parsed) return { status: 401, text: () => 'missing signature', headers: {} };

    const drift = NOW - parsed.timestamp;
    if (drift > 10 * 60 * 1000 || drift < -60 * 1000) {
      return { status: 400, text: () => 'timestamp outside tolerance', headers: {} };
    }

    const expected = sign(body, SECRET, parsed.timestamp, parsed.nonce);
    const secondary = headers[SECONDARY_SIGNATURE_HEADER.toLowerCase()];
    const secondarySignature = parseSignature(secondary);
    const validPrimary = expected.endsWith(parsed.signature);
    const validSecondary = Boolean(
      secondarySignature
      && sign(body, PREVIOUS_SECRET, secondarySignature.timestamp, secondarySignature.nonce)
        .endsWith(secondarySignature.signature),
    );

    const requiresSecondary = probe === 'rotated_secondary_signature';
    const rejectedSecondary = options.rejectSecondary && requiresSecondary;
    if ((!validPrimary && !validSecondary) || rejectedSecondary) {
      return { status: 401, text: () => 'invalid signature', headers: {} };
    }

    if (usedNonces.has(parsed.nonce)) {
      return { status: 401, text: () => 'nonce already used', headers: {} };
    }
    usedNonces.add(parsed.nonce);

    const deliveryId = headers['x-certification-delivery-id'] ?? '';
    const duplicate = deliveries.has(deliveryId);
    deliveries.set(deliveryId, (deliveries.get(deliveryId) ?? 0) + 1);

    return {
      status: 200,
      text: () => 'ok',
      headers: duplicate ? { 'x-certification-duplicate': 'true' } : {},
    };
  };

  return { fetchImpl, requests };
}

function limiter(allowed = true): CertificationRateLimiter {
  return {
    consume: vi.fn(async () => ({ allowed, remaining: allowed ? 4 : 0, retryAfterMs: 30_000 })),
  };
}

function suiteFor(receiver: Receiver, rateLimiter = limiter()) {
  let clock = NOW;
  const suite = new WebhookCertificationSuite({
    fetchImpl: receiver.fetchImpl,
    validateUrl: async (url) => ({ url: new URL(url), resolvedIps: ['93.184.216.34'] }),
    rateLimiter,
    now: () => {
      clock += 1;
      return clock;
    },
    probeTimeoutMs: 1_000,
  });
  return { suite, rateLimiter };
}

async function runSuite(suite: WebhookCertificationSuite): Promise<CertificationReport> {
  return suite.run({ userId: 'user-1', targetUrl: TARGET, secret: SECRET, previousSecret: PREVIOUS_SECRET });
}

describe('WebhookCertificationSuite (#1039)', () => {
  it('certifies a compliant receiver across all ten probes', async () => {
    const receiver = createReceiver({ compliant: true });
    const { suite, rateLimiter } = suiteFor(receiver);

    const report = await runSuite(suite);

    expect(rateLimiter.consume).toHaveBeenCalledWith('user-1');
    expect(report.checks).toHaveLength(10);
    expect(report.checks.map((check) => check.id)).toEqual([
      'valid_signature',
      'tampered_body',
      'expired_timestamp',
      'future_clock_skew',
      'missing_signature',
      'corrupted_hmac',
      'replayed_nonce',
      'duplicate_delivery_id',
      'out_of_order_ledger',
      'rotated_secondary_signature',
    ]);
    expect(report.passed).toBe(10);
    expect(report.failed).toBe(0);
    expect(report.score).toBe(1);
    expect(report.certified).toBe(true);
    expect(report.durationMs).toBeGreaterThan(0);
    for (const check of report.checks) {
      expect(check.status).toBe('PASS');
      expect(check.latencyMs).toBeGreaterThanOrEqual(0);
      expect(check.httpStatus).not.toBeNull();
    }
    expect(receiver.requests).toHaveLength(13);
    expect(receiver.requests.filter((entry) => entry.probe === 'replayed_nonce')).toHaveLength(2);
    expect(JSON.stringify(report)).not.toContain(SECRET);
    expect(JSON.stringify(report)).not.toContain(PREVIOUS_SECRET);
  });

  it('reports raw statuses and fails a receiver that accepts invalid payloads', async () => {
    const receiver = createReceiver({ compliant: false });
    const { suite } = suiteFor(receiver);

    const report = await runSuite(suite);
    const byId = Object.fromEntries(report.checks.map((check) => [check.id, check]));

    expect(report.certified).toBe(false);
    expect(report.score).toBeLessThan(1);
    expect(byId.tampered_body.status).toBe('FAIL');
    expect(byId.tampered_body.httpStatus).toBe(200);
    expect(byId.expired_timestamp.status).toBe('FAIL');
    expect(byId.missing_signature.status).toBe('FAIL');
    expect(byId.corrupted_hmac.status).toBe('FAIL');
    expect(byId.replayed_nonce.httpStatuses).toEqual([200, 200]);
    expect(byId.replayed_nonce.message).toContain('Replay defense failed');
    expect(byId.valid_signature.status).toBe('PASS');
    expect(byId.duplicate_delivery_id.status).toBe('PASS');
  });

  it('fails rotation when the receiver cannot verify the secondary header', async () => {
    const receiver = createReceiver({ compliant: true, rejectSecondary: true });
    const { suite } = suiteFor(receiver);

    const report = await runSuite(suite);

    expect(report.certified).toBe(false);
    expect(report.checks.find((check) => check.id === 'rotated_secondary_signature')).toMatchObject({
      status: 'FAIL',
      httpStatus: 401,
    });
  });

  it('fails the rotation probe when no previous secret is supplied', async () => {
    const receiver = createReceiver({ compliant: true });
    const { suite } = suiteFor(receiver);

    const report = await suite.run({ userId: 'user-1', targetUrl: TARGET, secret: SECRET });

    expect(report.checks.find((check) => check.id === 'rotated_secondary_signature')).toMatchObject({
      status: 'FAIL',
      httpStatus: null,
    });
    expect(receiver.requests.some((entry) => entry.probe === 'rotated_secondary_signature')).toBe(false);
  });

  it('rejects unsafe URLs before sending any probe', async () => {
    const fetchImpl = vi.fn() as unknown as CertificationFetch;
    const suite = new WebhookCertificationSuite({
      fetchImpl,
      rateLimiter: limiter(),
      now: () => NOW,
    });

    await expect(suite.run({
      userId: 'user-1',
      targetUrl: 'http://127.0.0.1:8080/hook',
      secret: SECRET,
    })).rejects.toBeInstanceOf(ValidationError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('enforces the per-user rate limit before touching the network', async () => {
    const fetchImpl = vi.fn() as unknown as CertificationFetch;
    const suite = new WebhookCertificationSuite({
      fetchImpl,
      rateLimiter: limiter(false),
      validateUrl: async (url) => ({ url: new URL(url), resolvedIps: ['93.184.216.34'] }),
      now: () => NOW,
    });

    await expect(runSuite(suite)).rejects.toBeInstanceOf(RateLimitError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('records a failed probe instead of aborting the report on transport errors', async () => {
    const fetchImpl: CertificationFetch = async () => {
      throw new Error('connection reset');
    };
    const suite = new WebhookCertificationSuite({
      fetchImpl,
      validateUrl: async (url) => ({ url: new URL(url), resolvedIps: ['93.184.216.34'] }),
      rateLimiter: limiter(),
      now: () => NOW,
    });

    const report = await runSuite(suite);

    expect(report.checks).toHaveLength(10);
    expect(report.failed).toBe(10);
    expect(report.checks[0].message).toContain('connection reset');
  });
});
