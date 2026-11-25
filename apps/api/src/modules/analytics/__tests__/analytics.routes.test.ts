import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ query: vi.fn() }));

vi.mock('../../../middleware/auth.middleware', () => ({
  authenticateHook: async (request: any, reply: any) => {
    if (!request.headers.authorization) return reply.code(401).send({ error: 'Unauthorized' });
  },
}));
vi.mock('../timeseries-rollup', () => ({
  TIME_SERIES_INTERVALS: { '1m': 60_000, '5m': 300_000, '1h': 3_600_000 },
  timeSeriesRollupEngine: { query: mocks.query },
}));

import { analyticsRoutes } from '../analytics.routes';

describe('analytics time-series route', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    vi.clearAllMocks();
    mocks.query.mockResolvedValue([]);
    app = Fastify();
    await app.register(analyticsRoutes);
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  it('requires authentication and validates interval/range parameters', async () => {
    const unauthenticated = await app.inject({ method: 'GET', url: '/analytics/timeseries' });
    expect(unauthenticated.statusCode).toBe(401);

    const invalidInterval = await app.inject({
      method: 'GET',
      url: '/analytics/timeseries?interval=15m&from=2026-01-01&to=2026-01-02',
      headers: { authorization: 'Bearer test' },
    });
    expect(invalidInterval.statusCode).toBe(400);

    const invalidRange = await app.inject({
      method: 'GET',
      url: '/analytics/timeseries?interval=1m&from=2026-01-02&to=2026-01-01',
      headers: { authorization: 'Bearer test' },
    });
    expect(invalidRange.statusCode).toBe(400);
    expect(mocks.query).not.toHaveBeenCalled();
  });

  it('queries the selected pre-aggregated interval and bounds result limits', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/analytics/timeseries?interval=5m&from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&asset=USD%3AGISSUER&limit=2000',
      headers: { authorization: 'Bearer test' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ buckets: [] });
    expect(mocks.query).toHaveBeenCalledWith({
      interval: '5m',
      from: new Date('2026-01-01T00:00:00Z'),
      to: new Date('2026-01-02T00:00:00Z'),
      asset: 'USD:GISSUER',
      limit: 2000,
    });
  });
});
