import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../middleware/rbac.middleware', () => ({
  authenticate: async (request: { user?: unknown }) => {
    request.user = { id: 'user-1' };
  },
  requireScopes: () => async () => {},
}));
vi.mock('../certification-suite.service', () => ({
  webhookCertificationSuite: { run: vi.fn(async () => ({
    runId: 'cert-1',
    certified: true,
    score: 1,
    checks: [],
    passed: 10,
    failed: 0,
    startedAt: '2026-11-24T10:00:00.000Z',
    completedAt: '2026-11-24T10:00:01.000Z',
    durationMs: 1000,
    targetUrl: 'https://hooks.example.com/certify',
  })) },
}));

import { webhooksRoutes } from '../webhooks.routes';

describe('webhook certification route (#1039)', () => {
  it('exposes POST /webhooks/certification/run and accepts a valid request', async () => {
    const app = Fastify();
    await app.register(webhooksRoutes);

    expect(app.hasRoute({ method: 'POST', url: '/webhooks/certification/run' })).toBe(true);

    const response = await app.inject({
      method: 'POST',
      url: '/webhooks/certification/run',
      payload: {
        targetUrl: 'https://hooks.example.com/certify',
        secret: 'primary-secret-long-enough',
        previousSecret: 'previous-secret-long-enough',
      },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({ success: true, score: 1 });
    await app.close();
  });
});
