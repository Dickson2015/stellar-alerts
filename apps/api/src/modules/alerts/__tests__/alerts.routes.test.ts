import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../lib/redis', () => ({
  getRedisClient: vi.fn(),
  registerRedisCleanupTask: vi.fn(),
}));
vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../middleware/auth.middleware', () => ({
  authenticateHook: vi.fn(),
  authenticateToken: vi.fn(),
}));

import { alertsRoutes } from '../alerts.routes';
import { AlertStreamHub } from '../sse-stream.controller';

describe('alerts routes (#1038)', () => {
  it('registers GET /alerts/stream and rejects unauthenticated requests', async () => {
    const app = Fastify();
    app.setErrorHandler((error: Error, _request, reply) => {
      const status = (error as Error & { statusCode?: number }).statusCode ?? 500;
      return reply.status(status).send({ code: (error as Error & { code?: string }).code });
    });

    await app.register(alertsRoutes, {
      hub: new AlertStreamHub(),
      startRedisSubscriber: false,
    });

    expect(app.hasRoute({ method: 'GET', url: '/alerts/stream' })).toBe(true);
    const response = await app.inject({ method: 'GET', url: '/alerts/stream' });
    expect(response.statusCode).toBe(401);
    await app.close();
  });
});
