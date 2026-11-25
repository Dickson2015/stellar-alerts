import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../../middleware/auth.middleware', () => ({
  authenticateHook: async (request: { user?: { id: string } }) => {
    request.user = { id: 'operator-1' };
  },
}));
vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../../lib/queue', () => ({ createRedisConnectionConfig: () => ({}) }));
vi.mock('../../../lib/redis', () => ({ registerRedisCleanupTask: vi.fn() }));
vi.mock('../../../config/env', () => ({ env: { NOTIFICATION_PROVIDER_TIMEOUT_MS: 1000 } }));
vi.mock('../../../modules/notifications/providers/pagerduty.provider', () => ({
  pagerDutyProvider: { dispatchTrigger: vi.fn() },
}));
vi.mock('../../../utils/ssrf', () => ({ ssrfSafeFetch: vi.fn() }));

import { registerSagaRoutes } from '../saga.routes';
import type { IncidentSagaOrchestrator } from '../saga-orchestrator';

describe('incident saga routes', () => {
  it('creates a playbook for the authenticated user and exposes acknowledgement', async () => {
    const orchestrator = {
      start: vi.fn(async () => ({ id: 'saga-1', status: 'RUNNING' })),
      get: vi.fn(),
      acknowledge: vi.fn(async () => true),
      conditionCleared: vi.fn(async () => true),
    } as unknown as IncidentSagaOrchestrator;
    const app = Fastify();
    await registerSagaRoutes(app, orchestrator);

    const created = await app.inject({
      method: 'POST',
      url: '/incidents/incident-1/sagas',
      payload: {
        playbook: {
          steps: [{
            name: 'notify',
            action: { type: 'pagerduty', message: 'Investigate incident' },
          }],
        },
      },
    });
    expect(created.statusCode).toBe(201);
    expect(orchestrator.start).toHaveBeenCalledWith(expect.objectContaining({
      incidentId: 'incident-1',
      userId: 'operator-1',
    }));

    const acknowledged = await app.inject({
      method: 'POST',
      url: '/incidents/sagas/saga-1/acknowledge',
    });
    expect(acknowledged.statusCode).toBe(200);
    expect(orchestrator.acknowledge).toHaveBeenCalledWith('saga-1', 'operator-1', 'operator-1');
    await app.close();
  });
});
