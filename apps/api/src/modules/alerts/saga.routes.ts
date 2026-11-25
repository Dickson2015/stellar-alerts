import type { FastifyInstance } from 'fastify';
import { authenticateHook } from '../../middleware/auth.middleware';
import {
  incidentSagaOrchestrator,
  type IncidentSagaOrchestrator,
  type SagaPlaybook,
} from './saga-orchestrator';

const playbookSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['steps'],
  properties: {
    steps: {
      type: 'array',
      minItems: 1,
      maxItems: 50,
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['name', 'action'],
        properties: {
          name: { type: 'string', minLength: 1, maxLength: 120 },
          delayMs: { type: 'integer', minimum: 0, maximum: 604800000 },
          action: { type: 'object' },
          compensation: { type: 'object' },
        },
      },
    },
  },
} as const;

export async function registerSagaRoutes(
  app: FastifyInstance,
  orchestrator: IncidentSagaOrchestrator = incidentSagaOrchestrator,
): Promise<void> {
  app.post<{ Params: { incidentId: string }; Body: { playbook: SagaPlaybook; context?: Record<string, unknown> } }>(
    '/incidents/:incidentId/sagas',
    {
      preHandler: [authenticateHook],
      schema: {
        body: {
          type: 'object',
          additionalProperties: false,
          required: ['playbook'],
          properties: {
            playbook: playbookSchema,
            context: { type: 'object', additionalProperties: true },
          },
        },
      },
    },
    async (request, reply) => {
      if (!request.user?.id) return reply.status(401).send({ error: 'Authentication required' });
      try {
        const saga = await orchestrator.start({
          incidentId: request.params.incidentId,
          userId: request.user.id,
          playbook: request.body.playbook,
          context: request.body.context,
        });
        return reply.status(201).send(saga);
      } catch (error) {
        return reply.status(400).send({
          error: error instanceof Error ? error.message : 'Invalid saga playbook',
        });
      }
    },
  );

  app.get<{ Params: { sagaId: string } }>(
    '/incidents/sagas/:sagaId',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      if (!request.user?.id) return reply.status(401).send({ error: 'Authentication required' });
      const saga = await orchestrator.get(request.params.sagaId, request.user.id);
      if (!saga) return reply.status(404).send({ error: 'Saga not found' });
      return saga;
    },
  );

  app.post<{ Params: { sagaId: string } }>(
    '/incidents/sagas/:sagaId/acknowledge',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      if (!request.user?.id) return reply.status(401).send({ error: 'Authentication required' });
      const acknowledged = await orchestrator.acknowledge(
        request.params.sagaId,
        request.user.id,
        request.user.id,
      );
      if (!acknowledged) return reply.status(404).send({ error: 'Active saga not found' });
      return { status: 'ACKNOWLEDGED' };
    },
  );

  app.post<{ Params: { sagaId: string } }>(
    '/incidents/sagas/:sagaId/condition-cleared',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      if (!request.user?.id) return reply.status(401).send({ error: 'Authentication required' });
      const resolved = await orchestrator.conditionCleared(request.params.sagaId, request.user.id);
      if (!resolved) return reply.status(404).send({ error: 'Active saga not found' });
      return { status: 'RESOLVED' };
    },
  );
}
