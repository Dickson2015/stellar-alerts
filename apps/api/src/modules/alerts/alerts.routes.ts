import type { FastifyInstance } from 'fastify';
import {
  registerSseAlertStreamRoutes,
  type SseRouteOptions,
} from './sse-stream.controller';
import { registerSagaRoutes } from './saga.routes';

/** Alert routes mounted at /api/v1 (see app.ts). */
export async function alertsRoutes(
  app: FastifyInstance,
  options: SseRouteOptions = {},
): Promise<void> {
  await registerSseAlertStreamRoutes(app, options);
  await registerSagaRoutes(app);
}
