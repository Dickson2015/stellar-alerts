import { Worker } from 'bullmq';
import { prisma } from '../lib/prisma';
import { createLogger } from '../lib/logger';
import { createRedisConnectionConfig } from '../lib/queue';
import { WorkerLifecycleManager } from '../lib/worker-lifecycle';
import {
  incidentSagaOrchestrator,
  SAGA_QUEUE_NAME,
  type ScheduledSagaStep,
} from '../modules/alerts/saga-orchestrator';

const log = createLogger({ module: 'SagaWorker' });
const RECOVERY_INTERVAL_MS = 30_000;

export const sagaWorkerLifecycle = new WorkerLifecycleManager({
  workerName: 'SagaWorker',
  drainTimeoutMs: 30_000,
  maxInFlight: 10,
  autoRegisterSignals: true,
});

export async function sagaJobProcessor(job: { data: ScheduledSagaStep }): Promise<void> {
  await incidentSagaOrchestrator.processStep(job.data);
}

export async function runSagaWorker() {
  const worker = new Worker<ScheduledSagaStep>(SAGA_QUEUE_NAME, sagaJobProcessor, {
    connection: createRedisConnectionConfig() as any,
    concurrency: 10,
  });
  worker.on('failed', (job, error) => {
    log.error(
      { sagaId: job?.data.sagaId, stepIndex: job?.data.stepIndex, err: error.message },
      'Saga step failed',
    );
  });

  const recover = async () => {
    try {
      await Promise.all([
        incidentSagaOrchestrator.recoverScheduledSteps(),
        incidentSagaOrchestrator.recoverCompensations(),
      ]);
    } catch (error) {
      log.error(
        { err: error instanceof Error ? error.message : String(error) },
        'Saga schedule recovery failed',
      );
    }
  };
  await recover();
  sagaWorkerLifecycle.trackInterval(setInterval(recover, RECOVERY_INTERVAL_MS));
  sagaWorkerLifecycle.registerCleanup('bullmq', async () => worker.close());
  sagaWorkerLifecycle.registerCleanup('prisma', async () => prisma.$disconnect());
  sagaWorkerLifecycle.markRunning();
  log.info({ recoveryIntervalMs: RECOVERY_INTERVAL_MS }, 'Saga worker started');
  return worker;
}

if (require.main === module) {
  process.on('message', (message: any) => {
    if (message?.type === 'ping') process.send?.({ type: 'pong' });
  });
  runSagaWorker().catch((error) => {
    log.error(
      { err: error instanceof Error ? error.message : String(error) },
      'Saga worker failed to start',
    );
    process.exit(1);
  });
}
