import { randomUUID } from 'node:crypto';
import { Queue } from 'bullmq';
import { Prisma, type PrismaClient } from '../../../generated/prisma/client';
import { env } from '../../config/env';
import { prisma } from '../../lib/prisma';
import { createRedisConnectionConfig } from '../../lib/queue';
import { registerRedisCleanupTask } from '../../lib/redis';
import { pagerDutyProvider } from '../notifications/providers/pagerduty.provider';
import { ssrfSafeFetch } from '../../utils/ssrf';

export type SagaStatus =
  | 'RUNNING'
  | 'ACKNOWLEDGED'
  | 'COMPENSATING'
  | 'RESOLVED'
  | 'COMPLETED'
  | 'FAILED';

export type SagaAction =
  | {
      type: 'webhook';
      url: string;
      method?: 'POST' | 'PUT' | 'PATCH';
      headers?: Record<string, string>;
      body?: Record<string, unknown>;
    }
  | {
      type: 'pagerduty';
      message: string;
      title?: string;
      severity?: 'critical' | 'error' | 'warning' | 'info';
      dedupKey?: string;
    };

export interface SagaStepDefinition {
  name: string;
  delayMs?: number;
  action: SagaAction;
  compensation?: SagaAction;
}

export interface SagaPlaybook {
  steps: SagaStepDefinition[];
}

export interface SagaStepSnapshot extends SagaStepDefinition {
  index: number;
  status: 'PENDING' | 'SCHEDULED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  scheduledAt?: Date | null;
  startedAt?: Date | null;
  completedAt?: Date | null;
  error?: string | null;
  compensationStatus?: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED' | null;
}

export interface SagaSnapshot {
  id: string;
  incidentId: string;
  userId: string;
  status: SagaStatus;
  currentStep: number;
  context: Record<string, unknown>;
  acknowledgedBy?: string | null;
  acknowledgedAt?: Date | null;
  createdAt: Date;
  updatedAt: Date;
  steps: SagaStepSnapshot[];
}

export interface ScheduledSagaStep {
  sagaId: string;
  stepIndex: number;
  scheduledAt: Date;
}

export interface SagaRepository {
  create(input: {
    incidentId: string;
    userId: string;
    playbook: SagaPlaybook;
    context: Record<string, unknown>;
    firstScheduledAt: Date;
  }): Promise<SagaSnapshot>;
  get(sagaId: string, userId?: string): Promise<SagaSnapshot | null>;
  claimStep(sagaId: string, stepIndex: number): Promise<(SagaStepDefinition & {
    index: number;
    context: Record<string, unknown>;
    incidentId: string;
  }) | null>;
  completeStep(sagaId: string, stepIndex: number, nextScheduledAt?: Date): Promise<number | null>;
  failStep(sagaId: string, stepIndex: number, error: string): Promise<void>;
  acknowledge(sagaId: string, userId: string, actorId: string): Promise<boolean>;
  beginConditionClear(sagaId: string, userId: string): Promise<boolean>;
  listScheduledSteps(): Promise<ScheduledSagaStep[]>;
  listRecoverableCompensations(): Promise<Array<{ sagaId: string; status: SagaStatus }>>;
  claimCompensation(sagaId: string, stepIndex: number): Promise<{
    action: SagaAction;
    context: Record<string, unknown>;
    incidentId: string;
  } | null>;
  completeCompensation(sagaId: string, stepIndex: number, error?: string): Promise<void>;
  finishCompensation(sagaId: string, status: 'RESOLVED' | 'FAILED'): Promise<void>;
}

export interface SagaScheduler {
  schedule(job: ScheduledSagaStep): Promise<void>;
  cancelSaga(sagaId: string): Promise<void>;
}

type RawExecutor = Pick<PrismaClient, '$queryRaw' | '$executeRaw' | '$transaction'>;

const EXECUTION_TABLE = Prisma.raw('"IncidentSagaExecution"');
const STEP_TABLE = Prisma.raw('"IncidentSagaStep"');

function decodeJson<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

function rowToSaga(row: Record<string, any>, steps: Record<string, any>[]): SagaSnapshot {
  return {
    id: row.id,
    incidentId: row.incidentId,
    userId: row.userId,
    status: row.status,
    currentStep: row.currentStep,
    context: decodeJson(row.context, {}),
    acknowledgedBy: row.acknowledgedBy,
    acknowledgedAt: row.acknowledgedAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    steps: steps.map((step) => ({
      index: step.stepIndex,
      name: step.name,
      delayMs: step.delayMs,
      action: decodeJson(step.action, { type: 'webhook', url: '' }),
      compensation: decodeJson(step.compensation, undefined),
      status: step.status,
      scheduledAt: step.scheduledAt,
      startedAt: step.startedAt,
      completedAt: step.completedAt,
      error: step.error,
      compensationStatus: step.compensationStatus,
    })),
  };
}

/** SQL-backed repository; raw queries let this module compile before Prisma client regeneration. */
export class PrismaSagaRepository implements SagaRepository {
  constructor(private readonly db: RawExecutor = prisma) {}

  async create(input: {
    incidentId: string;
    userId: string;
    playbook: SagaPlaybook;
    context: Record<string, unknown>;
    firstScheduledAt: Date;
  }): Promise<SagaSnapshot> {
    const id = randomUUID();
    const now = new Date();
    await this.db.$transaction(async (tx) => {
      await tx.$executeRaw`
        INSERT INTO ${PrismaSagaRepository.executionTable}
          ("id", "incidentId", "userId", "status", "playbook", "context", "currentStep", "createdAt", "updatedAt")
        VALUES (${id}, ${input.incidentId}, ${input.userId}, 'RUNNING',
          ${JSON.stringify(input.playbook)}::jsonb, ${JSON.stringify(input.context)}::jsonb, 0, ${now}, ${now})
      `;
      for (const [stepIndex, step] of input.playbook.steps.entries()) {
        await tx.$executeRaw`
          INSERT INTO ${PrismaSagaRepository.stepTable}
            ("id", "sagaId", "stepIndex", "name", "action", "delayMs", "compensation", "status", "scheduledAt", "createdAt", "updatedAt")
          VALUES (${randomUUID()}, ${id}, ${stepIndex}, ${step.name},
            ${JSON.stringify(step.action)}::jsonb, ${step.delayMs ?? 0},
            ${step.compensation ? JSON.stringify(step.compensation) : null}::jsonb,
            ${stepIndex === 0 ? 'SCHEDULED' : 'PENDING'},
            ${stepIndex === 0 ? input.firstScheduledAt : null}, ${now}, ${now})
        `;
      }
    });
    const saga = await this.get(id);
    if (!saga) throw new Error('Saga was created but could not be loaded');
    return saga;
  }

  async get(sagaId: string, userId?: string): Promise<SagaSnapshot | null> {
    const rows = userId
      ? await this.db.$queryRaw<Array<Record<string, any>>>`
          SELECT * FROM ${PrismaSagaRepository.executionTable}
          WHERE "id" = ${sagaId} AND "userId" = ${userId} LIMIT 1
        `
      : await this.db.$queryRaw<Array<Record<string, any>>>`
          SELECT * FROM ${PrismaSagaRepository.executionTable}
          WHERE "id" = ${sagaId} LIMIT 1
        `;
    if (!rows[0]) return null;
    const steps = await this.db.$queryRaw<Array<Record<string, any>>>`
      SELECT * FROM ${PrismaSagaRepository.stepTable}
      WHERE "sagaId" = ${sagaId} ORDER BY "stepIndex" ASC
    `;
    return rowToSaga(rows[0], steps);
  }

  async claimStep(
    sagaId: string,
    stepIndex: number,
  ): Promise<(SagaStepDefinition & {
    index: number;
    context: Record<string, unknown>;
    incidentId: string;
  }) | null> {
    const claimed = await this.db.$queryRaw<Array<Record<string, any>>>`
      UPDATE ${PrismaSagaRepository.stepTable} AS step
      SET "status" = 'RUNNING', "startedAt" = NOW(), "updatedAt" = NOW()
      FROM ${PrismaSagaRepository.executionTable} AS saga
      WHERE step."sagaId" = saga."id" AND saga."id" = ${sagaId}
        AND saga."status" = 'RUNNING' AND saga."currentStep" = ${stepIndex}
        AND step."stepIndex" = ${stepIndex}
        AND (step."status" = 'SCHEDULED' OR (
          step."status" = 'RUNNING' AND step."startedAt" < NOW() - INTERVAL '5 minutes'
        ))
      RETURNING step.*
    `;
    if (!claimed[0]) return null;
    const sagaRows = await this.db.$queryRaw<Array<Record<string, any>>>`
      SELECT "incidentId", "context" FROM ${PrismaSagaRepository.executionTable}
      WHERE "id" = ${sagaId}
    `;
    if (!sagaRows[0]) return null;
    const step = claimed[0];
    return {
      index: stepIndex,
      name: step.name,
      delayMs: step.delayMs,
      action: decodeJson<SagaAction>(step.action, { type: 'webhook', url: '' }),
      compensation: decodeJson<SagaAction | undefined>(step.compensation, undefined),
      context: decodeJson(sagaRows[0].context, {}),
      incidentId: sagaRows[0].incidentId,
    };
  }

  async completeStep(
    sagaId: string,
    stepIndex: number,
    nextScheduledAt?: Date,
  ): Promise<number | null> {
    return this.db.$transaction(async (tx) => {
      const completed = await tx.$executeRaw`
        UPDATE ${PrismaSagaRepository.stepTable}
        SET "status" = 'COMPLETED', "completedAt" = NOW(), "updatedAt" = NOW()
        WHERE "sagaId" = ${sagaId} AND "stepIndex" = ${stepIndex} AND "status" = 'RUNNING'
      `;
      if (!completed) return null;
      const rows = await tx.$queryRaw<Array<{ count: bigint }>>`
        SELECT COUNT(*)::bigint AS count FROM ${PrismaSagaRepository.stepTable}
        WHERE "sagaId" = ${sagaId} AND "stepIndex" > ${stepIndex}
      `;
      const next = Number(rows[0]?.count ?? 0) > 0 ? stepIndex + 1 : null;
      if (next === null) {
        await tx.$executeRaw`
          UPDATE ${PrismaSagaRepository.executionTable}
          SET "status" = 'COMPLETED', "updatedAt" = NOW()
          WHERE "id" = ${sagaId} AND "status" = 'RUNNING' AND "currentStep" = ${stepIndex}
        `;
      } else {
        const advanced = await tx.$executeRaw`
          UPDATE ${PrismaSagaRepository.executionTable}
          SET "currentStep" = ${next}, "updatedAt" = NOW()
          WHERE "id" = ${sagaId} AND "status" = 'RUNNING' AND "currentStep" = ${stepIndex}
        `;
        if (!advanced) return null;
        const scheduled = await tx.$executeRaw`
          UPDATE ${PrismaSagaRepository.stepTable}
          SET "status" = 'SCHEDULED', "scheduledAt" = ${nextScheduledAt ?? new Date()},
            "updatedAt" = NOW()
          WHERE "sagaId" = ${sagaId} AND "stepIndex" = ${next} AND "status" = 'PENDING'
        `;
        if (!scheduled) throw new Error('Saga next step could not be scheduled atomically');
      }
      return next;
    });
  }

  async failStep(sagaId: string, stepIndex: number, error: string): Promise<void> {
    await this.db.$transaction(async (tx) => {
      await tx.$executeRaw`
        UPDATE ${PrismaSagaRepository.stepTable}
        SET "status" = 'FAILED', "error" = ${error.slice(0, 2000)}, "updatedAt" = NOW()
        WHERE "sagaId" = ${sagaId} AND "stepIndex" = ${stepIndex} AND "status" = 'RUNNING'
      `;
      await tx.$executeRaw`
        UPDATE ${PrismaSagaRepository.executionTable}
        SET "status" = 'FAILED', "updatedAt" = NOW()
        WHERE "id" = ${sagaId} AND "status" = 'RUNNING'
      `;
    });
  }

  async acknowledge(sagaId: string, userId: string, actorId: string): Promise<boolean> {
    const changed = await this.db.$executeRaw`
      UPDATE ${PrismaSagaRepository.executionTable}
      SET "status" = 'ACKNOWLEDGED', "acknowledgedBy" = ${actorId},
        "acknowledgedAt" = NOW(), "updatedAt" = NOW()
      WHERE "id" = ${sagaId} AND "userId" = ${userId} AND "status" = 'RUNNING'
    `;
    return changed > 0;
  }

  async beginConditionClear(sagaId: string, userId: string): Promise<boolean> {
    const changed = await this.db.$executeRaw`
      UPDATE ${PrismaSagaRepository.executionTable}
      SET "status" = 'COMPENSATING', "updatedAt" = NOW()
      WHERE "id" = ${sagaId} AND "userId" = ${userId} AND "status" = 'RUNNING'
    `;
    return changed > 0;
  }

  async listScheduledSteps(): Promise<ScheduledSagaStep[]> {
    const rows = await this.db.$queryRaw<Array<Record<string, any>>>`
      SELECT step."sagaId", step."stepIndex", step."scheduledAt"
      FROM ${PrismaSagaRepository.stepTable} AS step
      JOIN ${PrismaSagaRepository.executionTable} AS saga ON saga."id" = step."sagaId"
      WHERE (step."status" = 'SCHEDULED' OR (
          step."status" = 'RUNNING' AND step."startedAt" < NOW() - INTERVAL '5 minutes'
        )) AND saga."status" = 'RUNNING'
        AND saga."currentStep" = step."stepIndex"
    `;
    return rows.map((row) => ({
      sagaId: row.sagaId,
      stepIndex: row.stepIndex,
      scheduledAt: row.scheduledAt,
    }));
  }

  async listRecoverableCompensations(): Promise<Array<{ sagaId: string; status: SagaStatus }>> {
    const rows = await this.db.$queryRaw<Array<{ sagaId: string; status: SagaStatus }>>`
      SELECT DISTINCT saga."id" AS "sagaId", saga."status"
      FROM ${PrismaSagaRepository.executionTable} AS saga
      WHERE saga."status" = 'COMPENSATING'
        OR (saga."status" = 'FAILED' AND EXISTS (
          SELECT 1 FROM ${PrismaSagaRepository.stepTable} AS step
          WHERE step."sagaId" = saga."id" AND step."status" = 'COMPLETED'
            AND step."compensation" IS NOT NULL
            AND (
              COALESCE(step."compensationStatus", 'PENDING') = 'PENDING'
              OR (step."compensationStatus" = 'RUNNING'
                AND step."compensationStartedAt" < NOW() - INTERVAL '5 minutes')
            )
        ))
    `;
    return rows;
  }

  async claimCompensation(sagaId: string, stepIndex: number) {
    const rows = await this.db.$queryRaw<Array<Record<string, any>>>`
      UPDATE ${PrismaSagaRepository.stepTable} AS step
      SET "compensationStatus" = 'RUNNING', "compensationStartedAt" = NOW(), "updatedAt" = NOW()
      FROM ${PrismaSagaRepository.executionTable} AS saga
      WHERE step."sagaId" = saga."id" AND saga."id" = ${sagaId}
        AND saga."status" IN ('COMPENSATING', 'FAILED')
        AND step."stepIndex" = ${stepIndex} AND step."status" = 'COMPLETED'
        AND step."compensation" IS NOT NULL
        AND (COALESCE(step."compensationStatus", 'PENDING') = 'PENDING'
          OR (step."compensationStatus" = 'RUNNING'
            AND step."compensationStartedAt" < NOW() - INTERVAL '5 minutes'))
      RETURNING step."compensation"
    `;
    if (!rows[0]) return null;
    const sagaRows = await this.db.$queryRaw<Array<Record<string, any>>>`
      SELECT "context", "incidentId" FROM ${PrismaSagaRepository.executionTable}
      WHERE "id" = ${sagaId}
    `;
    if (!sagaRows[0]) return null;
    return {
      action: decodeJson<SagaAction>(rows[0].compensation, { type: 'webhook', url: '' }),
      context: decodeJson(sagaRows[0].context, {}),
      incidentId: sagaRows[0].incidentId,
    };
  }

  async completeCompensation(sagaId: string, stepIndex: number, error?: string): Promise<void> {
    await this.db.$executeRaw`
      UPDATE ${PrismaSagaRepository.stepTable}
      SET "compensationStatus" = ${error ? 'FAILED' : 'COMPLETED'},
        "compensationError" = ${error?.slice(0, 2000) ?? null},
        "compensatedAt" = ${error ? null : new Date()}, "updatedAt" = NOW()
      WHERE "sagaId" = ${sagaId} AND "stepIndex" = ${stepIndex}
        AND "compensationStatus" = 'RUNNING'
    `;
  }

  async finishCompensation(sagaId: string, status: 'RESOLVED' | 'FAILED'): Promise<void> {
    await this.db.$executeRaw`
      UPDATE ${PrismaSagaRepository.executionTable}
      SET "status" = CASE
          WHEN "status" = 'COMPENSATING' AND EXISTS (
            SELECT 1 FROM ${PrismaSagaRepository.stepTable} AS failed
            WHERE failed."sagaId" = ${sagaId} AND failed."compensationStatus" = 'FAILED'
          ) THEN 'FAILED'
          WHEN "status" = 'COMPENSATING' THEN ${status}
          ELSE "status"
        END,
        "updatedAt" = NOW()
      WHERE "id" = ${sagaId} AND "status" IN ('COMPENSATING', 'FAILED')
        AND NOT EXISTS (
          SELECT 1 FROM ${PrismaSagaRepository.stepTable} AS step
          WHERE step."sagaId" = ${sagaId} AND step."status" = 'COMPLETED'
            AND step."compensation" IS NOT NULL
            AND step."compensationStatus" IN ('PENDING', 'RUNNING')
        )
    `;
  }

  private static get executionTable() {
    return EXECUTION_TABLE;
  }

  private static get stepTable() {
    return STEP_TABLE;
  }
}

export const SAGA_QUEUE_NAME = 'incident-saga-steps';
const SAGA_MAX_DELAY_MS = 7 * 24 * 60 * 60 * 1000;
let sagaQueue: Queue<ScheduledSagaStep> | null = null;

export function getSagaQueue(): Queue<ScheduledSagaStep> {
  if (!sagaQueue) {
    sagaQueue = new Queue<ScheduledSagaStep>(SAGA_QUEUE_NAME, {
      connection: createRedisConnectionConfig() as any,
      defaultJobOptions: {
        attempts: 1,
        removeOnComplete: 1000,
        removeOnFail: 1000,
      },
    });
    const queue = sagaQueue;
    registerRedisCleanupTask(async () => {
      await queue.close().catch(() => {});
    });
  }
  return sagaQueue;
}

export class BullMqSagaScheduler implements SagaScheduler {
  async schedule(job: ScheduledSagaStep): Promise<void> {
    const delay = Math.max(0, job.scheduledAt.getTime() - Date.now());
    const queue = getSagaQueue();
    const jobId = `saga-${job.sagaId}-step-${job.stepIndex}`;
    const existing = await queue.getJob(jobId);
    if (existing) {
      const state = await existing.getState();
      if (state === 'failed') await existing.remove();
      else if (state !== 'completed') return;
    }
    await queue.add('execute-step', job, {
      jobId,
      delay,
    });
  }

  async cancelSaga(sagaId: string): Promise<void> {
    const queue = getSagaQueue();
    const jobs = await queue.getJobs(['delayed', 'waiting', 'prioritized']);
    await Promise.all(
      jobs
        .filter((job) => job.data.sagaId === sagaId)
        .map((job) => job.remove().catch(() => undefined)),
    );
  }
}

export type SagaActionRunner = (
  action: SagaAction,
  context: Record<string, unknown>,
  incidentId: string,
) => Promise<void>;

async function runSagaAction(
  action: SagaAction,
  context: Record<string, unknown>,
  incidentId: string,
): Promise<void> {
  if (action.type === 'webhook') {
    const response = await ssrfSafeFetch(action.url, {
      method: action.method ?? 'POST',
      headers: { 'content-type': 'application/json', ...action.headers },
      body: JSON.stringify({ incidentId, ...context, ...(action.body ?? {}) }),
      signal: AbortSignal.timeout(env.NOTIFICATION_PROVIDER_TIMEOUT_MS),
      maxRequestBytes: 1024 * 1024,
      maxResponseBytes: 1024 * 1024,
    });
    if (!response.ok) throw new Error(`Saga webhook returned HTTP ${response.status}`);
    return;
  }
  const result = await pagerDutyProvider.dispatchTrigger({
    alertId: incidentId,
    message: action.message,
    title: action.title,
    severity: action.severity ?? 'error',
    dedupKey: action.dedupKey,
    customDetails: context,
  });
  if (!result.success) throw new Error(result.error ?? 'PagerDuty dispatch failed');
}

function validatePlaybook(playbook: SagaPlaybook): void {
  if (!playbook || !Array.isArray(playbook.steps) || playbook.steps.length === 0 || playbook.steps.length > 50) {
    throw new Error('A playbook must contain between 1 and 50 steps');
  }
  for (const step of playbook.steps) {
    if (!step || typeof step.name !== 'string' || step.name.trim().length === 0 || step.name.length > 120) {
      throw new Error('Every saga step must have a name of 1–120 characters');
    }
    const delayMs = step.delayMs ?? 0;
    if (!Number.isInteger(delayMs) || delayMs < 0 || delayMs > SAGA_MAX_DELAY_MS) {
      throw new Error('Saga step delays must be between 0 and 7 days');
    }
    for (const action of [step.action, step.compensation].filter(Boolean) as SagaAction[]) {
      if (!action || !['webhook', 'pagerduty'].includes(action.type)) {
        throw new Error('Saga actions must be webhook or pagerduty actions');
      }
      if (action.type === 'webhook') {
        let url: URL;
        try {
          url = new URL(action.url);
        } catch {
          throw new Error('Webhook actions require a valid URL');
        }
        if (url.protocol !== 'https:' && url.protocol !== 'http:') {
          throw new Error('Webhook actions only support HTTP(S) URLs');
        }
        if (action.method && !['POST', 'PUT', 'PATCH'].includes(action.method)) {
          throw new Error('Webhook actions only support POST, PUT, or PATCH');
        }
      } else if (
        typeof action.message !== 'string' ||
        action.message.trim().length === 0 ||
        action.message.length > 2000
      ) {
        throw new Error('PagerDuty actions require a message of 1–2000 characters');
      }
    }
  }
}

export class IncidentSagaOrchestrator {
  private readonly repository: SagaRepository;
  private readonly scheduler: SagaScheduler;
  private readonly runAction: SagaActionRunner;
  private readonly now: () => Date;

  constructor(options: {
    repository?: SagaRepository;
    scheduler?: SagaScheduler;
    runAction?: SagaActionRunner;
    now?: () => Date;
  } = {}) {
    this.repository = options.repository ?? new PrismaSagaRepository();
    this.scheduler = options.scheduler ?? new BullMqSagaScheduler();
    this.runAction = options.runAction ?? runSagaAction;
    this.now = options.now ?? (() => new Date());
  }

  async start(input: {
    incidentId: string;
    userId: string;
    playbook: SagaPlaybook;
    context?: Record<string, unknown>;
  }): Promise<SagaSnapshot> {
    validatePlaybook(input.playbook);
    if (!input.incidentId || input.incidentId.length > 200 || !input.userId) {
      throw new Error('Incident and authenticated user identifiers are required');
    }
    const firstScheduledAt = new Date(this.now().getTime() + (input.playbook.steps[0].delayMs ?? 0));
    const saga = await this.repository.create({
      ...input,
      context: input.context ?? {},
      firstScheduledAt,
    });
    try {
      await this.scheduler.schedule({ sagaId: saga.id, stepIndex: 0, scheduledAt: firstScheduledAt });
    } catch (error) {
      console.warn('[Saga] Initial job enqueue failed; durable schedule recovery will retry', error);
    }
    return (await this.repository.get(saga.id)) ?? saga;
  }

  get(sagaId: string, userId: string): Promise<SagaSnapshot | null> {
    return this.repository.get(sagaId, userId);
  }

  async acknowledge(sagaId: string, userId: string, actorId: string): Promise<boolean> {
    const acknowledged = await this.repository.acknowledge(sagaId, userId, actorId);
    if (acknowledged) await this.cancelPendingJobs(sagaId);
    return acknowledged;
  }

  async conditionCleared(sagaId: string, userId: string): Promise<boolean> {
    const started = await this.repository.beginConditionClear(sagaId, userId);
    if (!started) return false;
    await this.cancelPendingJobs(sagaId);
    if (!(await this.waitForInFlightStep(sagaId))) {
      await this.repository.finishCompensation(sagaId, 'FAILED');
      return true;
    }
    await this.compensate(sagaId, 'RESOLVED');
    return true;
  }

  async processStep(job: ScheduledSagaStep): Promise<void> {
    const step = await this.repository.claimStep(job.sagaId, job.stepIndex);
    if (!step) return;
    try {
      await this.runAction(step.action, { ...step.context, stepName: step.name }, step.incidentId);
      const saga = await this.repository.get(job.sagaId);
      const nextStep = saga?.steps[job.stepIndex + 1];
      const nextScheduledAt = nextStep
        ? new Date(this.now().getTime() + (nextStep.delayMs ?? 0))
        : undefined;
      const nextIndex = await this.repository.completeStep(job.sagaId, job.stepIndex, nextScheduledAt);
      if (nextIndex !== null) {
        try {
          await this.scheduler.schedule({
            sagaId: job.sagaId,
            stepIndex: nextIndex,
            scheduledAt: nextScheduledAt ?? this.now(),
          });
        } catch (error) {
          console.warn('[Saga] Next job enqueue failed; durable schedule recovery will retry', error);
        }
      }
    } catch (error) {
      await this.repository.failStep(job.sagaId, job.stepIndex, error instanceof Error ? error.message : String(error));
      await this.compensate(job.sagaId, 'FAILED');
      throw error;
    }
  }

  async recoverScheduledSteps(): Promise<void> {
    const scheduled = await this.repository.listScheduledSteps();
    const results = await Promise.allSettled(scheduled.map((job) => this.scheduler.schedule(job)));
    if (results.some((result) => result.status === 'rejected')) {
      throw new Error('Some persisted saga steps could not be re-enqueued');
    }
  }

  async recoverCompensations(): Promise<void> {
    const sagas = await this.repository.listRecoverableCompensations();
    await Promise.all(sagas.map((saga) =>
      this.compensate(saga.sagaId, saga.status === 'FAILED' ? 'FAILED' : 'RESOLVED'),
    ));
  }

  private async waitForInFlightStep(sagaId: string): Promise<boolean> {
    const deadline = Date.now() + 60_000;
    while (Date.now() < deadline) {
      const saga = await this.repository.get(sagaId);
      if (!saga?.steps.some((step) => step.status === 'RUNNING')) return true;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return false;
  }

  private async cancelPendingJobs(sagaId: string): Promise<void> {
    try {
      await this.scheduler.cancelSaga(sagaId);
    } catch (error) {
      console.warn('[Saga] Pending queue jobs could not be cancelled; persisted status prevents execution', error);
    }
  }

  private async compensate(sagaId: string, finalStatus: 'RESOLVED' | 'FAILED'): Promise<void> {
    const saga = await this.repository.get(sagaId);
    if (!saga) return;
    let compensationFailed = false;
    for (const step of [...saga.steps].reverse()) {
      if (step.status !== 'COMPLETED' || !step.compensation) continue;
      const compensation = await this.repository.claimCompensation(sagaId, step.index);
      if (!compensation) continue;
      try {
        await this.runAction(compensation.action, {
          ...compensation.context,
          stepName: step.name,
          compensation: true,
        }, compensation.incidentId);
        await this.repository.completeCompensation(sagaId, step.index);
      } catch (error) {
        compensationFailed = true;
        await this.repository.completeCompensation(
          sagaId,
          step.index,
          error instanceof Error ? error.message : String(error),
        );
      }
    }
    await this.repository.finishCompensation(
      sagaId,
      compensationFailed ? 'FAILED' : finalStatus,
    );
  }
}

export const incidentSagaOrchestrator = new IncidentSagaOrchestrator();

export function resetSagaQueueForTests(): void {
  sagaQueue = null;
}
