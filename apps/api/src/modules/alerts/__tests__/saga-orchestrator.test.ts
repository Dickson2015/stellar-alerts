import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../lib/prisma', () => ({ prisma: {} }));
vi.mock('../../../lib/queue', () => ({ createRedisConnectionConfig: () => ({}) }));
vi.mock('../../../lib/redis', () => ({ registerRedisCleanupTask: vi.fn() }));
vi.mock('../../../config/env', () => ({ env: { NOTIFICATION_PROVIDER_TIMEOUT_MS: 1000 } }));
vi.mock('../../../modules/notifications/providers/pagerduty.provider', () => ({
  pagerDutyProvider: { dispatchTrigger: vi.fn() },
}));
vi.mock('../../../utils/ssrf', () => ({ ssrfSafeFetch: vi.fn() }));
import {
  IncidentSagaOrchestrator,
  type SagaActionRunner,
  type SagaPlaybook,
  type SagaRepository,
  type SagaScheduler,
  type SagaSnapshot,
  type ScheduledSagaStep,
} from '../saga-orchestrator';

class MemorySagaRepository implements SagaRepository {
  saga!: SagaSnapshot;

  async create(input: {
    incidentId: string;
    userId: string;
    playbook: SagaPlaybook;
    context: Record<string, unknown>;
    firstScheduledAt: Date;
  }): Promise<SagaSnapshot> {
    const now = new Date('2026-01-01T00:00:00.000Z');
    this.saga = {
      id: 'saga-1',
      incidentId: input.incidentId,
      userId: input.userId,
      status: 'RUNNING',
      currentStep: 0,
      context: input.context,
      createdAt: now,
      updatedAt: now,
      steps: input.playbook.steps.map((step, index) => ({
        ...step,
        index,
        status: index === 0 ? 'SCHEDULED' : 'PENDING',
        scheduledAt: index === 0 ? input.firstScheduledAt : null,
      })),
    };
    return this.saga;
  }

  async get(sagaId: string, userId?: string): Promise<SagaSnapshot | null> {
    return sagaId === this.saga.id && (!userId || userId === this.saga.userId) ? this.saga : null;
  }

  async scheduleStep(sagaId: string, stepIndex: number, scheduledAt: Date): Promise<boolean> {
    const step = this.saga.steps[stepIndex];
    if (sagaId !== this.saga.id || this.saga.status !== 'RUNNING' ||
      this.saga.currentStep !== stepIndex || step?.status !== 'PENDING') return false;
    step.status = 'SCHEDULED';
    step.scheduledAt = scheduledAt;
    return true;
  }

  async claimStep(sagaId: string, stepIndex: number) {
    const step = this.saga.steps[stepIndex];
    if (sagaId !== this.saga.id || this.saga.status !== 'RUNNING' ||
      this.saga.currentStep !== stepIndex || step?.status !== 'SCHEDULED') return null;
    step.status = 'RUNNING';
    return { ...step, index: stepIndex, context: this.saga.context, incidentId: this.saga.incidentId };
  }

  async completeStep(_sagaId: string, stepIndex: number, nextScheduledAt?: Date): Promise<number | null> {
    this.saga.steps[stepIndex].status = 'COMPLETED';
    const next = stepIndex + 1;
    if (next >= this.saga.steps.length) {
      this.saga.status = 'COMPLETED';
      return null;
    }
    this.saga.currentStep = next;
    this.saga.steps[next].status = 'SCHEDULED';
    this.saga.steps[next].scheduledAt = nextScheduledAt;
    return next;
  }

  async failStep(_sagaId: string, stepIndex: number): Promise<void> {
    this.saga.steps[stepIndex].status = 'FAILED';
    this.saga.status = 'FAILED';
  }

  async acknowledge(_sagaId: string, userId: string, actorId: string): Promise<boolean> {
    if (this.saga.userId !== userId || this.saga.status !== 'RUNNING') return false;
    this.saga.status = 'ACKNOWLEDGED';
    this.saga.acknowledgedBy = actorId;
    return true;
  }

  async beginConditionClear(_sagaId: string, userId: string): Promise<boolean> {
    if (this.saga.userId !== userId || this.saga.status !== 'RUNNING') return false;
    this.saga.status = 'COMPENSATING';
    return true;
  }

  async listScheduledSteps(): Promise<ScheduledSagaStep[]> {
    return this.saga.steps
      .filter((step) => step.status === 'SCHEDULED' && step.scheduledAt)
      .map((step) => ({ sagaId: this.saga.id, stepIndex: step.index, scheduledAt: step.scheduledAt! }));
  }

  async listRecoverableCompensations(): Promise<Array<{ sagaId: string; status: SagaSnapshot['status'] }>> {
    return [];
  }

  async claimCompensation(sagaId: string, stepIndex: number) {
    const step = this.saga.steps[stepIndex];
    if (sagaId !== this.saga.id || !['COMPENSATING', 'FAILED'].includes(this.saga.status) ||
      step?.status !== 'COMPLETED' || !step.compensation || step.compensationStatus) return null;
    step.compensationStatus = 'RUNNING';
    return { action: step.compensation, context: this.saga.context, incidentId: this.saga.incidentId };
  }

  async completeCompensation(_sagaId: string, stepIndex: number, error?: string): Promise<void> {
    this.saga.steps[stepIndex].compensationStatus = error ? 'FAILED' : 'COMPLETED';
  }

  async finishCompensation(_sagaId: string, status: 'RESOLVED' | 'FAILED'): Promise<void> {
    if (this.saga.status === 'COMPENSATING') this.saga.status = status;
  }
}

class MemorySagaScheduler implements SagaScheduler {
  jobs: ScheduledSagaStep[] = [];

  async schedule(job: ScheduledSagaStep): Promise<void> {
    this.jobs = this.jobs.filter((existing) => existing.stepIndex !== job.stepIndex || existing.sagaId !== job.sagaId);
    this.jobs.push(job);
  }

  async cancelSaga(sagaId: string): Promise<void> {
    this.jobs = this.jobs.filter((job) => job.sagaId !== sagaId);
  }
}

const action = (name: string) => ({ type: 'pagerduty' as const, message: name });
const playbook: SagaPlaybook = {
  steps: [
    { name: 'notify', action: action('notify'), compensation: action('cancel') },
    { name: 'escalate', delayMs: 120_000, action: action('escalate') },
  ],
};

describe('IncidentSagaOrchestrator', () => {
  let repository: MemorySagaRepository;
  let scheduler: MemorySagaScheduler;
  let runAction: ReturnType<typeof vi.fn<SagaActionRunner>>;
  let orchestrator: IncidentSagaOrchestrator;

  beforeEach(() => {
    repository = new MemorySagaRepository();
    scheduler = new MemorySagaScheduler();
    runAction = vi.fn(async (_action, _context, _incidentId) => {});
    orchestrator = new IncidentSagaOrchestrator({
      repository,
      scheduler,
      runAction,
      now: () => new Date('2026-01-01T00:00:00.000Z'),
    });
  });

  it('schedules escalation after the configured delay and completes the playbook', async () => {
    await orchestrator.start({ incidentId: 'incident-1', userId: 'user-1', playbook });
    expect(scheduler.jobs[0].scheduledAt).toEqual(new Date('2026-01-01T00:00:00.000Z'));

    await orchestrator.processStep(scheduler.jobs.find((job) => job.stepIndex === 0)!);
    const escalation = scheduler.jobs.find((job) => job.stepIndex === 1)!;
    expect(escalation.stepIndex).toBe(1);
    expect(escalation.scheduledAt).toEqual(new Date('2026-01-01T00:02:00.000Z'));
    await orchestrator.processStep(scheduler.jobs.find((job) => job.stepIndex === 1)!);

    expect(repository.saga.status).toBe('COMPLETED');
    expect(runAction.mock.calls.map(([stepAction]) => stepAction.message)).toEqual(['notify', 'escalate']);
  });

  it('halts queued escalation when acknowledged', async () => {
    await orchestrator.start({ incidentId: 'incident-1', userId: 'user-1', playbook });
    expect(await orchestrator.acknowledge('saga-1', 'user-1', 'operator-1')).toBe(true);
    expect(scheduler.jobs).toHaveLength(0);

    await orchestrator.processStep({ sagaId: 'saga-1', stepIndex: 0, scheduledAt: new Date() });
    expect(repository.saga.status).toBe('ACKNOWLEDGED');
    expect(runAction).not.toHaveBeenCalled();
  });

  it('compensates completed steps when the condition clears', async () => {
    await orchestrator.start({ incidentId: 'incident-1', userId: 'user-1', playbook });
    await orchestrator.processStep(scheduler.jobs[0]);
    expect(repository.saga.steps[0].status).toBe('COMPLETED');

    expect(await orchestrator.conditionCleared('saga-1', 'user-1')).toBe(true);
    expect(repository.saga.status).toBe('RESOLVED');
    expect(runAction.mock.calls.map(([stepAction]) => stepAction.message)).toEqual(['notify', 'cancel']);
    expect(repository.saga.steps[0].compensationStatus).toBe('COMPLETED');
  });

  it('runs compensations after a step failure', async () => {
    runAction.mockImplementationOnce(async () => {})
      .mockImplementationOnce(async () => { throw new Error('escalation failed'); });
    await orchestrator.start({ incidentId: 'incident-1', userId: 'user-1', playbook });
    await orchestrator.processStep(scheduler.jobs.find((job) => job.stepIndex === 0)!);

    await expect(
      orchestrator.processStep(scheduler.jobs.find((job) => job.stepIndex === 1)!),
    ).rejects.toThrow('escalation failed');
    expect(repository.saga.status).toBe('FAILED');
    expect(runAction.mock.calls.map(([stepAction]) => stepAction.message)).toEqual([
      'notify',
      'escalate',
      'cancel',
    ]);
  });
});
