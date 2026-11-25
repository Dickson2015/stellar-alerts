import { describe, expect, it, vi } from 'vitest';
import { ValidationError } from '../../../lib/errors';

vi.mock('../certification-suite.service', () => ({
  webhookCertificationSuite: { run: vi.fn() },
}));

import { webhooksController } from '../webhooks.controller';
import { webhookCertificationSuite } from '../certification-suite.service';

function replyDouble() {
  const value = {
    status: vi.fn(() => value),
    send: vi.fn(() => value),
  };
  return value;
}

const body = {
  targetUrl: 'https://hooks.example.com/certify',
  secret: 'primary-secret-long-enough',
  previousSecret: 'previous-secret-long-enough',
};

describe('certification controller (#1039)', () => {
  it('runs the suite for the authenticated user and returns the report', async () => {
    const report = {
      runId: 'cert-1',
      certified: true,
      score: 1,
      checks: [],
    };
    vi.mocked(webhookCertificationSuite.run).mockResolvedValue(report as never);

    const reply = replyDouble();
    await webhooksController.runCertification(
      { user: { id: 'user-1' }, body } as never,
      reply as never,
    );

    expect(webhookCertificationSuite.run).toHaveBeenCalledWith({ userId: 'user-1', ...body });
    expect(reply.status).not.toHaveBeenCalled();
    expect(reply.send).toHaveBeenCalledWith({ success: true, score: 1, report });
  });

  it('rejects malformed certification requests before any probe runs', async () => {
    vi.mocked(webhookCertificationSuite.run).mockClear();
    const reply = replyDouble();

    await expect(webhooksController.runCertification(
      { user: { id: 'user-1' }, body: { targetUrl: 'not-a-url', secret: 'short' } } as never,
      reply as never,
    )).rejects.toBeInstanceOf(ValidationError);
    expect(webhookCertificationSuite.run).not.toHaveBeenCalled();
  });
});
