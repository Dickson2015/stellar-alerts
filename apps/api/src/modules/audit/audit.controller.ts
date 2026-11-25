import { FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { MerkleAuditService } from './merkle.service';
import { MerkleProof } from '@stellar-alerts/shared';
import { NotFoundError, zodValidationError } from '../../lib/errors';
import { onChainNotaryService } from './onchain-notary.service';

const auditProofParamsSchema = z.object({
  id: z.string().min(1),
});

export class AuditHttpError extends Error {
  public readonly statusCode: number;
  public readonly response: Record<string, unknown>;

  constructor(response: Record<string, unknown>, statusCode: number) {
    super(typeof response.error === 'string' ? response.error : 'Audit request failed');
    this.name = 'AuditHttpError';
    this.statusCode = statusCode;
    this.response = response;
  }
}

/**
 * AuditController
 *
 * Handlers for Merkle tree audit operations.
 */
export class AuditController {
  constructor(private readonly merkleService: MerkleAuditService = new MerkleAuditService()) {}

  async getMerkleRoot(date: string, userId?: string) {
    try {
      if (!this.isValidDateFormat(date)) {
        throw new Error('Invalid date format. Expected YYYY-MM-DD');
      }

      const result = await this.merkleService.generateDailyMerkleRoot(date, userId);
      return {
        success: true,
        date,
        root: result.root,
        treeSize: result.treeSize,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      throw new AuditHttpError(
        {
          success: false,
          error: error instanceof Error ? error.message : 'Failed to generate Merkle root',
        },
        500,
      );
    }
  }

  async getInclusionProof(alertId: string, date: string, userId?: string) {
    try {
      if (!this.isValidDateFormat(date)) {
        throw new Error('Invalid date format. Expected YYYY-MM-DD');
      }

      const proof = await this.merkleService.generateAlertInclusionProof(alertId, date, userId);
      return {
        success: true,
        alertId,
        date,
        proof,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to generate inclusion proof';
      throw new AuditHttpError(
        {
          success: false,
          error: message,
        },
        message.includes('not found') ? 404 : 500,
      );
    }
  }

  async verifyProof(body: { alertId: string; proof: MerkleProof; expectedRoot: string }) {
    try {
      const { alertId, proof, expectedRoot } = body;

      if (!alertId || !proof || !expectedRoot) {
        throw new Error('Missing required fields: alertId, proof, expectedRoot');
      }

      const isValid = this.merkleService.verifyAlertInclusion(alertId, proof, expectedRoot);

      return {
        success: true,
        alertId,
        verified: isValid,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      throw new AuditHttpError(
        {
          success: false,
          error: error instanceof Error ? error.message : 'Verification failed',
        },
        400,
      );
    }
  }

  async commitMerkleRoot(body: { date: string; root: string; treeSize: number }) {
    try {
      const { date, root, treeSize } = body;

      if (!date || !root || treeSize === undefined) {
        throw new Error('Missing required fields: date, root, treeSize');
      }

      if (!this.isValidDateFormat(date)) {
        throw new Error('Invalid date format. Expected YYYY-MM-DD');
      }

      const commitment = await this.merkleService.storeDailyMerkleCommitment(date, root, treeSize);

      return {
        success: true,
        commitment,
        timestamp: new Date().toISOString(),
      };
    } catch (error) {
      throw new AuditHttpError(
        {
          success: false,
          error: error instanceof Error ? error.message : 'Failed to store commitment',
        },
        400,
      );
    }
  }

  /**
   * GET /audit/:id/proof — returns a verifiable RFC 6962 inclusion proof for
   * the audit log, the Merkle root and the Stellar transaction that anchored
   * it (null until the hourly anchor job has published the root).
   */
  async getProof(request: FastifyRequest, reply: FastifyReply) {
    const parsed = auditProofParamsSchema.safeParse(request.params);
    if (!parsed.success) throw zodValidationError(parsed, 'Invalid parameters');

    const proof = await onChainNotaryService.getProof(parsed.data.id);
    if (!proof) throw new NotFoundError('Audit log not found');

    return reply.header('Cache-Control', 'no-store').send({ success: true, proof });
  }

  private isValidDateFormat(dateString: string): boolean {
    return /^\d{4}-\d{2}-\d{2}$/.test(dateString) && !isNaN(Date.parse(`${dateString}T00:00:00Z`));
  }
}

export const auditController = new AuditController();
