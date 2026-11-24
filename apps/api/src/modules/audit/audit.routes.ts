import { FastifyInstance } from 'fastify';
import { MerkleProof } from '@stellar-alerts/shared';
import { authenticateHook } from '../../middleware/auth.middleware';
import { AuditController, AuditHttpError } from './audit.controller';

const auditController = new AuditController();

/**
 * Audit routes for Merkle tree operations.
 * All endpoints require authentication and scope database queries to the authenticated user.
 */
export async function auditRoutes(app: FastifyInstance) {
  app.addHook('preHandler', authenticateHook);

  app.get<{ Params: { date: string } }>(
    '/audit/merkle-root/:date',
    async (request, reply) => {
      try {
        const result = await auditController.getMerkleRoot(
          request.params.date,
          request.user?.id,
        );
        return reply.status(200).send(result);
      } catch (error) {
        if (error instanceof AuditHttpError) {
          return reply.status(error.statusCode).send(error.response);
        }
        return reply.status(500).send({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to generate Merkle root',
        });
      }
    },
  );

  app.get<{ Params: { alertId: string; date: string } }>(
    '/audit/proof/:alertId/:date',
    async (request, reply) => {
      try {
        const result = await auditController.getInclusionProof(
          request.params.alertId,
          request.params.date,
          request.user?.id,
        );
        return reply.status(200).send(result);
      } catch (error) {
        if (error instanceof AuditHttpError) {
          return reply.status(error.statusCode).send(error.response);
        }
        return reply.status(500).send({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to generate inclusion proof',
        });
      }
    },
  );

  /**
   * On-chain anchored proof for issue #1041. Distinct from the daily Merkle
   * proof above: this returns the hourly root and Stellar anchor transaction.
   */
  app.get<{ Params: { id: string } }>(
    '/audit/:id/proof',
    auditController.getProof.bind(auditController),
  );

  app.post<{ Body: { alertId: string; proof: MerkleProof; expectedRoot: string } }>(
    '/audit/verify',
    async (request, reply) => {
      try {
        const result = await auditController.verifyProof(request.body);
        return reply.status(200).send(result);
      } catch (error) {
        if (error instanceof AuditHttpError) {
          return reply.status(error.statusCode).send(error.response);
        }
        return reply.status(400).send({
          success: false,
          error: error instanceof Error ? error.message : 'Verification failed',
        });
      }
    },
  );

  app.post<{ Body: { date: string; root: string; treeSize: number } }>(
    '/audit/commit',
    async (request, reply) => {
      try {
        const result = await auditController.commitMerkleRoot(request.body);
        return reply.status(200).send(result);
      } catch (error) {
        if (error instanceof AuditHttpError) {
          return reply.status(error.statusCode).send(error.response);
        }
        return reply.status(400).send({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to store commitment',
        });
      }
    },
  );
}
