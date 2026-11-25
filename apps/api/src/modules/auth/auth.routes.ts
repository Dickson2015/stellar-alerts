import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { authController } from './auth.controller';
import { sep10Controller } from './sep10.controller';
import { authenticateHook } from '../../middleware/auth.middleware';
import { webAuthnService, WebAuthnError } from './webauthn.service';

const registerVerifySchema = z.object({
  nickname: z.string().trim().min(1).max(100),
  clientDataJSON: z.string().min(1),
  attestationObject: z.string().min(1),
  transports: z.array(z.string()).optional(),
});

const assertionChallengeSchema = z.object({
  purpose: z.enum(['login', 'step-up']).optional().default('login'),
});

const assertionVerifySchema = z.object({
  credentialId: z.string().min(1),
  clientDataJSON: z.string().min(1),
  authenticatorData: z.string().min(1),
  signature: z.string().min(1),
  expectedPurpose: z.enum(['login', 'step-up']).optional(),
});

export async function authRoutes(app: FastifyInstance) {
  app.post('/auth/request-link', authController.requestMagicLink.bind(authController));
  app.get('/auth/verify', authController.verifyMagicLink.bind(authController));
  app.post('/auth/did/challenge', authController.requestDIDChallenge.bind(authController));
  app.post('/auth/did/verify', authController.verifyDIDAuth.bind(authController));
  app.post('/auth/telegram', authController.verifyTelegramInitData.bind(authController));
  app.post('/auth/refresh', authController.refreshTokens.bind(authController));
  app.post('/auth/revoke-session', { preHandler: [authenticateHook] }, authController.revokeSession.bind(authController));
  app.get('/auth/me', { preHandler: [authenticateHook] }, authController.getMe.bind(authController));
  app.post('/auth/logout', { preHandler: [authenticateHook] }, authController.logout.bind(authController));
  
  // SEP-0010 Stellar Web Authentication endpoints
  // Public and cryptographic, so both are rate limited per client.
  app.get(
    '/auth/sep10/challenge',
    { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } },
    sep10Controller.getChallenge.bind(sep10Controller),
  );
  app.post(
    '/auth/sep10/verify',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    sep10Controller.verify.bind(sep10Controller),
  );

  // MFA endpoints (require authentication)
  app.post('/auth/mfa/setup', { preHandler: [authenticateHook] }, authController.setupMFA.bind(authController));
  app.post('/auth/mfa/enable', { preHandler: [authenticateHook] }, authController.enableMFA.bind(authController));
  app.post('/auth/mfa/disable', { preHandler: [authenticateHook] }, authController.disableMFA.bind(authController));
  app.get('/auth/mfa/status', { preHandler: [authenticateHook] }, authController.getMFAStatus.bind(authController));
  app.post('/auth/mfa/recovery-codes', { preHandler: [authenticateHook] }, authController.generateRecoveryCodes.bind(authController));
  app.get('/auth/mfa/recovery-codes', { preHandler: [authenticateHook] }, authController.getRecoveryCodeStatus.bind(authController));

  // Lost device recovery (public)
  app.post('/auth/mfa/recover', authController.recoverAccount.bind(authController));

  // WebAuthn / FIDO2 Hardware Security Key endpoints (#993)
  app.post(
    '/auth/webauthn/register/challenge',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const user = request.user!;
      const options = await webAuthnService.generateRegistrationChallenge({
        userId: user.id,
        email: user.email,
      });
      return reply.send({ success: true, options });
    },
  );

  app.post(
    '/auth/webauthn/register/verify',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const parsed = registerVerifySchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
      }
      try {
        const credential = await webAuthnService.verifyRegistrationAttestation({
          userId: request.user!.id,
          ...parsed.data,
        });
        return reply.status(201).send({
          success: true,
          credential: {
            id: credential.id,
            credentialId: credential.credentialId,
            nickname: credential.nickname,
            algorithm: credential.algorithm,
            signCount: credential.signCount,
            createdAt: credential.createdAt,
          },
        });
      } catch (err: unknown) {
        if (err instanceof WebAuthnError) {
          return reply.status(err.statusCode).send({ error: err.code, message: err.message });
        }
        throw err;
      }
    },
  );

  app.get(
    '/auth/webauthn/credentials',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const credentials = await webAuthnService.listCredentials(request.user!.id);
      return reply.send({ success: true, credentials });
    },
  );

  app.delete(
    '/auth/webauthn/credentials/:id',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const deleted = await webAuthnService.deleteCredential(request.user!.id, id);
      if (!deleted) {
        return reply.status(404).send({ error: 'NOT_FOUND', message: 'Credential not found' });
      }
      return reply.send({ success: true });
    },
  );

  app.post(
    '/auth/webauthn/authenticate/challenge',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const parsed = assertionChallengeSchema.safeParse(request.body ?? {});
      if (!parsed.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
      }
      try {
        const options = await webAuthnService.generateAssertionChallenge({
          userId: request.user!.id,
          purpose: parsed.data.purpose,
        });
        return reply.send({ success: true, options });
      } catch (err: unknown) {
        if (err instanceof WebAuthnError) {
          return reply.status(err.statusCode).send({ error: err.code, message: err.message });
        }
        throw err;
      }
    },
  );

  app.post(
    '/auth/webauthn/authenticate/verify',
    { preHandler: [authenticateHook] },
    async (request, reply) => {
      const parsed = assertionVerifySchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.status(400).send({ error: 'VALIDATION_ERROR', details: parsed.error.flatten() });
      }
      try {
        const result = await webAuthnService.verifyAssertion({
          userId: request.user!.id,
          ...parsed.data,
        });
        return reply.send({ success: true, ...result });
      } catch (err: unknown) {
        if (err instanceof WebAuthnError) {
          return reply.status(err.statusCode).send({ error: err.code, message: err.message });
        }
        throw err;
      }
    },
  );
}

