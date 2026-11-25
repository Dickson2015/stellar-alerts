import { FastifyRequest, FastifyReply } from 'fastify';
import { verifyToken, UserPayload } from '../utils/jwt';
import { isTokenRevoked } from '../lib/tokenBlocklist';
import { isFamilyRevoked } from '../lib/session-manager';
import { AuthenticationError } from '../lib/errors';
import {
  createMacaroonServiceFromEnv,
  type MacaroonTokenService,
  type MacaroonVerificationResult,
} from '../modules/auth/macaroon.service';

declare module 'fastify' {
  interface FastifyRequest {
    user?: UserPayload;
    /** Set when the request authenticated with a scoped macaroon token (#930). */
    macaroon?: MacaroonVerificationResult;
    authMethod?: 'jwt' | 'macaroon';
  }
}

let configuredMacaroonService: MacaroonTokenService | null | undefined;

/**
 * Lazily builds the macaroon service from env (root keys are read once per
 * process). Returns null when the deployment has not configured macaroon
 * tokens; JWT authentication keeps working in that case.
 */
export function getConfiguredMacaroonService(): MacaroonTokenService | null {
  if (configuredMacaroonService === undefined) {
    configuredMacaroonService = createMacaroonServiceFromEnv();
  }
  return configuredMacaroonService;
}

/** Test helper: drop the cached env-derived service. */
export function resetConfiguredMacaroonService(): void {
  configuredMacaroonService = undefined;
}

function extractMacaroonToken(authHeader: string | undefined): string | null {
  if (!authHeader) return null;

  if (authHeader.startsWith('Macaroon ')) {
    return authHeader.slice('Macaroon '.length).trim() || null;
  }

  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice('Bearer '.length).trim();
    // Macaroons are self-identifying, so the standard Bearer form works for
    // clients that only know how to set a bearer token.
    return token.startsWith('MCR1.') ? token : null;
  }

  return null;
}

function requestedMacaroonAction(method: string): 'read' | 'write' {
  return method === 'GET' || method === 'HEAD' || method === 'OPTIONS'
    ? 'read'
    : 'write';
}

function extractDischarges(request: FastifyRequest): string[] {
  const raw = request.headers['x-macaroon-discharge'];
  if (typeof raw !== 'string' || raw.length === 0) return [];
  return raw
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value.startsWith('MCR1.'));
}

function extractWalletId(request: FastifyRequest): string | undefined {
  const params = (request.params ?? {}) as Record<string, unknown>;
  const query = (request.query ?? {}) as Record<string, unknown>;
  const candidates = [params.walletId, params.id, query.walletId];
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) return candidate;
  }
  return undefined;
}

/**
 * The primary authentication gate for nearly every protected route in the
 * API (auth, wallets, payments, webhooks, dead-letters, notifications).
 * Throws AuthenticationError (see lib/errors.ts) rather than replying
 * directly, so every one of those routes' 401s goes through the same
 * error envelope as everything else — this used to hand-roll its own
 * `{ error, message, code }` shape independently of the rest of the API.
 */
export async function authenticateHook(request: FastifyRequest, reply: FastifyReply) {
  const authHeader = request.headers.authorization;

  // Scoped macaroon tokens (#930) are verified cryptographically — no DB
  // lookup — and carry their own caveats (wallet, scope, expiry, path).
  const macaroonToken = extractMacaroonToken(authHeader);
  if (macaroonToken) {
    const service = getConfiguredMacaroonService();
    if (!service) {
      throw new AuthenticationError(
        'Macaroon API tokens are not enabled on this deployment.',
        'MACAROON_NOT_CONFIGURED',
      );
    }

    const result = service.verify(
      macaroonToken,
      {
        method: request.method,
        path: request.url,
        walletId: extractWalletId(request),
        action: requestedMacaroonAction(request.method),
      },
      { discharges: extractDischarges(request) },
    );

    if (!result.valid || !result.identifier) {
      request.log.warn(
        { reason: result.reason, detail: result.detail },
        '[Auth] Macaroon token rejected',
      );
      throw new AuthenticationError('Invalid or expired API token.', 'INVALID_TOKEN');
    }

    request.macaroon = result;
    request.authMethod = 'macaroon';
    request.user = {
      id: result.identifier.userId,
      email: result.identifier.email ?? '',
    };
    return;
  }

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new AuthenticationError('You must be logged in to perform this action.', 'AUTH_REQUIRED');
  }

  await authenticateToken(request, reply, authHeader.split(' ')[1]);
}

/**
 * Same verification as the header hook, for transports that cannot set headers
 * (browser EventSource). Used only by the SSE alert stream with a short-lived
 * access token supplied as a query parameter.
 */
export async function authenticateToken(
  request: FastifyRequest,
  reply: FastifyReply,
  token: string,
): Promise<void> {
  let decoded: UserPayload;

  try {
    decoded = verifyToken<UserPayload>(token);
  } catch (error) {
    throw new AuthenticationError('Invalid or expired session token.', 'INVALID_TOKEN');
  }

  // Check Redis blocklist — reject if token has been explicitly revoked (logout).
  if (decoded.jti) {
    try {
  // PR placeholder for issue #532 – JWT session revocation
    const revoked = await isTokenRevoked(decoded.jti);
      if (revoked) {
        throw new AuthenticationError('Session has been revoked. Please log in again.', 'TOKEN_REVOKED');
      }
    } catch (redisError: any) {
      if (redisError instanceof AuthenticationError) throw redisError;
      // Fail-open: if Redis is unreachable, do not block the request.
      // Log the error so operators can investigate.
      request.log.error(`[Auth] Redis blocklist check failed: ${redisError.message}`);
    }
  }

  // Check session family revocation (access token rotation & reuse detection #315)
  if (decoded.familyId) {
    try {
      const familyRevoked = await isFamilyRevoked(decoded.familyId);
      if (familyRevoked) {
        throw new AuthenticationError('Session family has been revoked. Please log in again.', 'SESSION_REVOKED');
      }
    } catch (famErr: any) {
      if (famErr instanceof AuthenticationError) throw famErr;
      request.log.error(`[Auth] Family revocation check failed: ${famErr.message}`);
    }
  }

  request.authMethod = 'jwt';
  request.user = decoded;

  // Bind the authenticated user to the async request chain so every Prisma
  // mutation records an RYOW watermark and every replica read can be checked
  // against it (see lib/prisma-causal-router.ts). Sharing this with the SSE
  // token path keeps header and query-parameter authentication consistent.
  const tenantHeader = request.headers['x-tenant-id'];
  const tenantId =
    (decoded as UserPayload & { tenantId?: string }).tenantId ??
    (Array.isArray(tenantHeader) ? tenantHeader[0] : tenantHeader);
  enterCausalContext({ userId: decoded.id, ...(tenantId ? { tenantId } : {}) });
}
