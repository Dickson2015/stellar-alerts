/**
 * Middleware integration for scoped macaroon API tokens (#930): the shared
 * authentication hook must accept them alongside JWTs and enforce caveats
 * against the incoming request.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  authenticateHook,
  getConfiguredMacaroonService,
  resetConfiguredMacaroonService,
} from '../auth.middleware';
import { MacaroonTokenService } from '../../modules/auth/macaroon.service';
import { AuthenticationError } from '../../lib/errors';

const ROOT_KEY = 'middleware-test-root-key-0123456789';

function fakeRequest(overrides: Record<string, unknown> = {}) {
  return {
    headers: {},
    method: 'GET',
    url: '/api/v1/wallets',
    params: {},
    query: {},
    log: { warn: () => undefined, error: () => undefined },
    ...overrides,
  } as any;
}

function mintToken(service: MacaroonTokenService, caveats: string[] = []) {
  return service.mint({
    userId: 'user-1',
    email: 'user@example.com',
    caveats,
  });
}

describe('authenticateHook macaroon support (#930)', () => {
  beforeEach(() => {
    process.env.MACAROON_ROOT_KEY = ROOT_KEY;
    resetConfiguredMacaroonService();
  });

  afterEach(() => {
    delete process.env.MACAROON_ROOT_KEY;
    resetConfiguredMacaroonService();
  });

  it('authenticates an unterminated token and exposes the macaroon context', async () => {
    const service = getConfiguredMacaroonService()!;
    const request = fakeRequest({
      headers: { authorization: `Macaroon ${mintToken(service)}` },
    });

    await authenticateHook(request, {} as any);

    expect(request.authMethod).toBe('macaroon');
    expect(request.user).toEqual({ id: 'user-1', email: 'user@example.com' });
    expect(request.macaroon.valid).toBe(true);
  });

  it('accepts a macaroon presented as a Bearer token', async () => {
    const service = getConfiguredMacaroonService()!;
    const request = fakeRequest({
      headers: { authorization: `Bearer ${mintToken(service)}` },
    });

    await authenticateHook(request, {} as any);
    expect(request.authMethod).toBe('macaroon');
  });

  it('enforces wallet caveats against route params', async () => {
    const service = getConfiguredMacaroonService()!;
    const token = mintToken(service, ['wallet = GWALLET123']);

    const allowed = fakeRequest({
      headers: { authorization: `Macaroon ${token}` },
      params: { walletId: 'GWALLET123' },
    });
    await authenticateHook(allowed, {} as any);
    expect(allowed.macaroon.valid).toBe(true);

    const denied = fakeRequest({
      headers: { authorization: `Macaroon ${token}` },
      params: { walletId: 'GOTHER' },
    });
    await expect(authenticateHook(denied, {} as any)).rejects.toBeInstanceOf(
      AuthenticationError,
    );
  });

  it('maps the HTTP method onto read/write scope caveats', async () => {
    const service = getConfiguredMacaroonService()!;
    const token = mintToken(service, ['scope = wallets:read']);

    await authenticateHook(
      fakeRequest({ headers: { authorization: `Macaroon ${token}` }, method: 'GET' }),
      {} as any,
    );

    await expect(
      authenticateHook(
        fakeRequest({ headers: { authorization: `Macaroon ${token}` }, method: 'DELETE' }),
        {} as any,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects expired and tampered tokens', async () => {
    const service = getConfiguredMacaroonService()!;
    const expired = service.mint({
      userId: 'user-1',
      caveats: ['expires = 2020-01-01T00:00:00Z'],
    });

    await expect(
      authenticateHook(
        fakeRequest({ headers: { authorization: `Macaroon ${expired}` } }),
        {} as any,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);

    const parts = mintToken(service).split('.');
    parts[parts.length - 1] = Buffer.alloc(32).toString('base64url');
    await expect(
      authenticateHook(
        fakeRequest({ headers: { authorization: `Macaroon ${parts.join('.')}` } }),
        {} as any,
      ),
    ).rejects.toBeInstanceOf(AuthenticationError);
  });

  it('rejects macaroon auth when no root key is configured', async () => {
    const service = getConfiguredMacaroonService()!;
    const token = mintToken(service);
    delete process.env.MACAROON_ROOT_KEY;
    resetConfiguredMacaroonService();

    await expect(
      authenticateHook(
        fakeRequest({ headers: { authorization: `Macaroon ${token}` } }),
        {} as any,
      ),
    ).rejects.toMatchObject({ code: 'MACAROON_NOT_CONFIGURED' });
  });

  it('still requires authentication when no credentials are present', async () => {
    await expect(authenticateHook(fakeRequest(), {} as any)).rejects.toMatchObject({
      code: 'AUTH_REQUIRED',
    });
  });
});
