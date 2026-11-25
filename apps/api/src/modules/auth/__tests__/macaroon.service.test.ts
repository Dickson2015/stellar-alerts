/**
 * Unit tests for macaroon API tokens (#930): minting, offline attenuation,
 * cryptographic verification and third-party discharge caveats.
 */
import { describe, it, expect } from 'vitest';
import {
  MACAROON_VERSION,
  MacaroonConfigurationError,
  MacaroonTokenService,
  createMacaroonServiceFromEnv,
  firstPartyCaveat,
  parseMacaroonKeyring,
  parseMacaroonToken,
  thirdPartyCaveat,
} from '../macaroon.service';

const ROOT_KEY = 'root-key-material-for-tests-0123456789';
const OTHER_ROOT_KEY = 'rotated-root-key-material-0123456789';

function buildService(extraKeys: Record<string, string> = {}) {
  return new MacaroonTokenService({
    primaryKid: 'k1',
    keyring: { k1: ROOT_KEY, ...extraKeys },
  });
}

function mint(service: MacaroonTokenService, caveats: string[] = []) {
  return service.mint({
    userId: 'user-1',
    email: 'user@example.com',
    caveats,
    issuedAt: 1_700_000_000_000,
    nonce: 'fixed-nonce',
  });
}

describe('Macaroon minting and verification (#930)', () => {
  it('mints a token that verifies with the root key and no context', () => {
    const service = buildService();
    const token = mint(service);

    expect(token.startsWith(`${MACAROON_VERSION}.`)).toBe(true);
    const parsed = parseMacaroonToken(token);
    expect(parsed?.identifier).toMatchObject({
      kid: 'k1',
      userId: 'user-1',
      email: 'user@example.com',
    });

    const result = service.verify(token);
    expect(result.valid).toBe(true);
    expect(result.caveats).toEqual([]);
    expect(result.identifier?.userId).toBe('user-1');
    expect(result.signature).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a token signed by a different root key', () => {
    const token = mint(buildService());
    const other = new MacaroonTokenService({
      primaryKid: 'k1',
      keyring: { k1: OTHER_ROOT_KEY },
    });

    expect(other.verify(token)).toMatchObject({
      valid: false,
      reason: 'invalid_signature',
    });
  });

  it('rejects an unknown root key id', () => {
    const token = mint(buildService());
    const other = new MacaroonTokenService({
      primaryKid: 'k2',
      keyring: { k2: OTHER_ROOT_KEY },
    });

    expect(other.verify(token)).toMatchObject({
      valid: false,
      reason: 'unknown_root_key',
    });
  });

  it('rejects malformed tokens', () => {
    const service = buildService();
    expect(service.verify('')).toMatchObject({ reason: 'malformed_token' });
    expect(service.verify('MCR1.not-a-token')).toMatchObject({
      reason: 'malformed_token',
    });
    expect(service.verify('MCR1.abc.def')).toMatchObject({
      reason: 'malformed_token',
    });
  });

  it('rejects a token whose caveats were edited without re-signing', () => {
    const service = buildService();
    const token = mint(service, ['wallet = GABC']);
    const [prefix, identifier, , signature] = token.split('.');

    const forged = [
      prefix,
      identifier,
      Buffer.from('wallet = GXYZ').toString('base64url'),
      signature,
    ].join('.');

    expect(service.verify(forged)).toMatchObject({
      valid: false,
      reason: 'invalid_signature',
    });
  });
});

describe('Macaroon attenuation (#930)', () => {
  it('narrows a token to a wallet without the root key', () => {
    const service = buildService();
    const token = mint(service);

    // Attenuation is a pure HMAC-chain operation: no service or key required.
    const attenuated = service.attenuate(token, ['wallet = GWALLET123']);

    expect(service.verify(attenuated, { walletId: 'GWALLET123' }).valid).toBe(true);
    expect(service.verify(attenuated, { walletId: 'GOTHER' })).toMatchObject({
      valid: false,
      reason: 'caveat_failed',
    });
    expect(service.verify(attenuated)).toMatchObject({
      valid: false,
      reason: 'caveat_failed',
    });
  });

  it('cannot remove a parent caveat', () => {
    const service = buildService();
    const token = service.attenuate(mint(service), ['wallet = GWALLET123']);
    const parsed = parseMacaroonToken(token)!;

    // Re-serializing without the caveat leaves the old signature in place, so
    // the restriction cannot be stripped.
    const stripped = [
      `MCR1.${Buffer.from(parsed.identifierRaw).toString('base64url')}`,
      parsed.signature,
    ].join('.');

    expect(service.verify(stripped, { walletId: 'GWALLET123' })).toMatchObject({
      valid: false,
      reason: 'invalid_signature',
    });
  });

  it('supports chained attenuation and multiple restrictions', () => {
    const service = buildService();
    const once = service.attenuate(mint(service), ['wallet = GWALLET123']);
    const twice = service.attenuate(once, [
      'method = GET',
      'path = /api/v1/wallets/*',
    ]);

    expect(
      service.verify(twice, {
        walletId: 'GWALLET123',
        method: 'GET',
        path: '/api/v1/wallets/GWALLET123/payments?limit=10',
      }).valid,
    ).toBe(true);

    expect(
      service.verify(twice, {
        walletId: 'GWALLET123',
        method: 'POST',
        path: '/api/v1/wallets/GWALLET123/payments',
      }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });
  });

  it('leaves a token unchanged when no caveats are supplied', () => {
    const service = buildService();
    const token = mint(service);
    expect(service.attenuate(token, [])).toBe(token);
  });

  it('rejects malformed input or caveats during attenuation', () => {
    const service = buildService();
    expect(() => service.attenuate('nope', ['wallet = GABC'])).toThrow(
      MacaroonConfigurationError,
    );
    expect(() =>
      service.attenuate(mint(service), ['x'.repeat(5000)]),
    ).toThrow(/invalid caveat/i);
  });
});

describe('Macaroon caveat predicates (#930)', () => {
  it('enforces expiry and not-before windows', () => {
    const service = buildService();
    const token = mint(service, [
      firstPartyCaveat('expires', '2026-12-31T00:00:00Z'),
    ]);

    expect(
      service.verify(token, {}, { now: new Date('2026-06-01T00:00:00Z') }).valid,
    ).toBe(true);
    expect(
      service.verify(token, {}, { now: new Date('2027-01-01T00:00:00Z') }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });

    const future = mint(service, [
      firstPartyCaveat('not_before_ms', Date.parse('2027-01-01T00:00:00Z')),
    ]);
    expect(
      service.verify(future, {}, { now: new Date('2026-06-01T00:00:00Z') }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });
    expect(
      service.verify(future, {}, { now: new Date('2027-06-01T00:00:00Z') }).valid,
    ).toBe(true);
  });

  it('enforces user, method, path, action and scope', () => {
    const service = buildService();
    const token = mint(service, [
      firstPartyCaveat('user', 'user-1'),
      firstPartyCaveat('method', 'GET'),
      firstPartyCaveat('path', '/api/v1/payments'),
      firstPartyCaveat('scope', 'wallets:read'),
    ]);

    expect(
      service.verify(token, {
        userId: 'user-1',
        method: 'get',
        path: '/api/v1/payments?cursor=abc',
        action: 'read',
      }).valid,
    ).toBe(true);

    expect(
      service.verify(token, {
        userId: 'user-2',
        method: 'GET',
        path: '/api/v1/payments',
        action: 'read',
      }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });

    expect(
      service.verify(token, {
        userId: 'user-1',
        method: 'GET',
        path: '/api/v1/wallets',
        action: 'read',
      }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });

    expect(
      service.verify(token, {
        userId: 'user-1',
        method: 'POST',
        path: '/api/v1/payments',
        action: 'write',
      }),
    ).toMatchObject({ valid: false, reason: 'caveat_failed' });
  });

  it('fails closed on unknown caveats', () => {
    const service = buildService();
    const token = mint(service, ['ip_limit = 10.0.0.1']);

    expect(service.verify(token)).toMatchObject({
      valid: false,
      reason: 'unknown_caveat',
      detail: 'ip_limit',
    });
  });

  it('rejects unparsable expiry values', () => {
    const service = buildService();
    const token = mint(service, [firstPartyCaveat('expires', 'tomorrow')]);
    expect(service.verify(token)).toMatchObject({
      valid: false,
      reason: 'caveat_failed',
    });
  });
});

describe('Macaroon third-party caveats (#930)', () => {
  function mintWithDischarge() {
    const service = buildService({ k2: OTHER_ROOT_KEY });
    const discharge = service.mint({
      userId: 'user-1',
      kid: 'k2',
      issuedAt: 1_700_000_000_000,
      nonce: 'discharge-nonce',
    });
    const dischargeIdentifier = parseMacaroonToken(discharge)!.identifierRaw;

    const token = service.mint({
      userId: 'user-1',
      caveats: [
        thirdPartyCaveat({
          provider: 'billing-service',
          identifier: dischargeIdentifier,
        }),
      ],
      issuedAt: 1_700_000_000_000,
      nonce: 'root-nonce',
    });

    return { service, token, discharge };
  }

  it('requires a matching discharge macaroon', () => {
    const { service, token } = mintWithDischarge();

    expect(service.verify(token)).toMatchObject({
      valid: false,
      reason: 'missing_discharge',
    });
  });

  it('accepts a matching discharge macaroon', () => {
    const { service, token, discharge } = mintWithDischarge();

    expect(service.verify(token, {}, { discharges: [discharge] }).valid).toBe(true);
  });

  it('rejects a discharge for a different identifier', () => {
    const { service, token, discharge } = mintWithDischarge();
    const other = service.mint({
      userId: 'user-1',
      kid: 'k2',
      issuedAt: 1_700_000_000_000,
      nonce: 'other-discharge',
    });

    expect(
      service.verify(token, {}, { discharges: [other] }),
    ).toMatchObject({ valid: false, reason: 'missing_discharge' });
  });

  it('rejects a tampered discharge', () => {
    const { service, token, discharge } = mintWithDischarge();
    const parts = discharge.split('.');
    const signature = Buffer.from(parts[parts.length - 1], 'base64url');
    signature[0] ^= 0xff;
    parts[parts.length - 1] = signature.toString('base64url');
    const tampered = parts.join('.');

    expect(
      service.verify(token, {}, { discharges: [tampered] }),
    ).toMatchObject({ valid: false, reason: 'invalid_discharge' });
  });
});

describe('Macaroon key rotation and env configuration (#930)', () => {
  it('accepts tokens signed with a retained older key id', () => {
    const oldService = new MacaroonTokenService({
      primaryKid: 'k1',
      keyring: { k1: ROOT_KEY },
    });
    const oldToken = oldService.mint({ userId: 'user-1', issuedAt: Date.now() });

    const rotated = new MacaroonTokenService({
      primaryKid: 'k2',
      keyring: { k1: ROOT_KEY, k2: OTHER_ROOT_KEY },
    });

    expect(rotated.verify(oldToken).valid).toBe(true);
    const newToken = rotated.mint({ userId: 'user-1' });
    expect(parseMacaroonToken(newToken)?.identifier.kid).toBe('k2');
  });

  it('parses MACAROON_ROOT_KEYS and MACAROON_ROOT_KEY', () => {
    const fromJson = parseMacaroonKeyring({
      MACAROON_ROOT_KEYS: JSON.stringify({ k1: ROOT_KEY, k2: OTHER_ROOT_KEY }),
      MACAROON_PRIMARY_KEY_ID: 'k2',
    } as NodeJS.ProcessEnv);
    expect(fromJson?.primaryKid).toBe('k2');
    expect(Object.keys(fromJson?.keyring ?? {})).toEqual(['k1', 'k2']);

    const fromSingle = parseMacaroonKeyring({
      MACAROON_ROOT_KEY: ROOT_KEY,
    } as NodeJS.ProcessEnv);
    expect(fromSingle?.primaryKid).toBe('k1');

    expect(parseMacaroonKeyring({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it('ignores short or malformed root keys', () => {
    expect(
      parseMacaroonKeyring({ MACAROON_ROOT_KEYS: '{oops' } as NodeJS.ProcessEnv),
    ).toBeNull();
    expect(
      parseMacaroonKeyring({
        MACAROON_ROOT_KEYS: JSON.stringify({ k1: 'short' }),
      } as NodeJS.ProcessEnv),
    ).toBeNull();
    expect(
      parseMacaroonKeyring({
        MACAROON_ROOT_KEYS: JSON.stringify({ k1: ROOT_KEY }),
        MACAROON_PRIMARY_KEY_ID: 'missing',
      } as NodeJS.ProcessEnv),
    ).toBeNull();
  });

  it('creates a service only when root key material exists', () => {
    expect(createMacaroonServiceFromEnv({} as NodeJS.ProcessEnv)).toBeNull();
    const service = createMacaroonServiceFromEnv({
      MACAROON_ROOT_KEY: ROOT_KEY,
    } as NodeJS.ProcessEnv);
    expect(service).not.toBeNull();
    expect(service!.verify(service!.mint({ userId: 'u' })).valid).toBe(true);
  });

  it('validates service construction inputs', () => {
    expect(
      () => new MacaroonTokenService({ primaryKid: 'k1', keyring: { k1: 'short' } }),
    ).toThrow(MacaroonConfigurationError);
    expect(
      () => new MacaroonTokenService({ primaryKid: 'missing', keyring: { k1: ROOT_KEY } }),
    ).toThrow(/no root key/i);
  });
});
