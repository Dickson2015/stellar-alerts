import { describe, expect, it } from 'vitest';
import {
  AUTH_CLAWBACK_ENABLED,
  AUTH_IMMUTABLE,
  AUTH_REQUIRED,
  AUTH_REVOCABLE,
  AssetIssuerSentinel,
  decodeIssuerFlags,
  describeIssuerFlags,
  type IssuerOperation,
  type RegisteredAssetIssuer,
} from '../asset-issuer-sentinel';

const ISSUER = 'GISSUERAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

function op(overrides: Partial<IssuerOperation> = {}): IssuerOperation {
  return {
    id: 'op-1',
    type: 'payment',
    transaction_hash: 'tx-1',
    created_at: '2026-11-24T10:00:00.000Z',
    from: ISSUER,
    asset_code: 'USD',
    asset_issuer: ISSUER,
    amount: '100',
    ...overrides,
  };
}

function sentinel(issuer: Partial<RegisteredAssetIssuer> = {}): AssetIssuerSentinel {
  return new AssetIssuerSentinel([{ issuer: ISSUER, ...issuer }]);
}

describe('decodeIssuerFlags (#1035)', () => {
  it('decodes every documented numeric bit', () => {
    const decoded = decodeIssuerFlags([AUTH_REQUIRED, AUTH_REVOCABLE, AUTH_IMMUTABLE, AUTH_CLAWBACK_ENABLED]);

    expect(decoded).toMatchObject({
      mask: 15,
      authRequired: true,
      authRevocable: true,
      authImmutable: true,
      authClawbackEnabled: true,
      unknownBits: [],
    });
  });

  it('maps Horizon named aliases including clawback-enabled', () => {
    const decoded = decodeIssuerFlags([
      'auth_required_flag',
      'auth_revocable_flag',
      'auth_immutable_flag',
      'auth_clawback_enabled_flag',
    ]);

    expect(decoded.mask).toBe(15);
    expect(decoded.authClawbackEnabled).toBe(true);
    expect(decodeIssuerFlags('8').mask).toBe(8);
    expect(decodeIssuerFlags('0x8').mask).toBe(8);
  });

  it('records unknown bits and ignores invalid values', () => {
    const decoded = decodeIssuerFlags([1, 16, 64, 'nonsense', -1, 1.5]);

    expect(decoded.mask).toBe(1);
    expect(decoded.unknownBits).toEqual([16, 64]);
    expect(describeIssuerFlags(decoded)).toBe('AUTH_REQUIRED, UNKNOWN(16,64)');
    expect(decodeIssuerFlags(undefined).mask).toBe(0);
  });
});

describe('AssetIssuerSentinel flag and home-domain detection (#1035)', () => {
  it('emits a critical alert when AUTH_REVOCABLE is set and tracks the new mask', () => {
    const subject = sentinel({ flags: [AUTH_REQUIRED] });

    const alerts = subject.assess(op({
      type: 'set_options',
      from: undefined,
      source_account: ISSUER,
      set_flags: [AUTH_REVOCABLE],
    }));

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      eventType: 'ISSUER_FLAG_MUTATION',
      severity: 'CRITICAL',
      issuer: ISSUER,
      setFlags: 'AUTH_REVOCABLE',
    });
    expect(subject.stateFor(ISSUER)?.flags).toBe(3);
  });

  it('emits a critical alert when AUTH_CLAWBACK_ENABLED is cleared', () => {
    const subject = sentinel({ flags: [AUTH_CLAWBACK_ENABLED] });

    const alerts = subject.assess(op({
      type: 'set_options',
      from: undefined,
      source_account: ISSUER,
      clear_flags_s: ['auth_clawback_enabled_flag'],
    }));

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      eventType: 'ISSUER_FLAG_MUTATION',
      severity: 'CRITICAL',
      clearedFlags: 'AUTH_CLAWBACK_ENABLED',
    });
    expect(subject.stateFor(ISSUER)?.flags).toBe(0);
  });

  it('does not alert for a redundant flag operation that leaves the mask unchanged', () => {
    const subject = sentinel({ flags: [AUTH_IMMUTABLE] });

    expect(subject.assess(op({
      type: 'set_options',
      from: undefined,
      source_account: ISSUER,
      set_flags: [AUTH_IMMUTABLE],
    }))).toEqual([]);
  });

  it('emits a critical alert on home_domain drift and none for the same domain', () => {
    const subject = sentinel({ homeDomain: 'old.example' });
    const change = op({ type: 'set_options', from: undefined, source_account: ISSUER, home_domain: 'new.example' });

    expect(subject.assess(change)).toMatchObject([{
      eventType: 'HOME_DOMAIN_DRIFT',
      severity: 'CRITICAL',
      homeDomain: 'new.example',
      previousHomeDomain: 'old.example',
    }]);
    expect(subject.assess(change)).toEqual([]);
  });

  it('ignores failed transactions and operations from other accounts', () => {
    const subject = sentinel();

    expect(subject.assess(op({
      type: 'set_options',
      from: undefined,
      source_account: ISSUER,
      set_flags: [AUTH_REVOCABLE],
      transaction_successful: false,
    }))).toEqual([]);
    expect(subject.assess(op({
      type: 'set_options',
      from: undefined,
      source_account: 'GOTHER',
      set_flags: [AUTH_REVOCABLE],
    }))).toEqual([]);
  });
});

describe('AssetIssuerSentinel mint/burn detection (#1035)', () => {
  it('detects issuance when from matches the issuer', () => {
    const alerts = sentinel({ supplyCap: 150 }).assess(op({ amount: '100' }));

    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      eventType: 'ISSUANCE',
      severity: 'WARNING',
      amount: 100,
      circulatingSupply: 100,
    });
  });

  it('detects redemption when to matches the issuer and reduces circulating supply', () => {
    const subject = sentinel();
    subject.assess(op({ amount: '100' }));

    const alerts = subject.assess(op({ id: 'op-2', from: 'GHOLDER', to: ISSUER, amount: '40' }));

    expect(alerts).toMatchObject([{
      eventType: 'REDEMPTION',
      amount: 40,
      circulatingSupply: 60,
    }]);
  });

  it('emits a critical supply-cap alert once net issuance exceeds the cap', () => {
    const subject = sentinel({ supplyCap: 150 });

    expect(subject.assess(op({ amount: '100' })).map((alert) => alert.eventType)).toEqual(['ISSUANCE']);
    expect(subject.assess(op({ id: 'op-2', amount: '60' })).map((alert) => alert.eventType))
      .toEqual(['ISSUANCE', 'SUPPLY_CAP_EXCEEDED']);
    expect(subject.stateFor(ISSUER)?.circulatingSupply).toBe(160);
  });

  it('ignores payments of a different asset issuer and invalid amounts', () => {
    const subject = sentinel();

    expect(subject.assess(op({ asset_issuer: 'GOTHER', amount: '10' }))).toEqual([]);
    expect(subject.assess(op({ asset_issuer: undefined, amount: 'not-a-number' }))).toEqual([]);
  });

  it('preserves circulating supply when the registry is refreshed', () => {
    const subject = sentinel();
    subject.assess(op({ amount: '100' }));
    subject.setIssuers([{ issuer: ISSUER, assetCode: 'USD' }]);

    expect(subject.stateFor(ISSUER)?.circulatingSupply).toBe(100);
    expect(subject.isIssuer(ISSUER)).toBe(true);
    expect(subject.isIssuer('GOTHER')).toBe(false);
  });
});
