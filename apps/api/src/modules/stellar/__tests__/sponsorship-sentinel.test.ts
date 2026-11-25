import { describe, expect, it } from 'vitest';
import {
  calculateSponsorshipHeadroom,
  calculateSponsorshipLiability,
  parseSponsorshipOperation,
  SponsorshipSentinel,
  sponsorshipEntryType,
  sponsorshipReserveUnits,
  type SponsorshipOperation,
} from '../sponsorship-sentinel';

describe('SponsorshipSentinel (#977)', () => {
  describe('operation parsing', () => {
    it('parses sponsorship start/end operations and ignores failed operations', () => {
      expect(parseSponsorshipOperation({
        type: 'begin_sponsoring_future_reserves',
        source_account: 'GSPONSOR',
        sponsored_id: 'GSPONSORED',
        id: '1',
      })).toMatchObject({
        type: 'SPONSORSHIP_GRANTED',
        account: 'GSPONSORED',
        sponsor: 'GSPONSOR',
      });

      expect(parseSponsorshipOperation({
        type: 'end_sponsoring_future_reserves',
        source_account: 'GSPONSORED',
      })).toMatchObject({ type: 'SPONSORSHIP_ENDED', account: 'GSPONSORED' });
      expect(parseSponsorshipOperation({
        type: 'begin_sponsoring_future_reserves',
        transaction_successful: false,
        sponsored_id: 'GSPONSORED',
      })).toBeNull();
    });

    it.each([
      ['account', { account_id: 'GACCOUNT' }],
      ['signer', { signer_account_id: 'GACCOUNT', signer_key: 'GSIGNER' }],
      ['trustline', { trustline_account: 'GACCOUNT', trustline_asset: 'USDC:GISSUER' }],
      ['offer', { offer_id: '42' }],
      ['data', { data_account: 'GACCOUNT', data_name: 'name' }],
      ['claimable_balance', { claimable_balance_id: 'balance-id' }],
      ['liquidity_pool', { liquidity_pool_id: 'pool-id' }],
    ] as const)('recognizes revoked %s ledger entries', (entryType, fields) => {
      const event = parseSponsorshipOperation({
        type: 'revoke_sponsorship',
        source_account: 'GACCOUNT',
        id: `revoke-${entryType}`,
        ...fields,
      } as SponsorshipOperation);
      expect(event).toMatchObject({ type: 'SPONSORSHIP_REVOKED', entryType });
      expect(sponsorshipEntryType({ type: 'revoke_sponsorship', ...fields } as SponsorshipOperation)).toBe(entryType);
    });

    it.each([
      ['create_account', 'account'],
      ['set_options', 'signer'],
      ['change_trust', 'trustline'],
      ['manage_sell_offer', 'offer'],
      ['manage_data', 'data'],
      ['create_claimable_balance', 'claimable_balance'],
      ['liquidity_pool_deposit', 'liquidity_pool'],
    ] as const)('parses sponsored %s grants', (operationType, entryType) => {
      expect(parseSponsorshipOperation({
        type: operationType,
        sponsor: 'GSPONSOR',
        source_account: operationType === 'create_account' ? 'GSPONSOR' : 'GACCOUNT',
        id: `grant-${operationType}`,
        ...(operationType === 'create_account' ? { account: 'GACCOUNT' } : {}),
        ...(operationType === 'set_options' ? { signer_key: 'GSIGNER' } : {}),
      })).toMatchObject({
        type: 'SPONSORSHIP_GRANTED',
        account: 'GACCOUNT',
        sponsor: 'GSPONSOR',
        entryType,
      });
    });

    it('accepts camel-case Horizon/SDK fields and handles claimable balance reserve weight', () => {
      expect(parseSponsorshipOperation({
        type: 'revoke_sponsorship',
        source_account: 'GACCOUNT',
        claimableBalanceId: 'balance-id',
      })).toMatchObject({ type: 'SPONSORSHIP_REVOKED', entryType: 'claimable_balance' });
      expect(sponsorshipReserveUnits('claimable_balance')).toBe(2);
      expect(sponsorshipReserveUnits('trustline')).toBe(1);
    });
  });

  describe('reserve accounting', () => {
    it('calculates the locked reserve from sponsored entry-count deltas', () => {
      expect(calculateSponsorshipLiability(2)).toBe(1);
      expect(calculateSponsorshipLiability(5, 0.75)).toBe(3.75);
      expect(calculateSponsorshipLiability(-1)).toBe(0);

      const afterGrant = calculateSponsorshipHeadroom({
        account: 'GTREASURY',
        balanceXlm: 20,
        subentryCount: 6,
        numSponsoring: 4,
        numSponsored: 1,
      });
      const afterRevocation = calculateSponsorshipHeadroom({
        account: 'GTREASURY',
        balanceXlm: 20,
        subentryCount: 6,
        numSponsoring: 3,
        numSponsored: 1,
      });
      expect(afterGrant.liabilityXlm).toBe(2);
      expect(afterRevocation.liabilityXlm).toBe(1.5);
      expect(afterRevocation.headroomXlm - afterGrant.headroomXlm).toBe(0.5);
    });

    it('alerts below the transferable-balance safety threshold and suppresses repeats', () => {
      let now = 1_000;
      const sentinel = new SponsorshipSentinel({ safetyThresholdXlm: 1, alertCooldownMs: 100 }, () => now);
      const snapshot = {
        account: 'GTREASURY',
        balanceXlm: 4,
        subentryCount: 3,
        numSponsoring: 5,
        numSponsored: 1,
      };

      const alert = sentinel.assessAccount(snapshot);
      expect(alert).toMatchObject({
        type: 'RESERVE_HEADROOM_LOW',
        severity: 'CRITICAL',
        liability: {
          liabilityXlm: 2.5,
          availableXlm: 2,
          headroomXlm: -0.5,
          belowThreshold: true,
        },
      });
      expect(sentinel.assessAccount(snapshot)).toBeNull();
      now += 101;
      expect(sentinel.assessAccount(snapshot)?.type).toBe('RESERVE_HEADROOM_LOW');
    });

    it('does not alert while headroom is at or above the configured threshold', () => {
      const sentinel = new SponsorshipSentinel({ safetyThresholdXlm: 1 });
      expect(sentinel.assessAccount({
        account: 'GTREASURY',
        balanceXlm: 20,
        subentryCount: 0,
        numSponsoring: 2,
        numSponsored: 0,
      })).toBeNull();
      expect(sentinel.assessAccount({
        account: 'GOTHER',
        balanceXlm: 0.5,
        subentryCount: 0,
        numSponsoring: 0,
        numSponsored: 0,
      })).toBeNull();
    });
  });
});
