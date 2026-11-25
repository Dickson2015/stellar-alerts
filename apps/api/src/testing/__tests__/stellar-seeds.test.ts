import { describe, expect, it } from 'vitest';
import { Keypair, StrKey } from 'stellar-sdk';
import {
  createSeededAccountAddress,
  createSeededContractId,
  createSeededContractIds,
  createSeededKeypair,
  createSeededKeypairs,
  deriveSeedHash,
} from '../stellar-seeds';

describe('stellar-seeds', () => {
  it('derives the same raw seed hash for the same input', () => {
    expect(deriveSeedHash(42)).toEqual(deriveSeedHash(42));
    expect(deriveSeedHash('alice')).toEqual(deriveSeedHash('alice'));
    expect(deriveSeedHash(42)).not.toEqual(deriveSeedHash(43));
  });

  it('returns an identical keypair for the same numeric seed', () => {
    const first = createSeededKeypair(42);
    const second = createSeededKeypair(42);

    expect(first).toBeInstanceOf(Keypair);
    expect(first.publicKey()).toBe(second.publicKey());
    expect(first.secret()).toBe(second.secret());
  });

  it('returns an identical keypair for the same string seed', () => {
    const first = createSeededKeypair('wallet-alice');
    const second = createSeededKeypair('wallet-alice');

    expect(first.publicKey()).toBe(second.publicKey());
    expect(first.secret()).toBe(second.secret());
  });

  it('produces StrKey-valid public keys and secret seeds', () => {
    for (const seed of [0, 1, 42, 'alice', 'wallet-bob']) {
      const keypair = createSeededKeypair(seed);

      expect(StrKey.isValidEd25519PublicKey(keypair.publicKey())).toBe(true);
      expect(StrKey.isValidEd25519SecretSeed(keypair.secret())).toBe(true);
      expect(Keypair.fromSecret(keypair.secret()).publicKey()).toBe(keypair.publicKey());
      expect(createSeededAccountAddress(seed)).toBe(keypair.publicKey());
    }
  });

  it('produces distinct keypairs for distinct seeds', () => {
    const publicKeys = [createSeededKeypair(1), createSeededKeypair(2), createSeededKeypair('1')].map(
      (keypair) => keypair.publicKey(),
    );

    expect(new Set(publicKeys).size).toBe(2);
    expect(publicKeys[0]).not.toBe(publicKeys[1]);
    expect(createSeededKeypair('alice').publicKey()).not.toBe(
      createSeededKeypair('bob').publicKey(),
    );
  });

  it('derives deterministic StrKey-valid contract IDs', () => {
    const numeric = createSeededContractId(7);
    const textual = createSeededContractId('registry');

    expect(numeric).toBe(createSeededContractId(7));
    expect(textual).toBe(createSeededContractId('registry'));
    expect(StrKey.isValidContract(numeric)).toBe(true);
    expect(StrKey.isValidContract(textual)).toBe(true);
    expect(StrKey.decodeContract(numeric)).toHaveLength(32);
    expect(numeric).not.toBe(createSeededContractId(8));
  });

  it('generates deterministic batches of keypairs', () => {
    const first = createSeededKeypairs(5, 10);
    const second = createSeededKeypairs(5, 10);

    expect(first).toHaveLength(5);
    expect(first.map((keypair) => keypair.publicKey())).toEqual(
      second.map((keypair) => keypair.publicKey()),
    );
    expect(new Set(first.map((keypair) => keypair.secret())).size).toBe(5);
    expect(createSeededKeypairs(0)).toEqual([]);
  });

  it('generates deterministic batches of contract IDs', () => {
    const first = createSeededContractIds(3, 'contract');
    const second = createSeededContractIds(3, 'contract');

    expect(first).toEqual(second);
    expect(new Set(first).size).toBe(3);
    expect(first.every((id) => StrKey.isValidContract(id))).toBe(true);
    expect(createSeededContractIds(0)).toEqual([]);
  });

  it('rejects invalid batch sizes', () => {
    expect(() => createSeededKeypairs(-1)).toThrow(RangeError);
    expect(() => createSeededContractIds(1.5)).toThrow(RangeError);
  });
});
