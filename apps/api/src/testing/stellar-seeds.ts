import { createHash } from 'node:crypto';
import { Keypair, StrKey } from 'stellar-sdk';

export type StellarSeed = number | string;

export function deriveSeedHash(seed: StellarSeed): Buffer {
  return createHash('sha256').update(String(seed), 'utf8').digest();
}

export function createSeededKeypair(seed: StellarSeed): Keypair {
  return Keypair.fromRawEd25519Seed(deriveSeedHash(seed));
}

export function createSeededKeypairs(count: number, startSeed: StellarSeed = 0): Keypair[] {
  if (!Number.isInteger(count) || count < 0) {
    throw new RangeError('count must be a non-negative integer');
  }

  return Array.from({ length: count }, (_, index) =>
    createSeededKeypair(typeof startSeed === 'number' ? startSeed + index : `${startSeed}:${index}`),
  );
}

export const createSeededKeypairBatch = createSeededKeypairs;

export function createSeededAccountAddress(seed: StellarSeed): string {
  return createSeededKeypair(seed).publicKey();
}

export function createSeededContractId(seed: StellarSeed): string {
  return StrKey.encodeContract(deriveSeedHash(seed));
}

export function createSeededContractIds(count: number, startSeed: StellarSeed = 0): string[] {
  if (!Number.isInteger(count) || count < 0) {
    throw new RangeError('count must be a non-negative integer');
  }

  return Array.from({ length: count }, (_, index) =>
    createSeededContractId(
      typeof startSeed === 'number' ? startSeed + index : `${startSeed}:${index}`,
    ),
  );
}
