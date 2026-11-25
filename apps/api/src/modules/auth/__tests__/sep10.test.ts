import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as StellarSdk from 'stellar-sdk';
import { SEP10Service, Sep10Error, type ClientAccountSigners } from '../sep10.service';

vi.mock('../../../config/env', () => ({
  env: {
    JWT_SECRET: 'test-sep10-jwt-secret-key-32-chars-long!!',
    STELLAR_NETWORK_PASSPHRASE: StellarSdk.Networks.TESTNET,
  },
}));

const mockPrisma = vi.hoisted(() => ({
  wallet: {
    findUnique: vi.fn(),
  },
  user: {
    create: vi.fn(),
  },
}));

vi.mock('../../../lib/prisma', () => ({
  prisma: mockPrisma,
}));

describe('SEP-0010 Stellar Web Authentication API (#634)', () => {
  let sep10Service: SEP10Service;
  let serverKeypair: StellarSdk.Keypair;
  // Unfunded account by default: only the master key can sign.
  let loadClientSigners: ReturnType<typeof vi.fn<(publicKey: string) => Promise<ClientAccountSigners | null>>>;
  let consumed: Set<string>;
  const homeDomain = 'stellar-alerts.org';
  const networkPassphrase = StellarSdk.Networks.TESTNET;

  beforeEach(() => {
    vi.clearAllMocks();
    serverKeypair = StellarSdk.Keypair.random();
    consumed = new Set();
    loadClientSigners = vi.fn().mockResolvedValue(null);
    sep10Service = new SEP10Service(serverKeypair.secret(), homeDomain, networkPassphrase, {
      replayGuard: {
        consume: async (key) => {
          if (consumed.has(key)) return false;
          consumed.add(key);
          return true;
        },
      },
      loadClientSigners,
      issueSession: async () => ({ accessToken: 'access-token', refreshToken: 'refresh-token' }),
    });
  });

  const signedChallenge = (client: StellarSdk.Keypair, extraSigners: StellarSdk.Keypair[] = [client]) => {
    const challenge = sep10Service.generateChallenge(client.publicKey());
    const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
    extraSigners.forEach((signer) => tx.sign(signer));
    return tx.toEnvelope().toXDR('base64');
  };

  describe('generateChallenge', () => {
    it('generates a valid SEP-0010 challenge transaction envelope signed by the server', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      expect(challenge).toHaveProperty('transaction');
      expect(challenge).toHaveProperty('networkPassphrase', networkPassphrase);

      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      
      // Sequence number must be 0
      expect(tx.sequence).toBe('0');
      // Source account must match server public key
      expect(tx.source).toBe(serverKeypair.publicKey());
      // Timebounds must exist
      expect(tx.timeBounds).toBeDefined();
      expect(Number(tx.timeBounds?.minTime)).toBeLessThanOrEqual(Math.floor(Date.now() / 1000));
      expect(Number(tx.timeBounds?.maxTime)).toBeGreaterThan(Math.floor(Date.now() / 1000));

      // Operations: client auth manageData with a 64-byte nonce, then web_auth_domain from the server
      expect(tx.operations).toHaveLength(2);
      const op = tx.operations[0] as StellarSdk.Operation.ManageData;
      expect(op.type).toBe('manageData');
      expect(op.source).toBe(clientKeypair.publicKey());
      expect(op.name).toBe(`${homeDomain} auth`);
      expect(op.value).toHaveLength(64);

      const domainOp = tx.operations[1] as StellarSdk.Operation.ManageData;
      expect(domainOp.source).toBe(serverKeypair.publicKey());
      expect(domainOp.name).toBe('web_auth_domain');
      expect(domainOp.value?.toString('utf-8')).toBe(homeDomain);

      // Signed by server key
      const txHash = tx.hash();
      const serverSigValid = tx.signatures.some((sig) => {
        try {
          return serverKeypair.verify(txHash, sig.signature());
        } catch {
          return false;
        }
      });
      expect(serverSigValid).toBe(true);
    });

    it('throws error for invalid client public key', () => {
      expect(() => sep10Service.generateChallenge('invalid-key')).toThrow(
        /Invalid client Stellar public key/
      );
    });
  });

  describe('verifyChallenge', () => {
    it('successfully validates when client signs the challenge envelope', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      // Client signs the challenge transaction
      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      tx.sign(clientKeypair);

      const clientSignedXdr = tx.toEnvelope().toXDR('base64');
      const result = sep10Service.verifyChallenge(clientSignedXdr);

      expect(result.valid).toBe(true);
      expect(result.clientPublicKey).toBe(clientKeypair.publicKey());
    });

    it('rejects challenge if client has not signed', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      expect(() => sep10Service.verifyChallenge(challenge.transaction)).toThrow(
        /Challenge transaction is missing a valid signature from client/
      );
    });

    it('rejects challenge if signed by wrong client key', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const attackerKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      tx.sign(attackerKeypair);

      const signedXdr = tx.toEnvelope().toXDR('base64');
      expect(() => sep10Service.verifyChallenge(signedXdr)).toThrow(
        /Challenge transaction is missing a valid signature from client/
      );
    });

    it('rejects expired challenge transaction', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const serverAccount = new StellarSdk.Account(serverKeypair.publicKey(), '-1');

      // Expired timebounds (in the past)
      const pastTime = Math.floor(Date.now() / 1000) - 500;
      const expiredTx = new StellarSdk.TransactionBuilder(serverAccount, {
        fee: '100',
        networkPassphrase,
        timebounds: { minTime: pastTime - 100, maxTime: pastTime },
      })
        .addOperation(
          StellarSdk.Operation.manageData({
            source: clientKeypair.publicKey(),
            name: `${homeDomain} auth`,
            value: Buffer.from('test-nonce', 'utf-8'),
          })
        )
        .build();

      expiredTx.sign(serverKeypair);
      expiredTx.sign(clientKeypair);

      const xdr = expiredTx.toEnvelope().toXDR('base64');
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(/expired/);
    });

    it('rejects tampered transaction with non-zero sequence number', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const serverAccount = new StellarSdk.Account(serverKeypair.publicKey(), '100'); // sequence != 0

      const tx = new StellarSdk.TransactionBuilder(serverAccount, {
        fee: '100',
        networkPassphrase,
        timebounds: {
          minTime: Math.floor(Date.now() / 1000) - 10,
          maxTime: Math.floor(Date.now() / 1000) + 300,
        },
      })
        .addOperation(
          StellarSdk.Operation.manageData({
            source: clientKeypair.publicKey(),
            name: `${homeDomain} auth`,
            value: Buffer.from('test-nonce', 'utf-8'),
          })
        )
        .build();

      tx.sign(serverKeypair);
      tx.sign(clientKeypair);

      const xdr = tx.toEnvelope().toXDR('base64');
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(/Invalid sequence number/);
    });

    it('rejects tampered transaction where server signature is missing', () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const serverAccount = new StellarSdk.Account(serverKeypair.publicKey(), '-1');

      const tx = new StellarSdk.TransactionBuilder(serverAccount, {
        fee: '100',
        networkPassphrase,
        timebounds: {
          minTime: Math.floor(Date.now() / 1000) - 10,
          maxTime: Math.floor(Date.now() / 1000) + 300,
        },
      })
        .addOperation(
          StellarSdk.Operation.manageData({
            source: clientKeypair.publicKey(),
            name: `${homeDomain} auth`,
            value: Buffer.from('test-nonce', 'utf-8'),
          })
        )
        .build();

      // Only client signs, server did NOT sign
      tx.sign(clientKeypair);

      const xdr = tx.toEnvelope().toXDR('base64');
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(
        /Challenge transaction was not signed by the server key/
      );
    });
  });

  describe('verifyAndIssueSession', () => {
    it('creates new user and wallet and issues session token for new client', async () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      tx.sign(clientKeypair);
      const signedXdr = tx.toEnvelope().toXDR('base64');

      mockPrisma.wallet.findUnique.mockResolvedValue(null);
      mockPrisma.user.create.mockResolvedValue({
        id: 'user-new-sep10',
        email: `${clientKeypair.publicKey().substring(0, 12).toLowerCase()}@stellar-alerts.org`,
      });

      const session = await sep10Service.verifyAndIssueSession(signedXdr);

      expect(session).toBeDefined();
      expect(session.token).toBeDefined();
      expect(session.accessToken).toBe(session.token);
      expect(session.user.id).toBe('user-new-sep10');
      expect(session.user.publicKey).toBe(clientKeypair.publicKey());
      expect(mockPrisma.user.create).toHaveBeenCalled();
    });

    it('returns existing user if wallet already registered', async () => {
      const clientKeypair = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(clientKeypair.publicKey());

      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      tx.sign(clientKeypair);
      const signedXdr = tx.toEnvelope().toXDR('base64');

      mockPrisma.wallet.findUnique.mockResolvedValue({
        id: 'wallet-1',
        publicKey: clientKeypair.publicKey(),
        user: {
          id: 'user-existing',
          email: 'existing@stellar-alerts.org',
        },
      });

      const session = await sep10Service.verifyAndIssueSession(signedXdr);

      expect(session.user.id).toBe('user-existing');
      expect(session.user.email).toBe('existing@stellar-alerts.org');
      expect(mockPrisma.user.create).not.toHaveBeenCalled();
    });
  });

  describe('challenge structure', () => {
    const build = (ops: StellarSdk.xdr.Operation[], client: StellarSdk.Keypair) => {
      const now = Math.floor(Date.now() / 1000);
      const tx = new StellarSdk.TransactionBuilder(new StellarSdk.Account(serverKeypair.publicKey(), '-1'), {
        fee: '100',
        networkPassphrase,
        timebounds: { minTime: Math.max(0, now - 30), maxTime: now + 300 },
      });
      ops.forEach((op) => tx.addOperation(op));
      const built = tx.build();
      built.sign(serverKeypair);
      built.sign(client);
      return built.toEnvelope().toXDR('base64');
    };
    const authOp = (client: StellarSdk.Keypair, value: Buffer) =>
      StellarSdk.Operation.manageData({ source: client.publicKey(), name: `${homeDomain} auth`, value });

    it('rejects a nonce that is not 64 bytes', () => {
      const client = StellarSdk.Keypair.random();
      const xdr = build([authOp(client, Buffer.from('short'))], client);
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(/nonce must be exactly 64 bytes/);
    });

    it('rejects extra operations that are not the server web_auth_domain', () => {
      const client = StellarSdk.Keypair.random();
      const xdr = build(
        [
          authOp(client, Buffer.alloc(64, 1)),
          StellarSdk.Operation.payment({
            source: serverKeypair.publicKey(),
            destination: client.publicKey(),
            asset: StellarSdk.Asset.native(),
            amount: '1',
          }),
        ],
        client,
      );
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(/unexpected operation/);
    });

    it('rejects a web_auth_domain for a different domain', () => {
      const client = StellarSdk.Keypair.random();
      const xdr = build(
        [
          authOp(client, Buffer.alloc(64, 1)),
          StellarSdk.Operation.manageData({
            source: serverKeypair.publicKey(),
            name: 'web_auth_domain',
            value: Buffer.from('evil.example.com'),
          }),
        ],
        client,
      );
      expect(() => sep10Service.verifyChallenge(xdr)).toThrow(/Invalid web_auth_domain/);
    });

    it('rejects a challenge signed for a different network passphrase', () => {
      const client = StellarSdk.Keypair.random();
      const publicService = new SEP10Service(serverKeypair.secret(), homeDomain, StellarSdk.Networks.PUBLIC);
      const challenge = publicService.generateChallenge(client.publicKey());
      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, StellarSdk.Networks.PUBLIC) as StellarSdk.Transaction;
      tx.sign(client);

      // Hash (and so every signature) differs per network, so the testnet service cannot validate it.
      expect(() => sep10Service.verifyChallenge(tx.toEnvelope().toXDR('base64'))).toThrow(/not signed by the server key/);
    });

    it('supports a MEMO_ID and reports it', () => {
      const client = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(client.publicKey(), { memo: '12345' });
      const tx = StellarSdk.TransactionBuilder.fromXDR(challenge.transaction, networkPassphrase) as StellarSdk.Transaction;
      tx.sign(client);

      expect(sep10Service.verifyChallenge(tx.toEnvelope().toXDR('base64')).memo).toBe('12345');
    });
  });

  describe('verifyChallengeSigners', () => {
    it('accepts the master key of an unfunded account', async () => {
      const client = StellarSdk.Keypair.random();
      const result = await sep10Service.verifyChallengeSigners(signedChallenge(client));

      expect(result).toMatchObject({ accountExists: false, signersUsed: [client.publicKey()], signedWeight: 1 });
    });

    it('accepts a delegated signer whose weight meets the medium threshold', async () => {
      const client = StellarSdk.Keypair.random();
      const delegate = StellarSdk.Keypair.random();
      loadClientSigners.mockResolvedValue({
        mediumThreshold: 2,
        signers: [
          { key: client.publicKey(), weight: 0 },
          { key: delegate.publicKey(), weight: 2 },
        ],
      });

      const result = await sep10Service.verifyChallengeSigners(signedChallenge(client, [delegate]));

      expect(result).toMatchObject({ accountExists: true, signedWeight: 2, threshold: 2, signersUsed: [delegate.publicKey()] });
    });

    it('rejects a master key whose weight was set to zero', async () => {
      const client = StellarSdk.Keypair.random();
      const delegate = StellarSdk.Keypair.random();
      loadClientSigners.mockResolvedValue({
        mediumThreshold: 1,
        signers: [
          { key: client.publicKey(), weight: 0 },
          { key: delegate.publicKey(), weight: 1 },
        ],
      });

      await expect(sep10Service.verifyChallengeSigners(signedChallenge(client))).rejects.toThrow(/signature/);
    });

    it('rejects signatures whose combined weight is below the threshold', async () => {
      const client = StellarSdk.Keypair.random();
      const second = StellarSdk.Keypair.random();
      loadClientSigners.mockResolvedValue({
        mediumThreshold: 3,
        signers: [
          { key: client.publicKey(), weight: 1 },
          { key: second.publicKey(), weight: 1 },
        ],
      });

      await expect(sep10Service.verifyChallengeSigners(signedChallenge(client, [client, second]))).rejects.toMatchObject({
        code: 'INSUFFICIENT_SIGNER_WEIGHT',
      });
    });

    it('sums the weight of several signers', async () => {
      const client = StellarSdk.Keypair.random();
      const second = StellarSdk.Keypair.random();
      loadClientSigners.mockResolvedValue({
        mediumThreshold: 2,
        signers: [
          { key: client.publicKey(), weight: 1 },
          { key: second.publicKey(), weight: 1 },
        ],
      });

      const result = await sep10Service.verifyChallengeSigners(signedChallenge(client, [client, second]));
      expect(result.signedWeight).toBe(2);
    });

    it('rejects signatures from keys that are not signers of the account', async () => {
      const client = StellarSdk.Keypair.random();
      const stranger = StellarSdk.Keypair.random();

      await expect(sep10Service.verifyChallengeSigners(signedChallenge(client, [client, stranger]))).rejects.toThrow(
        /do not belong to the client account/,
      );
    });

    it('fails closed when the signers cannot be loaded', async () => {
      const client = StellarSdk.Keypair.random();
      loadClientSigners.mockRejectedValue(new Sep10Error('Horizon down', 'SIGNER_LOOKUP_FAILED'));

      await expect(sep10Service.verifyChallengeSigners(signedChallenge(client))).rejects.toMatchObject({
        code: 'SIGNER_LOOKUP_FAILED',
      });
    });
  });

  describe('wallet ownership', () => {
    it('does not log into a real user account that merely tracks the wallet', async () => {
      const client = StellarSdk.Keypair.random();
      mockPrisma.wallet.findUnique.mockResolvedValue({
        id: 'watch-only',
        publicKey: client.publicKey(),
        deletedAt: null,
        user: { id: 'victim', email: 'victim@example.com' },
      });
      mockPrisma.user.create.mockResolvedValue({
        id: 'sep10-user',
        email: `${client.publicKey().substring(0, 12).toLowerCase()}@stellar-alerts.org`,
      });

      const session = await sep10Service.verifyAndIssueSession(signedChallenge(client));

      expect(session.user.id).toBe('sep10-user');
      expect(session.user.id).not.toBe('victim');
      // The key already belongs to another user's wallet row, so none is linked to the new user.
      expect(mockPrisma.user.create.mock.calls[0][0].data).not.toHaveProperty('wallets');
    });

    it('does not reuse a soft-deleted wallet', async () => {
      const client = StellarSdk.Keypair.random();
      mockPrisma.wallet.findUnique.mockResolvedValue({
        id: 'deleted',
        publicKey: client.publicKey(),
        deletedAt: new Date(),
        user: { id: 'old-user', email: 'old@stellar-alerts.org' },
      });
      mockPrisma.user.create.mockResolvedValue({ id: 'fresh', email: 'fresh@stellar-alerts.org' });

      const session = await sep10Service.verifyAndIssueSession(signedChallenge(client));

      expect(session.user.id).toBe('fresh');
    });
  });

  describe('replay protection', () => {
    it('lets a signed challenge be redeemed only once', async () => {
      const client = StellarSdk.Keypair.random();
      const xdr = signedChallenge(client);
      mockPrisma.wallet.findUnique.mockResolvedValue({
        id: 'w',
        publicKey: client.publicKey(),
        user: { id: 'user-1', email: 'u@stellar-alerts.org' },
      });

      const first = await sep10Service.verifyAndIssueSession(xdr);
      expect(first.refreshToken).toBe('refresh-token');

      await expect(sep10Service.verifyAndIssueSession(xdr)).rejects.toMatchObject({ code: 'CHALLENGE_REPLAYED' });
    });

    it('does not burn the challenge when verification fails', async () => {
      const client = StellarSdk.Keypair.random();
      const challenge = sep10Service.generateChallenge(client.publicKey());

      await expect(sep10Service.verifyAndIssueSession(challenge.transaction)).rejects.toThrow(/missing a valid signature/);
      expect(consumed.size).toBe(0);
    });
  });
});
