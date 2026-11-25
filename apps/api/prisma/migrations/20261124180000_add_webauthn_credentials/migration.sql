-- Add WebAuthnCredential table for FIDO2 / WebAuthn hardware security keys (#993)
-- Additive-only migration (zero-downtime compatible).

CREATE TABLE IF NOT EXISTS "WebAuthnCredential" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "credentialId" TEXT NOT NULL,
    "nickname" TEXT NOT NULL,
    "publicKeyCose" TEXT NOT NULL,
    "algorithm" INTEGER NOT NULL DEFAULT -7,
    "signCount" INTEGER NOT NULL DEFAULT 0,
    "transports" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "aaguid" TEXT,
    "backedUp" BOOLEAN NOT NULL DEFAULT false,
    "lastUsedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WebAuthnCredential_pkey" PRIMARY KEY ("id")
);

-- safe-migration: brand-new empty table created in this same migration
CREATE UNIQUE INDEX IF NOT EXISTS "WebAuthnCredential_credentialId_key" ON "WebAuthnCredential"("credentialId");
-- safe-migration: brand-new empty table created in this same migration
CREATE INDEX IF NOT EXISTS "WebAuthnCredential_userId_idx" ON "WebAuthnCredential"("userId");
-- safe-migration: brand-new empty table created in this same migration
CREATE INDEX IF NOT EXISTS "WebAuthnCredential_credentialId_idx" ON "WebAuthnCredential"("credentialId");

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'WebAuthnCredential_userId_fkey'
  ) THEN
    ALTER TABLE "WebAuthnCredential"
      ADD CONSTRAINT "WebAuthnCredential_userId_fkey"
      FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
  END IF;
END $$;
