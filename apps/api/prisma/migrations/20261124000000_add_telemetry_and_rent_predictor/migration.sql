CREATE TABLE "TimeSeriesRollup" (
    "id" TEXT NOT NULL,
    "asset" TEXT NOT NULL,
    "interval" TEXT NOT NULL,
    "bucketStart" TIMESTAMP(3) NOT NULL,
    "count" INTEGER NOT NULL,
    "volume" DECIMAL(30,7) NOT NULL,
    "minAmount" DECIMAL(30,7) NOT NULL,
    "maxAmount" DECIMAL(30,7) NOT NULL,
    "uniqueSenders" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "TimeSeriesRollup_pkey" PRIMARY KEY ("id")
);

-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE UNIQUE INDEX "TimeSeriesRollup_asset_interval_bucketStart_key"
    ON "TimeSeriesRollup"("asset", "interval", "bucketStart");
-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE INDEX "TimeSeriesRollup_interval_bucketStart_idx"
    ON "TimeSeriesRollup"("interval", "bucketStart");
-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE INDEX "TimeSeriesRollup_asset_interval_bucketStart_idx"
    ON "TimeSeriesRollup"("asset", "interval", "bucketStart");

CREATE TABLE "SorobanRentObservation" (
    "id" TEXT NOT NULL,
    "contractId" TEXT NOT NULL,
    "ledgerKey" TEXT NOT NULL,
    "durability" TEXT NOT NULL,
    "byteSize" INTEGER NOT NULL,
    "liveUntilLedgerSeq" INTEGER NOT NULL,
    "ledgerSeq" INTEGER NOT NULL,
    "previousByteSize" INTEGER,
    "previousLedgerSeq" INTEGER,
    "warningTier" TEXT,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "SorobanRentObservation_pkey" PRIMARY KEY ("id")
);

-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE UNIQUE INDEX "SorobanRentObservation_contractId_ledgerKey_key"
    ON "SorobanRentObservation"("contractId", "ledgerKey");
-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE INDEX "SorobanRentObservation_contractId_ledgerSeq_idx"
    ON "SorobanRentObservation"("contractId", "ledgerSeq");
-- safe-migration: Index is built on a newly created table before application code can use it.
CREATE INDEX "SorobanRentObservation_liveUntilLedgerSeq_idx"
    ON "SorobanRentObservation"("liveUntilLedgerSeq");
