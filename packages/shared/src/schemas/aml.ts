import { z } from 'zod';

/**
 * Anti-money-laundering (AML) risk scoring contracts shared by the API and
 * its consumers (#928).
 *
 * A payment is scored by walking the transaction graph *backwards* from the
 * counterparty that sent it: direct matches against a locally-held
 * sanctioned / exploiter address list score highest, then one-hop and
 * two-hop propagation decay the score. Scores are always normalised to the
 * 0–100 range so a caller can apply a single threshold.
 */

/** Payments whose source scores above this are escalated to a Critical alert. */
export const AML_CRITICAL_RISK_THRESHOLD = 70;

/** How far taint is propagated through the transaction graph. */
export const AML_MAX_HOPS = 2;

export const amlRiskCategorySchema = z.enum([
  'sanctioned',
  'exploiter',
  'mixer',
  'darknet',
  'other',
]);
export type AmlRiskCategory = z.infer<typeof amlRiskCategorySchema>;

export const amlRiskLevelSchema = z.enum(['low', 'medium', 'high', 'critical']);
export type AmlRiskLevel = z.infer<typeof amlRiskLevelSchema>;

/**
 * A locally-maintained flagged counterparty. `severity` is a multiplier in
 * [0, 1] applied to the hop score; it defaults per category when omitted.
 */
export const flaggedAddressSchema = z.object({
  address: z.string().min(1),
  category: amlRiskCategorySchema,
  label: z.string().min(1).max(256).optional(),
  severity: z.number().min(0).max(1).optional(),
});
export type FlaggedAddress = z.infer<typeof flaggedAddressSchema>;

/** A directed value-transfer edge: `from` sent funds to `to`. */
export const amlTransactionEdgeSchema = z.object({
  from: z.string().min(1),
  to: z.string().min(1),
  weight: z.number().positive().max(1).optional(),
});
export type AmlTransactionEdge = z.infer<typeof amlTransactionEdgeSchema>;

/** One reason a score was contributed to the final assessment. */
export const amlRiskMatchSchema = z.object({
  address: z.string(),
  category: amlRiskCategorySchema,
  label: z.string().optional(),
  hops: z.number().int().min(0).max(AML_MAX_HOPS),
  contribution: z.number().min(0).max(100),
});
export type AmlRiskMatch = z.infer<typeof amlRiskMatchSchema>;

export const amlRiskAssessmentSchema = z.object({
  address: z.string(),
  score: z.number().min(0).max(100),
  level: amlRiskLevelSchema,
  /** Shortest path to a flagged address, or null when nothing was found. */
  hops: z.number().int().min(0).max(AML_MAX_HOPS).nullable(),
  matches: z.array(amlRiskMatchSchema),
});
export type AmlRiskAssessment = z.infer<typeof amlRiskAssessmentSchema>;

/** A payment whose counterparty should be evaluated for AML risk. */
export const amlPaymentInputSchema = z.object({
  txHash: z.string().min(1),
  fromAddress: z.string().min(1),
  toAddress: z.string().min(1),
  amount: z.union([z.string(), z.number()]).optional(),
  asset: z.string().optional(),
});
export type AmlPaymentInput = z.infer<typeof amlPaymentInputSchema>;

/** True when a score crosses the configured Critical-escalation threshold. */
export function isCriticalAmlRisk(score: number): boolean {
  return score > AML_CRITICAL_RISK_THRESHOLD;
}

/** Maps a normalised 0–100 score to its coarse risk band. */
export function amlRiskLevelFromScore(score: number): AmlRiskLevel {
  if (isCriticalAmlRisk(score)) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}
