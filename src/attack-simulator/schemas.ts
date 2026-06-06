import { z } from 'zod';

/**
 * Runtime schemas for the attack-simulator domain.
 *
 * These are the single source of truth for the shapes that cross a boundary
 * (scenario output -> engines -> reporter -> disk). The TypeScript types used
 * elsewhere are *inferred* from these schemas so the static and runtime views
 * can never drift apart.
 */

export const SecurityLayerSchema = z.enum(['AUTH', 'INFRA', 'SESSION', 'UNKNOWN']);

export const ClassificationSchema = z.enum([
  'ALLOW',
  'AUTH_REJECT',
  'BLOCKED',
  'RATE_LIMITED',
  'UNKNOWN',
]);

export const SocEventTypeSchema = z.enum([
  'REFRESH',
  'REFRESH_ERROR',
  'REFRESH_FIRST',
  'REFRESH_REUSE',
  'SESSION_GET',
  'TOKEN_REUSE',
  'FINGERPRINT',
  'LOGIN_ATTEMPT',
  'JWT_TAMPER',
]);

const BaseEventSchema = z.object({
  id: z.string().uuid(),
  timestamp: z.number().int().nonnegative(),
  scenario: z.string().min(1),
  type: SocEventTypeSchema,
  status: z.number().int(),
  layer: SecurityLayerSchema,
  classification: ClassificationSchema,
  message: z.string().optional(),
});

/** Event carrying network identity (ip + ua). */
export const NetworkEventSchema = BaseEventSchema.extend({
  ip: z.string().min(1),
  userAgent: z.string().min(1),
});

/** Event with no network context. */
export const SystemEventSchema = BaseEventSchema.extend({
  ip: z.undefined().optional(),
  userAgent: z.undefined().optional(),
});

export const SocEventSchema = z.union([NetworkEventSchema, SystemEventSchema]);

export const SeveritySchema = z.enum(['LOW', 'MEDIUM', 'HIGH']);

export const AlertSchema = z.object({
  rule: z.string().min(1),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(1),
  ip: z.string().optional(),
  description: z.string().min(1),
});

export const CorrelationAlertSchema = z.object({
  ip: z.string(),
  severity: SeveritySchema,
  confidence: z.number().min(0).max(1),
  sequence: z.array(ClassificationSchema),
});

/**
 * A per-scenario verdict. Each scenario declares the defensive behaviour the
 * backend is *supposed* to exhibit (e.g. a replayed token must be rejected).
 * After a run we check the observed events against that expectation, which
 * turns the simulator from "prints what happened" into a pass/fail regression
 * test for the auth defenses.
 */
export const ScenarioVerdictSchema = z.object({
  scenario: z.string().min(1),
  description: z.string().min(1),
  total: z.number().int().nonnegative(),
  blocked: z.number().int().nonnegative(),
  required: z.number().int().nonnegative(),
  passed: z.boolean(),
});

export const VerdictSchema = z.object({
  /** True only if every evaluated scenario's defense held. */
  passed: z.boolean(),
  scenarios: z.array(ScenarioVerdictSchema),
});

export const ScenarioReportSchema = z.object({
  generatedAt: z.string(),
  target: z.string().url(),
  scenarios: z.array(z.string()),
  events: z.array(SocEventSchema),
  ruleAlerts: z.array(AlertSchema),
  correlationAlerts: z.array(CorrelationAlertSchema),
  summary: z.object({
    high: z.number().int().nonnegative(),
    medium: z.number().int().nonnegative(),
    low: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    status: z.enum(['ACTIVE_THREAT', 'SUSPICIOUS', 'CLEAN']),
  }),
  verdict: VerdictSchema,
});

/** Validated configuration for a simulator run. */
export const SimConfigSchema = z.object({
  target: z.string().url().default('http://localhost:3000'),
  out: z.string().optional(),
  scenarios: z.array(z.string()).default([]),
  email: z.string().email().optional(),
  password: z.string().optional(),
  bruteForceEmail: z.string().email().optional(),
});

export type SecurityLayer = z.infer<typeof SecurityLayerSchema>;
export type Classification = z.infer<typeof ClassificationSchema>;
export type SocEventType = z.infer<typeof SocEventTypeSchema>;
export type NetworkEvent = z.infer<typeof NetworkEventSchema>;
export type SystemEvent = z.infer<typeof SystemEventSchema>;
export type SocEvent = z.infer<typeof SocEventSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type CorrelationAlert = z.infer<typeof CorrelationAlertSchema>;
export type ScenarioReport = z.infer<typeof ScenarioReportSchema>;
export type SimConfig = z.infer<typeof SimConfigSchema>;
export type ScenarioVerdict = z.infer<typeof ScenarioVerdictSchema>;
export type Verdict = z.infer<typeof VerdictSchema>;
