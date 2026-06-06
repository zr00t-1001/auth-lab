export const RISK_LEVELS = {
  TRUSTED: 'TRUSTED',
  LOW_RISK: 'LOW_RISK',
  SUSPICIOUS: 'SUSPICIOUS',
  HIGH_RISK: 'HIGH_RISK',
} as const;

export type RiskLevel =
  typeof RISK_LEVELS[keyof typeof RISK_LEVELS];

export type SecurityAction =
  | 'ALLOW'
  | 'STEP_UP'
  | 'REVOKE';