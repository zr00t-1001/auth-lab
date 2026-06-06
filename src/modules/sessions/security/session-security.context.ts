import { RiskLevel } from "./risk-level.types";

export type SecurityContext = {
  score: number;
  level: RiskLevel;
  reasons: string[];

  driftScore: number;
  driftLevel: RiskLevel;
  driftReasons: string[];

  isSuspicious: boolean;
  requireReauth: boolean;

  action: 'ALLOW' | 'STEP_UP' | 'REVOKE';
};