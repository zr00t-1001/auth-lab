export type RiskLevel =
  | 'TRUSTED'
  | 'LOW_RISK'
  | 'SUSPICIOUS'
  | 'HIGH_RISK';

export type SessionResponse = {
  id: string;
  deviceName: string;
  ipAddress?: string;
  createdAt?: Date;
  expiresAt?: Date;
  revoked: boolean;

  isCurrent?: boolean;
  label?: string;

  isSuspicious?: boolean;
  reasons?: string[];

  autoRevoked?: boolean;

  device?: {
    type: string;
    model?: string;
    vendor?: string;
  };

  browser?: string;
  os?: string;

  country?: string;
  city?: string;
  lat?: number;
  lon?: number;

  risk?: {
    score: number;
    level: RiskLevel;
  };

  security?: {
    autoRevoked: boolean;
    requireReauth: boolean;
  };

  drift?: {
    score: number;
    level: RiskLevel;
    reasons: string[];
  };
};