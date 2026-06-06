import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

export enum SecurityEventType {
  BINDING_VIOLATION = 'BINDING_VIOLATION',
  TOKEN_REPLAY = 'TOKEN_REPLAY',
  HIGH_RISK_BLOCK = 'HIGH_RISK_BLOCK',
  STEP_UP_REQUIRED = 'STEP_UP_REQUIRED',
  REFRESH_REUSE = 'REFRESH_REUSE',
  REFRESH_RACE = 'REFRESH_RACE',
  LOGIN_FAILED = 'LOGIN_FAILED',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
  JWT_TAMPER = 'JWT_TAMPER',
  MFA_ENABLED = 'MFA_ENABLED',
  MFA_FAILED = 'MFA_FAILED',
  IMPOSSIBLE_TRAVEL = 'IMPOSSIBLE_TRAVEL',
}

export type SecuritySeverity = 'LOW' | 'MEDIUM' | 'HIGH';

@Entity('security_events')
export class SecurityEvent {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column({ nullable: true })
  userId?: string;

  @Index()
  @Column({ nullable: true })
  sessionId?: string;

  @Column({ type: 'enum', enum: SecurityEventType })
  type!: SecurityEventType;

  @Column({ default: 'MEDIUM' })
  severity!: SecuritySeverity;

  @Column({ nullable: true })
  ip?: string;

  @Column({ nullable: true })
  userAgent?: string;

  /** Free-form structured context (risk score, reasons, etc.). */
  @Column({ type: 'jsonb', nullable: true })
  detail?: Record<string, unknown>;

  @CreateDateColumn()
  createdAt!: Date;
}
