import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  Index,
} from 'typeorm';

@Entity('sessions')
export class Session {
  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @Index()
  @Column()
  userId!: string;

  @Column({ type: 'text', nullable: true })
  refreshTokenHash!: string;

  @Column({ default: 0 })
  tokenVersion!: number;

  @Column({ default: false })
  revoked!: boolean;

  @Column({ nullable: true })
  ipAddress?: string;

  @Column({ nullable: true })
  userAgent?: string;

  @Column({ nullable: true })
  fingerprint?: string;

  @Column({ type: 'timestamp' })
  expiresAt!: Date;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ nullable: true })
  deviceName?: string;

  @Column({ nullable: true })
  currentAccessJti?: string;

  @Column({ nullable: true })
  currentRefreshJti?: string;

  @Column({ nullable: true })
  lastRefreshJti?: string;

  // --- Geo (filled from the IP at login; null for private/loopback) ---
  @Column({ nullable: true })
  country?: string;

  @Column({ nullable: true })
  city?: string;

  @Column({ type: 'double precision', nullable: true })
  lat?: number;

  @Column({ type: 'double precision', nullable: true })
  lon?: number;
}