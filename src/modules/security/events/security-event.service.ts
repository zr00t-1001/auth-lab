import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import {
  SecurityEvent,
  SecurityEventType,
  type SecuritySeverity,
} from './security-event.entity';

export type RecordEventInput = {
  type: SecurityEventType;
  severity?: SecuritySeverity;
  userId?: string;
  sessionId?: string;
  ip?: string;
  userAgent?: string;
  detail?: Record<string, unknown>;
};

export type FindEventsOptions = {
  type?: SecurityEventType;
  limit?: number;
  offset?: number;
};

@Injectable()
export class SecurityEventService {
  private readonly logger = new Logger(SecurityEventService.name);

  constructor(
    @InjectRepository(SecurityEvent)
    private readonly repo: Repository<SecurityEvent>,
  ) {}

  /**
   * Persist a security decision. Recording must never break the request it is
   * describing, so failures are logged and swallowed rather than thrown.
   */
  async record(input: RecordEventInput): Promise<void> {
    try {
      await this.repo.save(
        this.repo.create({ severity: 'MEDIUM', ...input }),
      );
    } catch (err) {
      this.logger.error(
        `failed to record security event ${input.type}`,
        err as Error,
      );
    }
  }

  async findForUser(
    userId: string,
    { type, limit = 50, offset = 0 }: FindEventsOptions = {},
  ): Promise<{ total: number; items: SecurityEvent[] }> {
    const [items, total] = await this.repo.findAndCount({
      where: { userId, ...(type ? { type } : {}) },
      order: { createdAt: 'DESC' },
      take: Math.min(limit, 200),
      skip: offset,
    });

    return { total, items };
  }

  /** Admin: every user's events (newest first). Not user-scoped. */
  async findAll({
    type,
    limit = 50,
    offset = 0,
  }: FindEventsOptions = {}): Promise<{ total: number; items: SecurityEvent[] }> {
    const [items, total] = await this.repo.findAndCount({
      where: { ...(type ? { type } : {}) },
      order: { createdAt: 'DESC' },
      take: Math.min(limit, 200),
      skip: offset,
    });

    return { total, items };
  }
}
