import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';

import { SessionsService } from 'src/modules/sessions/sessions.service';
import { SessionSecurityEngine } from 'src/modules/sessions/security/session-security.engine';
import { SecurityEventService } from 'src/modules/security/events/security-event.service';
import { SecurityEventType } from 'src/modules/security/events/security-event.entity';

@Injectable()
export class ZeroTrustGuard implements CanActivate {
  constructor(
    private readonly sessionsService: SessionsService,
    private readonly securityEngine: SessionSecurityEngine,
    private readonly securityEvents: SecurityEventService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();

    const user = req.user;
    const sessionId = user?.sessionId;

    if (!user || !sessionId) {
      throw new UnauthorizedException('Missing session context');
    }

    const session = await this.sessionsService.findActive(sessionId);

    if (!session) {
      throw new UnauthorizedException('Session invalid or expired');
    }

    if (session.revoked) {
      throw new UnauthorizedException('Session revoked');
    }

    // 1. Extract request metadata
    const ip =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      '';

    const userAgent = req.headers['user-agent'] || '';

    // 2. Risk evaluation (compare the stored session against this request)
    const risk = this.securityEngine.evaluate(session, {
      userId: session.userId,
      ipAddress: ip,
      userAgent,
    });

    // 3. HARD BLOCK RULES
    if (risk.level === 'HIGH_RISK' || risk.score >= 80) {
      await this.sessionsService.revoke(sessionId);
      await this.securityEvents.record({
        type: SecurityEventType.HIGH_RISK_BLOCK,
        severity: 'HIGH',
        userId: session.userId,
        sessionId,
        ip,
        userAgent,
        detail: { score: risk.score, reasons: risk.reasons },
      });
      throw new ForbiddenException('High risk session blocked');
    }

    // Suspicious → step-up required (future MFA hook)
    if (risk.level === 'SUSPICIOUS' && risk.score >= 50) {
      await this.securityEvents.record({
        type: SecurityEventType.STEP_UP_REQUIRED,
        severity: 'MEDIUM',
        userId: session.userId,
        sessionId,
        ip,
        userAgent,
        detail: { score: risk.score, reasons: risk.reasons },
      });
      throw new ForbiddenException('Step-up authentication required');
    }

    // attach risk to request (for controllers/logging)
    req.risk = risk;

    return true;
  }
}