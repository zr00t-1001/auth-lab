import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';

import { SessionsService } from '../sessions.service';
import { SessionFingerprintService } from '../fingerprint/session-fingerprint.service';
import { SecurityEventService } from '../../security/events/security-event.service';
import { SecurityEventType } from '../../security/events/security-event.entity';

@Injectable()
export class SessionBindingGuard implements CanActivate {
  constructor(
    private readonly sessionsService: SessionsService,
    private readonly fingerprintService: SessionFingerprintService,
    private readonly securityEvents: SecurityEventService,
  ) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest();
    const user = req.user;

    if (!user?.sessionId) {
      throw new UnauthorizedException('Missing session');
    }

    const session = await this.sessionsService.findActive(user.sessionId);

    if (!session) {
      throw new UnauthorizedException('Invalid session');
    }

    const ip = this.getIp(req);
    const ua = req.headers['user-agent'] || 'unknown';

    const fingerprint = this.fingerprintService.generate(session.id, ip, ua);

    // 1. FIRST TIME BINDING
    if (!session.fingerprint) {
      await this.sessionsService.update(session.id, { fingerprint });
      req.session = session;
      return true;
    }

    // 2. FINGERPRINT VALIDATION
    if (session.fingerprint !== fingerprint) {
      await this.sessionsService.revoke(session.id);
      await this.securityEvents.record({
        type: SecurityEventType.BINDING_VIOLATION,
        severity: 'HIGH',
        userId: user.userId,
        sessionId: session.id,
        ip,
        userAgent: ua,
      });
      throw new ForbiddenException('Session binding violation');
    }

    // 3. JTI VALIDATION (REPLAY PROTECTION)
    const tokenJti = user.jti;

    if (
      session.currentAccessJti &&
      tokenJti &&
      session.currentAccessJti !== tokenJti
    ) {
      await this.sessionsService.revoke(session.id);
      await this.securityEvents.record({
        type: SecurityEventType.TOKEN_REPLAY,
        severity: 'HIGH',
        userId: user.userId,
        sessionId: session.id,
        ip,
        userAgent: ua,
      });
      throw new ForbiddenException('Token replay detected');
    }

    req.session = session;
    return true;
  }

  private getIp(req: any): string {
    return (
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      'unknown'
    );
  }
}
