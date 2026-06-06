import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, LessThan } from 'typeorm';
import { Session } from './session.entity';
import { SessionResponse } from './dto/session-response.dto';
import { deviceLabel, prettyIp } from '../../common/device-label';
import { SessionSecurityEngine } from './security/session-security.engine';
import { GeoService, GeoInfo } from './security/geo.service';
import { SecurityEventService } from '../security/events/security-event.service';
import { SecurityEventType } from '../security/events/security-event.entity';

@Injectable()
export class SessionsService {
  constructor(
    @InjectRepository(Session)
    private readonly repo: Repository<Session>,
    private readonly securityEngine: SessionSecurityEngine,
    private readonly securityEvents: SecurityEventService,
    private readonly geo: GeoService,
  ) {}

  // --------------------------------------------------
  // CREATE SESSION
  // --------------------------------------------------
  async create(data: Partial<Session>) {
    // Resolve the login IP to a location and stamp it on the session. The
    // engine's drift scoring compares country across a user's sessions, so a
    // login from a new country raises risk automatically.
    const geo = this.geo.lookup(data.ipAddress);

    // Impossible travel: two logins too far apart in too little time.
    if (data.userId && geo.lat != null && geo.lon != null) {
      await this.detectImpossibleTravel(data.userId, geo);
    }

    return this.repo.save(this.repo.create({ ...data, ...geo }));
  }

  // --------------------------------------------------
  // IMPOSSIBLE TRAVEL
  // --------------------------------------------------
  // Compare a new login's location to the user's most recent prior session.
  // If the implied speed to get from there to here exceeds a commercial flight
  // over a meaningful distance, it cannot be the same human — flag it.
  private async detectImpossibleTravel(userId: string, geo: GeoInfo) {
    if (geo.lat == null || geo.lon == null) return;

    const prior = await this.repo.findOne({
      where: { userId },
      order: { createdAt: 'DESC' },
    });
    if (!prior || prior.lat == null || prior.lon == null) return;

    const km = this.geo.distanceKm(prior.lat, prior.lon, geo.lat, geo.lon);
    const hours = Math.max(
      (Date.now() - new Date(prior.createdAt).getTime()) / 3_600_000,
      1 / 60, // floor at ~1 minute so simultaneous logins don't divide by ~0
    );
    const speedKmh = km / hours;

    if (km > 100 && speedKmh > 900) {
      await this.securityEvents.record({
        type: SecurityEventType.IMPOSSIBLE_TRAVEL,
        severity: 'HIGH',
        userId,
        detail: {
          distanceKm: Math.round(km),
          elapsedHours: Number(hours.toFixed(2)),
          impliedSpeedKmh: Math.round(speedKmh),
          from: { country: prior.country, city: prior.city },
          to: { country: geo.country, city: geo.city },
        },
      });
    }
  }

  // --------------------------------------------------
  // FIND ACTIVE SESSION
  // --------------------------------------------------
  async findActive(sessionId: string) {
    const session = await this.repo.findOne({
      where: { id: sessionId, revoked: false },
    });

    if (!session) return null;

    if (session.expiresAt.getTime() <= Date.now()) {
      await this.revoke(sessionId);
      return null;
    }

    return session;
  }

  // --------------------------------------------------
  // ROTATE REFRESH TOKEN (STATE UPDATE ONLY)
  // --------------------------------------------------
  async rotateRefreshToken(
    sessionId: string,
    currentVersion: number,
    newVersion: number,
    newHash: string,
    newRefreshJti: string,
  ): Promise<boolean> {
    const result = await this.repo.update(
      {
        id: sessionId,
        tokenVersion: currentVersion,
        revoked: false,
      },
      {
        tokenVersion: newVersion,
        refreshTokenHash: newHash,

        lastRefreshJti: newRefreshJti,
        currentRefreshJti: newRefreshJti,
      },
    );

    return result.affected === 1;
  }

  // --------------------------------------------------
  // GET USER SESSIONS (PURE ORCHESTRATION)
  // --------------------------------------------------
  async getUserSessions(
    userId: string,
    currentSessionId?: string,
    enforce = false,
  ): Promise<SessionResponse[]> {

    const sessions = await this.repo.find({
      where: { userId },
      order: { createdAt: 'DESC' },
    });

    const current = sessions.find(s => s.id === currentSessionId);

    sessions.sort((a, b) =>
      a.id === currentSessionId ? -1 :
      b.id === currentSessionId ? 1 : 0,
    );

    const results: SessionResponse[] = [];

    for (const session of sessions) {

      const isCurrent = session.id === currentSessionId;

      // --------------------------------------------------
      // SINGLE SOURCE OF TRUTH
      // --------------------------------------------------
      const context =
        current && !isCurrent
          ? this.securityEngine.evaluate(current, session)
          : this.securityEngine.emptyContext();

      let autoRevoked = false;

      // --------------------------------------------------
      // ENFORCEMENT (ONLY SIDE EFFECT HERE)
      // --------------------------------------------------
      if (context.action === 'REVOKE') {
        // Only audit the transition into "revoked" — re-viewing an already
        // revoked session must not spam a new event on every refresh.
        const firstRevoke = !session.revoked;
        await this.revoke(session.id);
        autoRevoked = true;

        if (firstRevoke) {
          await this.securityEvents.record({
            type: SecurityEventType.HIGH_RISK_BLOCK,
            severity: 'HIGH',
            userId: session.userId,
            sessionId: session.id,
            ip: session.ipAddress,
            userAgent: session.userAgent,
            detail: {
              score: context.score,
              level: context.level,
              reasons: context.reasons,
              autoRevoked: true,
            },
          });
        }
      }

      const device = deviceLabel(session.userAgent);

      results.push({
        id: session.id,
        deviceName: session.deviceName?.trim() || device.label,
        browser: device.browser,
        os: device.os,
        ipAddress: prettyIp(session.ipAddress),
        country: session.country,
        city: session.city,
        lat: session.lat,
        lon: session.lon,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        revoked: session.revoked || autoRevoked,

        isCurrent,
        label: isCurrent ? 'This device' : 'Other device',

        isSuspicious: context.isSuspicious,
        reasons: context.reasons,

        risk: {
          score: context.score,
          level: context.level,
        },

        drift: {
          score: context.driftScore,
          level: context.driftLevel,
          reasons: context.driftReasons,
        },

        security: {
          autoRevoked,
          requireReauth: context.requireReauth,
        },
      });
    }

    return results;
  }

  // --------------------------------------------------
  // ADMIN / SOC: ALL SESSIONS (read-only, no side effects)
  // --------------------------------------------------
  // Unlike getUserSessions, this never auto-revokes or scores risk relative to
  // a "current" session — the admin is an observer of the whole system, not a
  // participant. Detection lives in the guards + the security-events feed.
  async getAllSessions() {
    const sessions = await this.repo.find({ order: { createdAt: 'DESC' } });

    return sessions.map((s) => {
      const device = deviceLabel(s.userAgent);
      return {
        id: s.id,
        userId: s.userId,
        deviceName: s.deviceName?.trim() || device.label,
        browser: device.browser,
        os: device.os,
        ipAddress: prettyIp(s.ipAddress),
        country: s.country,
        city: s.city,
        lat: s.lat,
        lon: s.lon,
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        revoked: s.revoked,
        state: s.revoked ? 'REVOKED' : 'ACTIVE',
      };
    });
  }

  // --------------------------------------------------
  // REVOKE SINGLE SESSION
  // --------------------------------------------------
  async revokeUserSession(userId: string, sessionId: string) {
    const session = await this.repo.findOne({
      where: { id: sessionId, userId },
    });

    if (!session) {
      return { success: false, message: 'Session not found' };
    }

    await this.revoke(sessionId);

    return { success: true, message: 'Session revoked' };
  }

  // --------------------------------------------------
  // UPDATE SESSION
  // --------------------------------------------------
  async update(sessionId: string, data: Partial<Session>) {
    return this.repo.update({ id: sessionId }, data);
  }

  // --------------------------------------------------
  // REVOKE HELPERS
  // --------------------------------------------------
  async revoke(sessionId: string) {
    return this.repo.update({ id: sessionId }, { revoked: true });
  }

  async revokeAll(userId: string) {
    return this.repo.update({ userId }, { revoked: true });
  }

  // --------------------------------------------------
  // CLEANUP
  // --------------------------------------------------
  async cleanup() {
    return this.repo.delete({
      expiresAt: LessThan(new Date()),
    });
  }
}