import { toUserResponse, UserResponseDto } from '../../users/dto/user-response.dto';
import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';

import { UsersService } from 'src/modules/users/users.service';
import { SessionsService } from 'src/modules/sessions/sessions.service';
import { TokenService } from '../../tokens/token.service';
import { PasswordService } from '../../security/services/password.service';
import { SessionFingerprintService } from 'src/modules/sessions/fingerprint/session-fingerprint.service';
import { LoginAttemptService } from './login-attempt.service';
import { MfaService } from './mfa.service';
import { SecurityEventService } from '../../security/events/security-event.service';
import { SecurityEventType } from '../../security/events/security-event.entity';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly sessionsService: SessionsService,
    private readonly tokensService: TokenService,
    private readonly passwordService: PasswordService,
    private readonly fingerprintService: SessionFingerprintService,
    private readonly loginAttempts: LoginAttemptService,
    private readonly mfaService: MfaService,
    private readonly securityEvents: SecurityEventService,
  ) {}

  // --------------------------------------------------
  // REGISTER
  // --------------------------------------------------
  async register(email: string, password: string) {
    // Optional lockdown: set AUTH_ALLOW_REGISTRATION=false to require an admin
    // to provision accounts instead of open self-signup.
    if (process.env.AUTH_ALLOW_REGISTRATION === 'false') {
      throw new ForbiddenException('Self-registration is disabled');
    }
    const normalizedEmail = email.toLowerCase().trim();

    const existing = await this.usersService.findByEmail(normalizedEmail);
    if (existing) {
      throw new BadRequestException('User already exists');
    }

    const hashedPassword = await this.passwordService.hash(password);

    const user = await this.usersService.create({
      email: normalizedEmail,
      passwordHash: hashedPassword,
    });

    return toUserResponse(user);
  }

  // --------------------------------------------------
  // CURRENT USER (for the dashboard: role + MFA status)
  // --------------------------------------------------
  async me(userId: string): Promise<UserResponseDto> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException();
    return toUserResponse(user);
  }

  // --------------------------------------------------
  // LOGIN
  // --------------------------------------------------
  async login(email: string, password: string, req: any, code?: string) {
    const normalizedEmail = email.toLowerCase().trim();
    const meta = this.extractMeta(req);
    const ip = meta.ip;

    // Defense-in-depth: refuse early if the account is locked from prior abuse.
    this.loginAttempts.assertNotLocked(normalizedEmail, ip);

    const user = await this.usersService.findByEmail(normalizedEmail);
    if (!user) {
      await this.loginAttempts.recordFailure(normalizedEmail, ip);
      throw new UnauthorizedException('Invalid credentials');
    }

    const valid = await this.passwordService.compare(
      password,
      user.passwordHash,
    );

    if (!valid) {
      await this.loginAttempts.recordFailure(normalizedEmail, ip);
      throw new UnauthorizedException('Invalid credentials');
    }

    // Successful auth clears the failure counter.
    this.loginAttempts.reset(normalizedEmail);

    // -----------------------------
    // 1. MFA CHALLENGE (if enabled for this user)
    // -----------------------------
    if (user.mfaEnabled) {
      if (!code) {
        return { mfaRequired: true };
      }
      const ok = user.mfaSecret
        ? this.mfaService.verify(code, user.mfaSecret)
        : false;
      if (!ok) {
        await this.securityEvents.record({
          type: SecurityEventType.MFA_FAILED,
          severity: 'HIGH',
          userId: user.id,
          ip: meta.ip,
          userAgent: meta.userAgent,
          detail: { stage: 'login' },
        });
        throw new UnauthorizedException('Invalid MFA code');
      }
    }

    // -----------------------------
    // 2. CREATE SESSION
    // -----------------------------
    const session = await this.sessionsService.create({
      userId: user.id,
      ipAddress: meta.ip,
      userAgent: meta.userAgent,
      tokenVersion: 0,
      revoked: false,
      expiresAt: this.getExpiry(),
    });

    // -----------------------------
    // 3. GENERATE TOKENS (WITH JTI)
    // -----------------------------
    const tokens = this.tokensService.generateTokens(
      user.id,
      session.id,
      0,
      user.role,
    );

    // -----------------------------
    // 4. BUILD FINGERPRINT
    // -----------------------------
    const fingerprint = this.fingerprintService.generate(
      session.id,
      meta.ip,
      meta.userAgent,
    );

    // -----------------------------
    // 5. PERSIST SESSION STATE (CRITICAL FIX)
    // -----------------------------
    await this.sessionsService.update(session.id, {
      fingerprint,

      currentAccessJti: tokens.accessJti,
      currentRefreshJti: tokens.refreshJti,

      refreshTokenHash: await this.passwordService.hash(
        tokens.refreshToken,
      ),
    });

    return {
      sessionId: session.id,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  // --------------------------------------------------
  // REFRESH TOKEN ROTATION (SECURE + JTI SAFE)
  // --------------------------------------------------
  async refresh(req: any) {
    const {
      sessionId,
      version,
      refreshToken,
      userId,
      jti: oldJti,
    } = req.user;

    if (!sessionId || !refreshToken) {
      throw new UnauthorizedException('Invalid refresh request');
    }

    const session = await this.sessionsService.findActive(sessionId);
    if (!session) {
      throw new UnauthorizedException('Session invalid or expired');
    }

    // -----------------------------
    // 1. VERSION CHECK (ANTI-REPLAY)
    // -----------------------------
    if (session.tokenVersion !== version) {
      await this.sessionsService.revoke(sessionId);
      throw new UnauthorizedException('Token reuse detected');
    }

    // -----------------------------
    // 2. REFRESH TOKEN VALIDATION
    // -----------------------------
    const valid = await this.passwordService.compare(
      refreshToken,
      session.refreshTokenHash,
    );

    if (!valid) {
      await this.sessionsService.revoke(sessionId);
      throw new UnauthorizedException('Invalid refresh token');
    }

    // -----------------------------
    // 3. ROTATE VERSION + JTI
    // -----------------------------
    const newVersion = version + 1;

    // Re-read the role so a rotated access token keeps correct authorization.
    const owner = await this.usersService.findById(userId);

    const tokens = this.tokensService.generateTokens(
      userId,
      sessionId,
      newVersion,
      owner?.role ?? 'user',
    );

    const newHash = await this.passwordService.hash(tokens.refreshToken);

    // -----------------------------
    // 4. ATOMIC SESSION UPDATE (IMPORTANT FIX)
    // -----------------------------
    const success = await this.sessionsService.rotateRefreshToken(
      sessionId,
      version,
      newVersion,
      newHash,
      tokens.refreshJti,
    );

    if (!success) {
      await this.sessionsService.revoke(sessionId);
      throw new UnauthorizedException('Refresh race detected');
    }

    // -----------------------------
    // 5. UPDATE ACCESS JTI (CRITICAL FIX)
    // -----------------------------
    await this.sessionsService.update(sessionId, {
      currentAccessJti: tokens.accessJti,
    });

    return tokens;
  }

  // --------------------------------------------------
  // LOGOUT
  // --------------------------------------------------
  async logout(sessionId: string) {
    await this.sessionsService.revoke(sessionId);

    return {
      success: true,
      message: 'Session revoked',
    };
  }

  // --------------------------------------------------
  // LOGOUT ALL
  // --------------------------------------------------
  async logoutAll(userId: string) {
    await this.sessionsService.revokeAll(userId);

    return {
      success: true,
      message: 'All sessions revoked',
    };
  }

  // --------------------------------------------------
  // MFA ENROLLMENT
  // --------------------------------------------------
  async setupMfa(userId: string) {
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException();

    const secret = this.mfaService.generateSecret();
    // Store the secret but keep MFA disabled until the user proves they can
    // generate a valid code (enable step).
    await this.usersService.update(userId, { mfaSecret: secret, mfaEnabled: false });

    return { secret, otpauthUrl: this.mfaService.keyUri(user.email, secret) };
  }

  async enableMfa(userId: string, code: string) {
    const user = await this.usersService.findById(userId);
    if (!user?.mfaSecret) {
      throw new BadRequestException('Call /auth/mfa/setup first');
    }
    if (!this.mfaService.verify(code, user.mfaSecret)) {
      throw new UnauthorizedException('Invalid MFA code');
    }
    await this.usersService.update(userId, { mfaEnabled: true });
    await this.securityEvents.record({
      type: SecurityEventType.MFA_ENABLED,
      severity: 'LOW',
      userId,
      detail: {},
    });
    return { enabled: true };
  }

  async disableMfa(userId: string, code: string) {
    const user = await this.usersService.findById(userId);
    if (!user?.mfaEnabled || !user.mfaSecret) return { enabled: false };
    if (!this.mfaService.verify(code, user.mfaSecret)) {
      throw new UnauthorizedException('Invalid MFA code');
    }
    await this.usersService.update(userId, { mfaEnabled: false, mfaSecret: null });
    return { enabled: false };
  }

  // --------------------------------------------------
  // META HELPERS
  // --------------------------------------------------
  private extractMeta(req: any) {
    const headerIp = this.firstHeaderIp(req.headers?.['x-forwarded-for']);
    const socketIp = req.socket?.remoteAddress || req.ip || 'unknown';
    const rawIp = headerIp || socketIp;

    return {
      ip: this.resolveGeoIp(rawIp),
      userAgent: req.headers['user-agent'] || 'unknown',
    };
  }

  private firstHeaderIp(value: string | string[] | undefined): string | undefined {
    const raw = Array.isArray(value) ? value[0] : value;
    return raw?.split(',')[0]?.trim() || undefined;
  }

  /**
   * Local browser logins arrive as ::1 / 127.0.0.1, which cannot be GeoIP
   * resolved. For the lab UI, map loopback traffic to a deterministic demo IP
   * so sessions still get country/city/lat/lon in development.
   *
   * Set LOCAL_DEV_GEO_IP to change the local demo origin, or set it to an
   * empty value in production-like runs where localhost should remain local.
   */
  private resolveGeoIp(ip: string): string {
    const clean = ip.replace(/^::ffff:/, '');
    const isLoopback = clean === '::1' || clean === '127.0.0.1' || clean === 'localhost';

    if (isLoopback && process.env.NODE_ENV !== 'production') {
      return process.env.LOCAL_DEV_GEO_IP || '8.8.8.8';
    }

    return clean;
  }

  private getExpiry() {
    return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  }
}