import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(configService: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  async validate(payload: any) {
    return {
      userId: payload.sub,
      sessionId: payload.sid,
      version: payload.ver,
      // Needed by SessionBindingGuard's token-replay (JTI) check; without it
      // that protection silently never fires.
      jti: payload.jti,
      // Used by RolesGuard for authorization checks.
      role: payload.role ?? 'user',
    };
  }
}