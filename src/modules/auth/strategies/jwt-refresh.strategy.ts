import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(config: ConfigService) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'), // CLEAN + EXPLICIT
      secretOrKey: config.get<string>('JWT_REFRESH_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(req: any, payload: any) {
    const refreshToken = req.body?.refreshToken;

    if (!payload?.sub || !payload?.sid || !refreshToken) {
      throw new UnauthorizedException('Invalid refresh request');
    }

    return {
      userId: payload.sub,
      sessionId: payload.sid,
      version: payload.ver,
      refreshToken,
    };
  }
}