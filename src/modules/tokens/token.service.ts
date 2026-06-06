import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { randomUUID } from 'crypto';

@Injectable()
export class TokenService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) { }

  generateTokens(
    userId: string,
    sessionId: string,
    version: number,
    role: string = 'user',
  ) {
    const accessJti = randomUUID();
    const refreshJti = randomUUID();

    return {
      accessToken: this.jwtService.sign(
        {
          sub: userId,
          sid: sessionId,
          ver: version,
          jti: accessJti,
          role,
        },
        {
          secret: this.configService.get('JWT_ACCESS_SECRET'),
          expiresIn: '15m',
        },
      ),

      refreshToken: this.jwtService.sign(
        {
          sub: userId,
          sid: sessionId,
          ver: version,
          jti: refreshJti,
        },
        {
          secret: this.configService.get('JWT_REFRESH_SECRET'),
          expiresIn: '7d',
        },
      ),

      accessJti,
      refreshJti,
    };
  }
}