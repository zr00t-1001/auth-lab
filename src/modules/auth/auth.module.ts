import { Module } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';

import { UsersModule } from '../users/users.module';
import { SessionsModule } from '../sessions/sessions.module';
import { TokensModule } from '../tokens/tokens.module';
import { SecurityModule } from '../security/security.module';
import { SecurityEventsModule } from '../security/events/security-events.module';
import { FingerprintModule } from '../sessions/fingerprint/fingerprint.module';

import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { RefreshTokenGuard } from './guards/refresh-guard';

import { JwtStrategy } from './strategies/jwt.strategy';
import { LoginAttemptService } from './services/login-attempt.service';
import { MfaService } from './services/mfa.service';

@Module({
  imports: [
    UsersModule,
    SessionsModule,
    TokensModule,
    SecurityModule,
    SecurityEventsModule,
    FingerprintModule,
    ConfigModule,

    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.get<string>('JWT_ACCESS_SECRET'),
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtRefreshStrategy, RefreshTokenGuard, JwtStrategy, LoginAttemptService, MfaService],
})
export class AuthModule {}
