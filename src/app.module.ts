import { AppController } from './app.controller';
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';

import { DatabaseModule } from './infrastructure/db/database.module';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { SecurityEventsModule } from './modules/security/events/security-events.module';
import { AttackRangeModule } from './modules/attack-range/attack-range.module';
import { SeederModule } from './modules/seed/seeder.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),

    // Global rate limit. @nestjs/throttler v6 expects ttl in MILLISECONDS.
    // Login has its own strict @Throttle(3/min); this is the relaxed default
    // for everything else (dashboard reads, etc.) so it doesn't 429.
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60_000, // 60 seconds
          limit: 100, // 100 requests per minute
        },
      ],
    }),

    DatabaseModule,
    UsersModule,
    AuthModule,
    SecurityEventsModule,
    AttackRangeModule,
    SeederModule,
  ],

  // ✅ APPLY GLOBALLY
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}