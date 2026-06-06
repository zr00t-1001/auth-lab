import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Session } from './session.entity';

import { SessionsService } from './sessions.service';
import { SessionsController } from './session.controller';

import { FingerprintModule } from './fingerprint/fingerprint.module';
import { SessionSecurityEngine } from './security/session-security.engine';
import { GeoService } from './security/geo.service';
import { SecurityEventsModule } from '../security/events/security-events.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Session]),
    FingerprintModule,
    SecurityEventsModule,
    UsersModule,
  ],
  providers: [
    SessionsService,
    SessionSecurityEngine,
    GeoService,
  ],
  controllers: [
    SessionsController,
  ],
  exports: [
    SessionsService,
    SessionSecurityEngine,
  ],
})
export class SessionsModule {}