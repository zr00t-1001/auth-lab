import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SecurityEvent } from './security-event.entity';
import { SecurityEventService } from './security-event.service';
import { SecurityEventController } from './security-event.controller';
import { UsersModule } from '../../users/users.module';

@Module({
  imports: [TypeOrmModule.forFeature([SecurityEvent]), UsersModule],
  providers: [SecurityEventService],
  controllers: [SecurityEventController],
  exports: [SecurityEventService],
})
export class SecurityEventsModule {}
