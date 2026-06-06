import { Module } from '@nestjs/common';
import { AttackRangeController } from './attack-range.controller';
import { AttackRangeService } from './attack-range.service';
import { SecurityEventsModule } from '../security/events/security-events.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [SecurityEventsModule, UsersModule],
  controllers: [AttackRangeController],
  providers: [AttackRangeService],
})
export class AttackRangeModule {}
