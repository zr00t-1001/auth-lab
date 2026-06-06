import { Module } from '@nestjs/common';
import { UsersModule } from '../users/users.module';
import { SecurityModule } from '../security/security.module';
import { SeederService } from './seeder.service';

@Module({
  imports: [UsersModule, SecurityModule],
  providers: [SeederService],
})
export class SeederModule {}
