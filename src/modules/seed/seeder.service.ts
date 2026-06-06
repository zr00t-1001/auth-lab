import { Injectable, OnApplicationBootstrap, Logger } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/users.entity';
import { PasswordService } from '../security/services/password.service';

/**
 * Seeds a ready-to-use admin + victim on first boot when SEED_ON_BOOT=true
 * (set in docker-compose). Makes the project download-and-run: bring the stack
 * up and log straight in as admin@test.com — no manual SQL needed. Idempotent:
 * skips users that already exist.
 */
@Injectable()
export class SeederService implements OnApplicationBootstrap {
  private readonly log = new Logger('Seeder');

  constructor(
    private readonly users: UsersService,
    private readonly passwords: PasswordService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    if (process.env.SEED_ON_BOOT !== 'true') return;

    await this.ensure(
      process.env.SEED_ADMIN_EMAIL ?? 'admin@test.com',
      process.env.SEED_ADMIN_PASSWORD ?? 'admin12345',
      UserRole.ADMIN,
    );
    await this.ensure(
      process.env.SEED_VICTIM_EMAIL ?? 'test@test.com',
      process.env.SEED_VICTIM_PASSWORD ?? '12345678',
      UserRole.USER,
    );
  }

  private async ensure(
    email: string,
    password: string,
    role: UserRole,
  ): Promise<void> {
    const existing = await this.users.findByEmail(email);
    if (existing) {
      this.log.log(`exists: ${email} (${existing.role})`);
      return;
    }
    const passwordHash = await this.passwords.hash(password);
    await this.users.create({ email, passwordHash, role });
    this.log.log(`seeded ${role}: ${email} / ${password}`);
  }
}
