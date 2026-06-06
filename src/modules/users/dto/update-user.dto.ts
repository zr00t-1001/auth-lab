import { IsOptional, IsBoolean, IsEnum } from 'class-validator';
import { UserRole } from '../users.entity';

/**
 * Deliberately narrow. Only these fields may change after a user is created.
 * id, email, passwordHash and createdAt are intentionally NOT updatable here,
 * so a stray `update()` call can never rewrite identity or credentials.
 */
export class UpdateUserDto {
  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @IsOptional()
  @IsBoolean()
  mfaEnabled?: boolean;

  @IsOptional()
  mfaSecret?: string | null;
}
