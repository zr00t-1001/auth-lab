import { IsEmail, IsString, IsOptional, IsEnum } from 'class-validator';
import { UserRole } from '../users.entity';

/**
 * Contract for creating a user. The users layer only ever receives an
 * already-hashed password (argon2) — raw passwords are hashed in the auth
 * layer and never reach here.
 */
export class CreateUserDto {
  @IsEmail()
  email!: string;

  @IsString()
  passwordHash!: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;
}
