import { IsEmail, IsString, MaxLength, MinLength, IsOptional } from 'class-validator';
import { Transform } from 'class-transformer';

/** Body for POST /auth/login. */
export class LoginDto {
  @Transform(({ value }) => (typeof value === 'string' ? value.toLowerCase().trim() : value))
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  @MaxLength(128)
  password!: string;

  @IsOptional()
  @IsString()
  code?: string;
}
