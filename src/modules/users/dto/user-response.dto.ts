import { User, UserRole } from '../users.entity';

/**
 * The canonical PUBLIC shape of a user — what is safe to send to a client.
 * Note what is absent on purpose: passwordHash and mfaSecret never leave the
 * server. Always map a User through toUserResponse() before returning it.
 */
export class UserResponseDto {
  id!: string;
  email!: string;
  role!: UserRole;
  mfaEnabled!: boolean;
  createdAt!: Date;
}

export function toUserResponse(user: User): UserResponseDto {
  return {
    id: user.id,
    email: user.email,
    role: user.role,
    mfaEnabled: user.mfaEnabled,
    createdAt: user.createdAt,
  };
}
