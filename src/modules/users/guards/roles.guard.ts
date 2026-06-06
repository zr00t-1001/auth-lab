import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { UsersService } from '../users.service';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private usersService: UsersService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const requiredRoles = this.reflector.get<string[]>(
      'roles',
      context.getHandler(),
    );

    if (!requiredRoles) return true;

    const { user } = context.switchToHttp().getRequest();
    if (!user || !requiredRoles.includes(user.role)) return false;

    // Admin accounts hold the keys to the whole system (all sessions, all
    // events, the attack range). They MUST have a second factor enabled.
    // Fresh DB read so that enabling MFA takes effect on the very next request
    // (no waiting for the 15-minute access token to expire).
    if (user.role === 'admin') {
      const record = await this.usersService.findById(user.userId);
      if (!record?.mfaEnabled) {
        throw new ForbiddenException(
          'Admin accounts must enable MFA before accessing this resource',
        );
      }
    }

    return true;
  }
}
