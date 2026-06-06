import { SetMetadata } from '@nestjs/common';

/**
 * Marks a route as requiring one of the given roles. Read by RolesGuard.
 * Usage: `@Roles('admin')`
 */
export const ROLES_KEY = 'roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);
