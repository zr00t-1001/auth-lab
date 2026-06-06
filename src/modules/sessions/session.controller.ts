import { Controller, Get, Delete, Param, UseGuards, Req, Query } from '@nestjs/common';
import { SessionsService } from './sessions.service';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { ZeroTrustGuard } from 'src/modules/auth/guards/zero-trust.guard';
import { SessionBindingGuard } from './guards/session-binding.guard';
import { RolesGuard } from 'src/modules/users/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';

@Controller('sessions')
@UseGuards(JwtAuthGuard)
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  // List the CURRENT user's own sessions (guarded by zero-trust + binding)
  @UseGuards(JwtAuthGuard, ZeroTrustGuard, SessionBindingGuard)
  @Get()
  async getMySessions(@Req() req: any, @Query('enforce') enforce?: string) {
    return this.sessionsService.getUserSessions(
      req.user.userId,
      req.user.sessionId,
      enforce === 'true',
    );
  }

  // ADMIN / SOC: every session in the system, read-only. The admin observes;
  // it does not run zero-trust/binding against the admin's own fingerprint.
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('admin')
  @Get('all')
  async getAllSessions() {
    return this.sessionsService.getAllSessions();
  }

  // Revoke ONE session (logout a specific device)
  @Delete(':sessionId')
  async revokeSession(@Req() req: any, @Param('sessionId') sessionId: string) {
    return this.sessionsService.revokeUserSession(req.user.userId, sessionId);
  }
}