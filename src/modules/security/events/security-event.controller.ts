import { Controller, Get, Query, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/modules/users/guards/roles.guard';
import { Roles } from 'src/common/decorators/roles.decorator';
import { SecurityEventService } from './security-event.service';
import { QueryEventsDto } from './dto/query-events.dto';

@Controller('security/events')
@UseGuards(JwtAuthGuard)
export class SecurityEventController {
  constructor(private readonly events: SecurityEventService) {}

  /** Return the authenticated user's own security events (newest first). */
  @Get()
  async list(@Req() req: any, @Query() query: QueryEventsDto) {
    return this.events.findForUser(req.user.userId, {
      type: query.type,
      limit: query.limit,
      offset: query.offset,
    });
  }

  /** Admin-only: every user's security events. Demonstrates RBAC. */
  @Get('all')
  @UseGuards(RolesGuard)
  @Roles('admin')
  async listAll(@Query() query: QueryEventsDto) {
    return this.events.findAll({
      type: query.type,
      limit: query.limit,
      offset: query.offset,
    });
  }
}
