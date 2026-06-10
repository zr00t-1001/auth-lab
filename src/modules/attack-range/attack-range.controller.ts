import { Body, Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { IsOptional, IsString } from 'class-validator';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../users/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AttackRangeService } from './attack-range.service';

class LaunchAttackDto {
  @IsOptional()
  @IsString()
  scenario?: string;

  @IsOptional()
  @IsString()
  email?: string;

  @IsOptional()
  @IsString()
  password?: string;

  @IsOptional()
  @IsString()
  sourceIp?: string;
}

@Controller('attack-range')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin')
export class AttackRangeController {
  constructor(private readonly range: AttackRangeService) {}

  @Get('scenarios')
  scenarios() {
    return this.range.listScenarios();
  }

  @Post('launch')
  launch(@Req() req: any, @Body() dto: LaunchAttackDto) {
    // The simulator runs in-process, inside THIS container, so it must call the
    // API on its local address — not the browser-facing origin. Behind the Caddy
    // TLS proxy, req.protocol/host resolve to https://localhost (port 443), which
    // has no listener inside the container (Caddy is a separate service) → the
    // sim got ECONNREFUSED. Hit the local port directly; override via SIM_TARGET.
    const target =
      process.env.SIM_TARGET ?? `http://127.0.0.1:${process.env.PORT ?? 3000}`;
    return this.range.launch({
      scenario: dto.scenario,
      email: dto.email,
      password: dto.password,
      sourceIp: dto.sourceIp,
      target,
      operatorUserId: req.user?.userId,
    });
  }
}