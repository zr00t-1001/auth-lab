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
    const protocol = req.protocol ?? 'http';
    const host = req.get?.('host') ?? req.headers.host ?? 'localhost:3000';
    return this.range.launch({
      scenario: dto.scenario,
      email: dto.email,
      password: dto.password,
      sourceIp: dto.sourceIp,
      target: `${protocol}://${host}`,
      operatorUserId: req.user?.userId,
    });
  }
}
