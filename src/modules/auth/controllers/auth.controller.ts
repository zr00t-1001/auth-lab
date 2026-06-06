import { Controller, Post, Get, Body, Req, UseGuards } from '@nestjs/common';
import { AuthService } from '../services/auth.service';

import { LoginDto } from '../dto/login.dto';
import { RegisterDto } from '../dto/register.dto';
import { MfaCodeDto } from '../dto/mfa-code.dto';

import { RefreshTokenGuard } from '../guards/refresh-guard';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { Throttle } from '@nestjs/throttler';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto.email, dto.password);
  }

  @Throttle({ default: { limit: 3, ttl: 60_000 } })
  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: any) {
    return this.authService.login(dto.email, dto.password, req, dto.code);
  }

  // ---- MFA enrollment (must be logged in) ----
  @UseGuards(JwtAuthGuard)
  @Post('mfa/setup')
  mfaSetup(@Req() req: any) {
    return this.authService.setupMfa(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/enable')
  mfaEnable(@Req() req: any, @Body() dto: MfaCodeDto) {
    return this.authService.enableMfa(req.user.userId, dto.code);
  }

  @UseGuards(JwtAuthGuard)
  @Post('mfa/disable')
  mfaDisable(@Req() req: any, @Body() dto: MfaCodeDto) {
    return this.authService.disableMfa(req.user.userId, dto.code);
  }

  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  refresh(@Req() req: any) {
    return this.authService.refresh(req);
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: any) {
    return this.authService.me(req.user.userId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  logout(@Req() req: any) {
    return this.authService.logout(req.user.sessionId);
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout-all')
  logoutAll(@Req() req: any) {
    return this.authService.logoutAll(req.user.userId);
  }
}