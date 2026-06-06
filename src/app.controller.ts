import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  // Lightweight liveness probe — useful for Docker/CI healthchecks.
  @Get('health')
  health() {
    return {
      status: 'ok',
      uptime: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
    };
  }
}