import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { UAParser } from 'ua-parser-js';

@Injectable()
export class SessionFingerprintService {

  generate(sessionId: string, ip: string, userAgent: string): string {
    const ua = new UAParser(userAgent).getResult();

    const normalized = {
      sessionId,
      ip,
      os: ua.os.name || 'unknown',
      browser: ua.browser.name || 'unknown',
      device: ua.device.type || 'desktop',
    };

    return this.hash(normalized);
  }

  private hash(payload: any): string {
    return createHash('sha256')
      .update(JSON.stringify(payload))
      .digest('hex');
  }
}