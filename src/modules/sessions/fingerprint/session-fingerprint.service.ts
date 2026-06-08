import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { UAParser } from 'ua-parser-js';

@Injectable()
export class SessionFingerprintService {
  generate(sessionId: string, ip: string, userAgent: string): string {
    const ua = new UAParser(userAgent).getResult();

    // The IP is part of the binding so a token replayed from a different
    // network/device is caught (e.g. the session-hijack scenario). But it is
    // NORMALIZED first: the localhost dual-stack forms (::1, 127.0.0.1) the
    // server sees interchangeably on the same machine collapse to one value,
    // so a benign flip doesn't look like a hijack and revoke a healthy session.
    const normalized = {
      sessionId,
      ip: this.normalizeIp(ip),
      os: ua.os.name || 'unknown',
      browser: ua.browser.name || 'unknown',
      device: ua.device.type || 'desktop',
    };

    return this.hash(normalized);
  }

  private normalizeIp(ip: string): string {
    if (!ip) return 'unknown';
    if (ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') {
      return 'local';
    }
    return ip.replace(/^::ffff:/, '');
  }

  private hash(payload: any): string {
    return createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  }
}