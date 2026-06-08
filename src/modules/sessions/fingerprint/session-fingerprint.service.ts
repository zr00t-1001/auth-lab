import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { UAParser } from 'ua-parser-js';

@Injectable()
export class SessionFingerprintService {

  generate(sessionId: string, ip: string, userAgent: string): string {
    const ua = new UAParser(userAgent).getResult();

    // NOTE: the client IP is deliberately NOT part of the binding. IPs change
    // for legitimate reasons (mobile networks, Wi-Fi switching, and on
    // localhost/Docker the server sees ::1 and 127.0.0.1 interchangeably),
    // which would revoke healthy sessions. Binding is to the stable device
    // fingerprint; the IP is still stored on the session and drives GeoIP /
    // impossible-travel detection separately.
    void ip;
    const normalized = {
      sessionId,
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