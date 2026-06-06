import { Injectable } from '@nestjs/common';
import { authenticator } from 'otplib';

// Thin wrapper over otplib's TOTP authenticator. The secret is per-user and
// stored on the user row; codes are 6-digit time-based one-time passwords that
// any authenticator app (Google Authenticator, Authy, 1Password…) can produce.
@Injectable()
export class MfaService {
  private readonly issuer = 'auth-lab';

  generateSecret(): string {
    return authenticator.generateSecret();
  }

  /** otpauth:// URI — encode as a QR for the user's authenticator app. */
  keyUri(email: string, secret: string): string {
    return authenticator.keyuri(email, this.issuer, secret);
  }

  verify(token: string, secret: string): boolean {
    try {
      return authenticator.verify({ token: (token ?? '').trim(), secret });
    } catch {
      return false;
    }
  }
}
