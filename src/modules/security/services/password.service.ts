import { Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';

@Injectable()
export class PasswordService {
  // argon2id with OWASP-recommended minimums (memory-hard, GPU-resistant).
  private readonly options: argon2.Options = {
    type: argon2.argon2id,
    memoryCost: 19456, // 19 MiB
    timeCost: 2,
    parallelism: 1,
  };

  async hash(secret: string): Promise<string> {
    return argon2.hash(secret, this.options);
  }

  // Keeps the existing (plain, hash) call order used across the codebase;
  // internally maps to argon2.verify(hash, plain). Returns false on malformed
  // hashes instead of throwing.
  async compare(secret: string, hash: string): Promise<boolean> {
    try {
      return await argon2.verify(hash, secret);
    } catch {
      return false;
    }
  }
}