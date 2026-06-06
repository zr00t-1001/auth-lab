import { Module } from '@nestjs/common';
import { SessionFingerprintService } from './session-fingerprint.service';

@Module({
  providers: [SessionFingerprintService],
  exports: [SessionFingerprintService],
})
export class FingerprintModule {}