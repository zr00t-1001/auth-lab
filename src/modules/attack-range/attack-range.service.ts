import { Injectable } from '@nestjs/common';
import { SCENARIOS } from 'src/attack-simulator/registry';
import { runScenarios } from 'src/attack-simulator/runner';
import { getSourceIp, setSourceIp } from 'src/attack-simulator/core/http';
import { SimConfigSchema, type ScenarioReport } from 'src/attack-simulator/schemas';
import { SecurityEventService } from '../security/events/security-event.service';
import { SecurityEventType } from '../security/events/security-event.entity';

export type LaunchAttackInput = {
  scenario?: string;
  target: string;
  operatorUserId?: string;
  email?: string;
  password?: string;
  sourceIp?: string;
};

@Injectable()
export class AttackRangeService {
  constructor(private readonly events: SecurityEventService) {}

  listScenarios() {
    return SCENARIOS.map(({ key, label, description }) => ({ key, label, description }));
  }

  async launch(input: LaunchAttackInput): Promise<ScenarioReport> {
    // The IP the simulated attacker presents (drives geo + IP on the feed).
    setSourceIp(input.sourceIp);
    const scenarios = input.scenario && input.scenario !== 'all' ? [input.scenario] : [];
    const report = await runScenarios(
      SimConfigSchema.parse({
        target: input.target,
        scenarios,
        email: input.email,
        password: input.password,
      }),
    );

    await this.mirrorReportToSecurityFeed(report, input.operatorUserId);
    return report;
  }

  private async mirrorReportToSecurityFeed(report: ScenarioReport, operatorUserId?: string) {
    const blocked = report.events.filter((e) =>
      ['AUTH_REJECT', 'BLOCKED', 'RATE_LIMITED'].includes(e.classification),
    );

    const eventsToMirror = blocked.length ? blocked : report.events.slice(0, 1);

    for (const event of eventsToMirror.slice(0, 8)) {
      await this.events.record({
        type: this.toSecurityEventType(event.scenario, event.classification),
        severity: event.classification === 'ALLOW' ? 'LOW' : 'HIGH',
        userId: operatorUserId,
        ip: event.ip ?? getSourceIp(),
        userAgent: event.userAgent ?? 'axios/auth-lab-simulator',
        detail: {
          source: 'attack-range',
          scenario: event.scenario,
          simulatorEvent: event.type,
          status: event.status,
          classification: event.classification,
          message: event.message,
        },
      });
    }
  }

  private toSecurityEventType(scenario: string, classification: string): SecurityEventType {
    if (scenario === 'TOKEN_REUSE') return SecurityEventType.REFRESH_REUSE;
    if (scenario === 'REFRESH_RACE') return SecurityEventType.REFRESH_RACE;
    if (scenario === 'BRUTE_FORCE') return SecurityEventType.ACCOUNT_LOCKED;
    if (scenario === 'JWT_TAMPER') return SecurityEventType.JWT_TAMPER;
    if (scenario === 'FINGERPRINT_SPOOF') return SecurityEventType.BINDING_VIOLATION;
    if (scenario === 'SESSION_HIJACK') return SecurityEventType.BINDING_VIOLATION;
    return classification === 'RATE_LIMITED'
      ? SecurityEventType.ACCOUNT_LOCKED
      : SecurityEventType.HIGH_RISK_BLOCK;
  }
}
