import { SocEvent } from './event-bus';
import { TimeWindow } from './time-window';
import { type Alert } from '../schemas';

export type { Alert };

export class RuleEngine {
  private window: TimeWindow;

  constructor(private events: SocEvent[]) {
    this.window = new TimeWindow(events);
  }

  run(): Alert[] {
    const recent = this.window.within(10_000); // 🔥 10s behavioral window
    const alerts: Alert[] = [];

    alerts.push(...this.rateLimitBurst(recent));
    alerts.push(...this.multiIpCampaign(recent));

    return alerts;
  }

  // --------------------------------------------------
  // RULE 1: RATE LIMIT BURST
  // --------------------------------------------------
  private rateLimitBurst(events: SocEvent[]): Alert[] {
    const rateLimited = events.filter(e => e.classification === 'RATE_LIMITED');

    if (rateLimited.length >= 5) {
      return [
        {
          rule: 'RATE_LIMIT_BURST',
          severity: 'MEDIUM',
          confidence: Math.min(0.9, rateLimited.length / 10),
          ip: 'GLOBAL',
          description: 'High frequency rate limiting detected',
        },
      ];
    }

    return [];
  }

  // --------------------------------------------------
  // RULE 2: MULTI-IP CAMPAIGN (hardened)
  // --------------------------------------------------
  private multiIpCampaign(events: SocEvent[]): Alert[] {
    const ips = new Set(events.map(e => e.ip).filter(Boolean));

    const authRejects = events.filter(
      e => e.classification === 'AUTH_REJECT'
    );

    const diversity = ips.size;
    const pressure = authRejects.length;

    if (diversity >= 3 && pressure >= 5) {
      return [
        {
          rule: 'MULTI_IP_CAMPAIGN',
          severity: 'HIGH',
          confidence: Math.min(0.95, (diversity + pressure) / 20),
          ip: 'GLOBAL',
          description: 'Coordinated multi-IP authentication attack detected',
        },
      ];
    }

    return [];
  }
}