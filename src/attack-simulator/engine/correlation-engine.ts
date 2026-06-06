import { type SocEvent } from './event-bus';
import { StateStore } from './state-store';
import { type CorrelationAlert as Alert } from '../schemas';

export type { Alert };

export class CorrelationEngine {
  private store = new StateStore();

  constructor(private events: SocEvent[]) {}

  build() {
    for (const e of this.events) {
      this.store.ingest(e);
    }

    return this.store.all().map(state => this.analyze(state.ip));
  }

  private analyze(ip: string): Alert {
    const state = this.store.get(ip);

    if (!state) {
      return {
        ip,
        severity: 'LOW',
        confidence: 0,
        sequence: [],
      };
    }

    const sequence = state.events.map(e => e.classification);

    const score = state.score;

    return {
      ip,
      severity: this.toSeverity(score),
      confidence: this.toConfidence(state.events),
      sequence,
    };
  }

  private toSeverity(score: number): Alert['severity'] {
    if (score > 12) return 'HIGH';
    if (score > 6) return 'MEDIUM';
    return 'LOW';
  }

  private toConfidence(events: SocEvent[]): number {
    const anomalies = events.filter(
      e => e.classification === 'AUTH_REJECT' || e.classification === 'RATE_LIMITED'
    ).length;

    return Math.min(1, anomalies / Math.max(events.length, 1));
  }
}