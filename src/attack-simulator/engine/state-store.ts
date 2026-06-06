import { type SocEvent } from './event-bus';

export type IpState = {
  ip: string;
  events: SocEvent[];
  lastSeen: number;
  score: number;
};

export class StateStore {
  private byIp = new Map<string, IpState>();

  ingest(event: SocEvent) {
    const ip = ('ip' in event && event.ip) ? event.ip : 'SYSTEM';

    if (!this.byIp.has(ip)) {
      this.byIp.set(ip, {
        ip,
        events: [],
        lastSeen: event.timestamp,
        score: 0,
      });
    }

    const state = this.byIp.get(ip)!;

    state.events.push(event);
    state.lastSeen = event.timestamp;

    // simple scoring baseline
    state.score += this.scoreEvent(event);

    this.byIp.set(ip, state);
  }

  private scoreEvent(event: SocEvent): number {
    if (event.classification === 'AUTH_REJECT') return 2;
    if (event.classification === 'RATE_LIMITED') return 3;
    return 1;
  }

  get(ip: string) {
    return this.byIp.get(ip);
  }

  all() {
    return [...this.byIp.values()];
  }
}