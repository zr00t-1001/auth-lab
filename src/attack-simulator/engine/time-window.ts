import { SocEvent } from './event-bus';

export class TimeWindow {
  constructor(private events: SocEvent[]) {}

  within(ms: number): SocEvent[] {
    const now = Date.now();
    return this.events.filter(e => now - e.timestamp <= ms);
  }

  between(start: number, end: number): SocEvent[] {
    return this.events.filter(e => e.timestamp >= start && e.timestamp <= end);
  }
}