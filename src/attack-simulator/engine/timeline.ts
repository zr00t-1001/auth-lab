import { type SocEvent } from './event-bus';

export class Timeline {
  constructor(private events: SocEvent[]) {}

  build() {
    return this.events
      .filter(e => e.scenario === 'SESSION_HIJACK')
      .map((e, i) => ({
        step: i + 1,
        type: e.type,
        status: e.status,
        ip: 'ip' in e ? e.ip : null,
        ua: 'userAgent' in e ? e.userAgent : null,
        result: e.classification,
      }));
  }
}