import { EventBus } from './event-bus';

export class AttackEngine {
  constructor(private bus: EventBus) {}

  async execute(event: any) {
    this.bus.emit({
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      scenario: event.type,
      type: event.type,

      status: event.status ?? 0,
      layer: 'SESSION',
      classification: 'UNKNOWN',

      ip: event.meta?.ip,
      userAgent: event.meta?.userAgent,

      message: event.message ?? 'OK',
    });
  }
}