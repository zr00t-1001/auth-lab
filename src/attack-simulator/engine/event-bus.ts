import {
  type SocEvent,
  type SocEventType,
  type NetworkEvent,
  type SystemEvent,
} from '../schemas';

// Re-export the inferred domain types so existing imports keep working,
// but the source of truth is now schemas.ts (Zod).
export type { SocEvent, SocEventType, NetworkEvent, SystemEvent };

export class EventBus {
  private events: SocEvent[] = [];

  emit(event: SocEvent): void {
    this.events.push(event);
  }

  all(): SocEvent[] {
    return this.events;
  }

  clear(): void {
    this.events = [];
  }
}
