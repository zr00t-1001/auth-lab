import {
  type SocEvent,
  type NetworkEvent,
  type SystemEvent,
  type Classification,
  type SocEventType,
} from '../schemas';

let counter = 0;

/** Deterministic-ish uuid that still satisfies the schema's uuid() check. */
function uuid(): string {
  counter += 1;
  const n = counter.toString(16).padStart(12, '0');
  return `00000000-0000-4000-8000-${n}`;
}

export function networkEvent(
  over: Partial<NetworkEvent> & {
    scenario: string;
    classification: Classification;
    ip: string;
  },
): NetworkEvent {
  return {
    id: uuid(),
    timestamp: over.timestamp ?? Date.now(),
    scenario: over.scenario,
    type: over.type ?? ('SESSION_GET' as SocEventType),
    status: over.status ?? 403,
    layer: over.layer ?? 'SESSION',
    classification: over.classification,
    ip: over.ip,
    userAgent: over.userAgent ?? 'test-agent',
    message: over.message,
  };
}

export function systemEvent(
  over: Partial<SystemEvent> & {
    scenario: string;
    classification: Classification;
  },
): SystemEvent {
  return {
    id: uuid(),
    timestamp: over.timestamp ?? Date.now(),
    scenario: over.scenario,
    type: over.type ?? ('REFRESH' as SocEventType),
    status: over.status ?? 401,
    layer: over.layer ?? 'AUTH',
    classification: over.classification,
    message: over.message,
  };
}

export function events(...e: SocEvent[]): SocEvent[] {
  return e;
}
