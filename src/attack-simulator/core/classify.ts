import {
  type SecurityLayer,
  type Classification,
} from '../schemas';

// Types now live in schemas.ts; re-export for existing import sites.
export type { SecurityLayer, Classification };

export function classify(status: number): {
  layer: SecurityLayer;
  classification: Classification;
} {
  if (status >= 200 && status < 300) return { layer: 'AUTH', classification: 'ALLOW' };
  if (status === 401) return { layer: 'AUTH', classification: 'AUTH_REJECT' };
  if (status === 403) return { layer: 'SESSION', classification: 'BLOCKED' };
  if (status === 429) return { layer: 'INFRA', classification: 'RATE_LIMITED' };

  return { layer: 'UNKNOWN', classification: 'UNKNOWN' };
}
