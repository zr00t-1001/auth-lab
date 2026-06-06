import { classify } from '../core/classify';

describe('classify', () => {
  it('maps 2xx to an allowed auth result', () => {
    expect(classify(200)).toEqual({ layer: 'AUTH', classification: 'ALLOW' });
    expect(classify(204)).toEqual({ layer: 'AUTH', classification: 'ALLOW' });
  });

  it('maps 401 to an auth rejection', () => {
    expect(classify(401)).toEqual({
      layer: 'AUTH',
      classification: 'AUTH_REJECT',
    });
  });

  it('maps 403 to a session block', () => {
    expect(classify(403)).toEqual({
      layer: 'SESSION',
      classification: 'BLOCKED',
    });
  });

  it('maps 429 to rate limiting at the infra layer', () => {
    expect(classify(429)).toEqual({
      layer: 'INFRA',
      classification: 'RATE_LIMITED',
    });
  });

  it('falls back to UNKNOWN for unhandled statuses', () => {
    expect(classify(500)).toEqual({
      layer: 'UNKNOWN',
      classification: 'UNKNOWN',
    });
    expect(classify(0)).toEqual({ layer: 'UNKNOWN', classification: 'UNKNOWN' });
  });
});
