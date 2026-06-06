import { GeoService } from './geo.service';
import { SessionsService } from '../sessions.service';
import { SecurityEventType } from '../../security/events/security-event.entity';

describe('GeoService.distanceKm', () => {
  const geo = new GeoService();

  it('is zero for identical points', () => {
    expect(geo.distanceKm(40, -74, 40, -74)).toBe(0);
  });

  it('roughly matches a known long distance (Tokyo to NYC ~10800km)', () => {
    const km = geo.distanceKm(35.68, 139.69, 40.71, -74.01);
    expect(km).toBeGreaterThan(10000);
    expect(km).toBeLessThan(11500);
  });
});

describe('SessionsService impossible-travel detection', () => {
  function build(prior: any) {
    const records: any[] = [];
    const repo: any = {
      create: (x: any) => x,
      save: async (x: any) => x,
      findOne: async () => prior,
    };
    const engine: any = {};
    const events: any = { record: async (e: any) => { records.push(e); } };
    const svc = new SessionsService(repo, engine, events, new GeoService());
    return { svc, records };
  }

  it('flags a far login moments after a distant one', async () => {
    // prior login in Tokyo, just now; new login resolves to the US (8.8.8.8)
    const prior = { userId: 'u1', lat: 35.68, lon: 139.69, country: 'JP', createdAt: new Date() };
    const { svc, records } = build(prior);
    await svc.create({ userId: 'u1', ipAddress: '8.8.8.8' });
    expect(records.some((r) => r.type === SecurityEventType.IMPOSSIBLE_TRAVEL)).toBe(true);
  });

  it('does not flag when the prior session has no geo', async () => {
    const prior = { userId: 'u1', lat: null, lon: null, createdAt: new Date() };
    const { svc, records } = build(prior);
    await svc.create({ userId: 'u1', ipAddress: '8.8.8.8' });
    expect(records.length).toBe(0);
  });
});
