import { Injectable } from '@nestjs/common';
import * as geoip from 'geoip-lite';

export type GeoInfo = {
  country?: string;
  city?: string;
  lat?: number;
  lon?: number;
};

@Injectable()
export class GeoService {
  /**
   * Resolve a public IP to an approximate location. Private / loopback IPs and
   * anything the database can't place return an empty object, so local traffic
   * never produces phantom geo or false "impossible travel" alerts.
   */
  lookup(ip?: string | null): GeoInfo {
    if (!ip) return {};
    const clean = ip.replace(/^::ffff:/, '');
    const hit = geoip.lookup(clean);
    if (!hit) return {};
    const [lat, lon] = hit.ll || [null, null];
    return {
      country: hit.country || undefined,
      city: hit.city || undefined,
      lat: typeof lat === 'number' ? lat : undefined,
      lon: typeof lon === 'number' ? lon : undefined,
    };
  }

  /** Great-circle distance in km between two coordinates (haversine). */
  distanceKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
    const R = 6371;
    const toRad = (d: number) => (d * Math.PI) / 180;
    const dLat = toRad(lat2 - lat1);
    const dLon = toRad(lon2 - lon1);
    const a =
      Math.sin(dLat / 2) ** 2 +
      Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
    return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  }
}
