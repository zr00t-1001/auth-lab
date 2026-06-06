/**
 * Best-effort, dependency-free User-Agent → human label.
 * Not a full UA database — just enough to turn "Unknown device" into something
 * readable in the sessions list (browser + OS, or "API client" for tooling).
 */
export type DeviceInfo = { label: string; browser?: string; os?: string };

export function deviceLabel(userAgent?: string | null): DeviceInfo {
  const ua = (userAgent ?? '').trim();
  if (!ua) return { label: 'Unknown client' };

  // Non-browser clients (the attack simulator, curl, Postman, etc.)
  if (/axios|node-fetch|undici|got\//i.test(ua)) return { label: 'API client', browser: 'axios' };
  if (/curl/i.test(ua)) return { label: 'curl', browser: 'curl' };
  if (/PostmanRuntime/i.test(ua)) return { label: 'Postman', browser: 'Postman' };

  const browser =
    /\bEdg\b|Edge/i.test(ua) ? 'Edge'
    : /OPR\/|Opera/i.test(ua) ? 'Opera'
    : /Firefox/i.test(ua) ? 'Firefox'
    : /Chrome|CriOS/i.test(ua) ? 'Chrome'
    : /Safari/i.test(ua) ? 'Safari'
    : undefined;

  const os =
    /Windows/i.test(ua) ? 'Windows'
    : /Macintosh|Mac OS X/i.test(ua) ? 'macOS'
    : /Android/i.test(ua) ? 'Android'
    : /iPhone|iPad|iOS/i.test(ua) ? 'iOS'
    : /Linux/i.test(ua) ? 'Linux'
    : undefined;

  const label =
    browser && os ? `${browser} on ${os}`
    : browser ? browser
    : os ? os
    : 'Unknown client';

  return { label, browser, os };
}

/** Make loopback addresses readable in the UI. */
export function prettyIp(ip?: string | null): string | undefined {
  if (!ip) return ip ?? undefined;
  if (ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') {
    return 'localhost';
  }
  // IPv4 mapped in IPv6 form: ::ffff:185.12.44.10 -> 185.12.44.10
  return ip.replace(/^::ffff:/, '');
}
