// Pure formatting helpers — no DOM, no state, no I/O.

export const riskClass = (lvl?: string) =>
  ({ TRUSTED: 'lv-ok', LOW_RISK: 'lv-low', SUSPICIOUS: 'lv-warn', HIGH_RISK: 'lv-crit' } as Record<string, string>)[lvl ?? ''] || '';

export const sevClass = (s?: string) =>
  ({ LOW: 'lv-low', MEDIUM: 'lv-warn', HIGH: 'lv-crit' } as Record<string, string>)[s ?? ''] || '';

export const fmtLoc = (country?: string, city?: string): string =>
  city && country ? city + ', ' + country : country || '—';