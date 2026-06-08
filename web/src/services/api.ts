// ---------------------------------------------------------------------------
// Centralized API layer for the dashboard.
//
// Every network call to the auth-lab backend goes through here: base URL,
// token storage, an authenticated fetch that transparently refreshes the
// access token, and small typed helpers grouped by domain (auth, sessions,
// events, attack-range). UI code never builds URLs or attaches tokens itself.
// ---------------------------------------------------------------------------

export type Tokens = { sessionId?: string; accessToken: string; refreshToken: string };

export const API = (
  (typeof document !== 'undefined' && document.body?.dataset.api) ||
  (import.meta as any).env?.PUBLIC_API_URL ||
  'http://localhost:3000'
).replace(/\/$/, '');

// ---- token storage ----
const KEY = 'authlab.tokens';
export const loadTokens = (): Tokens | null => {
  try { return JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { return null; }
};
export const saveTokens = (t: Tokens) => localStorage.setItem(KEY, JSON.stringify(t));
export const clearTokens = () => localStorage.removeItem(KEY);

// Refresh the access token once, using the stored refresh token.
// Returns true on success (new tokens saved), false otherwise.
async function tryRefresh(): Promise<boolean> {
  const t = loadTokens();
  if (!t?.refreshToken) return false;
  try {
    const res = await fetch(API + '/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: t.refreshToken }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    if (!data?.accessToken || !data?.refreshToken) return false;
    // sessionId is stable across refreshes, so keep the stored one.
    saveTokens({ sessionId: t.sessionId, accessToken: data.accessToken, refreshToken: data.refreshToken });
    return true;
  } catch {
    return false;
  }
}

// Authenticated fetch. On 401 it silently refreshes the access token once and
// retries the request; only if the refresh ALSO fails does it clear the tokens
// and call onAuthLost. This is why an active operator (admin or user) is not
// kicked out when the short-lived access token expires — the session stays
// alive for as long as the refresh token is valid.
export async function apiFetch(
  path: string,
  init: RequestInit = {},
  onAuthLost?: () => void,
): Promise<Response> {
  const build = (): RequestInit => {
    const t = loadTokens();
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(init.headers as Record<string, string>),
    };
    if (t?.accessToken) headers.Authorization = `Bearer ${t.accessToken}`;
    return { ...init, headers };
  };

  let res = await fetch(API + path, build());

  if (res.status === 401 && path !== '/auth/refresh') {
    const refreshed = await tryRefresh();
    if (refreshed) res = await fetch(API + path, build());
    if (res.status === 401) {
      clearTokens();
      onAuthLost?.();
    }
  }
  return res;
}

// ---- typed endpoint helpers (no auth header needed on login/register) ----
const post = (path: string, body: unknown) =>
  fetch(API + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

export const authApi = {
  login: (email: string, password: string, code?: string) => post('/auth/login', { email, password, code }),
  register: (email: string, password: string) => post('/auth/register', { email, password }),
  me: (onAuthLost?: () => void) => apiFetch('/auth/me', {}, onAuthLost),
  logout: (onAuthLost?: () => void) => apiFetch('/auth/logout', { method: 'POST' }, onAuthLost),
  logoutAll: (onAuthLost?: () => void) => apiFetch('/auth/logout-all', { method: 'POST' }, onAuthLost),
  mfaSetup: (o?: () => void) => apiFetch('/auth/mfa/setup', { method: 'POST' }, o),
  mfaEnable: (code: string, o?: () => void) => apiFetch('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) }, o),
  mfaDisable: (code: string, o?: () => void) => apiFetch('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ code }) }, o),
};

export const sessionsApi = {
  mine: (o?: () => void) => apiFetch('/sessions', {}, o),
  all: (o?: () => void) => apiFetch('/sessions/all', {}, o),
};

export const eventsApi = {
  mine: (o?: () => void) => apiFetch('/security/events', {}, o),
  all: (o?: () => void) => apiFetch('/security/events/all', {}, o),
};

export const attackRangeApi = {
  launch: (body: unknown, o?: () => void) => apiFetch('/attack-range/launch', { method: 'POST', body: JSON.stringify(body) }, o),
};
