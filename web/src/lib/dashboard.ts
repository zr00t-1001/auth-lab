      import QRCode from 'qrcode';
      import { API, loadTokens as load, saveTokens as save, clearTokens as clear, apiFetch, authApi } from '../services/api';
      import { els, esc, setStatus, setConn } from './dom';
      import { riskClass, sevClass, fmtLoc } from './format';
      type Tokens = { sessionId?: string; accessToken: string; refreshToken: string };
      type Risk = { level: string; score: number };
      type SessionRow = {
        id: string; userId?: string; deviceName?: string; browser?: string; os?: string;
        ipAddress?: string; createdAt?: string; expiresAt?: string; revoked?: boolean;
        state?: string; risk?: Risk; isCurrent?: boolean; isSuspicious?: boolean;
        country?: string; city?: string; lat?: number; lon?: number;
      };
      type SecurityEvent = {
        id?: string; userId?: string; type: string; severity?: string;
        ip?: string; userAgent?: string; createdAt?: string;
      };
      type AlertLike = { id?: string; type: string; severity?: string; ip?: string };
      type Account = { id: string; email: string; role: string; mfaEnabled: boolean; createdAt?: string };

      

      els.target.textContent = 'SRV ' + (API ? API.replace(/^https?:\/\//, '') : location.host);

      // Thin wrapper over the services layer. apiFetch attaches the token and,
      // on 401, silently refreshes + retries before giving up — so an active
      // operator is not logged out when the short access token expires.
      async function api(path: string, init: RequestInit = {}): Promise<Response> {
        const res = await apiFetch(path, init, () => showLogin('SESSION EXPIRED — re-authenticate'));
        setConn(true);
        return res;
      }

      function showLogin(msg = '') {
        stopPolling();
        seenEventIds = null;
        account = null; mfaSetup = null;
        if (els.mfaPanel) els.mfaPanel.hidden = true;
        mfaGated = false;
        if (els.mfaGate) els.mfaGate.hidden = true;
        els.mfaRow.hidden = true; els.mfaCode.value = '';
        els.app.hidden = true;
        els.login.hidden = false;
        els.loginMsg.textContent = msg;
        els.loginMsg.className = 'msg' + (msg ? ' err' : '');
      }
      function showApp() {
        els.login.hidden = true;
        els.app.hidden = false;
        initAudio();
        requestNotify();
        loadMe();
        startPolling();
      }


      // ── LOGIN ────────────────────────────────────────────────
      async function login() {
        els.loginBtn.disabled = true;
        els.loginMsg.className = 'msg';
        els.loginMsg.textContent = 'AUTHENTICATING…';
        try {
          const res = await authApi.login(els.email.value, els.password.value, els.mfaCode.value || undefined);
          setConn(true);
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data?.message || `HTTP ${res.status}`);
          if (data?.mfaRequired) {
            els.mfaRow.hidden = false;
            els.mfaCode.focus();
            els.loginMsg.className = 'msg';
            els.loginMsg.textContent = 'MFA REQUIRED // enter your 6-digit code';
            return;
          }
          save({ sessionId: data.sessionId, accessToken: data.accessToken, refreshToken: data.refreshToken });
          isAdmin = decodeRole(data.accessToken) === 'admin';
          els.who.textContent = els.email.value + ' // SID ' + String(data.sessionId ?? '').slice(0, 8) + (isAdmin ? ' // ADMIN·SOC' : '');
          applyMode();
          showApp();
          await refresh();
        } catch (e: any) {
          setConn(/Failed to fetch/i.test(e?.message) ? false : true);
          els.loginMsg.className = 'msg err';
          els.loginMsg.textContent = 'DENIED // ' + (e?.message || 'unknown error');
        } finally {
          els.loginBtn.disabled = false;
        }
      }

      // ── REGISTER (then auto-login) ───────────────────────────
      async function register() {
        els.registerBtn.disabled = true;
        els.loginMsg.className = 'msg';
        els.loginMsg.textContent = 'CREATING ACCOUNT…';
        try {
          const res = await authApi.register(els.email.value, els.password.value);
          setConn(true);
          const data = await res.json().catch(() => ({}));
          // 400 "User already exists" is fine — just proceed to login.
          if (!res.ok && !/exists/i.test(data?.message || '')) {
            throw new Error(data?.message || `HTTP ${res.status}`);
          }
          els.loginMsg.className = 'msg ok';
          els.loginMsg.textContent = 'ACCOUNT READY — logging in…';
          await login();
        } catch (e: any) {
          setConn(/Failed to fetch/i.test(e?.message) ? false : true);
          els.loginMsg.className = 'msg err';
          els.loginMsg.textContent = 'REGISTER FAILED // ' + (e?.message || 'unknown error');
        } finally {
          els.registerBtn.disabled = false;
        }
      }

      // ── DATA ─────────────────────────────────────────────────
      

      // ── ADMIN / SOC MODE ─────────────────────────────────────
      // Admins observe the WHOLE system (all users' sessions + events) as a
      // read-only operator. Regular users see only their own.
      let isAdmin = false;
      function decodeRole(token?: string): string {
        try {
          const part = (token || '').split('.')[1];
          if (!part) return 'user';
          const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'));
          return JSON.parse(json).role || 'user';
        } catch { return 'user'; }
      }
      function applyMode() {
        // SOC monitoring (events feed, alerts, attack range) is an ADMIN function.
        els.attackPanel.hidden = !isAdmin;
        els.evtPanel.hidden = !isAdmin;
        if (isAdmin) {
          els.sessTitle.textContent = '// ALL SESSIONS · SYSTEM';
          els.evtTitle.textContent = '// ALL EVENTS · SYSTEM';
          els.sessHead.innerHTML = '<th>OWNER</th><th>DEVICE</th><th>IP</th><th>LOCATION</th><th>STATE</th><th class="r">CREATED</th>';
          els.evtHead.innerHTML = '<th>OWNER</th><th>TIME</th><th>TYPE</th><th>SEV</th><th>IP</th><th>AGENT</th>';
        } else {
          els.sessTitle.textContent = '// ACTIVE SESSIONS';
          els.evtTitle.textContent = '// SECURITY EVENTS';
          els.sessHead.innerHTML = '<th>DEVICE</th><th>IP</th><th>LOCATION</th><th>RISK</th><th>LEVEL</th><th>FLAGS</th><th>STATE</th><th class="r">ACTION</th>';
          els.evtHead.innerHTML = '<th>TIME</th><th>TYPE</th><th>SEV</th><th>IP</th><th>AGENT</th>';
        }
      }

      

      async function loadSessions() {
        if (mfaGated) return;
        const cols = isAdmin ? 6 : 8;
        try {
          const res = await api(isAdmin ? '/sessions/all' : '/sessions');
          if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            els.sessions.innerHTML = `<tr><td colspan="${cols}" class="empty err">BLOCKED // ${esc(d?.message || res.status)}</td></tr>`;
            return;
          }
          const rows: SessionRow[] = await res.json();
          els.sessCount.textContent = `[${rows.length}]`;
          if (!rows.length) { els.sessions.innerHTML = `<tr><td colspan="${cols}" class="empty">— none —</td></tr>`; return; }

          if (isAdmin) {
            // System-wide, read-only: owner + device + state. No kill, no
            // risk-vs-current (the admin isn't the session owner).
            els.sessions.innerHTML = rows.map((s) => {
              const state = s.revoked ? '<span class="lv-crit">REVOKED</span>' : '<span class="lv-ok">ACTIVE</span>';
              const created = s.createdAt ? new Date(s.createdAt).toISOString().replace('T', ' ').slice(0, 19) : '—';
              return `<tr class="${s.revoked ? 'row-dead' : ''}">
                <td class="muted">${esc(String(s.userId || '').slice(0, 8))}</td>
                <td>${esc(s.deviceName || 'Unknown')}</td>
                <td>${esc(s.ipAddress || '—')}</td>
                <td class="muted">${esc(fmtLoc(s.country, s.city))}</td>
                <td>${state}</td>
                <td class="r muted">${esc(created)}</td>
              </tr>`;
            }).join('');
            return;
          }

          els.sessions.innerHTML = rows.map((s) => {
            const lvl = s?.risk?.level ?? 'TRUSTED';
            const score = s?.risk?.score ?? 0;
            const flags = [s.isCurrent ? 'THIS' : '', s.isSuspicious ? 'SUSPECT' : ''].filter(Boolean).join(' ');
            const state = s.revoked ? '<span class="lv-crit">REVOKED</span>' : '<span class="lv-ok">ACTIVE</span>';
            const action = s.revoked
              ? '<span class="muted">—</span>'
              : `<button class="key mini danger" data-revoke="${esc(s.id)}">KILL</button>`;
            const rowCls = s.revoked ? 'row-dead' : s.isSuspicious ? 'row-warn' : '';
            return `<tr class="${rowCls}">
              <td>${esc(s.deviceName || 'Unknown')}</td>
              <td>${esc(s.ipAddress || '—')}</td>
              <td class="muted">${esc(fmtLoc(s.country, s.city))}</td>
              <td class="r ${riskClass(lvl)}">${esc(score)}</td>
              <td class="${riskClass(lvl)}">${esc(lvl)}</td>
              <td class="muted">${esc(flags) || '—'}</td>
              <td>${state}</td>
              <td class="r">${action}</td>
            </tr>`;
          }).join('');
        } catch {
          setConn(false);
          els.sessions.innerHTML = `<tr><td colspan="${cols}" class="empty err">— link down —</td></tr>`;
        }
      }

      // Mirror the backend's labelling so the events panel reads like the sessions table.
      const prettyIp = (ip?: string | null): string => {
        if (!ip) return '—';
        if (ip === '::1' || ip === '127.0.0.1' || ip === '::ffff:127.0.0.1') return 'localhost';
        return ip.replace(/^::ffff:/, '');
      };
      const uaLabel = (ua?: string | null): string => {
        if (!ua) return '—';
        if (/axios|node-fetch|undici|got\//i.test(ua)) return 'API client';
        if (/curl/i.test(ua)) return 'curl';
        if (/PostmanRuntime/i.test(ua)) return 'Postman';
        const b = /\bEdg\b|Edge/i.test(ua) ? 'Edge' : /OPR\/|Opera/i.test(ua) ? 'Opera'
          : /Firefox/i.test(ua) ? 'Firefox' : /Chrome|CriOS/i.test(ua) ? 'Chrome'
          : /Safari/i.test(ua) ? 'Safari' : '';
        const o = /Windows/i.test(ua) ? 'Windows' : /Macintosh|Mac OS X/i.test(ua) ? 'macOS'
          : /Android/i.test(ua) ? 'Android' : /iPhone|iPad|iOS/i.test(ua) ? 'iOS'
          : /Linux/i.test(ua) ? 'Linux' : '';
        return b && o ? `${b} on ${o}` : b || o || 'Unknown client';
      };

      // ── REAL-TIME ALERTS ─────────────────────────────────────
      let seenEventIds: Set<string> | null = null;
      function toastWrap() {
        let w = document.getElementById('toastWrap');
        if (!w) {
          w = document.createElement('div');
          w.id = 'toastWrap';
          w.className = 'toast-wrap';
          document.body.appendChild(w);
        }
        return w;
      }
      function notify(e: AlertLike) {
        const sev = String(e.severity || 'HIGH').toUpperCase();
        const cls = sev === 'MEDIUM' ? 'sev-med' : sev === 'LOW' ? 'sev-low' : 'sev-high';
        const meta = [sev, e.ip ? '· ' + prettyIp(e.ip) : ''].filter(Boolean).join(' ');
        const t = document.createElement('div');
        t.className = 'toast ' + cls;
        t.innerHTML =
          '<div class="toast-h">⚠ SECURITY ALERT</div>' +
          '<div class="toast-b">' + esc(e.type) + '</div>' +
          '<div class="toast-m">' + esc(meta) + '</div>';
        toastWrap().appendChild(t);
        requestAnimationFrame(() => t.classList.add('show'));
        setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 6500);
      }
      // Audio alert (Web Audio — no asset). Created/resumed on a user gesture.
      let audioCtx: AudioContext | null = null;
      function initAudio() {
        try {
          if (!audioCtx) audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
          if (audioCtx.state === 'suspended') void audioCtx.resume();
        } catch { /* audio unsupported */ }
      }
      function playBeep() {
        if (!audioCtx || audioCtx.state !== 'running') return;
        try {
          const ctx = audioCtx;
          [880, 660].forEach((freq, i) => {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();
            osc.type = 'square';
            osc.frequency.value = freq;
            const t0 = ctx.currentTime + i * 0.14;
            gain.gain.setValueAtTime(0.0001, t0);
            gain.gain.exponentialRampToValueAtTime(0.12, t0 + 0.01);
            gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.12);
            osc.connect(gain).connect(ctx.destination);
            osc.start(t0);
            osc.stop(t0 + 0.13);
          });
        } catch { /* ignore */ }
      }

      // OS/browser notification — only when the tab is NOT focused (when it is,
      // the on-page toast already covers it).
      function requestNotify() {
        try {
          if ('Notification' in window && Notification.permission === 'default') {
            void Notification.requestPermission();
          }
        } catch { /* ignore */ }
      }
      function osNotify(e: AlertLike, count = 1) {
        try {
          if (!('Notification' in window) || Notification.permission !== 'granted') return;
          if (!document.hidden) return;
          const sev = String(e.severity || 'HIGH').toUpperCase();
          const title = '⚠ auth-lab security alert' + (count > 1 ? ' (' + count + ')' : '');
          new Notification(title, {
            body: sev + ' — ' + e.type + (e.ip ? ' · ' + prettyIp(e.ip) : ''),
            tag: 'authlab-alert',
          });
        } catch { /* ignore */ }
      }

      function detectNewEvents(items: SecurityEvent[]) {
        // First load establishes a baseline — don't alert on existing history.
        if (seenEventIds === null) {
          seenEventIds = new Set(items.map((e) => e.id).filter((x): x is string => Boolean(x)));
          return;
        }
        const seen = seenEventIds;
        const fresh = items.filter((e) => e.id && !seen.has(e.id));
        fresh.forEach((e) => { if (e.id) seen.add(e.id); });
        if (!fresh.length) return;
        fresh.slice(0, 3).forEach(notify); // cap visible toasts to avoid a storm
        if (fresh.length > 3) notify({ type: '+' + (fresh.length - 3) + ' more events', severity: 'HIGH' });
        // Sound + OS notification once per burst (not per toast).
        if (fresh.some((e) => String(e.severity).toUpperCase() === 'HIGH')) playBeep();
        osNotify(fresh[0], fresh.length);
      }

      async function loadEvents() {
        if (mfaGated) return;
        const cols = isAdmin ? 6 : 5;
        try {
          const res = await api(isAdmin ? '/security/events/all?limit=50' : '/security/events?limit=50');
          if (!res.ok) { els.events.innerHTML = `<tr><td colspan="${cols}" class="empty">— unavailable —</td></tr>`; return; }
          const data = await res.json();
          const items: SecurityEvent[] = Array.isArray(data) ? data : (data?.items ?? []);
          els.evtCount.textContent = `[${data?.total ?? items.length}]`;
          detectNewEvents(items);
          if (!items.length) { els.events.innerHTML = `<tr><td colspan="${cols}" class="empty">— clean —</td></tr>`; return; }
          els.events.innerHTML = items.map((e) => {
            const t = e.createdAt ? new Date(e.createdAt).toISOString().replace('T', ' ').slice(0, 19) : '—';
            const owner = isAdmin ? `<td class="muted">${esc(String(e.userId || '—').slice(0, 8))}</td>` : '';
            return `<tr>
              ${owner}
              <td class="muted">${esc(t)}</td>
              <td>${esc(e.type)}</td>
              <td class="${sevClass(e.severity)}">${esc(e.severity)}</td>
              <td>${esc(prettyIp(e.ip))}</td>
              <td class="muted">${esc(uaLabel(e.userAgent))}</td>
            </tr>`;
          }).join('');
        } catch {
          els.events.innerHTML = `<tr><td colspan="${cols}" class="empty err">— link down —</td></tr>`;
        }
      }

      let isRefreshing = false;
      // ── ACCOUNT SECURITY / MFA ENROLLMENT ────────────────────
      let account: Account | null = null;
      let mfaGated = false;
      let mfaSetup: { secret: string; otpauthUrl: string; qr?: string } | null = null;

      async function loadMe() {
        try {
          const r = await api('/auth/me');
          if (r.ok) { account = await r.json(); renderSecurity(); enforceAdminMfaGate(); }
        } catch { /* ignore */ }
      }

      function enforceAdminMfaGate() {
        const needs = !!account && account.role === 'admin' && !account.mfaEnabled;
        mfaGated = needs;
        els.mfaGate.hidden = !needs;
        if (needs) {
          els.sessPanel.hidden = true;
          els.evtPanel.hidden = true;
          els.attackPanel.hidden = true;
        } else {
          els.sessPanel.hidden = false;
          els.attackPanel.hidden = !isAdmin;
          els.evtPanel.hidden = !isAdmin;
        }
      }

      function renderSecurity() {
        if (!account) { els.mfaPanel.hidden = true; return; }
        els.mfaPanel.hidden = false;
        if (account.mfaEnabled) {
          els.mfaState.textContent = '[MFA ON]';
          els.mfaBody.innerHTML =
            '<div class="mfa-on">\u2713 Multi-factor is ENABLED for ' + esc(account.email) + '.</div>' +
            '<div class="mfa-actions"><input id="mfaDisCode" inputmode="numeric" maxlength="6" placeholder="code" />' +
            '<button class="key" id="mfaDisableBtn">Disable MFA</button></div><div class="msg" id="mfaMsg"></div>';
          document.getElementById('mfaDisableBtn')!.addEventListener('click', mfaDisable);
        } else if (mfaSetup) {
          els.mfaState.textContent = '[SETUP]';
          els.mfaBody.innerHTML =
            '<div class="hint">Scan this with your authenticator app (or paste the URL / type the secret), then enter the 6-digit code.</div>' +
            (mfaSetup.qr ? '<img class="mfa-qr" src="' + mfaSetup.qr + '" alt="MFA QR code" />' : '') +
            '<div class="mfa-secret">SECRET: <code>' + esc(mfaSetup.secret) + '</code></div>' +
            '<div class="mfa-secret">URL: <code>' + esc(mfaSetup.otpauthUrl) + '</code></div>' +
            '<div class="mfa-actions"><input id="mfaEnCode" inputmode="numeric" maxlength="6" placeholder="6-digit code" />' +
            '<button class="key primary" id="mfaEnableBtn">Verify &amp; Enable</button></div><div class="msg" id="mfaMsg"></div>';
          document.getElementById('mfaEnableBtn')!.addEventListener('click', mfaEnable);
        } else {
          els.mfaState.textContent = '[MFA OFF]';
          els.mfaBody.innerHTML =
            '<div class="mfa-warn">\u26a0 MFA is OFF. Protect this account with a second factor.</div>' +
            '<div class="mfa-actions"><button class="key primary" id="mfaSetupBtn">Set up MFA</button></div><div class="msg" id="mfaMsg"></div>';
          document.getElementById('mfaSetupBtn')!.addEventListener('click', beginMfaSetup);
        }
      }

      async function beginMfaSetup() {
        try {
          const r = await api('/auth/mfa/setup', { method: 'POST' });
          const d = await r.json();
          if (!r.ok) throw new Error(d?.message || 'setup failed');
          let qr: string | undefined;
          try { qr = await QRCode.toDataURL(d.otpauthUrl, { margin: 1, width: 180 }); } catch { /* text fallback */ }
          mfaSetup = { secret: d.secret, otpauthUrl: d.otpauthUrl, qr };
          renderSecurity();
        } catch (e: any) { flashMfa(e?.message || 'setup failed'); }
      }
      async function mfaEnable() {
        const code = (document.getElementById('mfaEnCode') as HTMLInputElement)?.value || '';
        try {
          const r = await api('/auth/mfa/enable', { method: 'POST', body: JSON.stringify({ code }) });
          const d = await r.json();
          if (!r.ok) throw new Error(d?.message || 'invalid code');
          mfaSetup = null; await loadMe();
        } catch (e: any) { flashMfa(e?.message || 'invalid code'); }
      }
      async function mfaDisable() {
        const code = (document.getElementById('mfaDisCode') as HTMLInputElement)?.value || '';
        try {
          const r = await api('/auth/mfa/disable', { method: 'POST', body: JSON.stringify({ code }) });
          const d = await r.json();
          if (!r.ok) throw new Error(d?.message || 'invalid code');
          mfaSetup = null; await loadMe();
        } catch (e: any) { flashMfa(e?.message || 'invalid code'); }
      }
      function flashMfa(msg: string) {
        const m = document.getElementById('mfaMsg');
        if (m) { m.className = 'msg err'; m.textContent = msg; }
      }

      async function refresh() {
        // Overlap guard: polling + a manual F5 must not stack concurrent loads.
        if (isRefreshing) return;
        isRefreshing = true;
        try {
          // Sessions FIRST: viewing them is what triggers the risk engine to
          // auto-revoke suspicious sessions and record the audit events. Running
          // these in parallel races that write, so events would only show on the
          // *next* refresh. Sequential = events appear on the same refresh.
          await loadSessions();
          if (isAdmin) await loadEvents();
          setStatus('● LIVE // updated ' + new Date().toLocaleTimeString(), 'ok');
        } finally {
          isRefreshing = false;
        }
      }

      // ── LIVE POLLING ─────────────────────────────────────────
      // Detection is synchronous at the API (guards record events the instant
      // an attack request lands). This just keeps the view current so events
      // surface within seconds without a manual refresh.
      let pollTimer: ReturnType<typeof setInterval> | null = null;
      const POLL_MS = 4000;
      function startPolling() {
        stopPolling();
        pollTimer = setInterval(() => {
          if (!els.app.hidden && document.visibilityState === 'visible') refresh();
        }, POLL_MS);
      }
      function stopPolling() {
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
      }
      // Refresh immediately when returning to the tab.
      document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible' && !els.app.hidden) refresh();
      });

      // ── IN-CONSOLE ATTACK RANGE ───────────────────────────────
      const scenarioName = (key: string) => ({
        'session-hijack': 'Session hijack',
        'brute-force': 'Brute force',
        'token-reuse': 'Token replay',
        'refresh-race': 'Refresh race',
        'fingerprint-spoof': 'Fingerprint spoof',
        'jwt-tamper': 'JWT tampering',
        all: 'Full attack chain',
      } as Record<string, string>)[key] || key;

      function renderRangeReport(report: any) {
        const verdict = report?.verdict?.passed ? 'DEFENSES HELD' : 'CHECK FAILURES';
        const summary = report?.summary || {};
        const rows = (report?.events || []).slice(-8).map((e: any) =>
          `${esc(e.scenario)} · ${esc(e.classification)} · HTTP ${esc(e.status)}${e.ip ? ' · ' + esc(prettyIp(e.ip)) : ''}`
        );
        els.rangeLog.innerHTML =
          `<b>${esc(verdict)}</b> // high:${esc(summary.high ?? 0)} med:${esc(summary.medium ?? 0)} low:${esc(summary.low ?? 0)}<br>` +
          (rows.length ? rows.map((r: string) => '↳ ' + r).join('<br>') : '↳ no simulator events returned');
      }

      async function launchAttack() {
        initAudio();
        const scenario = els.scenarioSelect.value;
        els.launchAttack.disabled = true;
        els.rangeState.textContent = '[RUNNING]';
        els.rangeLog.textContent = 'launching ' + scenarioName(scenario) + '…';
        setStatus('ATTACK RANGE RUNNING // ' + scenarioName(scenario));
        try {
          const res = await api('/attack-range/launch', {
            method: 'POST',
            body: JSON.stringify({
              // No email/password: the simulator attacks the demo victim
              // (test@test.com), never the logged-in operator. Sending the
              // admin's creds here would target an MFA-protected account and
              // the attack login would fail.
              scenario,
              sourceIp: els.sourceIpSelect.value,
            }),
          });
          const data = await res.json().catch(() => ({}));
          if (!res.ok) throw new Error(data?.message || `HTTP ${res.status}`);
          renderRangeReport(data);
          els.rangeState.textContent = data?.verdict?.passed ? '[BLOCKED]' : '[REVIEW]';
          setStatus('ATTACK COMPLETE // DEFENSE EVENTS RECORDED', data?.verdict?.passed ? 'ok' : 'err');
          await refresh();
        } catch (e: any) {
          els.rangeState.textContent = '[FAILED]';
          els.rangeLog.textContent = 'range failed — ' + (e?.message || 'unknown error');
          setStatus('ATTACK RANGE FAILED', 'err');
        } finally {
          els.launchAttack.disabled = false;
        }
      }

      async function revoke(id: string) {
        setStatus('REVOKING ' + id.slice(0, 8) + '…');
        const res = await api('/sessions/' + id, { method: 'DELETE' });
        setStatus(res.ok ? 'SESSION REVOKED' : 'REVOKE FAILED', res.ok ? 'ok' : 'err');
        await refresh();
      }

      async function logout() {
        await api('/auth/logout', { method: 'POST' }).catch(() => {});
        clear(); showLogin('LOGGED OUT'); setStatus('READY');
      }
      async function logoutAll() {
        await api('/auth/logout-all', { method: 'POST' }).catch(() => {});
        clear(); showLogin('ALL SESSIONS KILLED'); setStatus('READY');
      }

      // ── WIRING ───────────────────────────────────────────────
      els.loginBtn.addEventListener('click', login);
      els.registerBtn.addEventListener('click', register);
      els.launchAttack.addEventListener('click', launchAttack);
      els.password.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') login(); });
      els.mfaCode.addEventListener('keydown', (e) => { if ((e as KeyboardEvent).key === 'Enter') login(); });

      document.querySelectorAll<HTMLElement>('[data-act]').forEach((b) =>
        b.addEventListener('click', () => {
          const act = b.dataset.act;
          if (act === 'refresh') refresh();
          if (act === 'logout') logout();
          if (act === 'logoutAll') logoutAll();
        }),
      );
      els.sessions.addEventListener('click', (e) => {
        const id = (e.target as HTMLElement)?.dataset?.revoke;
        if (id) revoke(id);
      });
      document.addEventListener('keydown', (e) => {
        const k = (e as KeyboardEvent).key;
        if (els.app.hidden) return;
        if (k === 'F5') { e.preventDefault(); refresh(); }
        if (k === 'F10') { e.preventDefault(); logout(); }
      });

      // clock
      setInterval(() => { els.clock.textContent = new Date().toTimeString().slice(0, 8); }, 1000);

      // Browsers gate audio until a gesture — resume on the first interaction.
      ['click', 'keydown'].forEach((ev) =>
        document.addEventListener(ev, () => initAudio()),
      );

      // boot
      const booted = load();
      if (booted?.accessToken) {
        isAdmin = decodeRole(booted.accessToken) === 'admin';
        els.who.textContent = (isAdmin ? 'ADMIN·SOC' : 'SESSION') + ' // SID ' + String(booted.sessionId ?? '').slice(0, 8);
        applyMode();
        showApp();
        refresh();
      } else {
        showLogin();
      }
