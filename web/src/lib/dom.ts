// DOM element references + tiny view helpers, shared across dashboard modules.
// No application state lives here — just the document handles.

export const $ = <T extends HTMLElement = HTMLElement>(s: string) =>
  document.querySelector(s) as T;

export const els = {
  login: $('#login'), app: $('#app'),
  email: $<HTMLInputElement>('#email'), password: $<HTMLInputElement>('#password'),
  loginBtn: $<HTMLButtonElement>('#loginBtn'), loginMsg: $('#loginMsg'),
  registerBtn: $<HTMLButtonElement>('#registerBtn'),
  sessions: $('#sessions tbody'), events: $('#events tbody'),
  sessCount: $('#sessCount'), evtCount: $('#evtCount'),
  sessTitle: $('#sessTitle'), evtTitle: $('#evtTitle'),
  attackPanel: $('#attackPanel'), evtPanel: $('#evtPanel'),
  mfaPanel: $('#mfaPanel'), mfaState: $('#mfaState'), mfaBody: $('#mfaBody'),
  sessPanel: $('#sessPanel'), mfaGate: $('#mfaGate'),
  mfaRow: $('#mfaRow'), mfaCode: $<HTMLInputElement>('#mfaCode'),
  sessHead: $('#sessHead'), evtHead: $('#evtHead'),
  who: $('#who'), status: $('#status'),
  target: $('#target'), conn: $('#conn'), clock: $('#clock'),
  scenarioSelect: $<HTMLSelectElement>('#scenarioSelect'), sourceIpSelect: $<HTMLSelectElement>('#sourceIpSelect'), launchAttack: $<HTMLButtonElement>('#launchAttack'),
  rangeState: $('#rangeState'), rangeLog: $('#rangeLog'),
};

export const setStatus = (m: string, kind: 'ok' | 'err' | '' = '') => {
  els.status.textContent = m;
  els.status.className = kind;
};
export const setConn = (up: boolean) => {
  els.conn.textContent = up ? '● LINK UP' : '● LINK DOWN';
  els.conn.className = up ? 'conn on' : 'conn off';
};
export const esc = (s: unknown) =>
  String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!));