# auth-lab — diagrams

Visual walkthrough of how the system works, from logging in to catching an attack.

## Demo

![attack simulator demo](diagrams/demo/attack-simulator.gif)

---

## 1. Logging in & the roles

**Who's who.** The admin is the SOC analyst (sees everything, fires drills); normal users are the protected population; the attacker is the simulator, never a real user.

<img src="diagrams/login/auth_lab_three_roles.svg" width="680" alt="three roles">

**Login flow.** Email + password → argon2 verify → optional MFA code → a 15-minute access token and a 7-day refresh token.

<img src="diagrams/login/login_authentication_flow.svg" width="680" alt="login flow">

**How an attack becomes an alert.** The admin fires a drill, the simulator hammers the API, the guards catch it and log events, and the dashboard surfaces them live.

<img src="diagrams/login/attack_detection_dashboard_loop.svg" width="680" alt="attack detection loop">

## 2. Request pipeline

**The layers.** Every request passes guards (which can reject it) → controller → service → repository → Postgres.

<img src="diagrams/request-pipeline/nestjs_request_pipeline.svg" width="680" alt="request pipeline">

**One module.** Each feature bundles its controller, service, and entity.

<img src="diagrams/request-pipeline/nestjs_module_anatomy.svg" width="680" alt="module anatomy">

**Zero-trust on every request.** Token + session-binding checks, then a risk score → allow / step-up / block, logging an event either way.

<img src="diagrams/request-pipeline/zero_trust_per_request_check.svg" width="680" alt="zero trust per request">

**Security-event lifecycle.** From detection → `record()` → the `security_events` table → the dashboard feed.

<img src="diagrams/request-pipeline/security_event_lifecycle.svg" width="680" alt="security event lifecycle">

## 3. Admin-MFA gate

Admin accounts can see everything and fire attacks, so they're required to enable MFA before any admin endpoint will answer.

<img src="diagrams/admin-mfa-gate/auth-mfa-gate.svg" width="760" alt="admin MFA gate">

## 4. GeoIP & impossible travel

**Detection flow.** Each login's IP is resolved to a location, stored on the session, and compared to the previous login.

<img src="diagrams/geoip-impossible-travel/geoip_impossible_travel_flow.svg" width="680" alt="geoip flow">

**Worked example.** Two logins too far apart in too little time trip the rule.

<img src="diagrams/geoip-impossible-travel/geoip-impossible-travel.svg" width="760" alt="impossible travel example">

## 5. Refresh-token rotation & replay protection

Every refresh mints a new pair and retires the old token; reusing an old one is caught as a replay.

<img src="diagrams/token-rotation/refresh_token_rotation.svg" width="760" alt="refresh token rotation">
