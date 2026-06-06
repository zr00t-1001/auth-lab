# Schemas reference

A single place to study every shape that crosses a boundary in auth-lab: the
database entities, the JWT token claims, the HTTP request/response bodies, and
the attack-simulator's runtime (Zod) schemas.

Conventions: `uuid` = RFC-4122 v4 string · `?` = optional · times are ISO-8601
strings over the wire (TypeORM `Date` in code). Validation rules in the "DTOs"
section are enforced by a global `ValidationPipe` (`whitelist`,
`forbidNonWhitelisted`, `transform`).

---

## 1. Data model (TypeORM entities)

### `User` — table `users`

| Field          | Type                  | Constraints                       | Notes                                  |
| -------------- | --------------------- | --------------------------------- | -------------------------------------- |
| `id`           | uuid                  | PK, generated                     |                                        |
| `email`        | string                | **unique**                        | stored lower-cased + trimmed           |
| `passwordHash` | string                | column `password_hash`            | bcrypt hash; never leaves the server   |
| `role`         | enum `user` \| `admin`| default `user`                    | see `UserRole`                          |
| `createdAt`    | timestamp             | auto (`@CreateDateColumn`)        |                                        |

### `Session` — table `sessions`

One row per logged-in device. The security layer compares the live request
against this row.

| Field               | Type      | Constraints           | Notes                                                  |
| ------------------- | --------- | --------------------- | ------------------------------------------------------ |
| `id`                | uuid      | PK, generated         | this is the `sid` claim in tokens                      |
| `userId`            | uuid      | indexed               | owner                                                  |
| `refreshTokenHash`  | text?     |                       | bcrypt hash of the current refresh token               |
| `tokenVersion`      | int       | default `0`           | bumped on rotation; old versions are rejected          |
| `revoked`           | boolean   | default `false`       | soft kill switch                                       |
| `ipAddress`         | string?   |                       | captured at login                                      |
| `userAgent`         | string?   |                       | captured at login                                      |
| `fingerprint`       | string?   |                       | derived from session id + ip + ua; bound on first use  |
| `expiresAt`         | timestamp |                       | absolute session lifetime                              |
| `createdAt`         | timestamp | auto                  |                                                        |
| `deviceName`        | string?   |                       | display label                                          |
| `currentAccessJti`  | string?   |                       | jti of the access token currently valid                |
| `currentRefreshJti` | string?   |                       | jti of the refresh token currently valid               |
| `lastRefreshJti`    | string?   |                       | previous refresh jti (replay forensics)                |

### `SecurityEvent` — table `security_events`

Append-only audit trail. Recording is best-effort: a failure to write must
never break the request it describes.

| Field       | Type                | Constraints                | Notes                                |
| ----------- | ------------------- | -------------------------- | ------------------------------------ |
| `id`        | uuid                | PK, generated              |                                      |
| `userId`    | string?             | indexed                    |                                      |
| `sessionId` | string?             | indexed                    |                                      |
| `type`      | `SecurityEventType` | enum                       | see below                            |
| `severity`  | `LOW`\|`MEDIUM`\|`HIGH` | default `MEDIUM`        |                                      |
| `ip`        | string?             |                            |                                      |
| `userAgent` | string?             |                            |                                      |
| `detail`    | jsonb?              |                            | free-form context (score, reasons…)  |
| `createdAt` | timestamp           | auto                       |                                      |

`SecurityEventType` ∈ `BINDING_VIOLATION` · `TOKEN_REPLAY` · `HIGH_RISK_BLOCK`
· `STEP_UP_REQUIRED` · `REFRESH_REUSE` · `REFRESH_RACE`.

---

## 2. JWT token claims

Both tokens are signed JWTs (different secrets). The access token is sent as
`Authorization: Bearer <token>`; the refresh token is sent in the JSON body
field `refreshToken`.

| Claim | Meaning                | Access     | Refresh    |
| ----- | ---------------------- | ---------- | ---------- |
| `sub` | user id (uuid)         | ✓          | ✓          |
| `sid` | session id (uuid)      | ✓          | ✓          |
| `ver` | token version (int)    | ✓          | ✓          |
| `jti` | unique token id (uuid) | ✓          | ✓          |
| exp   | lifetime               | **15m**    | **7d**     |
| secret| signing key            | `JWT_ACCESS_SECRET` | `JWT_REFRESH_SECRET` |

After validation the access token is exposed to handlers/guards as:

```ts
req.user = { userId: sub, sessionId: sid, version: ver, jti }
```

---

## 3. HTTP API schemas

### Auth

**POST `/auth/register`** → `201`
Request `{ email, password }`. Response:

```json
{ "id": "uuid", "email": "you@example.com", "createdAt": "2026-01-01T00:00:00.000Z" }
```

Errors: `400` validation, `400 "User already exists"`.

**POST `/auth/login`** → `201` (throttled: 3 / 60s)
Request `{ email, password }`. Response:

```json
{ "sessionId": "uuid", "accessToken": "<jwt>", "refreshToken": "<jwt>" }
```

Only the two tokens are returned — the internal `jti`s are intentionally **not**
leaked. Errors: `401 "Invalid credentials"`, `429` rate-limited.

**POST `/auth/refresh`** → rotated token pair. Guarded by `RefreshTokenGuard`;
reads the refresh JWT from the body field `refreshToken`. Rotation bumps
`tokenVersion` and replaces the stored hash/jti, so a replayed refresh token is
rejected.

**POST `/auth/logout`** (Bearer) → `{ "success": true, "message": "..." }` — revokes the current session.
**POST `/auth/logout-all`** (Bearer) → revokes every session for the user.

### Sessions

**GET `/sessions`** (Bearer + `ZeroTrustGuard` + `SessionBindingGuard`) →
`SessionResponse[]`:

```jsonc
{
  "id": "uuid",
  "deviceName": "Unknown device",
  "ipAddress": "185.12.44.10",
  "createdAt": "…", "expiresAt": "…",
  "revoked": false,
  "isCurrent": true,
  "label": "This device",
  "isSuspicious": false,
  "reasons": [],
  "risk":  { "score": 0, "level": "TRUSTED" },        // TRUSTED|LOW_RISK|SUSPICIOUS|HIGH_RISK
  "drift": { "score": 0, "level": "TRUSTED", "reasons": [] },
  "security": { "autoRevoked": false, "requireReauth": false }
}
```

**DELETE `/sessions/:sessionId`** (Bearer) → `{ "success": true, "message": "Session revoked" }`.

### Security events

**GET `/security/events`** (Bearer). Query: `type?`, `limit` (1–200, def 50),
`offset` (≥0, def 0). Response:

```json
{ "total": 3, "items": [ /* SecurityEvent, newest first */ ] }
```

---

## 4. DTOs (request validation)

| DTO              | Field    | Rule                                                        |
| ---------------- | -------- | ----------------------------------------------------------- |
| `RegisterDto`    | email    | normalised (lower+trim), `@IsEmail`                         |
|                  | password | `@IsString`, length **8–128**                               |
| `LoginDto`       | email    | normalised, `@IsEmail`                                      |
|                  | password | `@IsString`, length **8–128**                               |
| `QueryEventsDto` | type     | optional, `@IsEnum(SecurityEventType)`                      |
|                  | limit    | optional int, **1–200**, default 50                         |
|                  | offset   | optional int, **≥0**, default 0                             |

---

## 5. Attack-simulator schemas (Zod, runtime-validated)

These live in `src/attack-simulator/schemas.ts` and are the **single source of
truth** for the simulator: the TypeScript types are *inferred* from them, so
static and runtime views can't drift. Validation happens at every boundary
(config in, report out).

**Enums**

- `SecurityLayer` = `AUTH` | `INFRA` | `SESSION` | `UNKNOWN`
- `Classification` = `ALLOW` | `AUTH_REJECT` | `BLOCKED` | `RATE_LIMITED` | `UNKNOWN`
- `SocEventType` = `REFRESH` | `REFRESH_ERROR` | `REFRESH_FIRST` | `REFRESH_REUSE` | `SESSION_GET` | `TOKEN_REUSE` | `FINGERPRINT`
- `Severity` = `LOW` | `MEDIUM` | `HIGH`

**`SocEvent`** (discriminated union of two shapes that share a base)

| Field            | Type           | Rule                       |
| ---------------- | -------------- | -------------------------- |
| `id`             | string         | uuid                       |
| `timestamp`      | number         | int ≥ 0 (epoch ms)         |
| `scenario`       | string         | non-empty                  |
| `type`           | SocEventType   | enum                       |
| `status`         | number         | int (HTTP status)          |
| `layer`          | SecurityLayer  | enum                       |
| `classification` | Classification | enum                       |
| `message`        | string?        |                            |
| `ip` / `userAgent` | string       | **NetworkEvent**: required, non-empty · **SystemEvent**: absent |

**`Alert`** (rule engine) — `{ rule: string≥1, severity, confidence: 0–1, ip?, description: string≥1 }`
**`CorrelationAlert`** (per IP) — `{ ip: string, severity, confidence: 0–1, sequence: Classification[] }`

**`ScenarioVerdict`** — `{ scenario, description, total≥0, blocked≥0, required≥0, passed: bool }`
**`Verdict`** — `{ passed: bool, scenarios: ScenarioVerdict[] }`

**`ScenarioReport`** (the JSON written by `--out`)

```jsonc
{
  "generatedAt": "ISO string",
  "target": "https://… (valid URL)",
  "scenarios": ["session-hijack", …],
  "events": [ /* SocEvent[] */ ],
  "ruleAlerts": [ /* Alert[] */ ],
  "correlationAlerts": [ /* CorrelationAlert[] */ ],
  "summary": { "high": 0, "medium": 0, "low": 0, "total": 0,
               "status": "CLEAN" },          // CLEAN | SUSPICIOUS | ACTIVE_THREAT
  "verdict": { "passed": true, "scenarios": [ /* ScenarioVerdict[] */ ] }
}
```

**`SimConfig`** (validated CLI input) — `{ target: url (default http://localhost:3000), out?: string, scenarios: string[] (default []) }`.
