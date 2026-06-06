# Postman — register & login workflow

Files:
- `auth-lab.postman_collection.json` — the test workflow
- `auth-lab.postman_environment.json` — `baseUrl` (http://localhost:3000)

## Import & run
1. Postman → **Import** → drop both files.
2. Select the **auth-lab (local)** environment (top-right).
3. Make sure the backend is running (`pnpm run start:dev`) with Postgres up.
4. Open the collection → **Run** (Collection Runner), or send requests 1→5 in order.

The first request generates a unique email and reuses it, so the run is
repeatable. It covers: register (happy), duplicate register (400), short-password
validation (400), login (200/201, token shape, no jti leak), and wrong password
(401).

> `POST /auth/login` is throttled to **3 requests / 60s** per IP. This run makes
> 2 login calls; running it again within a minute can return HTTP 429.

## CLI (optional)
```bash
npm i -g newman
newman run auth-lab.postman_collection.json -e auth-lab.postman_environment.json
```
