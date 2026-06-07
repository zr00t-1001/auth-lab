# auth-lab — review & changes

## What this project is

A NestJS auth backend (JWT access/refresh, rotation, session binding, a
zero-trust risk engine, a security-event audit trail) plus a **defensive
attack simulator**: a local harness that drives the backend's *own* HTTP
endpoints with scripted attack scenarios and checks that the defenses fire.
It is a lab for validating your own auth stack — not a tool aimed at third
parties.

## Honest assessment: it's ~80% done, not halfway

The hard parts are already in place and the architecture is sound:

- **Zod schemas already exist** (`src/attack-simulator/schemas.ts`) and are the
  single source of truth — the TypeScript types are *inferred* from them, so
  static and runtime views can't drift. This is exactly the "schemas" you asked
  for; they were already there.
- **The console already exists** (`src/attack-simulator/cli.ts`, `pnpm sim`):
  an interactive menu to pick a scenario, set the target, and write a JSON
  report.
- The SOC engine (event bus, time-window rule engine, per-IP correlation,
  report builder) is clean and well-separated.
- The backend's `logout-all` endpoint and `SecurityEventService` audit log are
  already implemented.

So the gap was never "build the core" — it was **tests** and **a reason for the
lab to fail loudly when a defense regresses.**

## The "shell / execute from a console" question

You asked whether the simulator should have a shell or be able to execute from a
small console. Recommendation: **keep the interactive scenario console; do not
add a remote-exec shell.**

- The interactive console (already in `cli.ts`) is the right shape: it picks
  and runs scenarios against the lab's own auth endpoints. That's a test
  harness.
- A shell that runs arbitrary commands or executes against arbitrary remote
  hosts would turn a defensive lab into a general-purpose offensive tool, and
  it's also a maintenance and safety liability for an open-source repo. The
  existing `cli.ts` header already documents this boundary; I kept it.

If you ever want "more interactive," extend the *menu* (e.g. choose a subset of
scenarios, replay a saved report), not the *capability surface*.

**Feature — a defense verdict layer.** Each scenario now declares the defensive
behaviour it's meant to provoke (e.g. "a replayed refresh token must be
rejected"). After a run, observed events are checked against those expectations
and the report gains a `verdict` block (per-scenario PASS/FAIL plus an overall
`passed`). The non-interactive CLI now exits non-zero when a defense fails to
fire — so `pnpm sim --all` is usable as a **CI regression test for your auth
defenses**, which is what makes the lab worth publishing.

Files: `expectations.ts` (new, pure/deterministic), plus `schemas.ts`,
`registry.ts`, `engine/report-builder.ts`, `runner.ts`, `cli.ts`, `index.ts`.

**Tests** — `src/attack-simulator/__tests__/` (22 tests, no network/DB):
`classify`, `rule-engine`, `correlation-engine`, `report-builder` (incl.
schema validity), and the new `expectations` evaluator. Run with `pnpm test`.

Verified here in isolation: `tsc --noEmit` clean, all 22 tests pass.




