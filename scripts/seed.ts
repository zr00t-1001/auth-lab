/**
 * Seed a demo user so the lab has something to log in with on first run.
 * Talks to the running API over HTTP (no DB coupling). Safe to re-run —
 * a 400 "already exists" is treated as success.
 *
 *   pnpm seed            # uses http://localhost:3000
 *   SIM_TARGET=... pnpm seed
 */
const TARGET = (process.env.SIM_TARGET ?? 'http://localhost:3000').replace(/\/$/, '');
const EMAIL = process.env.SEED_EMAIL ?? 'test@test.com';
const PASSWORD = process.env.SEED_PASSWORD ?? '12345678';

async function main() {
  const res = await fetch(`${TARGET}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
  }).catch((e) => {
    console.error(`\n✗ Could not reach ${TARGET}. Is the backend running?\n`, e.message);
    process.exit(1);
  });

  const body = await res.json().catch(() => ({}));
  if (res.ok) {
    console.log(`\n✓ Demo user created: ${EMAIL} / ${PASSWORD}\n`);
  } else if (/exist/i.test(body?.message ?? '')) {
    console.log(`\n✓ Demo user already exists: ${EMAIL} / ${PASSWORD}\n`);
  } else {
    console.error(`\n✗ Register failed (${res.status}):`, body);
    process.exit(1);
  }

  console.log('  To make this user an admin (for the RBAC /security/events/all route), run:');
  console.log(`  UPDATE users SET role='admin' WHERE email='${EMAIL}';\n`);
}
main();
