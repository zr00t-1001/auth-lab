#!/usr/bin/env node
/**
 * auth-lab attack-simulator console.
 *
 * This is a LOCAL TEST HARNESS. It only speaks HTTP to the lab's own auth
 * endpoints (login / refresh / sessions) to verify that the backend's
 * detections fire. It deliberately does NOT execute system commands, open a
 * shell, or run anything on a remote machine — it is a scenario runner, not a
 * remote-exec tool.
 *
 * Usage:
 *   pnpm sim                                  # interactive console
 *   pnpm sim --all --target http://localhost:3000 --out reports/run.json
 *   pnpm sim --scenario refresh-race,token-reuse
 */
import { createInterface } from 'readline/promises';
import { stdin as input, stdout as output } from 'process';
import { SCENARIOS } from './registry';
import { runScenarios } from './runner';
import { SimConfigSchema, type SimConfig } from './schemas';
import { getTarget } from './core/http';

function parseArgs(argv: string[]): { config: SimConfig; interactive: boolean } {
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };

  const target = get('--target') ?? 'http://localhost:3000';
  const out = get('--out');
  const all = argv.includes('--all');
  const scenarioArg = get('--scenario');
  const scenarios = all
    ? []
    : scenarioArg
      ? scenarioArg.split(',').map((s) => s.trim()).filter(Boolean)
      : [];

  const interactive = !all && !scenarioArg;

  // Validate/normalize through the schema so bad input fails loudly here.
  const config = SimConfigSchema.parse({ target, out, scenarios });
  return { config, interactive };
}

async function interactiveConsole(base: SimConfig): Promise<void> {
  const rl = createInterface({ input, output });
  let target = base.target;

  const menu = () => {
    console.log('\n🛡️  AUTH-LAB SIMULATOR CONSOLE');
    console.log(`    target: ${target}`);
    console.log('-----------------------------------------');
    SCENARIOS.forEach((s, i) => console.log(`  ${i + 1}) ${s.label.padEnd(18)} ${s.description}`));
    console.log(`  a) run ALL scenarios`);
    console.log(`  t) set target URL`);
    console.log(`  q) quit`);
  };

  try {
    for (;;) {
      menu();
      const answer = (await rl.question('\n> ')).trim().toLowerCase();

      if (answer === 'q' || answer === 'quit' || answer === 'exit') break;

      if (answer === 't') {
        const next = (await rl.question('new target URL: ')).trim();
        const parsed = SimConfigSchema.safeParse({ target: next, scenarios: [] });
        if (parsed.success) {
          target = parsed.data.target;
          console.log(`✅ target set to ${target}`);
        } else {
          console.log('❌ invalid URL, keeping previous target');
        }
        continue;
      }

      let scenarios: string[] = [];
      if (answer === 'a' || answer === 'all') {
        scenarios = [];
      } else {
        const idx = Number(answer) - 1;
        const picked = SCENARIOS[idx];
        if (!picked) {
          console.log('❓ unknown option');
          continue;
        }
        scenarios = [picked.key];
      }

      const out =
        (await rl.question('write JSON report to (blank = none): ')).trim() || undefined;

      await runScenarios(SimConfigSchema.parse({ target, out, scenarios }));
    }
  } finally {
    rl.close();
    console.log('\n👋 bye');
  }
}

async function main() {
  const { config, interactive } = parseArgs(process.argv.slice(2));

  if (interactive) {
    await interactiveConsole(config);
  } else {
    const report = await runScenarios(config);
    // CI-friendly: a defense that failed to fire is a failing run.
    if (!report.verdict.passed) process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('simulator failed:', err?.message ?? err);
  process.exit(1);
});
