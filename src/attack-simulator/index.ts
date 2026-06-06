/**
 * Non-interactive entry point: run the full scenario suite once against the
 * default target and print the SOC report. For an interactive menu use the
 * console (`pnpm sim`), which lives in cli.ts.
 */
import { runScenarios } from './runner';
import { SimConfigSchema } from './schemas';

async function main() {
  console.log('\n🛡️ SOC ATTACK SIMULATOR BOOTING...\n');
  const report = await runScenarios(
    SimConfigSchema.parse({
      target: process.env.SIM_TARGET ?? 'http://localhost:3000',
      out: process.env.SIM_OUT,
      scenarios: [],
    }),
  );
  if (!report.verdict.passed) process.exitCode = 1;
}

main().catch((err) => {
  console.error('simulator failed:', err?.message ?? err);
  process.exit(1);
});
