import { EventBus } from './engine/event-bus';
import { buildReport } from './engine/report-builder';
import { writeJsonReport } from './reporters/json.reporter';
import { SCENARIOS, findScenario, type Scenario } from './registry';
import { login, setTarget, getTarget } from './core/http';
import { type ScenarioReport, type SimConfig } from './schemas';

const DEMO_CREDENTIALS = { email: 'test@test.com', password: '12345678' };
const DEFAULT_BRUTE_FORCE_EMAIL = 'attack-range-decoy@authlab.local';

export function printAlertTable(report: ScenarioReport): void {
  const table = report.ruleAlerts.map((a, i) => ({
    id: i + 1,
    rule: a.rule,
    ip: a.ip ?? 'GLOBAL',
    severity: a.severity,
    confidence: Number(a.confidence.toFixed(2)),
    description: a.description,
  }));

  console.log('\n🚨 SOC ALERTS (RULE ENGINE)\n');
  if (table.length) console.table(table);
  else console.log('  (no rule alerts)');

  console.log('\n🔗 CORRELATION (PER-IP)\n');
  if (report.correlationAlerts.length) {
    console.table(
      report.correlationAlerts.map((a) => ({
        ip: a.ip,
        severity: a.severity,
        confidence: Number(a.confidence.toFixed(2)),
        steps: a.sequence.length,
      })),
    );
  } else {
    console.log('  (no correlation alerts)');
  }

  const { high, medium, low, status } = report.summary;
  console.log('\n📊 SUMMARY');
  console.log('-----------------------------');
  console.log('HIGH:', high, ' MEDIUM:', medium, ' LOW:', low);
  const banner =
    status === 'ACTIVE_THREAT'
      ? '🚨 INCIDENT STATUS: ACTIVE THREAT DETECTED'
      : status === 'SUSPICIOUS'
        ? '🟡 INCIDENT STATUS: SUSPICIOUS ACTIVITY'
        : '🟢 INCIDENT STATUS: CLEAN';
  console.log('\n' + banner);

  if (report.verdict.scenarios.length) {
    console.log('\n✅ DEFENSE VERDICT (did the backend block what it should?)\n');
    console.table(
      report.verdict.scenarios.map((v) => ({
        scenario: v.scenario,
        blocked: `${v.blocked}/${v.total}`,
        required: v.required,
        result: v.passed ? 'PASS' : 'FAIL',
      })),
    );
    console.log(
      report.verdict.passed
        ? '\n🟢 ALL DEFENSES HELD'
        : '\n🔴 ONE OR MORE DEFENSES DID NOT FIRE — see FAIL rows above',
    );
  }
}

/**
 * Run a set of scenarios against the configured target and produce a report.
 * Logs in once up front so token-bearing scenarios get a real token.
 */
export async function runScenarios(config: SimConfig): Promise<ScenarioReport> {
  setTarget(config.target);

  const selected: Scenario[] =
    config.scenarios.length === 0
      ? SCENARIOS
      : config.scenarios
          .map((k) => findScenario(k))
          .filter((s): s is Scenario => Boolean(s));

  const bus = new EventBus();

  let accessToken = '';
  let refreshToken = '';
  try {
    const session = await login(
      config.email ?? DEMO_CREDENTIALS.email,
      config.password ?? DEMO_CREDENTIALS.password,
    );
    accessToken = session?.accessToken ?? '';
    refreshToken = session?.refreshToken ?? '';
  } catch {
    console.warn(
      `⚠️  Could not log in at ${getTarget()} — token-bearing scenarios may all be rejected.`,
    );
  }

  for (const scenario of selected) {
    console.log(`\n============================`);
    console.log(`▶ ${scenario.label}`);
    console.log(`============================`);
    await scenario.run({
      bus,
      accessToken,
      refreshToken,
      email: config.email ?? DEMO_CREDENTIALS.email,
      password: config.password ?? DEMO_CREDENTIALS.password,
      bruteForceEmail: config.bruteForceEmail ?? DEFAULT_BRUTE_FORCE_EMAIL,
    });
  }

  const report = buildReport(bus.all(), {
    target: config.target,
    scenarios: selected.map((s) => s.key),
    expectations: selected.map((s) => s.expectation),
  });

  printAlertTable(report);

  if (config.out) {
    writeJsonReport(report, config.out);
    console.log(`\n💾 Report written to ${config.out}`);
  }

  return report;
}
