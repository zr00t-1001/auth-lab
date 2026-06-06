import { RuleEngine } from './rule-engine';
import { CorrelationEngine } from './correlation-engine';
import { type SocEvent } from './event-bus';
import { type ScenarioReport } from '../schemas';
import {
  evaluateExpectations,
  type ScenarioExpectation,
} from '../expectations';

/**
 * Turn a flat list of SOC events into a full report:
 *  - RuleEngine: stateless behavioral rules over a time window
 *  - CorrelationEngine: per-IP stateful scoring
 *  - summary + overall incident status
 *  - verdict: did each scenario's defense hold? (pass/fail)
 */
export function buildReport(
  events: SocEvent[],
  opts: {
    target: string;
    scenarios: string[];
    expectations?: ScenarioExpectation[];
  },
): ScenarioReport {
  const ruleAlerts = new RuleEngine(events).run();
  const correlationAlerts = new CorrelationEngine(events).build();

  // An IP-level correlation alert counts toward the incident status too.
  const severities = [
    ...ruleAlerts.map((a) => a.severity),
    ...correlationAlerts.map((a) => a.severity),
  ];

  const high = severities.filter((s) => s === 'HIGH').length;
  const medium = severities.filter((s) => s === 'MEDIUM').length;
  const low = severities.filter((s) => s === 'LOW').length;

  const status: ScenarioReport['summary']['status'] =
    high > 0 ? 'ACTIVE_THREAT' : medium > 0 ? 'SUSPICIOUS' : 'CLEAN';

  const verdict = evaluateExpectations(events, opts.expectations ?? []);

  return {
    generatedAt: new Date().toISOString(),
    target: opts.target,
    scenarios: opts.scenarios,
    events,
    ruleAlerts,
    correlationAlerts,
    summary: {
      high,
      medium,
      low,
      total: ruleAlerts.length + correlationAlerts.length,
      status,
    },
    verdict,
  };
}
