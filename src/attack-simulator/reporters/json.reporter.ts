import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { ScenarioReportSchema, type ScenarioReport } from '../schemas';

/**
 * Validate a report against the Zod schema and write it to disk as JSON.
 * Throws if the report does not satisfy the schema, so a malformed report
 * can never be silently persisted.
 */
export function writeJsonReport(report: ScenarioReport, path: string): ScenarioReport {
  const validated = ScenarioReportSchema.parse(report);

  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(validated, null, 2), 'utf-8');

  return validated;
}
