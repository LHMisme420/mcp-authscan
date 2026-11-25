type JsonObject = Record<string, unknown>;
type Probe = { probe_id: number | string; name: string; status: string };
type ComparableReport = {
  scheme: string;
  probes: Map<string, Probe>;
  totals: JsonObject;
  runDate: string;
};
export type ProbeDifference = {
  probeId: number | string;
  first: { name: string; status: string } | null;
  second: { name: string; status: string } | null;
};
export type GradeComparison = {
  outcome: 'identical' | 'different' | 'different-schemes' | 'unavailable';
  reason: string;
  schemes?: [string, string];
  runDates?: [string, string];
  probes: ProbeDifference[];
  totals: { name: string; first: unknown; second: unknown }[];
};
const TOTALS = ['total_checks', 'coverage', 'findings_count', 'severity_counts'] as const;
const object = (value: unknown): value is JsonObject =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

// Compare JSON values structurally, not object insertion order. No report is modified
// and these bytes are never used for verification, hashing or signing.
export function displayGradeValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(displayGradeValue).join(',')}]`;
  if (object(value)) return `{${Object.keys(value).sort().map(key =>
    `${JSON.stringify(key)}:${displayGradeValue(value[key])}`).join(',')}}`;
  return JSON.stringify(value) ?? 'Not declared';
}

function readReport(text: string, label: string): ComparableReport {
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw new Error(`${label} is not readable JSON.`); }
  if (!object(data)) throw new Error(`${label} must contain a report object.`);
  if (typeof data.hash_scheme !== 'string' || !data.hash_scheme.trim()) {
    throw new Error(`${label} does not declare a hash scheme.`);
  }
  if (!Array.isArray(data.probes)) throw new Error(`${label} has no probe rows to compare.`);
  const probes = new Map<string, Probe>();
  for (const row of data.probes) {
    if (!object(row) ||
        !(typeof row.probe_id === 'string' && row.probe_id.trim() ||
          typeof row.probe_id === 'number' && Number.isSafeInteger(row.probe_id)) ||
        typeof row.name !== 'string' || typeof row.status !== 'string') {
      throw new Error(`${label} has a probe row without a valid probe id, name or status.`);
    }
    const key = JSON.stringify(row.probe_id);
    if (probes.has(key)) throw new Error(`${label} contains duplicate probe id ${row.probe_id}; matching is ambiguous.`);
    probes.set(key, { probe_id: row.probe_id as number | string, name: row.name, status: row.status });
  }
  const totals: JsonObject = {};
  for (const name of TOTALS) {
    if (!Object.hasOwn(data, name) || data[name] === null) {
      throw new Error(`${label} does not declare ${name}.`);
    }
    totals[name] = data[name];
  }
  if (![data.total_checks, data.findings_count].every(value =>
    typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) ||
      !(typeof data.coverage === 'number' && Number.isFinite(data.coverage) || object(data.coverage)) ||
      !object(data.severity_counts) || !Object.values(data.severity_counts).every(value =>
        typeof value === 'number' && Number.isSafeInteger(value) && value >= 0)) {
    throw new Error(`${label} has invalid graded totals.`);
  }
  return {
    scheme: data.hash_scheme, probes, totals,
    runDate: typeof data.run_started_at === 'string' ? data.run_started_at : 'Not declared',
  };
}

/** Only the requested graded projection is compared; verification stays with /api/verify. */
export function compareReportGrades(firstText: string, secondText: string): GradeComparison {
  try {
    const first = readReport(firstText, 'File one');
    const second = readReport(secondText, 'File two');
    const probes: ProbeDifference[] = [];
    const ids = [...new Set([...first.probes.keys(), ...second.probes.keys()])].sort((a, b) =>
      a.localeCompare(b, 'en', { numeric: true }));
    for (const id of ids) {
      const a = first.probes.get(id);
      const b = second.probes.get(id);
      if (!a || !b || a.name !== b.name || a.status !== b.status) {
        probes.push({
          probeId: (a || b)!.probe_id,
          first: a ? { name: a.name, status: a.status } : null,
          second: b ? { name: b.name, status: b.status } : null,
        });
      }
    }
    const totals = TOTALS.filter(name =>
      displayGradeValue(first.totals[name]) !== displayGradeValue(second.totals[name]))
      .map(name => ({ name, first: first.totals[name], second: second.totals[name] }));
    const common = { schemes: [first.scheme, second.scheme] as [string, string],
      runDates: [first.runDate, second.runDate] as [string, string], probes, totals };
    if (first.scheme !== second.scheme) return {
      ...common, outcome: 'different-schemes',
      reason: `Different hash schemes: file one uses ${first.scheme}; file two uses ${second.scheme}. The reports are not classified as identical.`,
    };
    return {
      ...common, outcome: probes.length || totals.length ? 'different' : 'identical',
      reason: probes.length || totals.length ? 'Graded content differs.' : 'The graded content is identical.',
    };
  } catch (error) {
    return { outcome: 'unavailable', reason: error instanceof Error ? error.message : 'The reports could not be compared.',
      probes: [], totals: [] };
  }
}
