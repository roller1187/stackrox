export interface SLAStatus {
  daysRemaining: number;
  breached: boolean;
  tier: string;
  deadline: string;
}

const MS_PER_DAY = 86_400_000;

export function computeSLA(r: { sla_deadline: string; sla_tier: string; fix_status?: string }): SLAStatus | null {
  if (!r.sla_deadline) return null;
  const dl = new Date(r.sla_deadline + 'T00:00:00');
  if (isNaN(dl.getTime())) return null;
  const daysRemaining = Math.ceil((dl.getTime() - Date.now()) / MS_PER_DAY);
  const confirmed_unfixed = r.fix_status === 'STILL_VULNERABLE';
  return {
    daysRemaining,
    breached: daysRemaining < 0 && confirmed_unfixed,
    tier: r.sla_tier || '',
    deadline: r.sla_deadline,
  };
}

const TIER_WINDOWS: Record<string, number> = {
  'Critical/High': 30,
  'Moderate': 90,
  'Low': 180,
};

export function slaWindow(tier: string): number {
  return TIER_WINDOWS[tier] || 180;
}

const SEV_RANK: Record<string, number> = {
  CRITICAL: 4, CRITICAL_VULNERABILITY_SEVERITY: 4,
  IMPORTANT: 3, IMPORTANT_VULNERABILITY_SEVERITY: 3,
  MODERATE: 2, MODERATE_VULNERABILITY_SEVERITY: 2,
  LOW: 1, LOW_VULNERABILITY_SEVERITY: 1,
};

const SEV_LABEL: Record<number, string> = {
  4: 'Critical', 3: 'Important', 2: 'Moderate', 1: 'Low',
};

export interface DowngradeInfo {
  from: string;
  to: string;
}

export function getDowngrade(r: { severity: string; rh_severity: string }): DowngradeInfo | null {
  if (!r.severity || !r.rh_severity) return null;
  const nvdRank = SEV_RANK[r.severity.toUpperCase()] || SEV_RANK[r.severity] || 0;
  const rhRank = SEV_RANK[r.rh_severity.toUpperCase()] || SEV_RANK[r.rh_severity] || 0;
  if (!nvdRank || !rhRank || rhRank >= nvdRank) return null;
  return { from: SEV_LABEL[nvdRank] || r.severity, to: SEV_LABEL[rhRank] || r.rh_severity };
}

const METRIC_NAMES: Record<string, string> = {
  AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required',
  UI: 'User Interaction', S: 'Scope', C: 'Confidentiality', I: 'Integrity', A: 'Availability',
};
const METRIC_VALUES: Record<string, Record<string, string>> = {
  AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  AC: { L: 'Low', H: 'High' },
  PR: { N: 'None', L: 'Low', H: 'High' },
  UI: { N: 'None', R: 'Required' },
  S: { U: 'Unchanged', C: 'Changed' },
  C: { N: 'None', L: 'Low', H: 'High' },
  I: { N: 'None', L: 'Low', H: 'High' },
  A: { N: 'None', L: 'Low', H: 'High' },
};
const METRIC_SEVERITY: Record<string, Record<string, number>> = {
  AV: { N: 4, A: 3, L: 2, P: 1 }, AC: { L: 2, H: 1 },
  PR: { N: 3, L: 2, H: 1 }, UI: { N: 2, R: 1 },
  S: { C: 2, U: 1 }, C: { H: 3, L: 2, N: 1 },
  I: { H: 3, L: 2, N: 1 }, A: { H: 3, L: 2, N: 1 },
};

function parseVector(v: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const part of v.split('/')) {
    const [key, val] = part.split(':');
    if (key && val && METRIC_NAMES[key]) result[key] = val;
  }
  return result;
}

export interface VectorDiff { metric: string; rhValue: string; note: string }

const MAX_SLA_DAYS = 180;

export function getImageAge(publishedDate: string): number | null {
  if (!publishedDate) return null;
  const d = new Date(publishedDate);
  if (isNaN(d.getTime())) return null;
  return Math.floor((Date.now() - d.getTime()) / MS_PER_DAY);
}

export function isImageDeprecated(publishedDate: string): boolean {
  const age = getImageAge(publishedDate);
  if (age === null) return false;
  return age > MAX_SLA_DAYS;
}

export function explainDowngrade(rhVector: string, nvdCvss: string, rhCvss: string): { diffs: VectorDiff[]; summary: string } {
  const rh = parseVector(rhVector);
  const diffs: VectorDiff[] = [];

  for (const [key, val] of Object.entries(rh)) {
    const sev = METRIC_SEVERITY[key];
    if (!sev) continue;
    const valSev = sev[val] || 0;
    const maxSev = Math.max(...Object.values(sev));
    if (valSev < maxSev) {
      const name = METRIC_NAMES[key] || key;
      const display = METRIC_VALUES[key]?.[val] || val;
      diffs.push({ metric: name, rhValue: display, note: `${name}: ${display}` });
    }
  }

  const nvd = parseFloat(nvdCvss) || 0;
  const rhScore = parseFloat(rhCvss) || 0;
  const delta = nvd - rhScore;
  let summary = '';
  if (delta > 0) {
    summary = `Red Hat scored this ${delta.toFixed(1)} points lower than NVD`;
    if (diffs.length > 0) {
      const factors = diffs.slice(0, 3).map(d => d.note).join(', ');
      summary += ` based on: ${factors}.`;
    }
  } else if (rhScore > 0) {
    summary = 'Red Hat and NVD CVSS scores are identical, but Red Hat assigned a lower severity label based on product-specific impact analysis.';
    if (diffs.length > 0) {
      const factors = diffs.slice(0, 3).map(d => d.note).join(', ');
      summary += ` CVSS vector factors: ${factors}.`;
    }
  }
  return { diffs, summary };
}
