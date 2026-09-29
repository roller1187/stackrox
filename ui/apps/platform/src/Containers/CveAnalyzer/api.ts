import type { Report, Settings, CVERecord, PreflightResult, UpdatesMap } from './types';

function getBase(): string {
  const w = window as unknown as Record<string, unknown>;
  if (w.__CVE_ANALYZER_API__) return String(w.__CVE_ANALYZER_API__);
  return '/api/v1/cve-analyzer';
}
const BASE = getBase();

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, init);
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.error) msg = body.error;
    } catch { /* use default msg */ }
    throw new ApiError(res.status, msg);
  }
  return res.json();
}

export const api = {
  getReports: () => fetchJson<Report[]>(`${BASE}/reports`),

  uploadReport: async (file: File, name?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (name) form.append('name', name);
    return fetchJson<{ id: string; name: string; warnings?: string[] }>(
      `${BASE}/reports/upload`,
      { method: 'POST', body: form }
    );
  },

  analyzeReport: (id: string) =>
    fetchJson<{ ok: boolean; warnings?: string[] }>(
      `${BASE}/reports/${id}/analyze`,
      { method: 'POST' }
    ),

  rebuildReport: (id: string) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}/rebuild`, { method: 'POST' }),

  abortReport: (id: string) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}/abort`, { method: 'POST' }),

  deleteReport: (id: string) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}`, { method: 'DELETE' }),

  getReportData: (id: string) => fetchJson<CVERecord[]>(`${BASE}/reports/${id}/data`),

  getProcessedState: (id: string) => fetchJson<string[]>(`${BASE}/reports/${id}/state`),

  saveProcessedState: (id: string, keys: string[]) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}/state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(keys),
    }),

  getFPState: (id: string) => fetchJson<string[]>(`${BASE}/reports/${id}/fp_state`),

  saveFPState: (id: string, keys: string[]) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}/fp_state`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(keys),
    }),

  getUpdates: (id: string) => fetchJson<UpdatesMap>(`${BASE}/reports/${id}/updates`),

  acknowledgeUpdates: (id: string, keys: string[]) =>
    fetchJson<{ ok: boolean }>(`${BASE}/reports/${id}/updates/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ keys }),
    }),

  getSettings: () => fetchJson<Settings>(`${BASE}/settings`),

  saveSettings: (s: Settings) =>
    fetchJson<{ ok: boolean }>(`${BASE}/settings`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(s),
    }),

  testConnection: (ep: string, token: string, skipTls: boolean) =>
    fetchJson<{ ok: boolean; error?: string; output?: string }>(
      `${BASE}/settings/test`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rox_endpoint: ep, rox_api_token: token, skip_tls_verify: skipTls }),
      }
    ),

  preflightCheck: () => fetchJson<PreflightResult>(`${BASE}/settings/check`),
};
