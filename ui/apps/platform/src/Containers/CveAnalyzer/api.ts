import axios from 'services/instance';

import type { Report, Settings, CVERecord, PreflightResult, UpdatesMap } from './types';

const BASE = '/api/v1/cve-analyzer';

export const api = {
  getReports: () =>
    axios.get<Report[]>(`${BASE}/reports`).then((r) => r.data),

  uploadReport: async (file: File, name?: string) => {
    const form = new FormData();
    form.append('file', file);
    if (name) form.append('name', name);
    const res = await axios.post<{ id: string; name: string; warnings?: string[] }>(
      `${BASE}/reports/upload`,
      form
    );
    return res.data;
  },

  analyzeReport: (id: string) =>
    axios.post<{ ok: boolean; warnings?: string[] }>(`${BASE}/reports/${id}/analyze`).then((r) => r.data),

  rebuildReport: (id: string) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/rebuild`).then((r) => r.data),

  abortReport: (id: string) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/abort`).then((r) => r.data),

  deleteReport: (id: string) =>
    axios.delete<{ ok: boolean }>(`${BASE}/reports/${id}`).then((r) => r.data),

  getReportData: (id: string) =>
    axios.get<CVERecord[]>(`${BASE}/reports/${id}/data`).then((r) => r.data),

  getProcessedState: (id: string) =>
    axios.get<string[]>(`${BASE}/reports/${id}/state`).then((r) => r.data),

  saveProcessedState: (id: string, keys: string[]) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/state`, keys).then((r) => r.data),

  getNotes: (id: string) =>
    axios.get<Record<string, string>>(`${BASE}/reports/${id}/notes`).then((r) => r.data),

  saveNotes: (id: string, notes: Record<string, string>) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/notes`, notes).then((r) => r.data),

  getFPState: (id: string) =>
    axios.get<string[]>(`${BASE}/reports/${id}/fp_state`).then((r) => r.data),

  saveFPState: (id: string, keys: string[]) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/fp_state`, keys).then((r) => r.data),

  getUpdates: (id: string) =>
    axios.get<UpdatesMap>(`${BASE}/reports/${id}/updates`).then((r) => r.data),

  acknowledgeUpdates: (id: string, keys: string[]) =>
    axios.post<{ ok: boolean }>(`${BASE}/reports/${id}/updates/acknowledge`, { keys }).then((r) => r.data),

  getSettings: () =>
    axios.get<Settings>(`${BASE}/settings`).then((r) => r.data),

  saveSettings: (s: Settings) =>
    axios.post<{ ok: boolean }>(`${BASE}/settings`, s).then((r) => r.data),

  testConnection: () =>
    axios.post<{ ok: boolean; error?: string; output?: string }>(
      `${BASE}/settings/test`,
      {}
    ).then((r) => r.data),

  preflightCheck: () =>
    axios.get<PreflightResult>(`${BASE}/settings/check`).then((r) => r.data),

  getLog: (id: string) =>
    axios.get<string>(`${BASE}/reports/${id}/log`, { transformResponse: [(d) => d] }).then((r) => r.data),

  downloadFile: (url: string) =>
    axios.get(url, { responseType: 'blob' }),

  analyzeLocal: () =>
    axios.post<{ id: string; name: string }>(`${BASE}/reports/analyze-local`).then((r) => r.data),
};
