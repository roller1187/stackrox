import { useState, useEffect, useCallback, useRef } from 'react';
import { useParams, useNavigate, useSearchParams } from 'react-router-dom-v5-compat';
import {
  PageSection,
  Card, CardBody,
  Tabs, Tab, TabTitleText,
  Spinner, Button, Badge,
  Alert, AlertActionCloseButton,
  Dropdown, DropdownList, DropdownItem, MenuToggle,
} from '@patternfly/react-core';
import { ExportIcon, SyncAltIcon, StopCircleIcon } from '@patternfly/react-icons';
import { api } from './api';
import type { CVERecord, Report, UpdatesMap } from './types';
import { getDowngrade } from './sla';
import CVEDataTab from './CVEDataTab';
import SummaryTab from './SummaryTab';
import ProcessedTab from './ProcessedTab';
import FalsePositivesTab from './FalsePositivesTab';
import UpdatesTab from './UpdatesTab';

const BASE = '/api/v1/cve-analyzer';

const priorityColor: Record<string, string> = {
  'P1-CRITICAL': '#dc2626', 'P1-HIGH-EPSS': '#dc2626',
  'P2-HIGH-IMPACT': '#ea580c', 'P2-HIGH-EPSS': '#ea580c',
  'P3-MODERATE': '#d97706', 'P4-MONITOR': '#2563eb', 'P5-LOW': '#6b7280',
};

export default function ReportPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [report, setReport] = useState<Report | null>(null);
  const [data, setData] = useState<CVERecord[]>([]);
  const [processedKeys, setProcessedKeys] = useState<Set<string>>(new Set());
  const [fpKeys, setFpKeys] = useState<Set<string>>(new Set());
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [noteSaveStatus, setNoteSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchParams, setSearchParams] = useSearchParams();
  const activeTab = searchParams.get('tab') || 'cve';
  const setActiveTab = useCallback((tab: string | number) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      if (String(tab) === 'cve') next.delete('tab'); else next.set('tab', String(tab));
      return next;
    }, { replace: true });
  }, [setSearchParams]);
  const [updates, setUpdates] = useState<UpdatesMap>({});
  const drillParam = searchParams.get('drill');
  const drillFilter = drillParam ? { field: drillParam.split(':')[0], value: drillParam.split(':').slice(1).join(':') } : null;
  const [exportOpen, setExportOpen] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadAllData = useCallback(() => {
    if (!id) return;
    Promise.all([
      api.getReports().then(rs => rs.find(r => r.id === id) || null),
      api.getReportData(id),
      api.getProcessedState(id),
      api.getFPState(id),
      api.getUpdates(id),
      api.getNotes(id),
    ]).then(([rep, d, proc, fp, upd, n]) => {
      setReport(rep);
      const withKeys = d.map(r => ({ ...r, key: r.key || `${r.cve}|||${r.image_full}` }));
      setData(withKeys);
      setProcessedKeys(new Set(proc));
      setFpKeys(new Set(fp));
      setUpdates(upd);
      setNotes(n);
    }).catch(e => setError(String(e)));
  }, [id]);

  const startPolling = useCallback(() => {
    if (pollingRef.current || !id) return;
    pollingRef.current = setInterval(async () => {
      const reports = await api.getReports();
      const r = reports.find(rep => rep.id === id);
      if (r) {
        setReport(r);
        const pipelineDone = r.status !== 'running' && r.status !== 'queued';
        if (pipelineDone) {
          clearInterval(pollingRef.current!);
          pollingRef.current = null;
          setRegenerating(false);
          loadAllData();
        }
      }
    }, 5000);
  }, [id, loadAllData]);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    Promise.all([
      api.getReports().then(rs => rs.find(r => r.id === id) || null),
      api.getReportData(id),
      api.getProcessedState(id),
      api.getFPState(id),
      api.getUpdates(id),
      api.getNotes(id),
    ]).then(([rep, d, proc, fp, upd, n]) => {
      setReport(rep);
      const withKeys = d.map(r => ({ ...r, key: r.key || `${r.cve}|||${r.image_full}` }));
      setData(withKeys);
      setProcessedKeys(new Set(proc));
      setFpKeys(new Set(fp));
      setUpdates(upd);
      setNotes(n);
      if (rep?.status === 'running' || rep?.status === 'queued') {
        setRegenerating(true);
        startPolling();
      }
    }).catch(e => setError(String(e)))
      .finally(() => setLoading(false));
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [id, startPolling]);

  const toggleProcessed = useCallback((key: string) => {
    setProcessedKeys(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      api.saveProcessedState(id!, Array.from(next));
      return next;
    });
  }, [id]);

  const toggleFP = useCallback((key: string) => {
    setFpKeys(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      api.saveFPState(id!, Array.from(next));
      return next;
    });
  }, [id]);

  const batchSetProcessed = useCallback((keys: string[], checked: boolean) => {
    setProcessedKeys(prev => {
      const next = new Set(prev);
      for (const key of keys) {
        if (checked) next.add(key); else next.delete(key);
      }
      api.saveProcessedState(id!, Array.from(next));
      return next;
    });
  }, [id]);

  const setNote = useCallback(async (key: string, note: string) => {
    const next = { ...notes };
    if (note) next[key] = note; else delete next[key];
    setNotes(next);
    setNoteSaveStatus('saving');
    try {
      await api.saveNotes(id!, next);
      setNoteSaveStatus('saved');
      setTimeout(() => setNoteSaveStatus(s => s === 'saved' ? 'idle' : s), 2000);
    } catch {
      setNoteSaveStatus('error');
    }
  }, [id, notes]);

  const batchSetFP = useCallback((keys: string[], checked: boolean) => {
    setFpKeys(prev => {
      const next = new Set(prev);
      for (const key of keys) {
        if (checked) next.add(key); else next.delete(key);
      }
      api.saveFPState(id!, Array.from(next));
      return next;
    });
  }, [id]);

  const handleDrill = useCallback((field: string, value: string) => {
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      next.set('drill', `${field}:${value}`);
      next.delete('tab');
      return next;
    }, { replace: true });
  }, [setSearchParams]);

  const acknowledgeUpdate = useCallback((keys: string[]) => {
    if (!id) return;
    setUpdates(prev => {
      const next = { ...prev };
      for (const key of keys) {
        if (next[key]) next[key] = { ...next[key], acknowledged: true };
      }
      return next;
    });
    api.acknowledgeUpdates(id, keys).catch(() => {});
  }, [id]);

  const handleRegenerate = useCallback(async () => {
    if (!id || regenerating) return;
    setRegenerating(true);
    try {
      await api.analyzeReport(id);
      startPolling();
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Unknown error';
      alert(msg);
      setRegenerating(false);
    }
  }, [id, regenerating, startPolling]);

  const handleAbort = useCallback(async () => {
    if (!id) return;
    try {
      await api.abortReport(id);
      setRegenerating(false);
      if (pollingRef.current) {
        clearInterval(pollingRef.current);
        pollingRef.current = null;
      }
      loadAllData();
    } catch { /* ignore */ }
  }, [id, loadAllData]);

  if (loading) {
    return (
      <PageSection style={{ display: 'flex', justifyContent: 'center', paddingTop: 80 }}>
        <Spinner size="xl" />
      </PageSection>
    );
  }

  if (error) {
    return (
      <PageSection>
        <Alert variant="danger" title="Failed to load report" actionClose={<AlertActionCloseButton onClose={() => navigate('/main/cve-analyzer')} />}>
          {error}
        </Alert>
      </PageSection>
    );
  }

  const patchCount = data.filter(r => r.action === 'PATCH').length;
  const updateCount = data.filter(r => r.action === 'UPDATE').length;
  const monitorCount = data.filter(r => r.action === 'MONITOR').length;
  const kevCount = new Set(data.filter(r => r.kev_date_added).map(r => r.cve)).size;
  const uniqueCves = new Set(data.map(r => r.cve)).size;
  const p1Count = data.filter(r => r.priority.startsWith('P1')).length;
  const fixedCount = data.filter(r => r.fix_status === 'FIXED_IN_LATEST').length;
  const vulnCount = data.filter(r => r.fix_status === 'STILL_VULNERABLE').length;
  const downgradedCount = data.filter(r => getDowngrade(r) !== null).length;

  const priorityCounts: Record<string, number> = {};
  for (const r of data) {
    priorityCounts[r.priority] = (priorityCounts[r.priority] || 0) + 1;
  }

  const unackUpdates = Object.entries(updates).filter(([, u]) => !u.acknowledged);
  const cveUpdateCount = unackUpdates.filter(([key]) => !processedKeys.has(key) && !fpKeys.has(key)).length;
  const procUpdateCount = unackUpdates.filter(([key]) => processedKeys.has(key)).length;
  const fpUpdateCount = unackUpdates.filter(([key]) => fpKeys.has(key)).length;
  const totalUpdateCount = cveUpdateCount + procUpdateCount + fpUpdateCount;

  const updateBadge = (count: number) =>
    count > 0 ? (
      <Badge
        isRead={false}
        style={{ marginLeft: 8, cursor: 'pointer' }}
        onClick={(e: React.MouseEvent) => { e.stopPropagation(); setActiveTab('updates'); }}
      >
        {count}
      </Badge>
    ) : null;

  if (activeTab === 'updates' && totalUpdateCount === 0) {
    setActiveTab('cve');
  }

  return (
    <PageSection>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Button variant="link" onClick={() => navigate('/main/cve-analyzer')}>CVE Analyzer</Button>
          <span style={{ color: '#475569' }}>/</span>
          <span style={{ fontWeight: 600, fontSize: '1.1rem' }}>{report?.name || id}</span>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            {regenerating ? (
              <Button
                variant="danger"
                icon={<StopCircleIcon />}
                onClick={handleAbort}
              >
                Abort Regeneration
              </Button>
            ) : (
              <Button
                variant="secondary"
                icon={<SyncAltIcon />}
                onClick={handleRegenerate}
              >
                Regenerate
              </Button>
            )}
            {report?.regenerated_at && !regenerating && (
              <span style={{ fontSize: '.7rem', color: '#64748b', marginTop: 2 }}>
                Last: {new Date(report.regenerated_at).toLocaleDateString()} - {new Date(report.regenerated_at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}
              </span>
            )}
          </div>
          <Dropdown
          isOpen={exportOpen}
          onSelect={() => setExportOpen(false)}
          onOpenChange={setExportOpen}
          toggle={(toggleRef) => (
            <MenuToggle
              ref={toggleRef}
              onClick={() => setExportOpen(prev => !prev)}
              variant="secondary"
              icon={<ExportIcon />}
            >
              Export
            </MenuToggle>
          )}
          popperProps={{ position: 'right' }}
        >
          <DropdownList>
            <DropdownItem key="csv" onClick={async () => {
              try {
                const resp = await api.downloadFile(`${BASE}/reports/${id}/export.csv`);
                const blob = new Blob([resp.data], { type: 'text/csv' });
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = `${report?.name || 'report'}.csv`;
                a.click();
              } catch { /* ignore */ }
            }}>
              CSV
            </DropdownItem>
            <DropdownItem key="html" onClick={async () => {
              try {
                const resp = await api.downloadFile(`${BASE}/reports/${id}/report.html`);
                const blob = new Blob([resp.data], { type: 'text/html' });
                window.open(URL.createObjectURL(blob), '_blank');
              } catch { /* ignore */ }
            }}>
              HTML
            </DropdownItem>
          </DropdownList>
        </Dropdown>
        </div>
      </div>

      {regenerating && (
        <Alert variant="info" isInline title={report?.status === 'queued' ? 'Regeneration queued' : 'Regenerating report...'} style={{ marginBottom: 16 }}>
          <Spinner size="md" style={{ marginRight: 8 }} />
          {report?.status === 'queued'
            ? 'Waiting for other pipelines to finish. This report will start automatically.'
            : 'The pipeline is running. Data will refresh automatically when complete.'}
        </Alert>
      )}

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <StatCard label="Total Records" value={data.length} />
        <StatCard label="Unique CVEs" value={uniqueCves} />
        <StatCard label="PATCH" value={patchCount} color="#dc2626" onClick={() => handleDrill('action', 'PATCH')} />
        <StatCard label="UPDATE" value={updateCount} color="#16a34a" onClick={() => handleDrill('action', 'UPDATE')} />
        <StatCard label="MONITOR" value={monitorCount} color="#2563eb" onClick={() => handleDrill('action', 'MONITOR')} />
        <StatCard label="P1" value={p1Count} color="#dc2626" onClick={() => handleDrill('priority', 'P1')} />
        <StatCard label="KEV" value={kevCount} color="#d97706" onClick={() => handleDrill('kev', 'true')} />
        <StatCard label="Fixed" value={fixedCount} color="#16a34a" onClick={() => handleDrill('fix_status', 'FIXED_IN_LATEST')} />
        <StatCard label="Not Fixed" value={vulnCount} color="#dc2626" onClick={() => handleDrill('fix_status', 'STILL_VULNERABLE')} />
        <StatCard label="Downgraded" value={downgradedCount} color="#d97706" onClick={() => handleDrill('downgraded', 'true')} />
        <StatCard label="Processed" value={processedKeys.size} color="#6b7280" />
        <StatCard label="FP" value={fpKeys.size} color="#6b7280" />
      </div>

      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 12 }}>
        {Object.entries(priorityCounts)
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([p, c]) => (
            <span key={p} style={{
              backgroundColor: priorityColor[p] || '#6b7280', color: '#fff',
              padding: '2px 8px', borderRadius: 4, fontSize: '.72rem', cursor: 'pointer',
            }} onClick={() => handleDrill('priority', p)}>
              {p}: {c}
            </span>
          ))}
      </div>

      <Tabs activeKey={activeTab} onSelect={(_e, k) => setActiveTab(k)}>
        <Tab eventKey="cve" title={
          <TabTitleText>CVE Data ({data.length}){updateBadge(cveUpdateCount)}</TabTitleText>
        }>
          <CVEDataTab
            data={data}
            processedKeys={processedKeys}
            fpKeys={fpKeys}
            onToggleProcessed={toggleProcessed}
            onToggleFP={toggleFP}
            onBatchProcessed={batchSetProcessed}
            onBatchFP={batchSetFP}
            drillFilter={drillFilter}
            onClearDrill={() => setSearchParams(prev => { const next = new URLSearchParams(prev); next.delete('drill'); return next; }, { replace: true })}
            updates={updates}
            onAcknowledge={acknowledgeUpdate}
            searchParams={searchParams}
            setSearchParams={setSearchParams}
            notes={notes}
            onSetNote={setNote}
            noteSaveStatus={noteSaveStatus}
          />
        </Tab>
        <Tab eventKey="summary" title={<TabTitleText>Summary</TabTitleText>}>
          <SummaryTab data={data} onDrillDown={handleDrill} />
        </Tab>
        <Tab eventKey="processed" title={
          <TabTitleText>Processed ({processedKeys.size}){updateBadge(procUpdateCount)}</TabTitleText>
        }>
          <ProcessedTab data={data} processedKeys={processedKeys} fpKeys={fpKeys} onToggleProcessed={toggleProcessed} onToggleFP={toggleFP} updates={updates} onAcknowledge={acknowledgeUpdate} notes={notes} onSetNote={setNote} noteSaveStatus={noteSaveStatus} />
        </Tab>
        <Tab eventKey="fp" title={
          <TabTitleText>False Positives ({fpKeys.size}){updateBadge(fpUpdateCount)}</TabTitleText>
        }>
          <FalsePositivesTab data={data} processedKeys={processedKeys} fpKeys={fpKeys} onToggleProcessed={toggleProcessed} onToggleFP={toggleFP} updates={updates} onAcknowledge={acknowledgeUpdate} />
        </Tab>
        {totalUpdateCount > 0 && (
          <Tab eventKey="updates" title={
            <TabTitleText>Updates ({totalUpdateCount})</TabTitleText>
          }>
            <UpdatesTab data={data} updates={updates} processedKeys={processedKeys} fpKeys={fpKeys} onToggleProcessed={toggleProcessed} onToggleFP={toggleFP} onAcknowledge={acknowledgeUpdate} />
          </Tab>
        )}
      </Tabs>
    </PageSection>
  );
}

function StatCard({ label, value, color, onClick }: { label: string; value: number; color?: string; onClick?: () => void }) {
  return (
    <Card isCompact isClickable={!!onClick} onClick={onClick} style={{ flex: 1, minWidth: 0, textAlign: 'center', cursor: onClick ? 'pointer' : 'default' }}>
      <CardBody style={{ padding: '8px 4px' }}>
        <div style={{ fontSize: '1.4rem', fontWeight: 700, color: color || '#e2e8f0', lineHeight: 1.2 }}>{value}</div>
        <div style={{ fontSize: '.72rem', color: '#94a3b8', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</div>
      </CardBody>
    </Card>
  );
}
