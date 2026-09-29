import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { Button, Checkbox, Label } from '@patternfly/react-core';
import { FlagIcon, OutlinedFlagIcon } from '@patternfly/react-icons';
import type { CVERecord, UpdatesMap } from './types';
import { computeSLA, slaWindow, getDowngrade, explainDowngrade, isImageDeprecated, getImageAge } from './sla';

const priorityColor: Record<string, string> = {
  'P1-CRITICAL': '#dc2626', 'P1-HIGH-EPSS': '#dc2626',
  'P2-HIGH-IMPACT': '#ea580c', 'P2-HIGH-EPSS': '#ea580c',
  'P3-MODERATE': '#d97706', 'P4-MONITOR': '#2563eb', 'P5-LOW': '#6b7280',
};
const actionColor: Record<string, string> = { PATCH: '#dc2626', MONITOR: '#2563eb' };
const fixColor: Record<string, string> = {
  FIXED_IN_LATEST: '#16a34a', STILL_VULNERABLE: '#dc2626', SCAN_UNAVAILABLE: '#6b7280',
};
const fixLabel: Record<string, string> = {
  FIXED_IN_LATEST: 'FIXED', STILL_VULNERABLE: 'NOT FIXED', SCAN_UNAVAILABLE: 'N/A',
};
const roxColor: Record<string, string> = {
  CONFIRMED: '#16a34a', NOT_FOUND: '#d97706', SCAN_ERROR: '#dc2626',
};

const FIELD_LABELS: Record<string, string> = {
  priority: 'Priority', action: 'Action', cvss: 'CVSS', rh_cvss: 'RH CVSS',
  epss_pct: 'EPSS', fix_status: 'Fix Status', severity: 'Severity',
  rh_severity: 'RH Severity', kev_date_added: 'KEV', component_version: 'Version',
  fixed_in: 'Fixed In',
};

function buildImageLink(ref: string, catUrl: string) {
  if (!ref) return null;
  if (ref.includes('quay.io/') && ref.includes('@sha256:') && !ref.includes('ocp-v4.0-art-dev')) {
    const [repo, digest] = ref.split('@');
    const rp = repo.replace('quay.io/', '');
    return `https://quay.io/repository/${rp}/manifest/${digest}`;
  }
  if (catUrl) return catUrl;
  if (ref.includes('quay.io/')) {
    const rp = ref.replace('quay.io/', '').split(':')[0];
    return `https://quay.io/repository/${rp}`;
  }
  return null;
}

function DetailSection({ title, children, borderColor }: { title: string; children: React.ReactNode; borderColor?: string }) {
  return (
    <div style={{
      border: `1px solid ${borderColor || '#334155'}`,
      borderRadius: 6,
      padding: 12,
      marginBottom: 10,
      borderLeftWidth: 3,
      borderLeftColor: borderColor || '#334155',
    }}>
      <div style={{ fontSize: '.72rem', fontWeight: 600, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '.03em', marginBottom: 6 }}>{title}</div>
      {children}
    </div>
  );
}

const SEV_ORDER = ['Critical', 'Important', 'Moderate', 'Low'] as const;
const SEV_COLORS: Record<string, string> = {
  Critical: '#dc2626', Important: '#ea580c', Moderate: '#d97706', Low: '#6b7280',
};

function normalizeSeverity(sev: string): string {
  const s = sev.charAt(0).toUpperCase() + sev.slice(1).toLowerCase();
  if (s === 'High') return 'Important';
  if (s === 'Medium') return 'Moderate';
  if (SEV_ORDER.includes(s as typeof SEV_ORDER[number])) return s;
  return 'Low';
}

function VulnDonut({ counts, total, patchable, imageShort }: { counts: Record<string, number>; total: number; patchable: number; imageShort: string }) {
  const r = 46, cx = 56, cy = 56, stroke = 16;
  const circumference = 2 * Math.PI * r;
  let offset = -0.25 * circumference;

  const segments = SEV_ORDER.map(sev => {
    const count = counts[sev] || 0;
    const pct = total > 0 ? count / total : 0;
    const dashLen = pct * circumference;
    const seg = { sev, count, pct, dashLen, offset, color: SEV_COLORS[sev] };
    offset += dashLen;
    return seg;
  }).filter(s => s.count > 0);

  const centerContent = (
    <>
      <text x={cx} y={cy - 4} textAnchor="middle" fill="#e2e8f0" fontSize="16" fontWeight="700">{total}</text>
      <text x={cx} y={cy + 10} textAnchor="middle" fill="#94a3b8" fontSize="8">findings</text>
    </>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
      <svg width={112} height={112} viewBox="0 0 112 112">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#334155" strokeWidth={stroke} />
        {segments.map(s => (
          <circle key={s.sev} cx={cx} cy={cy} r={r} fill="none"
            stroke={s.color} strokeWidth={stroke}
            strokeDasharray={`${s.dashLen} ${circumference - s.dashLen}`}
            strokeDashoffset={-s.offset}
          />
        ))}
        {centerContent}
      </svg>
      <div style={{ fontSize: '.72rem' }}>
        {SEV_ORDER.map(sev => {
          const count = counts[sev] || 0;
          if (!count) return null;
          return (
            <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 2 }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV_COLORS[sev], display: 'inline-block', flexShrink: 0 }} />
              <span style={{ color: '#e2e8f0' }}>{sev}: {count}</span>
            </div>
          );
        })}
        <div style={{ marginTop: 4, fontSize: '.68rem' }}>
          <a
            href={`${window.location.pathname}?search=${encodeURIComponent(imageShort)}&drill=fix_status:FIXED_IN_LATEST`}
            style={{ color: '#38bdf8', textDecoration: 'none' }}
          >
            {patchable} patchable
          </a>
        </div>
      </div>
    </div>
  );
}

interface Props {
  row: CVERecord;
  processedKeys: Set<string>;
  fpKeys: Set<string>;
  onToggleProcessed: (key: string) => void;
  onToggleFP: (key: string) => void;
  updates: UpdatesMap;
  onAcknowledge: (keys: string[]) => void;
  onClose: () => void;
  toolbarRef?: React.RefObject<HTMLDivElement | null>;
  allData?: CVERecord[];
}

export default function RecordDetailPanel({ row, processedKeys, fpKeys, onToggleProcessed, onToggleFP, updates, onAcknowledge, onClose, toolbarRef, allData }: Props) {
  const upd = updates[row.key];
  const hasUpdate = upd && !upd.acknowledged;

  const imageVulns = useMemo(() => {
    if (!allData) return null;
    const records = allData.filter(r => r.image_full === row.image_full);
    if (records.length <= 1) return null;
    const counts: Record<string, number> = {};
    let patchable = 0;
    for (const r of records) {
      const sev = normalizeSeverity(r.rh_severity || r.severity || '');
      counts[sev] = (counts[sev] || 0) + 1;
      if (r.fix_status === 'FIXED_IN_LATEST') patchable++;
    }
    return { counts, total: records.length, patchable };
  }, [allData, row.image_full]);

  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [onClose]);

  const [drawerTop, setDrawerTop] = useState(0);

  const recalcTop = useCallback(() => {
    if (!toolbarRef?.current) return;
    const rect = toolbarRef.current.getBoundingClientRect();
    setDrawerTop(Math.max(0, rect.bottom));
  }, [toolbarRef]);

  useEffect(() => {
    recalcTop();

    let scrollEl: HTMLElement | Window = window;
    if (toolbarRef?.current) {
      let parent: HTMLElement | null = toolbarRef.current.parentElement;
      while (parent) {
        const s = getComputedStyle(parent);
        if (/(auto|scroll)/.test(s.overflow + s.overflowY)) {
          scrollEl = parent;
          break;
        }
        parent = parent.parentElement;
      }
    }

    scrollEl.addEventListener('scroll', recalcTop, { passive: true });
    window.addEventListener('resize', recalcTop, { passive: true });
    return () => {
      scrollEl.removeEventListener('scroll', recalcTop);
      window.removeEventListener('resize', recalcTop);
    };
  }, [recalcTop, toolbarRef]);

  return (
    <div ref={panelRef} style={{
      position: 'fixed', top: drawerTop, right: 0, width: '50%', maxWidth: 700,
      height: `calc(100vh - ${drawerTop}px)`, overflowY: 'auto', zIndex: 400,
      background: 'var(--pf-t--global--background--color--primary--default, #1b1d21)',
      borderLeft: '1px solid #334155',
      boxShadow: '-4px 0 12px rgba(0,0,0,.3)',
    }}>
      <div style={{ padding: '16px 20px' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
          <Label style={{ backgroundColor: priorityColor[row.priority] || '#6b7280', color: '#fff' }}>
            {row.priority}
          </Label>
          <Label style={{ backgroundColor: actionColor[row.action] || '#6b7280', color: '#fff' }}>
            {row.action}
          </Label>
          {row.primary_link ? (
            <a href={row.primary_link} target="_blank" rel="noreferrer"
              style={{ color: '#38bdf8', fontWeight: 600, fontSize: '1.1rem' }}>{row.cve}</a>
          ) : (
            <span style={{ fontWeight: 600, fontSize: '1.1rem' }}>{row.cve}</span>
          )}
          {row.kev_date_added && (
            <Label style={{ backgroundColor: '#d97706', color: '#fff' }}>KEV</Label>
          )}
        </div>
        <div style={{ display: 'flex', gap: 12, marginTop: 8, fontSize: '.82rem', color: '#94a3b8' }}>
          {row.rh_cvss && row.rh_cvss !== '0' && <span>RH CVSS: <strong style={{ color: '#e2e8f0' }}>{row.rh_cvss}</strong></span>}
          {row.cvss && row.cvss !== '0' && <span>CVSS: {row.cvss}</span>}
          {row.epss_pct && <span>EPSS: {row.epss_pct}%</span>}
        </div>
        <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
          <Checkbox
            id="drawer-processed"
            label="Processed"
            isChecked={processedKeys.has(row.key)}
            onChange={() => onToggleProcessed(row.key)}
          />
          <Button
            variant="plain"
            onClick={() => onToggleFP(row.key)}
            aria-label="Toggle false positive"
            style={{ color: fpKeys.has(row.key) ? '#ef4444' : '#6b7280', padding: 2 }}
          >
            {fpKeys.has(row.key) ? <FlagIcon /> : <OutlinedFlagIcon />}
          </Button>
        </div>
        {hasUpdate && (
          <div style={{ marginTop: 8, padding: '6px 10px', borderRadius: 4, backgroundColor: 'rgba(217,119,6,.15)', border: '1px solid #d97706' }}>
            <div style={{ fontSize: '.72rem', fontWeight: 600, color: '#d97706', marginBottom: 4 }}>Changed since last scan</div>
            {Object.entries(upd.fields).map(([f, v]) => (
              <div key={f} style={{ fontSize: '.78rem', color: '#e2e8f0' }}>
                {FIELD_LABELS[f] || f}: <span style={{ color: '#94a3b8' }}>{v.old || '--'}</span> {'->'} <span style={{ color: '#d97706' }}>{v.new || '--'}</span>
              </div>
            ))}
            <Button variant="link" size="sm" style={{ marginTop: 4, padding: 0 }} onClick={() => onAcknowledge([row.key])}>
              Acknowledge
            </Button>
          </div>
        )}
        <Button variant="plain" onClick={onClose} style={{ position: 'absolute', top: 12, right: 12 }} aria-label="Close">X</Button>
      </div>
      <div style={{ padding: '0 20px 20px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px 12px', fontSize: '.82rem', marginBottom: 8 }}>
          <span style={{ color: '#94a3b8' }}>Product</span><span>{row.product}</span>
          <span style={{ color: '#94a3b8' }}>Image</span><span>{row.image_short}</span>
          <span style={{ color: '#94a3b8' }}>Full Image</span>
          <span style={{ wordBreak: 'break-all', fontSize: '.75rem' }}>
            {row.image_catalog_url ? (
              <a href={row.image_catalog_url} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>{row.image_full}</a>
            ) : row.image_full}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '6px 12px', fontSize: '.82rem', flex: 1, minWidth: 0, alignContent: 'start' }}>
          <span style={{ color: '#94a3b8' }}>Cluster</span><span>{row.cluster}</span>
          <span style={{ color: '#94a3b8' }}>Namespaces</span><span>{row.namespaces}</span>
          <span style={{ color: '#94a3b8' }}>Deployments</span><span>{row.deployments}</span>
          <span style={{ color: '#94a3b8' }}>Component</span>
          <span>
            {row.component} {row.component_version}
          </span>
          <span style={{ color: '#94a3b8' }}>Fixed In</span><span>{row.fixed_in || '--'}</span>
          {row.cve_published && (
            <><span style={{ color: '#94a3b8' }}>CVE Published</span><span>{(() => {
              try {
                const d = new Date(row.cve_published);
                if (isNaN(d.getTime())) return row.cve_published;
                const formatted = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
                const days = Math.floor((Date.now() - d.getTime()) / 86_400_000);
                if (days < 0) return formatted;
                const ago = days === 0 ? 'today' : days === 1 ? '1 day ago' : `${days} days ago`;
                return <>{formatted} <span style={{ color: '#64748b', marginLeft: 6 }}>({ago})</span></>;
              } catch { return row.cve_published; }
            })()}</span></>
          )}
          <span style={{ color: '#94a3b8' }}>Discovered</span><span>{(() => {
            if (!row.discovered) return '--';
            try {
              const d = new Date(row.discovered);
              if (isNaN(d.getTime())) return row.discovered;
              const formatted = d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
              const days = Math.floor((Date.now() - d.getTime()) / 86_400_000);
              if (days < 0) return formatted;
              const ago = days === 0 ? 'today' : days === 1 ? '1 day ago' : `${days} days ago`;
              return <>{formatted} <span style={{ color: '#64748b', marginLeft: 6 }}>({ago})</span></>;
            } catch { return row.discovered; }
          })()}</span>
          {row.rh_severity && (
            <><span style={{ color: '#94a3b8' }}>RH Severity</span><span>{row.rh_severity}</span></>
          )}
          {row.rh_vector && (
            <><span style={{ color: '#94a3b8' }}>RH Vector</span><span style={{ fontSize: '.75rem' }}>{row.rh_vector}</span></>
          )}
        </div>
        {imageVulns && (
          <div style={{ flexShrink: 0 }}>
            <VulnDonut counts={imageVulns.counts} total={imageVulns.total} patchable={imageVulns.patchable} imageShort={row.image_short} />
          </div>
        )}
        </div>

        {(() => {
          const dg = getDowngrade(row);
          if (!dg) return null;
          const explanation = row.rh_vector ? explainDowngrade(row.rh_vector, row.cvss || row.nvd_cvss || '', row.rh_cvss || '') : null;
          return (
            <DetailSection title="Severity Downgrade" borderColor="#d97706">
              <div style={{ fontSize: '.82rem' }}>
                <div>NVD rated this <strong>{dg.from}</strong>, Red Hat downgraded to <strong>{dg.to}</strong></div>
                <div style={{ marginTop: 4, fontSize: '.75rem', color: '#94a3b8' }}>
                  CVSS: {row.cvss || row.nvd_cvss || '--'} (NVD) -&gt; {row.rh_cvss && row.rh_cvss !== '0' ? row.rh_cvss : '--'} (RH)
                </div>
                {explanation?.summary && (
                  <div style={{ marginTop: 8, padding: '8px 10px', background: 'rgba(217,119,6,.08)', borderRadius: 4, fontSize: '.78rem', color: '#d4a373' }}>
                    {explanation.summary}
                  </div>
                )}
                {explanation && explanation.diffs.length > 0 && (
                  <div style={{ marginTop: 8 }}>
                    <div style={{ fontSize: '.72rem', color: '#6b7280', marginBottom: 4 }}>RH CVSS vector factors reducing the score:</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {explanation.diffs.map(d => (
                        <span key={d.metric} style={{
                          padding: '2px 8px', borderRadius: 4, fontSize: '.7rem',
                          background: 'rgba(217,119,6,.12)', color: '#d97706',
                        }}>{d.metric}: {d.rhValue}</span>
                      ))}
                    </div>
                  </div>
                )}
                {row.rh_statement && (
                  <div style={{ marginTop: 8, fontSize: '.75rem', color: '#94a3b8' }}>See Red Hat Statement below for full justification</div>
                )}
              </div>
            </DetailSection>
          );
        })()}

        {row.remediation_path && (
          <DetailSection title="Remediation Path">
            <div style={{ fontSize: '.82rem' }}>{row.remediation_path}</div>
          </DetailSection>
        )}

        {row.rhsa_advisory && (
          <DetailSection title="Red Hat Advisory">
            <div style={{ fontSize: '.82rem' }}>
              {row.advisory_link ? (
                <a href={row.advisory_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>{row.rhsa_advisory}</a>
              ) : row.rhsa_advisory}
              {row.rhsa_description && (
                <div style={{ marginTop: 6, color: '#94a3b8' }}>{row.rhsa_description}</div>
              )}
            </div>
          </DetailSection>
        )}

        <DetailSection title="roxctl Scan Verification">
          <div style={{ fontSize: '.82rem' }}>
            <div>
              Current image:{' '}
              <Label style={{ backgroundColor: roxColor[row.rox_status] || '#6b7280', color: '#fff' }}>
                {row.rox_status || 'N/A'}
              </Label>
              {row.rox_fix_version && <span style={{ marginLeft: 8 }}>Fix: {row.rox_fix_version}</span>}
            </div>
            {row.image_full && (
              <div style={{ marginTop: 4, fontSize: '.78rem', wordBreak: 'break-all' }}>
                {row.image_catalog_url ? (
                  <a href={row.image_catalog_url} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>{row.image_full}</a>
                ) : <span style={{ color: '#94a3b8' }}>{row.image_full}</span>}
              </div>
            )}
            {row.fix_status && (
              <div style={{ marginTop: 8, borderTop: '1px solid #334155', paddingTop: 8 }}>
                <div>
                  Latest image:{' '}
                  <Label style={{ backgroundColor: fixColor[row.fix_status] || '#6b7280', color: '#fff' }}>
                    {fixLabel[row.fix_status] || row.fix_status}
                  </Label>
                  {row.fix_latest_tag && <span style={{ marginLeft: 8 }}>{row.fix_latest_tag}</span>}
                </div>
                {row.fix_latest_ref && (
                  <div style={{ marginTop: 4, fontSize: '.78rem', wordBreak: 'break-all' }}>
                    {(() => {
                      const href = buildImageLink(row.fix_latest_ref, row.fix_catalog_url);
                      return href ? (
                        <a href={href} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>{row.fix_latest_ref}</a>
                      ) : row.fix_latest_ref;
                    })()}
                  </div>
                )}
                {row.fix_status === 'SCAN_UNAVAILABLE' && row.fix_scan_error && (
                  <div style={{ marginTop: 4, fontSize: '.75rem', color: '#9ca3af' }}>
                    <em>Reason: {row.fix_scan_error}</em>
                  </div>
                )}
                {isImageDeprecated(row.fix_published_date) && (() => {
                  const ageDays = getImageAge(row.fix_published_date);
                  const isKev = !!row.kev_date_added;
                  const borderClr = isKev ? '#dc2626' : '#7c3aed';
                  const bgClr = isKev ? 'rgba(220,38,38,.12)' : 'rgba(124,58,237,.1)';
                  const headClr = isKev ? '#fca5a5' : '#a78bfa';
                  const textClr = isKev ? '#fecaca' : '#c4b5fd';
                  return (
                    <div style={{ marginTop: 10, padding: '10px 12px', borderRadius: 6, border: `2px solid ${borderClr}`, backgroundColor: bgClr }}>
                      <div style={{ fontSize: '.82rem', fontWeight: 700, color: headClr }}>
                        {isKev ? 'CRITICAL: Potentially Unmaintained Image (KEV)' : 'Potentially Unmaintained Image'}
                      </div>
                      <div style={{ fontSize: '.78rem', color: textClr, marginTop: 4 }}>
                        The latest available image is <strong>{ageDays} days old</strong>, exceeding the
                        longest FedRAMP SLA window (180 days). This suggests the image may no longer
                        be actively maintained by Red Hat.
                      </div>
                      {isKev && (
                        <div style={{ fontSize: '.78rem', color: '#fca5a5', marginTop: 6, fontWeight: 600 }}>
                          This is a Known Exploited Vulnerability on a potentially unmaintained image --
                          remediation may require migrating to a supported replacement.
                        </div>
                      )}
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        </DetailSection>

        {row.osv_verification && (
          <DetailSection title="OSV Verification">
            <div style={{ fontSize: '.82rem' }}>
              {row.osv_verification}
              {row.osv_affected_range && (
                <div style={{ marginTop: 4, color: '#94a3b8' }}>Range: {row.osv_affected_range}</div>
              )}
            </div>
          </DetailSection>
        )}

        {row.kev_date_added && (
          <DetailSection title="CISA KEV" borderColor="#d97706">
            <div style={{ fontSize: '.82rem' }}>
              <div>Date Added: <strong>{row.kev_date_added}</strong></div>
              <div>Remediation Due: <strong>{row.kev_due_date}</strong></div>
            </div>
          </DetailSection>
        )}

        {(() => {
          const sla = computeSLA(row);
          if (!sla) return null;
          const win = slaWindow(sla.tier);
          return (
            <DetailSection title="FedRAMP SLA" borderColor="#374151">
              <div style={{ fontSize: '.82rem', display: 'flex', gap: 16, flexWrap: 'wrap' }}>
                <div>Tier: <strong>{sla.tier}</strong></div>
                <div>Window: <strong>{win} days</strong></div>
                <div>Deadline: <strong>{sla.deadline}</strong></div>
                <div>Status: <strong>{sla.breached ? `${Math.abs(sla.daysRemaining)} days overdue -- no fix available` : sla.daysRemaining < 0 && row.fix_status === 'FIXED_IN_LATEST' ? `Fix available (window expired ${Math.abs(sla.daysRemaining)} days ago)` : sla.daysRemaining < 0 ? `Window expired ${Math.abs(sla.daysRemaining)} days ago (scan unavailable)` : `${sla.daysRemaining} days remaining`}</strong></div>
              </div>
              {row.kev_due_date && (
                <div style={{ marginTop: 4, fontSize: '.75rem', color: '#94a3b8' }}>
                  {row.kev_due_date === sla.deadline ? 'Effective deadline set by CISA KEV due date' : `CISA KEV due date: ${row.kev_due_date}`}
                </div>
              )}
            </DetailSection>
          );
        })()}

        {row.rh_mitigation && (
          <DetailSection title="Red Hat Mitigation">
            <div style={{ fontSize: '.82rem', whiteSpace: 'pre-wrap' }}>{row.rh_mitigation}</div>
          </DetailSection>
        )}

        {row.rh_statement && (
          <DetailSection title="Red Hat Statement">
            <div style={{ fontSize: '.82rem', whiteSpace: 'pre-wrap' }}>{row.rh_statement}</div>
          </DetailSection>
        )}

        {row.poam_justification && (
          <DetailSection title="POA&amp;M Justification">
            <div style={{ fontSize: '.82rem', whiteSpace: 'pre-wrap' }}>{row.poam_justification}</div>
          </DetailSection>
        )}

        <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', fontSize: '.75rem' }}>
          {row.primary_link && <a href={row.primary_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>Primary</a>}
          {row.secondary_link && <a href={row.secondary_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>Secondary</a>}
          {row.tertiary_link && <a href={row.tertiary_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>Tertiary</a>}
        </div>
      </div>
    </div>
  );
}
