import { useState, useMemo, useCallback, useRef, useEffect } from 'react';
import {
  Button, Checkbox, Label, Pagination,
  SearchInput, Toolbar, ToolbarContent, ToolbarItem, ToolbarGroup,
  ToggleGroup, ToggleGroupItem,
  MenuToggle, Select, SelectOption,
} from '@patternfly/react-core';
import { FlagIcon, OutlinedFlagIcon, BellIcon } from '@patternfly/react-icons';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import type { CVERecord, UpdatesMap } from './types';
import { computeSLA, getDowngrade, isImageDeprecated } from './sla';
import RecordDetailPanel from './RecordDetailPanel';

const priorityColor: Record<string, string> = {
  'P1-CRITICAL': '#dc2626', 'P1-HIGH-EPSS': '#dc2626',
  'P2-HIGH-IMPACT': '#ea580c', 'P2-HIGH-EPSS': '#ea580c',
  'P3-MODERATE': '#d97706', 'P4-MONITOR': '#2563eb', 'P5-LOW': '#6b7280',
};
const actionColor: Record<string, string> = { PATCH: '#dc2626', UPDATE: '#16a34a', MONITOR: '#2563eb' };
const fixColor: Record<string, string> = {
  FIXED_IN_LATEST: '#16a34a', STILL_VULNERABLE: '#dc2626', SCAN_UNAVAILABLE: '#6b7280',
};
const fixLabel: Record<string, string> = {
  FIXED_IN_LATEST: 'FIXED', STILL_VULNERABLE: 'NOT FIXED', SCAN_UNAVAILABLE: 'N/A',
};
const rhFixColor: Record<string, string> = {
  'Affected': '#dc2626', 'Fix deferred': '#d97706', 'Will not fix': '#d97706',
  'Not affected': '#16a34a', 'Fix Available': '#16a34a',
  'New': '#6b7280', 'Out of support scope': '#6b7280',
};
const rhFixLabel: Record<string, string> = {
  'Affected': 'AFFECTED', 'Fix deferred': 'DEFERRED', 'Will not fix': 'WONTFIX',
  'Not affected': 'N/A', 'Fix Available': 'FIX AVAIL',
  'New': 'NEW', 'Out of support scope': 'EOL',
};
const sevColor: Record<string, string> = {
  CRITICAL: '#dc2626', IMPORTANT: '#ea580c', MODERATE: '#d97706', LOW: '#6b7280',
};

const PER_PAGE = 50;
const PRIORITY_ORDER = ['P1-CRITICAL', 'P1-HIGH-EPSS', 'P2-HIGH-IMPACT', 'P2-HIGH-EPSS', 'P3-MODERATE', 'P4-MONITOR', 'P5-LOW'];

type SortCol = 'priority' | 'action' | 'cve' | 'severity' | 'rh_cvss' | 'cvss' | 'epss_pct' | 'product' | 'image_short' | 'component' | 'fixed_in' | 'fix_status' | 'rh_fix_state' | 'osv_verification' | 'rhsa_advisory' | 'discovered' | 'sla_deadline';

const FIELD_LABELS: Record<string, string> = {
  priority: 'Priority', action: 'Action', cvss: 'CVSS', rh_cvss: 'RH CVSS',
  epss_pct: 'EPSS', fix_status: 'Fix Status', severity: 'Severity',
  rh_severity: 'RH Severity', kev_date_added: 'KEV', component_version: 'Version',
  fixed_in: 'Fixed In', rh_fix_state: 'RH Fix State',
};

interface Props {
  data: CVERecord[];
  processedKeys: Set<string>;
  fpKeys: Set<string>;
  onToggleProcessed: (key: string) => void;
  onToggleFP: (key: string) => void;
  onBatchProcessed: (keys: string[], checked: boolean) => void;
  onBatchFP: (keys: string[], checked: boolean) => void;
  drillFilter: { field: string; value: string } | null;
  onClearDrill: () => void;
  updates: UpdatesMap;
  onAcknowledge: (keys: string[]) => void;
  searchParams?: URLSearchParams;
  setSearchParams?: (nextInit: URLSearchParams | ((prev: URLSearchParams) => URLSearchParams), navigateOpts?: { replace?: boolean; state?: unknown }) => void;
  notes?: Record<string, string>;
  onSetNote?: (key: string, note: string) => void;
  noteSaveStatus?: 'idle' | 'saving' | 'saved' | 'error';
}

function isRecent(discovered: string): boolean {
  if (!discovered) return false;
  const d = new Date(discovered);
  if (isNaN(d.getTime())) return false;
  return (Date.now() - d.getTime()) < 30 * 24 * 3600 * 1000;
}

export default function CVEDataTab({ data, processedKeys, fpKeys, onToggleProcessed, onToggleFP, onBatchProcessed, onBatchFP, drillFilter, onClearDrill, updates, onAcknowledge, searchParams, setSearchParams, notes, onSetNote, noteSaveStatus }: Props) {
  const sp = searchParams;
  const [search, setSearch] = useState(sp?.get('search') || '');
  const [actionFilter, setActionFilter] = useState(sp?.get('action') || '');
  const [priorityFilter, setPriorityFilter] = useState(sp?.get('priority') || '');
  const [productFilter, setProductFilter] = useState(sp?.get('product') || '');
  const [productOpen, setProductOpen] = useState(false);
  const [hideNew, setHideNew] = useState(sp?.get('hideNew') === '1');
  const [hideGhsa, setHideGhsa] = useState(sp?.get('hideGhsa') === '1');
  const [hideProcessed, setHideProcessed] = useState(sp?.has('hideProcessed') ? sp.get('hideProcessed') === '1' : true);
  const [hideFP, setHideFP] = useState(sp?.has('hideFP') ? sp.get('hideFP') === '1' : true);
  const [slaFilter, setSlaFilter] = useState(sp?.get('sla') || '');
  const [slaOpen, setSlaOpen] = useState(false);
  const [showDowngraded, setShowDowngraded] = useState(sp?.get('downgraded') === '1');
  const [sortCol, setSortCol] = useState<SortCol>((sp?.get('sortBy') as SortCol) || 'priority');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>((sp?.get('sortDir') as 'asc' | 'desc') || 'asc');
  const [perPage, setPerPage] = useState(Number(sp?.get('perPage')) || PER_PAGE);
  const [page, setPage] = useState(Number(sp?.get('page')) || 1);
  const [selectedRow, setSelectedRow] = useState<CVERecord | null>(null);
  const toolbarRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!setSearchParams) return;
    setSearchParams(prev => {
      const next = new URLSearchParams(prev);
      const set = (k: string, v: string, def: string) => { if (v !== def) next.set(k, v); else next.delete(k); };
      set('search', search, '');
      set('action', actionFilter, '');
      set('priority', priorityFilter, '');
      set('product', productFilter, '');
      set('hideNew', hideNew ? '1' : '0', '0');
      set('hideGhsa', hideGhsa ? '1' : '0', '0');
      set('hideProcessed', hideProcessed ? '1' : '0', '1');
      set('hideFP', hideFP ? '1' : '0', '1');
      set('sla', slaFilter, '');
      set('downgraded', showDowngraded ? '1' : '0', '0');
      set('sortBy', sortCol, 'priority');
      set('sortDir', sortDir, 'asc');
      set('page', String(page), '1');
      set('perPage', String(perPage), String(PER_PAGE));
      return next;
    }, { replace: true });
  }, [search, actionFilter, priorityFilter, productFilter, hideNew, hideGhsa, hideProcessed, hideFP, slaFilter, showDowngraded, sortCol, sortDir, page, perPage, setSearchParams]);

  const products = useMemo(() => {
    const s = new Set<string>();
    for (const r of data) if (r.product) s.add(r.product);
    return Array.from(s).sort();
  }, [data]);


  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return data.filter(r => {
      if (drillFilter) {
        if (drillFilter.field === 'action' && r.action !== drillFilter.value) return false;
        if (drillFilter.field === 'priority' && !r.priority.startsWith(drillFilter.value)) return false;
        if (drillFilter.field === 'product' && r.product !== drillFilter.value) return false;
        if (drillFilter.field === 'cve' && r.cve !== drillFilter.value) return false;
        if (drillFilter.field === 'fix_status' && r.fix_status !== drillFilter.value) return false;
        if (drillFilter.field === 'rh_fix_state' && r.rh_fix_state !== drillFilter.value) return false;
        if (drillFilter.field === 'kev' && !r.kev_date_added) return false;
        if (drillFilter.field === 'sla_breached') {
          const sla = computeSLA(r);
          if (!sla?.breached) return false;
          if (drillFilter.value && drillFilter.value !== 'all' && sla.tier !== drillFilter.value) return false;
        }
        if (drillFilter.field === 'downgraded' && !getDowngrade(r)) return false;
      }
      if (actionFilter && r.action !== actionFilter) return false;
      if (priorityFilter && !r.priority.startsWith(priorityFilter)) return false;
      if (productFilter && r.product !== productFilter) return false;
      if (hideNew && isRecent(r.discovered) && !r.kev_date_added) return false;
      if (hideGhsa && r.cve.startsWith('GHSA-')) return false;
      if (hideProcessed && processedKeys.has(r.key)) return false;
      if (hideFP && fpKeys.has(r.key)) return false;
      if (slaFilter) {
        const sla = computeSLA(r);
        if (!sla?.breached) return false;
        if (slaFilter !== 'all' && sla.tier !== slaFilter) return false;
      }
      if (showDowngraded && !getDowngrade(r)) return false;
      if (q && !(
        r.cve.toLowerCase().includes(q) ||
        r.component.toLowerCase().includes(q) ||
        r.image_short.toLowerCase().includes(q) ||
        r.rhsa_advisory.toLowerCase().includes(q) ||
        r.product.toLowerCase().includes(q)
      )) return false;
      return true;
    });
  }, [data, search, actionFilter, priorityFilter, productFilter, hideNew, hideGhsa, hideProcessed, hideFP, slaFilter, showDowngraded, processedKeys, fpKeys, drillFilter]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let av: string | number, bv: string | number;
      if (sortCol === 'priority') {
        av = PRIORITY_ORDER.indexOf(a.priority);
        bv = PRIORITY_ORDER.indexOf(b.priority);
        if (av === -1) av = 999;
        if (bv === -1) bv = 999;
      } else if (sortCol === 'rh_cvss' || sortCol === 'cvss' || sortCol === 'epss_pct') {
        av = parseFloat(a[sortCol]) || 0;
        bv = parseFloat(b[sortCol]) || 0;
      } else if (sortCol === 'discovered') {
        av = a.discovered ? new Date(a.discovered).getTime() || 0 : 0;
        bv = b.discovered ? new Date(b.discovered).getTime() || 0 : 0;
      } else if (sortCol === 'sla_deadline') {
        av = a.sla_deadline || '￿';
        bv = b.sla_deadline || '￿';
      } else {
        av = (a[sortCol] || '').toLowerCase();
        bv = (b[sortCol] || '').toLowerCase();
      }
      if (av < bv) return sortDir === 'asc' ? -1 : 1;
      if (av > bv) return sortDir === 'asc' ? 1 : -1;
      return 0;
    });
    return arr;
  }, [filtered, sortCol, sortDir]);

  const pageRows = sorted.slice((page - 1) * perPage, page * perPage);

  const allFilteredKeys = useMemo(() => sorted.map(r => r.key), [sorted]);
  const allProcessed = sorted.length > 0 && sorted.every(r => processedKeys.has(r.key));
  const someProcessed = !allProcessed && sorted.some(r => processedKeys.has(r.key));
  const allFP = sorted.length > 0 && sorted.every(r => fpKeys.has(r.key));
  const someFP = !allFP && sorted.some(r => fpKeys.has(r.key));

  const handleSort = useCallback((col: SortCol) => {
    if (sortCol === col) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortCol(col); setSortDir('asc'); }
  }, [sortCol]);

  const sortParams = (col: SortCol) => ({
    sort: {
      sortBy: { index: 0, direction: sortCol === col ? sortDir : undefined },
      onSort: () => handleSort(col),
      columnIndex: 0,
    },
    style: { cursor: 'pointer' } as React.CSSProperties,
  });

  const sortArrow = (col: SortCol) => sortCol === col ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '';

  return (
    <>
      {selectedRow && (
        <RecordDetailPanel
          row={selectedRow}
          processedKeys={processedKeys}
          fpKeys={fpKeys}
          onToggleProcessed={onToggleProcessed}
          onToggleFP={onToggleFP}
          updates={updates}
          onAcknowledge={onAcknowledge}
          onClose={() => setSelectedRow(null)}
          toolbarRef={toolbarRef}
          allData={data}
          notes={notes}
          onSetNote={onSetNote}
          noteSaveStatus={noteSaveStatus}
        />
      )}
      <div>
          <div ref={toolbarRef}>
          <Toolbar>
            <ToolbarContent>
              <ToolbarItem>
                <SearchInput
                  placeholder="Search CVE, component, image, RHSA, product..."
                  value={search}
                  onChange={(_e, v) => { setSearch(v); setPage(1); }}
                  onClear={() => { setSearch(''); setPage(1); }}
                  style={{ minWidth: 280 }}
                />
              </ToolbarItem>
              <ToolbarGroup>
                <ToolbarItem>
                  <ToggleGroup aria-label="Action filter">
                    <ToggleGroupItem text="All" isSelected={!actionFilter} onChange={() => { setActionFilter(''); setPage(1); }} />
                    <ToggleGroupItem text="PATCH" isSelected={actionFilter === 'PATCH'} onChange={() => { setActionFilter(actionFilter === 'PATCH' ? '' : 'PATCH'); setPage(1); }} />
                    <ToggleGroupItem text="UPDATE" isSelected={actionFilter === 'UPDATE'} onChange={() => { setActionFilter(actionFilter === 'UPDATE' ? '' : 'UPDATE'); setPage(1); }} />
                    <ToggleGroupItem text="MONITOR" isSelected={actionFilter === 'MONITOR'} onChange={() => { setActionFilter(actionFilter === 'MONITOR' ? '' : 'MONITOR'); setPage(1); }} />
                  </ToggleGroup>
                </ToolbarItem>
                <ToolbarItem>
                  <ToggleGroup aria-label="Priority filter">
                    {['P1', 'P2', 'P3', 'P4', 'P5'].map(p => (
                      <ToggleGroupItem key={p} text={p} isSelected={priorityFilter === p}
                        onChange={() => { setPriorityFilter(priorityFilter === p ? '' : p); setPage(1); }} />
                    ))}
                  </ToggleGroup>
                </ToolbarItem>
              </ToolbarGroup>
              <ToolbarItem>
                <Select
                  toggle={(toggleRef) => (
                    <MenuToggle ref={toggleRef} onClick={() => setProductOpen(o => !o)} isExpanded={productOpen}
                      style={{ minWidth: 150 }}>
                      {productFilter || 'All Products'}
                    </MenuToggle>
                  )}
                  isOpen={productOpen}
                  onOpenChange={setProductOpen}
                  onSelect={(_e, v) => { setProductFilter(v === '__all__' ? '' : String(v)); setProductOpen(false); setPage(1); }}
                  selected={productFilter || '__all__'}
                >
                  <SelectOption value="__all__">All Products</SelectOption>
                  {products.map(p => <SelectOption key={p} value={p}>{p}</SelectOption>)}
                </Select>
              </ToolbarItem>
              <ToolbarItem>
                <Select
                  toggle={(toggleRef) => (
                    <MenuToggle ref={toggleRef} onClick={() => setSlaOpen(o => !o)} isExpanded={slaOpen}
                      style={{ minWidth: 150 }}>
                      {slaFilter ? (slaFilter === 'all' ? 'All Breached' : `Breached: ${slaFilter}`) : 'All SLA'}
                    </MenuToggle>
                  )}
                  isOpen={slaOpen}
                  onOpenChange={setSlaOpen}
                  onSelect={(_e, v) => { setSlaFilter(v === '__all__' ? '' : String(v)); setSlaOpen(false); setPage(1); }}
                  selected={slaFilter || '__all__'}
                >
                  <SelectOption value="__all__">All SLA</SelectOption>
                  <SelectOption value="all">All Breached</SelectOption>
                  <SelectOption value="Critical/High">Breached: Critical/High</SelectOption>
                  <SelectOption value="Moderate">Breached: Moderate</SelectOption>
                  <SelectOption value="Low">Breached: Low</SelectOption>
                </Select>
              </ToolbarItem>
              <ToolbarGroup>
                <ToolbarItem><Checkbox id="hide-new" label="Hide < 30 days" isChecked={hideNew} onChange={(_e, v) => { setHideNew(v); setPage(1); }} /></ToolbarItem>
                <ToolbarItem><Checkbox id="hide-ghsa" label="Hide GHSA" isChecked={hideGhsa} onChange={(_e, v) => { setHideGhsa(v); setPage(1); }} /></ToolbarItem>
                <ToolbarItem><Checkbox id="hide-proc" label="Hide Processed" isChecked={hideProcessed} onChange={(_e, v) => { setHideProcessed(v); setPage(1); }} /></ToolbarItem>
                <ToolbarItem><Checkbox id="hide-fp" label="Hide FP" isChecked={hideFP} onChange={(_e, v) => { setHideFP(v); setPage(1); }} /></ToolbarItem>
                <ToolbarItem><Checkbox id="show-downgraded" label="Downgraded" isChecked={showDowngraded} onChange={(_e, v) => { setShowDowngraded(v); setPage(1); }} /></ToolbarItem>
              </ToolbarGroup>
              <ToolbarItem>
                <span style={{ fontSize: '.82rem', color: '#94a3b8' }}>{sorted.length} records</span>
              </ToolbarItem>
              {drillFilter && (
                <ToolbarItem>
                  <Label color="blue" onClose={onClearDrill}>
                    {drillFilter.field}: {drillFilter.value}
                  </Label>
                </ToolbarItem>
              )}
            </ToolbarContent>
          </Toolbar>
          </div>

          <div style={{ overflowX: 'auto' }}>
          <Table aria-label="CVE data" variant="compact" style={{ fontSize: '.78rem', whiteSpace: 'nowrap', minWidth: 2600, tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: 52 }} />
              <col style={{ width: 36 }} />
            </colgroup>
            <Thead>
              <Tr>
                <Th style={{ padding: '4px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{ fontSize: '.68rem', color: 'var(--pf-t--global--text--color--link--default)' }}>Done</span>
                    <Checkbox
                      id="select-all-done"
                      isChecked={someProcessed ? null : allProcessed}
                      onChange={() => onBatchProcessed(allFilteredKeys, !allProcessed)}
                      aria-label="Toggle all processed"
                    />
                  </div>
                </Th>
                <Th style={{ padding: '4px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                    <span style={{ fontSize: '.68rem', color: 'var(--pf-t--global--text--color--link--default)' }}>FP</span>
                    <Checkbox
                      id="select-all-fp"
                      isChecked={someFP ? null : allFP}
                      onChange={() => onBatchFP(allFilteredKeys, !allFP)}
                      aria-label="Toggle all false positive"
                    />
                  </div>
                </Th>
                <Th {...sortParams('priority')}>Priority{sortArrow('priority')}</Th>
                <Th {...sortParams('action')}>Action{sortArrow('action')}</Th>
                <Th {...sortParams('cve')}>CVE{sortArrow('cve')}</Th>
                <Th {...sortParams('severity')}>Severity{sortArrow('severity')}</Th>
                <Th {...sortParams('rh_cvss')}>RH CVSS{sortArrow('rh_cvss')}</Th>
                <Th {...sortParams('cvss')}>CVSS{sortArrow('cvss')}</Th>
                <Th {...sortParams('epss_pct')}>EPSS{sortArrow('epss_pct')}</Th>
                <Th {...sortParams('product')}>Product{sortArrow('product')}</Th>
                <Th {...sortParams('image_short')}>Image{sortArrow('image_short')}</Th>
                <Th {...sortParams('component')}>Component{sortArrow('component')}</Th>
                <Th {...sortParams('fixed_in')}>Fixed In{sortArrow('fixed_in')}</Th>
                <Th {...sortParams('fix_status')}>Fix Status{sortArrow('fix_status')}</Th>
                <Th {...sortParams('rh_fix_state')}>RH Fix{sortArrow('rh_fix_state')}</Th>
                <Th {...sortParams('osv_verification')}>OSV{sortArrow('osv_verification')}</Th>
                <Th {...sortParams('rhsa_advisory')}>RHSA{sortArrow('rhsa_advisory')}</Th>
                <Th {...sortParams('discovered')}>Discovered{sortArrow('discovered')}</Th>
                <Th {...sortParams('sla_deadline')}>SLA{sortArrow('sla_deadline')}</Th>
              </Tr>
            </Thead>
            <Tbody>
              {pageRows.map(r => {
                const upd = updates[r.key];
                const hasUpdate = upd && !upd.acknowledged;
                return (
                <Tr key={r.key}
                  className={[
                    r.kev_date_added ? 'kev-row' : '',
                    processedKeys.has(r.key) ? 'processed-row' : '',
                  ].filter(Boolean).join(' ')}
                  isClickable
                  onRowClick={() => setSelectedRow(r)}
                  style={{ cursor: 'pointer', ...(hasUpdate ? { borderLeft: '3px solid #d97706' } : {}) }}
                >
                  <Td className="col-narrow" onClick={e => e.stopPropagation()}>
                    <Checkbox id={`p-${r.key}`} isChecked={processedKeys.has(r.key)}
                      onChange={() => onToggleProcessed(r.key)} aria-label="Toggle processed" />
                  </Td>
                  <Td className="col-narrow" onClick={e => e.stopPropagation()}>
                    <Button variant="plain" onClick={() => onToggleFP(r.key)} aria-label="Toggle FP"
                      style={{ color: fpKeys.has(r.key) ? '#ef4444' : '#475569', padding: 0 }}>
                      {fpKeys.has(r.key) ? <FlagIcon /> : <OutlinedFlagIcon />}
                    </Button>
                  </Td>
                  <Td><Label style={{ backgroundColor: priorityColor[r.priority] || '#6b7280', color: '#fff', fontSize: '.7rem' }}>{r.priority}</Label></Td>
                  <Td><Label style={{ backgroundColor: actionColor[r.action] || '#6b7280', color: '#fff', fontSize: '.7rem' }}>{r.action}</Label></Td>
                  <Td>
                    <div>
                      {r.primary_link ? (
                        <a href={r.primary_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}
                          onClick={e => e.stopPropagation()}>{r.cve}</a>
                      ) : r.cve}
                    </div>
                    {(r.kev_date_added || isImageDeprecated(r.fix_published_date)) && (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 2, marginTop: 2 }}>
                        {r.kev_date_added && <div><Label style={{ backgroundColor: '#dc2626', color: '#fff', fontSize: '.65rem', padding: '1px 5px', fontWeight: 700 }}>{'⚠'} KEV</Label></div>}
                        {isImageDeprecated(r.fix_published_date) && <div><Label style={{ backgroundColor: '#7c3aed', color: '#fff', fontSize: '.65rem', padding: '1px 5px', fontWeight: 700 }}>UNMAINTAINED</Label></div>}
                      </div>
                    )}
                  </Td>
                  <Td>
                    {r.severity && (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                        <Label style={{ backgroundColor: sevColor[r.severity.toUpperCase()] || '#6b7280', color: '#fff', fontSize: '.7rem' }}>{r.severity}</Label>
                        {(() => {
                          const dg = getDowngrade(r);
                          return dg ? <span style={{ fontSize: '.65rem', color: '#d97706' }} title={`RH downgraded: ${dg.from} -> ${dg.to}`}>{'▼'}</span> : null;
                        })()}
                      </span>
                    )}
                  </Td>
                  <Td>{r.rh_cvss && r.rh_cvss !== '0' ? r.rh_cvss : ''}</Td>
                  <Td>{r.cvss && r.cvss !== '0' ? r.cvss : ''}</Td>
                  <Td>
                    {r.epss_pct ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                        <span style={{ fontSize: '.75rem' }}>{r.epss_pct}%</span>
                        <span className="epss-bar" style={{ width: Math.min(parseFloat(r.epss_pct) * 2, 60) }}></span>
                      </span>
                    ) : ''}
                  </Td>
                  <Td style={{ fontSize: '.78rem' }}>{r.product}</Td>
                  <Td style={{ fontSize: '.78rem', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.image_short}</Td>
                  <Td style={{ fontSize: '.78rem' }}>{r.component}</Td>
                  <Td style={{ fontSize: '.78rem' }}>{r.fixed_in}</Td>
                  <Td>
                    {r.fix_status && (
                      <Label style={{ backgroundColor: fixColor[r.fix_status] || '#6b7280', color: '#fff', fontSize: '.7rem' }}>
                        {fixLabel[r.fix_status] || r.fix_status}
                      </Label>
                    )}
                  </Td>
                  <Td>
                    {r.rh_fix_state && (
                      <Label style={{ backgroundColor: rhFixColor[r.rh_fix_state] || '#6b7280', color: '#fff', fontSize: '.7rem' }}>
                        {rhFixLabel[r.rh_fix_state] || r.rh_fix_state}
                      </Label>
                    )}
                  </Td>
                  <Td style={{ fontSize: '.78rem' }}>{r.osv_verification}</Td>
                  <Td style={{ fontSize: '.78rem' }}>
                    {r.rhsa_advisory && r.advisory_link ? (
                      <a href={r.advisory_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}
                        onClick={e => e.stopPropagation()}>{r.rhsa_advisory}</a>
                    ) : r.rhsa_advisory}
                  </Td>
                  <Td style={{ fontSize: '.75rem', color: '#94a3b8' }}>{r.discovered}</Td>
                  <Td style={{ fontSize: '.75rem', color: '#94a3b8' }}>
                    {(() => {
                      const sla = computeSLA(r);
                      if (!sla) return '--';
                      if (sla.breached) return <span style={{ color: '#b91c1c' }}>{sla.daysRemaining}d</span>;
                      if (sla.daysRemaining < 0 && r.fix_status === 'FIXED_IN_LATEST') return <span style={{ color: '#16a34a' }}>Fixed</span>;
                      if (sla.daysRemaining < 0) return '--';
                      return `${sla.daysRemaining}d`;
                    })()}
                  </Td>
                  {hasUpdate && (
                    <Td className="col-narrow" onClick={e => e.stopPropagation()}>
                      <Button variant="plain" onClick={() => onAcknowledge([r.key])} aria-label="Acknowledge update"
                        title={Object.entries(upd.fields).map(([f, v]) => `${FIELD_LABELS[f] || f}: ${v.old || '--'} -> ${v.new || '--'}`).join('\n')}
                        style={{ color: '#d97706', padding: 0 }}>
                        <BellIcon />
                      </Button>
                    </Td>
                  )}
                </Tr>
              );})}
            </Tbody>
          </Table>
          </div>

          <Pagination
            itemCount={sorted.length}
            perPage={perPage}
            page={page}
            onSetPage={(_e, p) => setPage(p)}
            onPerPageSelect={(_e, pp) => { setPerPage(pp); setPage(1); }}
            variant="bottom"
            isCompact
          />
      </div>
    </>
  );
}
