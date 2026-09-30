import { useState } from 'react';
import {
  Button, Label,
  Drawer, DrawerContent, DrawerContentBody,
} from '@patternfly/react-core';
import { FlagIcon, BellIcon } from '@patternfly/react-icons';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import type { CVERecord, UpdatesMap } from './types';
import RecordDetailPanel from './RecordDetailPanel';

const priorityColor: Record<string, string> = {
  'P1-CRITICAL': '#dc2626', 'P1-HIGH-EPSS': '#dc2626',
  'P2-HIGH-IMPACT': '#ea580c', 'P2-HIGH-EPSS': '#ea580c',
  'P3-MODERATE': '#d97706', 'P4-MONITOR': '#2563eb', 'P5-LOW': '#6b7280',
};

const fixColor: Record<string, string> = {
  FIXED_IN_LATEST: '#16a34a', STILL_VULNERABLE: '#dc2626', SCAN_UNAVAILABLE: '#6b7280',
};

const fixLabel: Record<string, string> = {
  FIXED_IN_LATEST: 'FIXED', STILL_VULNERABLE: 'NOT FIXED', SCAN_UNAVAILABLE: 'N/A',
};

const FIELD_LABELS: Record<string, string> = {
  priority: 'Priority', action: 'Action', cvss: 'CVSS', rh_cvss: 'RH CVSS',
  epss_pct: 'EPSS', fix_status: 'Fix Status', severity: 'Severity',
  rh_severity: 'RH Severity', kev_date_added: 'KEV', component_version: 'Version',
  fixed_in: 'Fixed In',
};

interface Props {
  data: CVERecord[];
  processedKeys: Set<string>;
  fpKeys: Set<string>;
  onToggleProcessed: (key: string) => void;
  onToggleFP: (key: string) => void;
  updates: UpdatesMap;
  onAcknowledge: (keys: string[]) => void;
}

export default function FalsePositivesTab({ data, processedKeys, fpKeys, onToggleProcessed, onToggleFP, updates, onAcknowledge }: Props) {
  const [selectedRow, setSelectedRow] = useState<CVERecord | null>(null);
  const rows = data.filter(r => fpKeys.has(r.key));

  if (!rows.length) {
    return <div style={{ padding: 40, textAlign: 'center', color: '#94a3b8' }}>No false positives flagged.</div>;
  }

  const drawerPanel = selectedRow ? (
    <RecordDetailPanel
      row={selectedRow}
      processedKeys={processedKeys}
      fpKeys={fpKeys}
      onToggleProcessed={onToggleProcessed}
      onToggleFP={onToggleFP}
      updates={updates}
      onAcknowledge={onAcknowledge}
      onClose={() => setSelectedRow(null)}
    />
  ) : undefined;

  return (
    <Drawer isExpanded={!!selectedRow} position="end">
      <DrawerContent panelContent={drawerPanel}>
        <DrawerContentBody>
          <div style={{ padding: '16px 0' }}>
            <div style={{ marginBottom: 8, fontSize: '.85rem', color: '#94a3b8' }}>
              {rows.length} flagged record{rows.length !== 1 ? 's' : ''}
            </div>
            <Table aria-label="False positive records" variant="compact">
              <Thead>
                <Tr>
                  <Th style={{ width: 40 }}></Th>
                  <Th>Priority</Th>
                  <Th>CVE</Th>
                  <Th>Product</Th>
                  <Th>Image</Th>
                  <Th>Component</Th>
                  <Th>Fix Status</Th>
                  <Th style={{ width: 60 }}></Th>
                </Tr>
              </Thead>
              <Tbody>
                {rows.map(r => {
                  const upd = updates[r.key];
                  const hasUpdate = upd && !upd.acknowledged;
                  return (
                    <Tr key={r.key}
                      isClickable
                      onRowClick={() => setSelectedRow(r)}
                      style={{ cursor: 'pointer', ...(hasUpdate ? { borderLeft: '3px solid #d97706' } : {}) }}
                    >
                      <Td onClick={e => e.stopPropagation()}>
                        <Button
                          variant="plain"
                          onClick={() => onToggleFP(r.key)}
                          aria-label="Unflag false positive"
                          style={{ color: '#ef4444', padding: 2 }}
                        >
                          <FlagIcon />
                        </Button>
                      </Td>
                      <Td>
                        <Label style={{ backgroundColor: priorityColor[r.priority] || '#6b7280', color: '#fff' }}>
                          {r.priority}
                        </Label>
                      </Td>
                      <Td>
                        {r.primary_link ? (
                          <a href={r.primary_link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}
                            onClick={e => e.stopPropagation()}>{r.cve}</a>
                        ) : r.cve}
                        {hasUpdate && (
                          <div style={{ fontSize: '.72rem', color: '#d97706', marginTop: 2 }}>
                            {Object.entries(upd.fields).map(([f, v]) => (
                              <div key={f}>{FIELD_LABELS[f] || f}: {v.old || '--'} {'->'} {v.new || '--'}</div>
                            ))}
                          </div>
                        )}
                      </Td>
                      <Td>{r.product}</Td>
                      <Td style={{ fontSize: '.8rem' }}>{r.image_short}</Td>
                      <Td style={{ fontSize: '.8rem' }}>{r.component}</Td>
                      <Td>
                        {r.fix_status && (
                          <Label style={{ backgroundColor: fixColor[r.fix_status] || '#6b7280', color: '#fff' }}>
                            {fixLabel[r.fix_status] || r.fix_status}
                          </Label>
                        )}
                      </Td>
                      <Td onClick={e => e.stopPropagation()}>
                        {hasUpdate && (
                          <Button
                            variant="plain"
                            onClick={() => onAcknowledge([r.key])}
                            aria-label="Acknowledge update"
                            style={{ color: '#d97706', padding: 2 }}
                          >
                            <BellIcon />
                          </Button>
                        )}
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </div>
        </DrawerContentBody>
      </DrawerContent>
    </Drawer>
  );
}
