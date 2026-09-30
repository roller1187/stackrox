import { useState } from 'react';
import {
  Button, Label,
  Drawer, DrawerContent, DrawerContentBody,
} from '@patternfly/react-core';
import { BellIcon } from '@patternfly/react-icons';
import { Table, Thead, Tbody, Tr, Th, Td } from '@patternfly/react-table';
import type { CVERecord, UpdatesMap } from './types';
import RecordDetailPanel from './RecordDetailPanel';

const priorityColor: Record<string, string> = {
  'P1-CRITICAL': '#dc2626', 'P1-HIGH-EPSS': '#dc2626',
  'P2-HIGH-IMPACT': '#ea580c', 'P2-HIGH-EPSS': '#ea580c',
  'P3-MODERATE': '#d97706', 'P4-MONITOR': '#2563eb', 'P5-LOW': '#6b7280',
};

const FIELD_LABELS: Record<string, string> = {
  priority: 'Priority', action: 'Action', cvss: 'CVSS', rh_cvss: 'RH CVSS',
  epss_pct: 'EPSS', fix_status: 'Fix Status', severity: 'Severity',
  rh_severity: 'RH Severity', kev_date_added: 'KEV', component_version: 'Version',
  fixed_in: 'Fixed In',
};

const statusColor: Record<string, 'blue' | 'orange' | 'grey'> = {
  Processed: 'blue', 'False Positive': 'orange', Active: 'grey',
};

interface Props {
  data: CVERecord[];
  updates: UpdatesMap;
  processedKeys: Set<string>;
  fpKeys: Set<string>;
  onToggleProcessed: (key: string) => void;
  onToggleFP: (key: string) => void;
  onAcknowledge: (keys: string[]) => void;
}

export default function UpdatesTab({ data, updates, processedKeys, fpKeys, onToggleProcessed, onToggleFP, onAcknowledge }: Props) {
  const [selectedRow, setSelectedRow] = useState<CVERecord | null>(null);
  const unackEntries = Object.entries(updates).filter(([, u]) => !u.acknowledged);
  const unackKeySet = new Set(unackEntries.map(([key]) => key));
  const rows = data.filter(r => unackKeySet.has(r.key));

  if (!rows.length) {
    return <div style={{ padding: 40, textAlign: 'center', color: '#94a3b8' }}>No pending updates.</div>;
  }

  const allKeys = rows.map(r => r.key);

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
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: '.85rem', color: '#94a3b8' }}>
                {rows.length} record{rows.length !== 1 ? 's' : ''} with unacknowledged updates
              </span>
              <Button variant="secondary" size="sm" onClick={() => onAcknowledge(allKeys)}>
                Acknowledge All
              </Button>
            </div>
            <Table aria-label="Updated records" variant="compact">
              <Thead>
                <Tr>
                  <Th>Status</Th>
                  <Th>Priority</Th>
                  <Th>CVE</Th>
                  <Th>Product</Th>
                  <Th>Image</Th>
                  <Th>Changes</Th>
                  <Th style={{ width: 60 }}></Th>
                </Tr>
              </Thead>
              <Tbody>
                {rows.map(r => {
                  const upd = updates[r.key];
                  const status = processedKeys.has(r.key) ? 'Processed' : fpKeys.has(r.key) ? 'False Positive' : 'Active';
                  return (
                    <Tr key={r.key}
                      isClickable
                      onRowClick={() => setSelectedRow(r)}
                      style={{ cursor: 'pointer', borderLeft: '3px solid #d97706' }}
                    >
                      <Td>
                        <Label color={statusColor[status]}>{status}</Label>
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
                      </Td>
                      <Td>{r.product}</Td>
                      <Td style={{ fontSize: '.8rem' }}>{r.image_short}</Td>
                      <Td>
                        <div style={{ fontSize: '.78rem', color: '#d97706' }}>
                          {Object.entries(upd.fields).map(([f, v]) => (
                            <div key={f}>
                              <strong>{FIELD_LABELS[f] || f}:</strong>{' '}
                              <span style={{ color: '#94a3b8' }}>{v.old || '--'}</span>
                              {' -> '}
                              <span style={{ color: '#e2e8f0' }}>{v.new || '--'}</span>
                            </div>
                          ))}
                        </div>
                      </Td>
                      <Td onClick={e => e.stopPropagation()}>
                        <Button
                          variant="plain"
                          onClick={() => onAcknowledge([r.key])}
                          aria-label="Acknowledge update"
                          style={{ color: '#d97706', padding: 2 }}
                        >
                          <BellIcon />
                        </Button>
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
