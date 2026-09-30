import { useState, useRef } from 'react';
import {
  Button, Checkbox, Label,
} from '@patternfly/react-core';
import { BellIcon, PencilAltIcon, CheckIcon } from '@patternfly/react-icons';
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
  fixed_in: 'Fixed In', rh_fix_state: 'RH Fix State',
};

interface Props {
  data: CVERecord[];
  processedKeys: Set<string>;
  fpKeys: Set<string>;
  onToggleProcessed: (key: string) => void;
  onToggleFP: (key: string) => void;
  updates: UpdatesMap;
  onAcknowledge: (keys: string[]) => void;
  notes: Record<string, string>;
  onSetNote: (key: string, note: string) => void;
  noteSaveStatus?: 'idle' | 'saving' | 'saved' | 'error';
}

export default function ProcessedTab({ data, processedKeys, fpKeys, onToggleProcessed, onToggleFP, updates, onAcknowledge, notes, onSetNote, noteSaveStatus }: Props) {
  const [selectedRow, setSelectedRow] = useState<CVERecord | null>(null);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editText, setEditText] = useState('');
  const toolbarRef = useRef<HTMLDivElement>(null);
  const rows = data.filter(r => processedKeys.has(r.key));

  if (!rows.length) {
    return <div style={{ padding: 40, textAlign: 'center', color: '#94a3b8' }}>No processed records yet.</div>;
  }

  const startEdit = (key: string) => {
    setEditingKey(key);
    setEditText(notes[key] || '');
  };

  const commitEdit = () => {
    if (editingKey !== null) {
      onSetNote(editingKey, editText);
      setEditingKey(null);
    }
  };

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
          notes={notes}
          onSetNote={onSetNote}
          noteSaveStatus={noteSaveStatus}
        />
      )}
      <div>
        <div ref={toolbarRef} style={{ padding: '16px 0' }}>
          <div style={{ marginBottom: 8, fontSize: '.85rem', color: '#94a3b8' }}>
            {rows.length} processed record{rows.length !== 1 ? 's' : ''}
          </div>
        </div>
        <Table aria-label="Processed records" variant="compact">
          <Thead>
            <Tr>
              <Th style={{ width: 40 }}></Th>
              <Th>Priority</Th>
              <Th>CVE</Th>
              <Th>Product</Th>
              <Th>Image</Th>
              <Th>Component</Th>
              <Th>Fix Status</Th>
              <Th>Note</Th>
              <Th style={{ width: 60 }}></Th>
            </Tr>
          </Thead>
          <Tbody>
            {rows.map(r => {
              const upd = updates[r.key];
              const hasUpdate = upd && !upd.acknowledged;
              const note = notes[r.key] || '';
              const isEditing = editingKey === r.key;
              return (
                <Tr key={r.key}
                  isClickable
                  onRowClick={() => setSelectedRow(r)}
                  style={{ cursor: 'pointer', ...(hasUpdate ? { borderLeft: '3px solid #d97706' } : {}) }}
                >
                  <Td onClick={e => e.stopPropagation()}>
                    <Checkbox
                      id={`proc-${r.key}`}
                      isChecked
                      onChange={() => onToggleProcessed(r.key)}
                      aria-label="Unmark processed"
                    />
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
                          <div key={f}>{FIELD_LABELS[f] || f}: {v.old || '—'} {'→'} {v.new || '—'}</div>
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
                  <Td onClick={e => e.stopPropagation()} style={{ maxWidth: 220 }}>
                    {isEditing ? (
                      <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <input
                          type="text"
                          value={editText}
                          onChange={e => setEditText(e.target.value)}
                          onBlur={() => setTimeout(commitEdit, 150)}
                          onKeyDown={e => { if (e.key === 'Enter') commitEdit(); if (e.key === 'Escape') setEditingKey(null); }}
                          autoFocus
                          style={{
                            flex: 1, background: '#1e293b', color: '#e2e8f0',
                            border: '1px solid #38bdf8', borderRadius: 4, padding: '4px 6px',
                            fontSize: '.8rem', fontFamily: 'inherit',
                          }}
                        />
                        <Button variant="plain" size="sm" onClick={commitEdit} style={{ padding: 2, color: '#16a34a' }} aria-label="Save note">
                          <CheckIcon />
                        </Button>
                      </div>
                    ) : (
                      <span
                        onClick={() => startEdit(r.key)}
                        style={{ cursor: 'text', fontSize: '.8rem', color: note ? '#e2e8f0' : '#64748b', display: 'flex', alignItems: 'center', gap: 4 }}
                        title={note || 'Click to add note'}
                      >
                        {note ? (
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 170 }}>{note}</span>
                        ) : (
                          <><PencilAltIcon style={{ fontSize: '.7rem' }} /> Add note</>
                        )}
                      </span>
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
    </>
  );
}
