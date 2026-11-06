import React, { useState, useEffect } from 'react';
import {
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Modal,
  TextArea,
  TextInput,
  Checkbox,
  InlineNotification,
} from '@carbon/react';
import {
  Star,
  CheckmarkOutline,
  Add,
} from '@carbon/icons-react';
import { SaveActionBar, PageHeader, SectionCard } from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey, TrafficTrustedException } from '../types';

interface TrustedExceptionsPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const TrustedExceptionsPage: React.FC<TrustedExceptionsPageProps> = () => {
  const [_loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isDirty, setIsDirty] = useState(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [exceptions, setExceptions] = useState<TrafficTrustedException[]>([]);
  const [initialExceptions, setInitialExceptions] = useState<TrafficTrustedException[]>([]);

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [addInputText, setAddInputText] = useState('');
  const [addNoteText, setAddNoteText] = useState('');
  const [selectedControls, setSelectedControls] = useState<Array<'flood' | 'rate' | 'geo' | 'reputation'>>([
    'flood',
    'rate',
  ]);

  const [pendingRemove, setPendingRemove] = useState<{ id: string; target: string } | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await apiService.getTrafficExceptions();
      setExceptions(data);
      setInitialExceptions(data);
      setIsDirty(false);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load trusted traffic exceptions.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const openAddVIPModal = () => {
    setAddInputText('');
    setAddNoteText('');
    setSelectedControls(['flood', 'rate']);
    setIsAddModalOpen(true);
  };

  const handleToggleControl = (ctrl: 'flood' | 'rate' | 'geo' | 'reputation') => {
    setSelectedControls((prev) =>
      prev.includes(ctrl) ? prev.filter((c) => c !== ctrl) : [...prev, ctrl]
    );
  };

  const handleSaveAddedVIPs = () => {
    if (!addInputText.trim()) return;

    const lines = addInputText.split('\n');
    const validEntries: string[] = [];
    const invalid: string[] = [];

    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const cidrV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
    const cidrV6Regex = /^([0-9a-fA-F:]+)\/([0-9]{1,3})$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^::$/;

    const isValidCidrV6 = (entry: string): boolean => {
      const match = cidrV6Regex.exec(entry);
      if (!match) return false;
      const prefix = Number.parseInt(match[2], 10);
      return prefix >= 1 && prefix <= 128;
    };

    lines.forEach((line: string) => {
      const clean = line.split('(')[0].trim().split(' ')[0];
      if (!clean) return;

      if (cidrV4Regex.test(clean) || isValidCidrV6(clean) || ipv4Regex.test(clean) || ipv6Regex.test(clean)) {
        validEntries.push(clean);
      } else {
        invalid.push(clean);
      }
    });

    if (invalid.length > 0) {
      setNotification({ kind: 'warning', message: `Skipped ${invalid.length} invalid entries` });
      if (validEntries.length === 0) return;
    }

    const existingTargets = new Set(exceptions.flatMap((exc) => exc.targets || []));
    const newItems: TrafficTrustedException[] = [];
    const controlsToApply = selectedControls.length ? selectedControls : (['flood', 'rate'] as const);

    for (const target of validEntries) {
      if (existingTargets.has(target)) continue;
      const identifier = `trusted-${target.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '')}`;
      newItems.push({
        id: identifier,
        targets: [target],
        controls: [...controlsToApply],
        note: addNoteText.trim() || 'Operator-created scoped exception',
      });
    }

    if (newItems.length > 0) {
      setExceptions((prev) => [...prev, ...newItems]);
      setIsDirty(true);
      setNotification({ kind: 'info', message: `Staged ${validEntries.length} scoped exceptions` });
    }

    setIsAddModalOpen(false);
    setAddInputText('');
    setAddNoteText('');
  };

  const openRemoveModal = (id: string, target: string) => {
    setPendingRemove({ id, target });
  };

  const confirmRemoveVIP = () => {
    if (!pendingRemove) return;
    setExceptions((prev) => prev.filter((exc) => exc.id !== pendingRemove.id));
    setPendingRemove(null);
    setIsDirty(true);
    setNotification({ kind: 'info', message: 'Trusted exception removal staged' });
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const ok = await apiService.saveTrafficExceptions(exceptions);
      if (ok) {
        setInitialExceptions(exceptions);
        setIsDirty(false);
        setNotification({ kind: 'success', message: 'Trusted exceptions saved successfully' });
      } else {
        setNotification({ kind: 'error', message: 'Failed to save trusted exceptions.' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Error saving trusted exceptions.' });
    } finally {
      setSaving(false);
    }
  };

  const handleReset = () => {
    setExceptions(initialExceptions);
    setIsDirty(false);
    setNotification({ kind: 'info', message: 'Changes reset' });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onClose={() => setNotification(null)}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      <PageHeader
        kicker="Traffic control"
        title="Trusted exceptions"
        icon={Star}
      />

      <SectionCard
        title="Trusted traffic exceptions"
        action={
          <Button
            kind="primary"
            size="md"
            renderIcon={Add}
            onClick={openAddVIPModal}
          >
            Add trusted source
          </Button>
        }
      >
        <Table aria-label="Trusted traffic exceptions" size="md">
          <TableHead>
            <TableRow>
              <TableHeader>SOURCE</TableHeader>
              <TableHeader>TYPE</TableHeader>
              <TableHeader>BYPASS CONTROLS</TableHeader>
              <TableHeader>NOTE</TableHeader>
              <TableHeader style={{ textAlign: 'right' }}>ACTION</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {exceptions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} style={{ textAlign: 'center', padding: '48px 16px' }}>
                  <Star size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                  <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>
                    No trusted exceptions configured
                  </div>
                  <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                    No trusted exceptions configured. All clients are subject to standard traffic controls.
                  </div>
                  <Button kind="tertiary" size="sm" renderIcon={Add} onClick={openAddVIPModal}>
                    Add trusted source
                  </Button>
                </TableCell>
              </TableRow>
            ) : (
              exceptions.map((exception) => {
                const targets = exception.targets || [];
                const target = targets.join(', ');
                const isCidr = targets.some((value: string) => value.includes('/'));
                const controls = exception.controls || [];

                return (
                  <TableRow key={exception.id}>
                    <TableCell>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div
                          style={{
                            display: 'inline-flex',
                            width: '28px',
                            height: '28px',
                            alignItems: 'center',
                            justifyContent: 'center',
                            borderRadius: '0',
                            background: 'var(--cds-support-success-subtle, rgba(36, 161, 72, 0.1))',
                            color: 'var(--cds-support-success, #24a148)',
                            flexShrink: 0,
                          }}
                        >
                          <CheckmarkOutline size={16} />
                        </div>
                        <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontWeight: 600, fontSize: '0.875rem' }}>
                          {target}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Tag type="cool-gray" size="sm">
                        {isCidr ? 'CIDR' : 'IP'}
                      </Tag>
                    </TableCell>
                    <TableCell>
                      <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                        {controls.length > 0 ? (
                          controls.map((ctrl) => (
                            <Tag
                              key={ctrl}
                              type={
                                ctrl === 'flood'
                                  ? 'red'
                                  : ctrl === 'rate'
                                  ? 'purple'
                                  : ctrl === 'geo'
                                  ? 'blue'
                                  : 'teal'
                              }
                              size="sm"
                            >
                              {ctrl.toUpperCase()}
                            </Tag>
                          ))
                        ) : (
                          <Tag type="cool-gray" size="sm">ALL</Tag>
                        )}
                      </div>
                    </TableCell>
                    <TableCell style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                      {exception.note || '—'}
                    </TableCell>
                    <TableCell style={{ textAlign: 'right' }}>
                      <Button
                        kind="danger--ghost"
                        size="sm"
                        onClick={() => openRemoveModal(exception.id, target)}
                        aria-label={`Remove trusted exception ${exception.id}`}
                      >
                        Remove
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </SectionCard>

      <Modal
        open={isAddModalOpen}
        modalHeading="Add Trusted Source"
        primaryButtonText="Add trusted source"
        secondaryButtonText="Cancel"
        onRequestClose={() => setIsAddModalOpen(false)}
        onRequestSubmit={handleSaveAddedVIPs}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', paddingTop: '1rem' }}>
          <div
            style={{
              padding: '0.875rem 1rem',
              background: 'var(--cds-layer-02)',
              borderLeft: '3px solid var(--cds-interactive, #ff832b)',
              fontSize: '0.875rem',
              color: 'var(--cds-text-secondary)',
              lineHeight: 1.5,
            }}
          >
            <strong style={{ color: 'var(--cds-text-primary)' }}>Bypass policy:</strong>{' '}
            Select which traffic controls this source will bypass. (Note: IP Blacklist is never bypassed).
          </div>

          <TextArea
            id="modal-vip-input"
            labelText="IP Addresses or CIDRs"
            helperText="One source per line. Optional comments in parentheses are ignored."
            placeholder={`192.168.1.50 (Uptime Monitor)\n10.20.0.0/24 (Internal VPN)`}
            rows={5}
            value={addInputText}
            onChange={(e) => setAddInputText(e.target.value)}
            style={{ fontFamily: 'var(--cds-font-mono, monospace)' }}
          />

          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '8px' }}>
              Bypass Controls
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <Checkbox
                id="ctrl-flood"
                labelText="Application Flood (DDoS)"
                checked={selectedControls.includes('flood')}
                onChange={() => handleToggleControl('flood')}
              />
              <Checkbox
                id="ctrl-rate"
                labelText="Rate Limiting"
                checked={selectedControls.includes('rate')}
                onChange={() => handleToggleControl('rate')}
              />
              <Checkbox
                id="ctrl-geo"
                labelText="Geographic Access (Geo)"
                checked={selectedControls.includes('geo')}
                onChange={() => handleToggleControl('geo')}
              />
              <Checkbox
                id="ctrl-reputation"
                labelText="IP Reputation Policy"
                checked={selectedControls.includes('reputation')}
                onChange={() => handleToggleControl('reputation')}
              />
            </div>
          </div>

          <TextInput
            id="modal-vip-note"
            labelText="Note / Description (optional)"
            placeholder="e.g. Partner API gateway"
            value={addNoteText}
            onChange={(e) => setAddNoteText(e.target.value)}
          />
        </div>
      </Modal>

      <Modal
        open={Boolean(pendingRemove)}
        danger
        modalHeading="Remove trusted exception"
        primaryButtonText="Remove"
        secondaryButtonText="Cancel"
        onRequestClose={() => setPendingRemove(null)}
        onRequestSubmit={confirmRemoveVIP}
      >
        <p style={{ paddingTop: '1rem', fontSize: '0.875rem' }}>
          Are you sure you want to remove trusted exception{' '}
          <strong>{pendingRemove?.target}</strong>?
        </p>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        onSave={handleSave}
        onReset={handleReset}
        isSaving={saving}
      />
    </div>
  );
};
export default TrustedExceptionsPage;
