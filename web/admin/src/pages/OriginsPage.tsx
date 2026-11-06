import React, { useState, useEffect } from 'react';
import {
  Button,
  DataTable,
  TableContainer,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Modal,
  TextInput,
  NumberInput,
  Select,
  SelectItem,
  Tag,
  InlineNotification,
  DataTableSkeleton,
  OverflowMenu,
  OverflowMenuItem,
} from '@carbon/react';
import { Add, TrashCan, Renew, Network_3 } from '@carbon/icons-react';
import type { OriginPool, UpstreamTargetRuntimeStatus } from '../types';
import { apiService } from '../services/api';
import { PageHeader, StatusToggle, PolicyTag } from '../components/common';

const headers = [
  { key: 'name', header: 'Origin pool' },
  { key: 'targets', header: 'Targets' },
  { key: 'strategy', header: 'Origin policy' },
  { key: 'health', header: 'Health checks' },
  { key: 'sticky', header: 'Session affinity' },
  { key: 'actions', header: 'Actions' },
];

export const OriginsPage: React.FC = () => {
  const [pools, setPools] = useState<OriginPool[]>([]);
  const [runtimeStatus, setRuntimeStatus] = useState<Map<string, UpstreamTargetRuntimeStatus>>(new Map());
  const [runtimeAvailable, setRuntimeAvailable] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'warning'; message: string } | null>(null);

  const [editorOpen, setEditorOpen] = useState<boolean>(false);
  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [editingName, setEditingName] = useState<string>('');
  const [name, setName] = useState<string>('');
  const [strategy, setStrategy] = useState<string>('round_robin');
  const [targets, setTargets] = useState<Array<{ url: string; weight: number }>>([{ url: '', weight: 1 }]);
  const [healthEnabled, setHealthEnabled] = useState<boolean>(false);
  const [healthInterval, setHealthInterval] = useState<string>('10s');
  const [healthPath, setHealthPath] = useState<string>('/health');
  const [healthTimeout, setHealthTimeout] = useState<string>('3s');
  const [healthMethod, setHealthMethod] = useState<'GET' | 'HEAD'>('GET');
  const [healthStatuses, setHealthStatuses] = useState<string>('200, 204');
  const [healthyThreshold, setHealthyThreshold] = useState<number>(2);
  const [unhealthyThreshold, setUnhealthyThreshold] = useState<number>(3);
  const [stickyEnabled, setStickyEnabled] = useState<boolean>(false);
  const [stickyCookie, setStickyCookie] = useState<string>('');
  const [stickyTtl, setStickyTtl] = useState<string>('24h');
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState<boolean>(false);

  const [deleteModalOpen, setDeleteModalOpen] = useState<boolean>(false);
  const [poolToDelete, setPoolToDelete] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [fetchedPools, statusRes] = await Promise.all([
        apiService.getOrigins(),
        apiService.getUpstreamStatus(),
      ]);
      setPools(fetchedPools);
      setRuntimeAvailable(statusRes.available);
      const indexed = new Map<string, UpstreamTargetRuntimeStatus>();
      for (const group of statusRes.data) {
        for (const t of group.targets) {
          indexed.set(`${group.name}\0${t.url}`, t);
        }
      }
      setRuntimeStatus(indexed);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load origin pools.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const getRuntimeTarget = (groupName: string, targetUrl: string): UpstreamTargetRuntimeStatus | undefined => {
    return runtimeStatus.get(`${groupName}\0${targetUrl}`);
  };

  const handleOpenEditor = (pool?: OriginPool) => {
    if (pool) {
      setIsEditing(true);
      setEditingName(pool.name);
      setName(pool.name);
      setStrategy(pool.strategy || 'round_robin');
      setTargets(
        pool.targets && pool.targets.length > 0
          ? pool.targets.map((t) => ({ url: t.url, weight: t.weight || 1 }))
          : [{ url: '', weight: 1 }]
      );
      setHealthEnabled(Boolean(pool.health_check?.enabled));
      setHealthInterval(pool.health_check?.interval || '10s');
      setHealthPath(pool.health_check?.path || '/health');
      setHealthTimeout(pool.health_check?.timeout || '3s');
      setHealthMethod((pool.health_check?.method as any) || 'GET');
      setHealthStatuses((pool.health_check?.expected_statuses || [200]).join(', '));
      setHealthyThreshold(pool.health_check?.healthy_threshold || 2);
      setUnhealthyThreshold(pool.health_check?.unhealthy_threshold || 3);
      setStickyEnabled(Boolean(pool.sticky?.enabled));
      setStickyCookie(pool.sticky?.cookie || '');
      setStickyTtl(pool.sticky?.ttl || '24h');
    } else {
      setIsEditing(false);
      setEditingName('');
      setName('');
      setStrategy('round_robin');
      setTargets([{ url: '', weight: 1 }]);
      setHealthEnabled(false);
      setHealthInterval('10s');
      setHealthPath('/health');
      setHealthTimeout('3s');
      setHealthMethod('GET');
      setHealthStatuses('200, 204');
      setHealthyThreshold(2);
      setUnhealthyThreshold(3);
      setStickyEnabled(false);
      setStickyCookie('');
      setStickyTtl('24h');
    }
    setFormError(null);
    setEditorOpen(true);
  };

  const handleAddTargetRow = () => {
    setTargets((prev) => [...prev, { url: '', weight: 1 }]);
  };

  const handleRemoveTargetRow = (index: number) => {
    if (targets.length <= 1) return;
    setTargets((prev) => prev.filter((_, i) => i !== index));
  };

  const handleTargetChange = (index: number, field: 'url' | 'weight', value: any) => {
    setTargets((prev) =>
      prev.map((t, i) => (i === index ? { ...t, [field]: value } : t))
    );
  };

  const handleSavePool = async () => {
    if (!name.trim()) {
      setFormError('Origin pool name is required.');
      return;
    }

    const validTargets = targets.filter((t) => t.url.trim() !== '');
    if (validTargets.length === 0) {
      setFormError('At least one target endpoint URL is required.');
      return;
    }

    for (const t of validTargets) {
      const trimmed = t.url.trim();
      try {
        const u = new URL(trimmed);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') {
          setFormError(`Target URL "${trimmed}" must start with http:// or https://`);
          return;
        }
        if (!u.host) {
          setFormError(`Target URL "${trimmed}" must contain a valid host`);
          return;
        }
      } catch {
        setFormError(`Target URL "${trimmed}" is not a valid URL (must start with http:// or https://)`);
        return;
      }
    }

    const statuses = healthStatuses
      .split(',')
      .map((s) => Number(s.trim()))
      .filter((n) => Number.isInteger(n) && n >= 100 && n <= 599);

    if (healthEnabled && statuses.length === 0) {
      setFormError('Expected statuses must be comma-separated HTTP status codes between 100 and 599 (e.g. 200, 204).');
      return;
    }

    setSaving(true);
    const poolToSave: OriginPool = {
      id: isEditing
        ? pools.find((p) => p.name === editingName)?.id || name.trim()
        : name.trim().toLowerCase().replace(/\s+/g, '-'),
      name: isEditing ? editingName : name.trim(),
      strategy,
      targets: validTargets.map((t) => ({ url: t.url.trim(), weight: Number(t.weight) || 1 })),
      health_check: {
        enabled: healthEnabled,
        interval: healthInterval.trim() || '10s',
        path: healthPath.trim() || '/health',
        timeout: healthTimeout.trim() || '3s',
        method: healthMethod,
        expected_statuses: statuses.length > 0 ? statuses : [200],
        healthy_threshold: Number(healthyThreshold) || 2,
        unhealthy_threshold: Number(unhealthyThreshold) || 3,
      },
      sticky: {
        enabled: stickyEnabled,
        cookie: stickyCookie.trim() || undefined,
        ttl: stickyTtl.trim() || '24h',
      },
    };

    const res = await apiService.saveOrigin(poolToSave);
    setSaving(false);
    if (res.success) {
      setEditorOpen(false);
      setNotification({
        kind: 'success',
        message: isEditing
          ? `Origin pool "${poolToSave.name}" updated successfully.`
          : `Origin pool "${poolToSave.name}" created successfully.`,
      });
      await loadData();
    } else {
      setFormError(res.error || 'Failed to save origin pool. Please check server logs.');
    }
  };

  const confirmDeletePool = (poolName: string) => {
    setPoolToDelete(poolName);
    setDeleteModalOpen(true);
  };

  const handleDeletePool = async () => {
    if (!poolToDelete) return;
    const res = await apiService.deleteOrigin(poolToDelete);
    if (res.success) {
      setNotification({ kind: 'success', message: `Origin pool "${poolToDelete}" deleted.` });
      setDeleteModalOpen(false);
      setPoolToDelete(null);
      await loadData();
    } else {
      setNotification({ kind: 'error', message: res.error || `Failed to delete origin pool "${poolToDelete}".` });
      setDeleteModalOpen(false);
    }
  };

  const formatStrategy = (strat = 'round_robin') => {
    const labels: Record<string, string> = {
      round_robin: 'Round robin',
      weighted_rr: 'Weighted round robin',
      least_conn: 'Least connections',
      ip_hash: 'IP hash',
      random: 'Random',
    };
    return labels[strat] || strat.replace(/_/g, ' ');
  };

  const tableRows = pools.map((pool) => ({
    id: pool.id || pool.name,
    name: pool.name,
    strategy: formatStrategy(pool.strategy),
    poolRaw: pool,
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Delivery"
        title="Origins"
        icon={Network_3}
        action={
          <Button renderIcon={Add} size="md" onClick={() => handleOpenEditor()}>
            Add pool
          </Button>
        }
      />

      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      {loading ? (
        <DataTableSkeleton headers={headers} rowCount={6} columnCount={headers.length} />
      ) : (
        <DataTable rows={tableRows} headers={headers}>
          {({ rows, headers, getHeaderProps, getRowProps, getTableProps, onInputChange }) => (
            <TableContainer title="Origin pools">
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search origin pools..."
                    onChange={(e: any) => onInputChange(e)}
                  />
                  <Button
                    kind="ghost"
                    hasIconOnly
                    renderIcon={Renew}
                    iconDescription="Refresh"
                    onClick={loadData}
                  />
                </TableToolbarContent>
              </TableToolbar>

              <Table {...getTableProps()} size="md" aria-label="Origin Pools Table">
                <TableHead>
                  <TableRow>
                    {headers.map((header) => {
                      const { key, ...props } = getHeaderProps({ header });
                      return (
                        <TableHeader key={key} {...props}>
                          {header.header}
                        </TableHeader>
                      );
                    })}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={headers.length} style={{ textAlign: 'center', padding: '48px 16px' }}>
                        <Network_3 size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                        <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>
                          No origin pools configured
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                          Define an origin pool to group backend servers for load balancing and health checks.
                        </div>
                        <Button kind="tertiary" size="sm" renderIcon={Add} onClick={() => handleOpenEditor()}>
                          Create pool
                        </Button>
                      </TableCell>
                    </TableRow>
                  ) : (
                    rows.map((row) => {
                      const pool = pools.find((p) => (p.id || p.name) === row.id || p.name === row.id);
                      if (!pool) return null;
                      const { key, ...rowProps } = getRowProps({ row });

                      return (
                        <TableRow key={key} {...rowProps}>
                          <TableCell style={{ fontWeight: 600 }}>
                            <Button
                              kind="ghost"
                              size="sm"
                              style={{ padding: '0 4px', fontWeight: 600, color: 'var(--cds-link-primary)' }}
                              onClick={() => handleOpenEditor(pool)}
                            >
                              <Network_3 size={16} style={{ marginRight: '8px' }} />
                              {pool.name}
                            </Button>
                          </TableCell>

                          <TableCell>
                            {pool.targets && pool.targets.length > 0 ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                {pool.targets.map((target, idx) => {
                                  const runtime = getRuntimeTarget(pool.name, target.url);
                                  return (
                                    <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                                      <code style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                                        {target.url}
                                      </code>
                                      {target.weight && target.weight > 1 && (
                                        <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                          (w:{target.weight})
                                        </span>
                                      )}
                                      {runtime?.health_check_enabled && (
                                        <span
                                          style={{
                                            fontSize: '11px',
                                            color: runtime.healthy ? 'var(--cds-support-success, #42be65)' : 'var(--cds-support-error, #fa4d56)',
                                          }}
                                        >
                                          • {runtime.healthy ? (runtime.last_latency_ms ? `${runtime.last_latency_ms} ms` : 'Healthy') : 'Down'}
                                        </span>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            ) : (
                              <span style={{ color: 'var(--cds-text-secondary)', fontSize: '13px' }}>No targets configured</span>
                            )}
                          </TableCell>

                          <TableCell>
                            <PolicyTag strategy={pool.strategy || 'round_robin'} />
                          </TableCell>

                          <TableCell>
                            {pool.health_check?.enabled ? (
                              runtimeAvailable ? (
                                (() => {
                                  const healthyCount = pool.targets.filter(
                                    (t) => getRuntimeTarget(pool.name, t.url)?.healthy
                                  ).length;
                                  const totalCount = pool.targets.length;
                                  const allHealthy = healthyCount === totalCount && totalCount > 0;
                                  return (
                                    <Tag type={allHealthy ? 'green' : 'red'} size="sm">
                                      {healthyCount}/{totalCount} healthy
                                    </Tag>
                                  );
                                })()
                              ) : (
                                <Tag type="blue" size="sm">Configured</Tag>
                              )
                            ) : (
                              <Tag type="cool-gray" size="sm">Disabled</Tag>
                            )}
                          </TableCell>

                          <TableCell>
                            <span style={{ fontSize: '13px', color: pool.sticky?.enabled ? 'var(--cds-text-primary)' : 'var(--cds-text-secondary)' }}>
                              {pool.sticky?.enabled ? `Cookie (${pool.sticky.cookie || 'aegis_sticky'})` : 'Disabled'}
                            </span>
                          </TableCell>

                          <TableCell>
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${pool.name}`}>
                              <OverflowMenuItem
                                itemText="Edit pool"
                                onClick={() => handleOpenEditor(pool)}
                              />
                              <OverflowMenuItem
                                isDelete
                                itemText="Delete pool"
                                onClick={() => confirmDeletePool(pool.name)}
                              />
                            </OverflowMenu>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </DataTable>
      )}

      <Modal
        open={editorOpen}
        modalHeading={isEditing ? `Edit Origin Pool: ${editingName}` : 'Add Origin Pool'}
        modalLabel="Network & Delivery"
        primaryButtonText={saving ? 'Saving...' : isEditing ? 'Save changes' : 'Create pool'}
        secondaryButtonText="Cancel"
        onRequestClose={() => setEditorOpen(false)}
        onRequestSubmit={handleSavePool}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '16px 0' }}>
          {formError && (
            <InlineNotification
              kind="error"
              title="Validation error"
              subtitle={formError}
              onCloseButtonClick={() => setFormError(null)}
            />
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ fontWeight: 600, fontSize: '14px', borderBottom: '1px solid var(--cds-border-subtle)', paddingBottom: '6px' }}>
              Origin Details
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px' }}>
              <TextInput
                id="modal-pool-name"
                labelText="Pool Name"
                placeholder="e.g. backend-api"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={isEditing}
                helperText={isEditing ? 'Pool name cannot be changed' : 'Unique identifier used in route rules'}
                required
              />
              <Select
                id="modal-pool-strategy"
                labelText="Origin Policy"
                value={strategy}
                onChange={(e) => setStrategy(e.target.value)}
              >
                <SelectItem value="round_robin" text="Round robin (Default)" />
                <SelectItem value="weighted_rr" text="Weighted round robin" />
                <SelectItem value="least_conn" text="Least connections" />
                <SelectItem value="ip_hash" text="IP hash" />
              </Select>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--cds-border-subtle)', paddingBottom: '6px' }}>
              <div style={{ fontWeight: 600, fontSize: '14px' }}>Targets</div>
              <Button kind="tertiary" size="sm" renderIcon={Add} onClick={handleAddTargetRow}>
                Add target
              </Button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {targets.map((target, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 40px', gap: '12px', alignItems: 'flex-end' }}>
                  <TextInput
                    id={`target-url-${idx}`}
                    labelText={idx === 0 ? 'Target URL / Endpoint' : ''}
                    hideLabel={idx > 0}
                    placeholder="http://10.0.1.10:8080"
                    value={target.url}
                    onChange={(e) => handleTargetChange(idx, 'url', e.target.value)}
                    required
                  />
                  <NumberInput
                    id={`target-weight-${idx}`}
                    label={idx === 0 ? 'Weight' : ''}
                    hideLabel={idx > 0}
                    value={target.weight}
                    min={1}
                    max={1000}
                    step={1}
                    onChange={(_, { value }) => handleTargetChange(idx, 'weight', Number(value) || 1)}
                  />
                  <Button
                    kind="danger--ghost"
                    size="md"
                    hasIconOnly
                    renderIcon={TrashCan}
                    iconDescription="Remove target"
                    onClick={() => handleRemoveTargetRow(idx)}
                    disabled={targets.length <= 1}
                  />
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px' }}>Health Checks</div>
                <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                  Periodic health probes to detect and isolate unhealthy targets.
                </div>
              </div>
              <StatusToggle
                id="toggle-modal-health"
                hideLabel
                ariaLabel="Enable Health Checks"
                toggled={healthEnabled}
                onToggle={(checked) => setHealthEnabled(checked)}
              />
            </div>

            {healthEnabled && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', padding: '16px', background: 'var(--cds-layer-01)', borderRadius: '4px' }}>
                <TextInput
                  id="hc-path"
                  labelText="Probe Path"
                  placeholder="/health"
                  value={healthPath}
                  onChange={(e) => setHealthPath(e.target.value)}
                />
                <TextInput
                  id="hc-interval"
                  labelText="Interval"
                  placeholder="10s"
                  value={healthInterval}
                  onChange={(e) => setHealthInterval(e.target.value)}
                />
                <TextInput
                  id="hc-timeout"
                  labelText="Timeout"
                  placeholder="3s"
                  value={healthTimeout}
                  onChange={(e) => setHealthTimeout(e.target.value)}
                />
                <Select
                  id="hc-method"
                  labelText="Method"
                  value={healthMethod}
                  onChange={(e) => setHealthMethod(e.target.value as 'GET' | 'HEAD')}
                >
                  <SelectItem value="GET" text="GET" />
                  <SelectItem value="HEAD" text="HEAD" />
                </Select>
                <TextInput
                  id="hc-statuses"
                  labelText="Expected Statuses"
                  placeholder="200, 204"
                  value={healthStatuses}
                  onChange={(e) => setHealthStatuses(e.target.value)}
                  helperText="Expected HTTP status codes (e.g. 200, 204)"
                />
                <NumberInput
                  id="hc-healthy-thresh"
                  label="Healthy Threshold"
                  min={1}
                  max={20}
                  value={healthyThreshold}
                  onChange={(_, { value }) => setHealthyThreshold(Number(value) || 2)}
                />
                <NumberInput
                  id="hc-unhealthy-thresh"
                  label="Unhealthy Threshold"
                  min={1}
                  max={20}
                  value={unhealthyThreshold}
                  onChange={(_, { value }) => setUnhealthyThreshold(Number(value) || 3)}
                />
              </div>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <div style={{ fontWeight: 600, fontSize: '14px' }}>Session Affinity</div>
                <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                  Route returning clients to the same target using cookie affinity.
                </div>
              </div>
              <StatusToggle
                id="toggle-modal-sticky"
                hideLabel
                ariaLabel="Enable Session Affinity"
                toggled={stickyEnabled}
                onToggle={(checked) => setStickyEnabled(checked)}
              />
            </div>

            {stickyEnabled && (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', padding: '16px', background: 'var(--cds-layer-01)', borderRadius: '4px' }}>
                <TextInput
                  id="sticky-cookie"
                  labelText="Cookie Name"
                  placeholder="AEGIS_AFFINITY"
                  value={stickyCookie}
                  onChange={(e) => setStickyCookie(e.target.value)}
                  helperText="Leave empty to auto-generate cookie name"
                />
                <TextInput
                  id="sticky-ttl"
                  labelText="Cookie TTL"
                  placeholder="24h"
                  value={stickyTtl}
                  onChange={(e) => setStickyTtl(e.target.value)}
                  helperText="Cookie lifetime (e.g. 1h, 24h, 7d)"
                />
              </div>
            )}
          </div>
        </div>
      </Modal>

      <Modal
        danger
        open={deleteModalOpen}
        modalHeading="Delete Origin Pool"
        primaryButtonText="Delete pool"
        secondaryButtonText="Cancel"
        onRequestClose={() => setDeleteModalOpen(false)}
        onRequestSubmit={handleDeletePool}
      >
        <p style={{ padding: '16px 0' }}>
          Are you sure you want to delete origin pool <strong>"{poolToDelete}"</strong>? Routes targeting this pool will fail until reassigned.
        </p>
      </Modal>
    </div>
  );
};
