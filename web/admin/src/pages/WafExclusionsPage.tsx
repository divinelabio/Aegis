import React, { useEffect, useState } from 'react';
import {
  DataTable,
  TableContainer,
  TableToolbar,
  TableToolbarContent,
  TableToolbarSearch,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Toggle,
  Modal,
  TextInput,
  Select,
  SelectItem,
  InlineNotification,
  DataTableSkeleton,
} from '@carbon/react';
import { Add, TrashCan, Renew, Filter, Security, Time, CheckmarkOutline } from '@carbon/icons-react';
import type { WAFExclusion } from '../types';
import { apiService } from '../services/api';
import { PageHeader, MetricStrip, KpiCard } from '../components/common';

export const WafExclusionsPage: React.FC = () => {
  const [exclusions, setExclusions] = useState<WAFExclusion[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [scopeFilter, setScopeFilter] = useState<'all' | 'global' | 'rule' | 'active' | 'inactive'>('all');
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [modalOpen, setModalOpen] = useState<boolean>(false);
  const [modalError, setModalError] = useState<string | null>(null);
  const [formRuleId, setFormRuleId] = useState<string>('');
  const [formPaths, setFormPaths] = useState<string>('');
  const [formParams, setFormParams] = useState<string>('');
  const [formIps, setFormIps] = useState<string>('');
  const [formExpiresAt, setFormExpiresAt] = useState<string>('');
  const [formReason, setFormReason] = useState<string>('');
  const [formEnabled, setFormEnabled] = useState<boolean>(true);

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [exclusionToDelete, setExclusionToDelete] = useState<WAFExclusion | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await apiService.getExclusions();
      setExclusions(data);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load exclusions' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();

    const handlePreselectedRule = () => {
      const hash = window.location.hash || '';
      let preselectedRuleId = '';
      let preselectedPath = '';
      let preselectedIp = '';
      let preselectedReason = '';

      const qIndex = hash.indexOf('?');
      if (qIndex !== -1) {
        const params = new URLSearchParams(hash.slice(qIndex + 1));
        preselectedRuleId = params.get('rule_id') || params.get('ruleId') || '';
        preselectedPath = params.get('path') || '';
        preselectedIp = params.get('ip') || '';
        preselectedReason = params.get('reason') || '';
      }

      try {
        const stored = sessionStorage.getItem('aegis_draft_waf_exclusion');
        if (stored) {
          const parsed = JSON.parse(stored);
          sessionStorage.removeItem('aegis_draft_waf_exclusion');
          if (parsed.rule_id) preselectedRuleId = String(parsed.rule_id);
          if (parsed.paths) {
            preselectedPath = Array.isArray(parsed.paths) ? parsed.paths.join(', ') : String(parsed.paths);
          }
          if (parsed.ips) {
            preselectedIp = Array.isArray(parsed.ips) ? parsed.ips.join(', ') : String(parsed.ips);
          }
          if (parsed.params) {
            setFormParams(Array.isArray(parsed.params) ? parsed.params.join(', ') : String(parsed.params));
          }
          if (parsed.reason) preselectedReason = String(parsed.reason);
        }
      } catch {
      }

      if (preselectedRuleId) {
        setFormRuleId(preselectedRuleId);
        if (preselectedPath) setFormPaths(preselectedPath);
        if (preselectedIp) setFormIps(preselectedIp);
        if (preselectedReason) setFormReason(preselectedReason);
        setModalOpen(true);
      }
    };

    handlePreselectedRule();
  }, []);

  const isExpired = (ex: WAFExclusion) => {
    if (!ex.expires_at) return false;
    const time = Date.parse(ex.expires_at);
    return !Number.isNaN(time) && Date.now() > time;
  };

  const handleToggle = async (ex: WAFExclusion, checked: boolean) => {
    const updated = { ...ex, enabled: checked };
    setExclusions((prev) => prev.map((item) => (item.id === ex.id ? updated : item)));
    const res = await apiService.toggleExclusion(ex.id, checked, ex);
    if (!res.success) {
      setExclusions((prev) => prev.map((item) => (item.id === ex.id ? ex : item)));
      setNotification({ kind: 'error', message: res.error || 'Failed to update exclusion state' });
    } else {
      setNotification({
        kind: 'success',
        message: `Exclusion ${checked ? 'enabled' : 'disabled'}`,
      });
    }
  };

  const openAddModal = () => {
    setModalError(null);
    setFormRuleId('');
    setFormPaths('');
    setFormParams('');
    setFormIps('');
    setFormExpiresAt('');
    setFormReason('');
    setFormEnabled(true);
    setModalOpen(true);
  };

  const handleSaveExclusion = async () => {
    setModalError(null);
    const ruleId = formRuleId.trim();
    const paths = formPaths
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const params = formParams
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const ips = formIps
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    const reason = formReason.trim();
    const expiresRaw = formExpiresAt.trim();

    if (ruleId && !/^\d+$/.test(ruleId)) {
      setModalError('Rule ID must be numeric (e.g. 942100). Leave empty for a global exclusion.');
      return;
    }
    if (!ruleId && paths.length === 0 && params.length === 0 && ips.length === 0) {
      setModalError('Specify a Rule ID or at least one condition (path, parameter, or IP).');
      return;
    }
    if (!ruleId && paths.length === 0) {
      setModalError('Global exclusions require at least one path.');
      return;
    }
    if (!ruleId && (params.length > 0 || ips.length > 0)) {
      setModalError('Parameter and IP exclusions require a numeric Rule ID.');
      return;
    }

    let formattedExpires: string | undefined;
    if (expiresRaw) {
      const parsed = new Date(expiresRaw);
      if (Number.isNaN(parsed.getTime())) {
        setModalError('Enter a valid expiration date/time.');
        return;
      }
      formattedExpires = parsed.toISOString();
    }

    const newExclusion: WAFExclusion = {
      id: '',
      rule_id: ruleId || undefined,
      paths,
      params,
      ips,
      reason,
      description: reason,
      comment: reason,
      path_pattern: paths.join(', '),
      expires_at: formattedExpires,
      enabled: formEnabled,
    };

    const result = await apiService.saveExclusion(newExclusion, false);
    if (result.success) {
      await loadData();
      setModalOpen(false);
      setNotification({ kind: 'success', message: 'Exclusion added' });
    } else {
      setModalError(result.error || 'Failed to add exclusion');
    }
  };

  const confirmDelete = (ex: WAFExclusion) => {
    setExclusionToDelete(ex);
    setDeleteConfirmOpen(true);
  };

  const handleDelete = async () => {
    if (!exclusionToDelete) return;
    const res = await apiService.deleteExclusion(exclusionToDelete.id);
    if (res.success) {
      setExclusions((prev) => prev.filter((item) => item.id !== exclusionToDelete.id));
      setNotification({ kind: 'success', message: 'Exclusion deleted' });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to delete exclusion' });
    }
    setDeleteConfirmOpen(false);
    setExclusionToDelete(null);
  };

  const filteredExclusions = exclusions.filter((ex) => {
    const isGlobal = !ex.rule_id;
    const enabled = ex.enabled !== false;

    if (scopeFilter === 'global' && !isGlobal) return false;
    if (scopeFilter === 'rule' && isGlobal) return false;
    if (scopeFilter === 'active' && !enabled) return false;
    if (scopeFilter === 'inactive' && enabled) return false;

    const q = searchQuery.trim().toLowerCase();
    if (!q) return true;

    const haystack = [
      ex.rule_id,
      ex.reason,
      ex.description,
      ex.comment,
      ...(ex.paths || []),
      ...(ex.params || []),
      ...(ex.ips || []),
      ex.path_pattern,
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(q);
  });

  const globalCount = exclusions.filter((e) => !e.rule_id).length;
  const ruleCount = exclusions.length - globalCount;
  const activeCount = exclusions.filter((e) => e.enabled !== false).length;
  const inactiveCount = exclusions.length - activeCount;
  const expiredCount = exclusions.filter((e) => isExpired(e)).length;

  const headers = [
    { key: 'scope', header: 'Rule / Scope' },
    { key: 'condition', header: 'Target Conditions' },
    { key: 'reason', header: 'Reason' },
    { key: 'expires', header: 'Expires' },
    { key: 'status', header: 'Status' },
    { key: 'actions', header: 'Actions' },
  ];

  const tableRows = filteredExclusions.map((ex, idx) => ({
    id: ex.id || `excl-${idx}`,
    scope: ex.rule_id ? `Rule #${ex.rule_id}` : 'All rules (Global)',
    condition: ex.path_pattern || 'All traffic',
    reason: ex.reason || ex.description || ex.comment || 'No reason provided',
    expires: ex.expires_at ? new Date(ex.expires_at).toLocaleDateString() : 'Never',
    status: ex.enabled !== false,
  }));

  const exclusionsMap = new Map(filteredExclusions.map((ex, idx) => [ex.id || `excl-${idx}`, ex]));

  return (
    <div style={{ padding: '32px' }}>
      <PageHeader
        kicker="Application firewall"
        title="Rule exclusions"
        icon={Filter}
        action={
          <Button kind="primary" renderIcon={Add} size="md" onClick={openAddModal}>
            Create Exclusion
          </Button>
        }
      />

      {notification && (
        <div style={{ marginBottom: '16px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <MetricStrip columns={4}>
        <KpiCard
          label="Total Exclusions"
          value={exclusions.length.toLocaleString()}
          subtext={`${globalCount} global · ${ruleCount} rule-specific`}
          icon={Filter}
        />
        <KpiCard
          label="Active Exceptions"
          value={activeCount.toLocaleString()}
          subtext={`${inactiveCount} disabled`}
          icon={CheckmarkOutline}
        />
        <KpiCard
          label="Expired Rules"
          value={expiredCount.toLocaleString()}
          subtext="Time-bound review"
          icon={Time}
        />
        <KpiCard
          label="Filtered View"
          value={filteredExclusions.length.toLocaleString()}
          subtext={`Scope: ${scopeFilter}`}
          icon={Security}
        />
      </MetricStrip>

      {loading ? (
        <DataTableSkeleton headers={headers} rowCount={6} columnCount={headers.length} />
      ) : (
        <DataTable rows={tableRows} headers={headers}>
          {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer
              title="Configured Exclusions"
              description="Bypass false positives and manage inspection exemptions for trusted traffic."
            >
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search exclusions..."
                    value={searchQuery}
                    onChange={(e: any, val?: string) => setSearchQuery(val ?? e?.target?.value ?? '')}
                    onClear={() => setSearchQuery('')}
                  />
                  <div style={{ width: '180px', marginRight: '8px' }}>
                    <Select
                      id="scope-filter"
                      labelText="Filter exclusions by scope"
                      hideLabel
                      size="md"
                      value={scopeFilter}
                      onChange={(e) => setScopeFilter(e.target.value as any)}
                    >
                      <SelectItem value="all" text="All Scopes" />
                      <SelectItem value="global" text="Global Only" />
                      <SelectItem value="rule" text="Rule-Specific" />
                      <SelectItem value="active" text="Active" />
                      <SelectItem value="inactive" text="Inactive" />
                    </Select>
                  </div>
                  <Button
                    kind="ghost"
                    hasIconOnly
                    renderIcon={Renew}
                    iconDescription="Refresh"
                    onClick={loadData}
                  />
                </TableToolbarContent>
              </TableToolbar>

              <Table {...getTableProps()} size="md" aria-label="WAF Exclusions Table">
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
                        <Filter size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                        <div
                          style={{
                            fontWeight: 600,
                            fontSize: '14px',
                            marginBottom: '4px',
                            color: 'var(--cds-text-primary)',
                          }}
                        >
                          {exclusions.length === 0
                            ? 'No exclusions configured'
                            : 'No matching exclusions found'}
                        </div>
                        <div
                          style={{
                            color: 'var(--cds-text-secondary)',
                            fontSize: '13px',
                            marginBottom: '16px',
                            maxWidth: '440px',
                            margin: '0 auto 16px',
                          }}
                        >
                          {exclusions.length === 0
                            ? 'Add an exclusion to bypass false positives on trusted traffic, specific paths, or known parameters.'
                            : 'No rule exclusions match the current search query or scope filter. Try clearing filters or adjust your search.'}
                        </div>
                        {exclusions.length === 0 ? (
                          <Button kind="primary" size="sm" renderIcon={Add} onClick={openAddModal}>
                            Create Exclusion
                          </Button>
                        ) : (
                          <div style={{ display: 'inline-flex', gap: '8px' }}>
                            <Button
                              kind="tertiary"
                              size="sm"
                              onClick={() => {
                                setSearchQuery('');
                                setScopeFilter('all');
                              }}
                            >
                              Clear filters
                            </Button>
                            <Button kind="primary" size="sm" renderIcon={Add} onClick={openAddModal}>
                              Create Exclusion
                            </Button>
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ) : (
                    rows.map((row) => {
                      const raw = exclusionsMap.get(row.id);
                      if (!raw) return null;
                      const expired = isExpired(raw);
                      const paths = raw.paths && raw.paths.length > 0 ? raw.paths : (raw.path_pattern ? [raw.path_pattern] : []);
                      const params = raw.params || [];
                      const ips = raw.ips || [];

                      return (
                        <TableRow {...getRowProps({ row })} key={row.id}>
                          <TableCell>
                            <Tag type={raw.rule_id ? 'blue' : 'cool-gray'} size="sm">
                              {raw.rule_id ? `Rule #${raw.rule_id}` : 'Global (All Rules)'}
                            </Tag>
                          </TableCell>
                          <TableCell>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                              {paths.length > 0 && (
                                <div style={{ fontSize: '12px' }}>
                                  <strong style={{ color: 'var(--cds-text-secondary)' }}>Paths: </strong>
                                  <code style={{ background: 'var(--cds-layer-02)', padding: '2px 6px' }}>
                                    {paths.join(', ')}
                                  </code>
                                </div>
                              )}
                              {params.length > 0 && (
                                <div style={{ fontSize: '12px' }}>
                                  <strong style={{ color: 'var(--cds-text-secondary)' }}>Params: </strong>
                                  <code style={{ background: 'var(--cds-layer-02)', padding: '2px 6px' }}>
                                    {params.join(', ')}
                                  </code>
                                </div>
                              )}
                              {ips.length > 0 && (
                                <div style={{ fontSize: '12px' }}>
                                  <strong style={{ color: 'var(--cds-text-secondary)' }}>IPs: </strong>
                                  <code style={{ background: 'var(--cds-layer-02)', padding: '2px 6px' }}>
                                    {ips.join(', ')}
                                  </code>
                                </div>
                              )}
                              {paths.length === 0 && params.length === 0 && ips.length === 0 && (
                                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>All traffic</span>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <div style={{ fontWeight: 500, color: 'var(--cds-text-primary)' }}>
                              {raw.reason || raw.description || raw.comment || 'No reason provided'}
                            </div>
                          </TableCell>
                          <TableCell>
                            <span style={{ color: expired ? 'var(--cds-support-error)' : 'inherit', fontWeight: expired ? 600 : 'normal' }}>
                              {raw.expires_at ? new Date(raw.expires_at).toLocaleString() : 'Never'}
                              {expired && ' (Expired)'}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Toggle
                              id={`toggle-excl-${raw.id}`}
                              size="sm"
                              labelText=""
                              hideLabel
                              toggled={raw.enabled !== false}
                              onToggle={(checked) => handleToggle(raw, checked)}
                              aria-label={`Toggle exclusion ${raw.id}`}
                            />
                          </TableCell>
                          <TableCell>
                            <Button
                              kind="danger--ghost"
                              hasIconOnly
                              renderIcon={TrashCan}
                              iconDescription="Delete Exclusion"
                              size="sm"
                              onClick={() => confirmDelete(raw)}
                            />
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
        open={modalOpen}
        modalHeading="Create Rule Exclusion"
        primaryButtonText="Add Exclusion"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleSaveExclusion}
        onRequestClose={() => setModalOpen(false)}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '8px 0' }}>
          {modalError && (
            <InlineNotification
              kind="error"
              title="Validation Error"
              subtitle={modalError}
              lowContrast
              onCloseButtonClick={() => setModalError(null)}
            />
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <TextInput
              id="excl-rule-id"
              labelText="Rule ID"
              helperText="Leave blank to apply to all rules"
              placeholder="e.g. 942100"
              value={formRuleId}
              onChange={(e) => setFormRuleId(e.target.value)}
            />
            <TextInput
              id="excl-expires"
              type="datetime-local"
              labelText="Expires At"
              helperText="Leave blank for no expiration"
              value={formExpiresAt}
              onChange={(e) => setFormExpiresAt(e.target.value)}
            />
          </div>

          <TextInput
            id="excl-paths"
            labelText="Paths (comma-separated)"
            placeholder="/api/upload, /webhook"
            value={formPaths}
            onChange={(e) => setFormPaths(e.target.value)}
          />

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
            <TextInput
              id="excl-params"
              labelText="Parameters (comma-separated)"
              placeholder="ARGS:content, ARGS:body"
              value={formParams}
              onChange={(e) => setFormParams(e.target.value)}
            />
            <TextInput
              id="excl-ips"
              labelText="IPs / CIDRs (comma-separated)"
              placeholder="192.168.1.10, 10.0.0.0/24"
              value={formIps}
              onChange={(e) => setFormIps(e.target.value)}
            />
          </div>

          <TextInput
            id="excl-reason"
            labelText="Reason"
            placeholder="e.g. False positive on file upload endpoint"
            value={formReason}
            onChange={(e) => setFormReason(e.target.value)}
          />

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '8px' }}>
            <span style={{ fontSize: '14px', fontWeight: 500, color: 'var(--cds-text-primary)' }}>
              Enable immediately
            </span>
            <Toggle
              id="excl-enabled"
              size="sm"
              labelText=""
              hideLabel
              toggled={formEnabled}
              onToggle={(checked) => setFormEnabled(checked)}
              aria-label="Enable exclusion immediately"
            />
          </div>
        </div>
      </Modal>

      <Modal
        open={deleteConfirmOpen}
        danger
        modalHeading="Delete Exclusion"
        primaryButtonText="Delete"
        secondaryButtonText="Cancel"
        onRequestSubmit={handleDelete}
        onRequestClose={() => setDeleteConfirmOpen(false)}
      >
        <p>
          Are you sure you want to delete exclusion{' '}
          <strong>"{exclusionToDelete?.reason || exclusionToDelete?.comment || exclusionToDelete?.id}"</strong>?
          Protected traffic will immediately be subject to WAF inspection again.
        </p>
      </Modal>
    </div>
  );
};

export default WafExclusionsPage;

