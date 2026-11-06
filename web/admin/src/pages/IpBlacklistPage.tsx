import React, { useState, useEffect, useMemo, useRef } from 'react';
import {
  Tile,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Button,
  Tag,
  Select,
  SelectItem,
  Modal,
  TextArea,
  Search,
  InlineNotification,
  DataTableSkeleton,
  Checkbox,
  Pagination,
} from '@carbon/react';
import { Add, Upload, Misuse } from '@carbon/icons-react';
import { PageHeader, KpiCard, MetricStrip } from '../components/common';
import type { NavItemKey } from '../types';
import { apiService } from '../services/api';

interface IpBlacklistPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

interface BlacklistRow {
  target: string;
  expires_at?: string;
  note?: string;
}

interface CsvEntry {
  target: string;
  expires_at?: string | null;
  note?: string;
}

function isValidTrafficBlacklistTarget(entry: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const cidrV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
  const cidrV6Regex = /^([0-9a-fA-F:]+)\/([0-9]{1,3})$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^::$/;
  const cidrV6Match = cidrV6Regex.exec(entry);
  const isValidCidrV6 = Boolean(cidrV6Match && Number.parseInt(cidrV6Match[2], 10) >= 1 && Number.parseInt(cidrV6Match[2], 10) <= 128);

  return cidrV4Regex.test(entry) || isValidCidrV6 || ipv4Regex.test(entry) || ipv6Regex.test(entry);
}

function parseTrafficCsvRows(content: string): string[][] | null {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let quoted = false;

  const finishRow = (): void => {
    row.push(cell);
    if (row.some((value) => value.trim() !== '')) rows.push(row);
    row = [];
    cell = '';
  };

  for (let index = 0; index < content.length; index++) {
    const character = content[index];
    if (character === '"') {
      if (quoted && content[index + 1] === '"') {
        cell += '"';
        index++;
      } else {
        quoted = !quoted;
      }
    } else if (character === ',' && !quoted) {
      row.push(cell);
      cell = '';
    } else if (character === '\n' && !quoted) {
      finishRow();
    } else if (character !== '\r') {
      cell += character;
    }
  }

  if (quoted) return null;
  if (cell !== '' || row.length > 0) finishRow();
  return rows;
}

function parseTrafficBlacklistCSV(content: string): { entries: CsvEntry[]; invalidRows: number; malformed: boolean } {
  const rows = parseTrafficCsvRows(content.replace(/^\uFEFF/, ''));
  if (!rows) return { entries: [], invalidRows: 0, malformed: true };
  if (rows.length === 0) return { entries: [], invalidRows: 0, malformed: false };

  const header = rows[0].map((value) => value.trim().toLowerCase().replace(/[\s-]+/g, '_'));
  const headerIndex = (...names: string[]): number => header.findIndex((value) => names.includes(value));
  const headerTarget = headerIndex('target', 'ip', 'ip_address', 'address');
  const headerExpiration = headerIndex('expiration', 'expires', 'expires_at');
  const headerNote = headerIndex('note', 'notes', 'comment');
  const hasHeader = headerTarget >= 0 || headerExpiration >= 0 || headerNote >= 0;
  const targetIndex = headerTarget >= 0 ? headerTarget : 0;
  const sourceRows = hasHeader ? rows.slice(1) : rows;
  const entries = new Map<string, CsvEntry>();
  let invalidRows = 0;

  for (const row of sourceRows) {
    const target = (row[targetIndex] || '').trim();
    if (!target) continue;
    if (!isValidTrafficBlacklistTarget(target)) {
      invalidRows++;
      continue;
    }

    const expiration = headerExpiration >= 0 ? (row[headerExpiration] || '').trim() : '';
    let expiresAt: string | null = null;
    if (expiration && !/^permanent$/i.test(expiration)) {
      const timestamp = Date.parse(expiration);
      if (Number.isNaN(timestamp)) {
        invalidRows++;
        continue;
      }
      expiresAt = new Date(timestamp).toISOString();
    }

    entries.set(target, {
      target,
      expires_at: expiresAt,
      note: headerNote >= 0 ? (row[headerNote] || '').trim() : '',
    });
  }

  return { entries: Array.from(entries.values()), invalidRows, malformed: false };
}

export const IpBlacklistPage: React.FC<IpBlacklistPageProps> = () => {
  const [loading, setLoading] = useState(true);
  const [engineEnabled, setEngineEnabled] = useState(true);
  const [entries, setEntries] = useState<BlacklistRow[]>([]);
  const [notification, setNotification] = useState<{ kind: 'info' | 'warning' | 'error'; message: string } | null>(null);

  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());

  const fileInputRef = useRef<HTMLInputElement>(null);

  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingTarget, setEditingTarget] = useState<string | null>(null);
  const [targetsText, setTargetsText] = useState('');
  const [modalDuration, setModalDuration] = useState('permanent');
  const [isSubmitting, setIsSubmitting] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  const [isBulkDeleteModalOpen, setIsBulkDeleteModalOpen] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getIPBlacklistConfig();
      setEngineEnabled(cfg.enabled !== false);

      const entryMap = new Map<string, BlacklistRow>();
      (cfg.entries || []).forEach((e) => {
        if (e.target) {
          entryMap.set(e.target.trim(), {
            target: e.target.trim(),
            expires_at: e.expires_at,
            note: e.note,
          });
        }
      });
      (cfg.ips || []).forEach((ip) => {
        const clean = ip.trim();
        if (clean && !entryMap.has(clean)) entryMap.set(clean, { target: clean });
      });
      (cfg.cidrs || []).forEach((cidr) => {
        const clean = cidr.trim();
        if (clean && !entryMap.has(clean)) entryMap.set(clean, { target: clean });
      });

      setEntries(Array.from(entryMap.values()));
    } catch (err) {
      console.error('Failed to load blacklist:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadData();
  }, []);

  const searchQuery = search.trim().toLowerCase();
  const totalCount = entries.length;
  const cidrCount = useMemo(() => entries.filter((e) => e.target.includes('/')).length, [entries]);
  const singleIpCount = totalCount - cidrCount;
  const expiringCount = useMemo(() => entries.filter((e) => Boolean(e.expires_at)).length, [entries]);

  const filteredEntries = useMemo(() => {
    if (!searchQuery) return entries;
    return entries.filter((e) => e.target.toLowerCase().includes(searchQuery));
  }, [entries, searchQuery]);

  const filteredCount = filteredEntries.length;
  const totalPages = Math.max(1, Math.ceil(filteredCount / pageSize));

  useEffect(() => {
    if (page > totalPages) setPage(1);
  }, [page, totalPages]);

  const pageEntries = useMemo(() => {
    const start = (page - 1) * pageSize;
    return filteredEntries.slice(start, start + pageSize);
  }, [filteredEntries, page, pageSize]);

  const allPageSelected = pageEntries.length > 0 && pageEntries.every((e) => selectedTargets.has(e.target));

  // Parse Targets from Textarea (supports multiple lines or comma-separated list)
  const parsedTargets = useMemo(() => {
    const rawLines = targetsText
      .split(/[\r\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    const valid: string[] = [];
    const invalid: string[] = [];

    rawLines.forEach((t) => {
      if (isValidTrafficBlacklistTarget(t)) {
        valid.push(t);
      } else {
        invalid.push(t);
      }
    });

    return { rawLines, valid, invalid };
  }, [targetsText]);

  const openAddModal = () => {
    setEditingTarget(null);
    setTargetsText('');
    setModalDuration('permanent');
    setIsAddModalOpen(true);
  };

  const editingEntry = useMemo(() => {
    if (!editingTarget) return null;
    return entries.find((e) => e.target === editingTarget) || null;
  }, [editingTarget, entries]);

  const existingExpiryLabel = editingEntry?.expires_at
    ? new Date(editingEntry.expires_at).toLocaleString()
    : '';

  const openEditModal = (entry: BlacklistRow) => {
    setEditingTarget(entry.target);
    setTargetsText(entry.target);
    setModalDuration(entry.expires_at ? 'existing' : 'permanent');
    setIsAddModalOpen(true);
  };

  const computeExpiresAt = (duration: string, existing?: string | null): string | undefined => {
    if (duration === 'existing' && existing) return existing;
    if (duration === 'permanent' || !duration) return undefined;
    const map: Record<string, number> = {
      '1h': 3600 * 1000,
      '24h': 86400 * 1000,
      '7d': 7 * 86400 * 1000,
      '30d': 30 * 86400 * 1000,
    };
    if (map[duration]) {
      return new Date(Date.now() + map[duration]).toISOString();
    }
    const parsed = Date.parse(duration);
    if (!Number.isNaN(parsed)) {
      return new Date(parsed).toISOString();
    }
    return undefined;
  };

  const handleAddSubmit = async () => {
    if (parsedTargets.valid.length === 0 || parsedTargets.invalid.length > 0) return;
    setIsSubmitting(true);
    try {
      const current = await apiService.getIPBlacklistConfig();
      const removeSet = new Set<string>();
      if (editingTarget && !parsedTargets.valid.includes(editingTarget)) {
        removeSet.add(editingTarget);
      }
      parsedTargets.valid.forEach((t) => removeSet.add(t));

      const nextIps = (current.ips || []).filter((ip) => !removeSet.has(ip));
      const nextCidrs = (current.cidrs || []).filter((cidr) => !removeSet.has(cidr));
      const nextEntries = (current.entries || []).filter((e) => !removeSet.has(e.target));

      const expiresAt = computeExpiresAt(modalDuration, editingEntry?.expires_at);

      for (const target of parsedTargets.valid) {
        nextEntries.push({
          target,
          note: 'Added via Web Admin',
          ...(expiresAt ? { expires_at: expiresAt } : {}),
        });
      }

      const ok = await apiService.saveIPBlacklistConfig({
        enabled: true,
        ips: nextIps,
        cidrs: nextCidrs,
        entries: nextEntries,
      });

      if (ok) {
        setNotification({
          kind: 'info',
          message: editingTarget ? 'Entry updated' : `Added ${parsedTargets.valid.length} block rule${parsedTargets.valid.length === 1 ? '' : 's'}`,
        });
        setIsAddModalOpen(false);
        setEditingTarget(null);
        setTargetsText('');
        setModalDuration('permanent');
        await loadData();
      } else {
        setNotification({ kind: 'error', message: 'Failed to save block rule(s)' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to save block rule(s)' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!deleteTarget) return;
    setIsSubmitting(true);
    try {
      const ok = await apiService.removeIPBlockEntry(deleteTarget);
      if (ok) {
        selectedTargets.delete(deleteTarget);
        setSelectedTargets(new Set(selectedTargets));
        setDeleteTarget(null);
        setNotification({ kind: 'info', message: `Removed block for ${deleteTarget}` });
        await loadData();
      } else {
        setNotification({ kind: 'error', message: 'Failed to remove block entry' });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleConfirmDeleteSelected = async () => {
    if (selectedTargets.size === 0) return;
    setIsSubmitting(true);
    const count = selectedTargets.size;
    try {
      const current = await apiService.getIPBlacklistConfig();
      const nextIps = (current.ips || []).filter((ip) => !selectedTargets.has(ip));
      const nextCidrs = (current.cidrs || []).filter((cidr) => !selectedTargets.has(cidr));
      const nextEntries = (current.entries || []).filter((e) => !selectedTargets.has(e.target));

      const ok = await apiService.saveIPBlacklistConfig({
        enabled: current.enabled,
        ips: nextIps,
        cidrs: nextCidrs,
        entries: nextEntries,
      });

      if (ok) {
        setSelectedTargets(new Set());
        setIsBulkDeleteModalOpen(false);
        setNotification({ kind: 'info', message: `Removed ${count} block entr${count === 1 ? 'y' : 'ies'}` });
        await loadData();
      } else {
        setNotification({ kind: 'error', message: 'Failed to remove selected entries' });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFileImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';

    const isCsv = file.name.toLowerCase().endsWith('.csv') || file.type === 'text/csv';
    if (!isCsv) {
      setNotification({ kind: 'warning', message: 'Choose a CSV file containing blacklist targets.' });
      return;
    }
    if (file.size === 0) {
      setNotification({ kind: 'warning', message: 'The selected CSV file is empty.' });
      return;
    }
    if (file.size > 2 * 1024 * 1024) {
      setNotification({ kind: 'warning', message: 'CSV imports are limited to 2 MB.' });
      return;
    }

    try {
      const text = await file.text();
      const parsed = parseTrafficBlacklistCSV(text);
      if (parsed.malformed) {
        setNotification({ kind: 'warning', message: 'The CSV has an unclosed quoted value.' });
        return;
      }
      if (parsed.entries.length === 0) {
        setNotification({ kind: 'warning', message: 'No valid IP addresses or CIDR ranges were found in the CSV.' });
        return;
      }

      const current = await apiService.getIPBlacklistConfig();
      const importedTargets = new Set(parsed.entries.map((e) => e.target));

      const nextIps = (current.ips || []).filter((ip) => !importedTargets.has(ip));
      const nextCidrs = (current.cidrs || []).filter((cidr) => !importedTargets.has(cidr));
      const nextEntries = (current.entries || []).filter((e) => !importedTargets.has(e.target));

      for (const entry of parsed.entries) {
        nextEntries.push({
          target: entry.target,
          note: entry.note || 'Imported via CSV',
          ...(entry.expires_at ? { expires_at: entry.expires_at } : {}),
        });
      }

      const ok = await apiService.saveIPBlacklistConfig({
        enabled: true,
        ips: nextIps,
        cidrs: nextCidrs,
        entries: nextEntries,
      });

      if (ok) {
        setSelectedTargets(new Set());
        setPage(1);
        setSearch('');
        const skipped = parsed.invalidRows > 0 ? ` Skipped ${parsed.invalidRows} invalid row${parsed.invalidRows === 1 ? '' : 's'}.` : '';
        setNotification({ kind: 'info', message: `Imported ${parsed.entries.length} block rule${parsed.entries.length === 1 ? '' : 's'}.${skipped}` });
        await loadData();
      } else {
        setNotification({ kind: 'error', message: 'Failed to save imported blacklist entries.' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'Unable to read the selected CSV file.' });
    }
  };

  return (
    <div style={{ padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <input
        ref={fileInputRef}
        type="file"
        accept=".csv,text/csv"
        style={{ display: 'none' }}
        onChange={handleFileImport}
      />

      <PageHeader
        kicker="Traffic control"
        title="IP Blacklist"
        icon={Misuse}
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Button
              kind="secondary"
              renderIcon={Upload}
              onClick={() => fileInputRef.current?.click()}
            >
              Import CSV
            </Button>
            <Button
              kind="primary"
              renderIcon={Add}
              onClick={openAddModal}
            >
              Add entry
            </Button>
          </div>
        }
      />

      {notification && (
        <div style={{ marginBottom: '20px' }}>
          <InlineNotification
            kind={notification.kind}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <MetricStrip minColWidth="200px">
        <KpiCard
          label="Total Blocked Targets"
          value={totalCount}
          subtext="Active block entries"
          status="default"
        />
        <KpiCard
          label="CIDR Subnets"
          value={cidrCount}
          subtext="Network ranges"
          status="default"
        />
        <KpiCard
          label="Host Addresses"
          value={singleIpCount}
          subtext="Single IP addresses"
          status="default"
        />
        <KpiCard
          label="Temporary Blocks"
          value={expiringCount}
          subtext="Expiring rules"
          status="default"
        />
      </MetricStrip>

      <Tile style={{ padding: 0 }}>
        {selectedTargets.size > 0 && (
          <div
            style={{
              padding: '12px 24px',
              backgroundColor: 'var(--cds-layer-02)',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              borderBottom: '1px solid var(--cds-border-subtle)',
            }}
          >
            <span style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
              <strong>{selectedTargets.size}</strong> {selectedTargets.size === 1 ? 'target' : 'targets'} selected
            </span>
            <div style={{ display: 'flex', gap: '8px' }}>
              <Button
                kind="secondary"
                size="sm"
                onClick={() => setSelectedTargets(new Set())}
              >
                Clear selection
              </Button>
              <Button
                kind="danger"
                size="sm"
                onClick={() => setIsBulkDeleteModalOpen(true)}
              >
                Delete selected
              </Button>
            </div>
          </div>
        )}

        <div
          style={{
            padding: '14px 24px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            gap: '16px',
            borderBottom: '1px solid var(--cds-border-subtle, #393939)',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
            <strong style={{ color: 'var(--cds-text-primary)' }}>{searchQuery ? filteredCount : totalCount}</strong>{' '}
            <span>{searchQuery ? `matching ${filteredCount === 1 ? 'entry' : 'entries'} of ${totalCount}` : totalCount === 1 ? 'entry' : 'entries'}</span>
          </div>
          <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
            <div style={{ width: '260px' }}>
              <Search
                size="md"
                labelText="Search blocked targets"
                placeholder="Search by IP or CIDR..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <div style={{ width: '130px' }}>
              <Select
                id="page-size-select"
                size="md"
                hideLabel
                labelText="Entries per page"
                value={String(pageSize)}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
              >
                <SelectItem value="10" text="10 rows" />
                <SelectItem value="25" text="25 rows" />
                <SelectItem value="100" text="100 rows" />
              </Select>
            </div>
          </div>
        </div>

        {loading ? (
          <DataTableSkeleton columnCount={7} rowCount={8} showHeader={false} showToolbar={false} />
        ) : (
          <Table size="md" aria-label="IP Blacklist Entries">
            <TableHead>
              <TableRow>
                <TableHeader style={{ width: '48px', textAlign: 'center' }}>
                  <Checkbox
                    id="select-all-targets-chk"
                    labelText="Select all items"
                    hideLabel
                    checked={allPageSelected}
                    title="Select all on page"
                    onChange={(_, { checked }) => {
                      if (checked) {
                        const next = new Set(selectedTargets);
                        pageEntries.forEach((item) => next.add(item.target));
                        setSelectedTargets(next);
                      } else {
                        const next = new Set(selectedTargets);
                        pageEntries.forEach((item) => next.delete(item.target));
                        setSelectedTargets(next);
                      }
                    }}
                  />
                </TableHeader>
                <TableHeader>Target</TableHeader>
                <TableHeader>Type</TableHeader>
                <TableHeader>Expiration</TableHeader>
                <TableHeader style={{ textAlign: 'right' }}>Actions</TableHeader>
              </TableRow>
            </TableHead>
            <TableBody>
              {pageEntries.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} style={{ textAlign: 'center', padding: '48px 16px' }}>
                    <Misuse size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                    <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px' }}>
                      {searchQuery ? 'No matching targets' : 'No blocks active'}
                    </div>
                    <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                      {searchQuery
                        ? 'Try a different IP address or network range.'
                        : 'No blacklisted IPs yet. Add an IP or import a CSV to block traffic.'}
                    </div>
                    {!searchQuery && (
                      <Button kind="tertiary" size="sm" renderIcon={Add} onClick={openAddModal}>
                        Add first entry
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ) : (
                pageEntries.map((entry) => {
                  const isCidr = entry.target.includes('/');
                  const expiresAt = entry.expires_at ? new Date(entry.expires_at) : null;
                  const now = new Date();
                  const isExpired = Boolean(expiresAt && expiresAt < now);
                  const expiresLabel = expiresAt
                    ? expiresAt.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
                    : 'Permanent';
                  const isSelected = selectedTargets.has(entry.target);

                  return (
                    <TableRow key={entry.target}>
                      <TableCell style={{ textAlign: 'center' }}>
                        <Checkbox
                          id={`select-target-chk-${entry.target.replace(/[^a-zA-Z0-9_-]/g, '_')}`}
                          labelText="Target chk ${entry.target.replace(/[^a zA Z0 9  ]/g, ' ')}"
                          hideLabel
                          checked={isSelected}
                          aria-label={`Select ${entry.target}`}
                          onChange={(_, { checked }) => {
                            const next = new Set(selectedTargets);
                            if (checked) next.add(entry.target);
                            else next.delete(entry.target);
                            setSelectedTargets(next);
                          }}
                        />
                      </TableCell>
                      <TableCell>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <Misuse size={16} style={{ color: isExpired ? 'var(--cds-text-muted, #6f6f6f)' : 'var(--cds-support-error, #da1e28)' }} />
                          <div>
                            <div style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                              {entry.target}
                            </div>
                            <small style={{ fontSize: '11px', color: 'var(--cds-text-helper)' }}>
                              {isCidr ? 'Network range' : 'Single address'}
                            </small>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Tag type={isCidr ? 'purple' : 'blue'} size="sm">
                          {isCidr ? 'CIDR' : 'IP'}
                        </Tag>
                      </TableCell>
                      <TableCell>
                        <Tag type={isExpired ? 'red' : 'cool-gray'} size="sm">
                          {isExpired ? 'EXPIRED' : expiresLabel}
                        </Tag>
                      </TableCell>
                      <TableCell style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '4px' }}>
                          <Button
                            kind="ghost"
                            size="sm"
                            onClick={() => openEditModal(entry)}
                          >
                            Edit
                          </Button>
                          <Button
                            kind="danger--ghost"
                            size="sm"
                            onClick={() => setDeleteTarget(entry.target)}
                          >
                            Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        )}

        {filteredCount > 0 && (
          <Pagination
            totalItems={filteredCount}
            page={page}
            pageSize={pageSize}
            pageSizes={[10, 25, 50, 100]}
            onChange={({ page: newPage, pageSize: newPageSize }) => {
              if (newPage) setPage(newPage);
              if (newPageSize) setPageSize(newPageSize);
            }}
          />
        )}
      </Tile>

      <Modal
        open={isAddModalOpen}
        modalHeading={editingTarget ? 'Edit Block Entry' : 'Block New Targets'}
        primaryButtonText={isSubmitting ? 'Saving...' : editingTarget ? 'Save Changes' : 'Block Targets'}
        secondaryButtonText="Cancel"
        primaryButtonDisabled={parsedTargets.valid.length === 0 || parsedTargets.invalid.length > 0 || isSubmitting}
        onRequestSubmit={handleAddSubmit}
        onRequestClose={() => {
          setIsAddModalOpen(false);
          setEditingTarget(null);
          setTargetsText('');
          setModalDuration('permanent');
        }}
        size="md"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          <InlineNotification
            kind={engineEnabled ? 'warning' : 'info'}
            lowContrast
            hideCloseButton
            title={engineEnabled ? 'After you save changes:' : 'Traffic Control is disabled.'}
            subtitle={
              engineEnabled
                ? 'matching requests are rejected before they reach protected services.'
                : 'Block entries are staged and do not reject traffic until you enable Traffic Control and save changes.'
            }
          />

          <Select
            id="modal-duration-input"
            labelText="Duration"
            value={modalDuration}
            onChange={(e) => setModalDuration(e.target.value)}
            helperText="Choose how long the block should remain active at the edge."
          >
            {editingEntry?.expires_at && (
              <SelectItem
                value="existing"
                text={`Keep current expiry (${existingExpiryLabel})`}
              />
            )}
            <SelectItem value="permanent" text="Permanent" />
            <SelectItem value="1h" text="1 Hour" />
            <SelectItem value="24h" text="24 Hours" />
            <SelectItem value="7d" text="7 Days" />
            <SelectItem value="30d" text="30 Days" />
          </Select>

          <TextArea
            id="modal-ip-input"
            labelText="Target Identifier"
            rows={editingTarget ? 3 : 4}
            className="text-mono"
            style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}
            placeholder={`203.0.113.1\n198.51.100.0/24`}
            value={targetsText}
            onChange={(e) => setTargetsText(e.target.value)}
            invalid={parsedTargets.invalid.length > 0}
            invalidText={
              parsedTargets.invalid.length > 0
                ? `Invalid target(s): ${parsedTargets.invalid.slice(0, 3).join(', ')}${parsedTargets.invalid.length > 3 ? '...' : ''}. Enter valid IPv4, IPv6, or CIDR range.`
                : undefined
            }
            helperText={
              editingTarget
                ? 'Update the IP or CIDR and adjust its duration if needed.'
                : 'Enter one IP address or CIDR range per line.'
            }
          />
        </div>
      </Modal>

      <Modal
        open={Boolean(deleteTarget)}
        danger
        modalHeading="Remove Block Entry"
        primaryButtonText={isSubmitting ? 'Removing...' : 'Remove'}
        secondaryButtonText="Cancel"
        onRequestSubmit={handleConfirmDelete}
        onRequestClose={() => setDeleteTarget(null)}
        size="sm"
      >
        <div style={{ padding: '8px 0' }}>
          <p style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
            Target: <strong style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>{deleteTarget}</strong>
          </p>
          <p style={{ fontSize: '14px', color: 'var(--cds-text-secondary)', marginTop: '8px' }}>
            This will immediately allow traffic from this identifier.
          </p>
        </div>
      </Modal>

      <Modal
        open={isBulkDeleteModalOpen}
        danger
        modalHeading="Delete Selected Entries"
        primaryButtonText={isSubmitting ? 'Deleting...' : 'Delete Selected'}
        secondaryButtonText="Cancel"
        onRequestSubmit={handleConfirmDeleteSelected}
        onRequestClose={() => setIsBulkDeleteModalOpen(false)}
        size="sm"
      >
        <div style={{ padding: '8px 0' }}>
          <p style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
            Are you sure you want to remove <strong>{selectedTargets.size}</strong> block{selectedTargets.size > 1 ? 's' : ''}?
          </p>
          <p style={{ fontSize: '14px', color: 'var(--cds-text-secondary)', marginTop: '8px' }}>
            Traffic from these identifiers will be allowed immediately.
          </p>
        </div>
      </Modal>
    </div>
  );
};

export default IpBlacklistPage;
