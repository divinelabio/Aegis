import React, { useState, useEffect, useMemo } from 'react';
import {
  Button,
  Tag,
  Search,
  Select,
  SelectItem,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Modal,
  TextInput,
  InlineNotification,
} from '@carbon/react';
import {
  Security,
  Add,
  TrashCan,
  Filter,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type { AntibotFullConfig, NavItemKey } from '../types';

interface BotExceptionsPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

type ExceptionCategory = 'ips' | 'paths' | 'methods' | 'headers' | 'user_agents';

interface ExceptionItem {
  id: string;
  category: ExceptionCategory;
  categoryLabel: string;
  value: string;
}

const TYPE_CONFIG: Record<
  ExceptionCategory,
  { label: string; placeholder: string; tagType: 'green' | 'blue' | 'teal' | 'purple' | 'cyan' }
> = {
  ips: {
    label: 'IP / CIDR',
    placeholder: '203.0.113.10 or 198.51.100.0/24',
    tagType: 'green',
  },
  paths: {
    label: 'Request Path',
    placeholder: '/health or /api/webhooks/stripe',
    tagType: 'blue',
  },
  methods: {
    label: 'HTTP Method',
    placeholder: 'OPTIONS',
    tagType: 'teal',
  },
  headers: {
    label: 'Header Pair',
    placeholder: 'X-Internal-Check:true',
    tagType: 'purple',
  },
  user_agents: {
    label: 'User Agent',
    placeholder: 'UptimeRobot',
    tagType: 'cyan',
  },
};

export const BotExceptionsPage: React.FC<BotExceptionsPageProps> = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [isDirty, setIsDirty] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [whitelist, setWhitelist] = useState<{
    ips: string[];
    paths: string[];
    methods: string[];
    headers: string[];
    user_agents: string[];
  }>({
    ips: [],
    paths: [],
    methods: [],
    headers: [],
    user_agents: [],
  });

  const [exceptionSearch, setExceptionSearch] = useState<string>('');
  const [exceptionCategoryFilter, setExceptionCategoryFilter] = useState<string>('all');
  const [addModalOpen, setAddModalOpen] = useState<boolean>(false);
  const [newType, setNewType] = useState<ExceptionCategory>('paths');
  const [newValue, setNewValue] = useState<string>('');

  const [initialConfig, setInitialConfig] = useState<AntibotFullConfig | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getAntibotConfig();
      if (cfg) {
        setInitialConfig(cfg);
        setWhitelist({
          ips: Array.isArray(cfg.whitelist?.ips) ? cfg.whitelist.ips : [],
          paths: Array.isArray(cfg.whitelist?.paths) ? cfg.whitelist.paths : [],
          methods: Array.isArray(cfg.whitelist?.methods) ? cfg.whitelist.methods : [],
          headers: Array.isArray(cfg.whitelist?.headers) ? cfg.whitelist.headers : [],
          user_agents: Array.isArray(cfg.whitelist?.user_agents) ? cfg.whitelist.user_agents : [],
        });
      }
      setIsDirty(false);
    } catch {
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const markDirty = () => setIsDirty(true);

  const unifiedExceptions = useMemo(() => {
    const list: ExceptionItem[] = [];

    (whitelist.ips || []).forEach((val) =>
      list.push({
        id: `ip-${val}`,
        category: 'ips',
        categoryLabel: TYPE_CONFIG.ips.label,
        value: val,
      })
    );
    (whitelist.paths || []).forEach((val) =>
      list.push({
        id: `path-${val}`,
        category: 'paths',
        categoryLabel: TYPE_CONFIG.paths.label,
        value: val,
      })
    );
    (whitelist.methods || []).forEach((val) =>
      list.push({
        id: `method-${val}`,
        category: 'methods',
        categoryLabel: TYPE_CONFIG.methods.label,
        value: val,
      })
    );
    (whitelist.headers || []).forEach((val) =>
      list.push({
        id: `header-${val}`,
        category: 'headers',
        categoryLabel: TYPE_CONFIG.headers.label,
        value: val,
      })
    );
    (whitelist.user_agents || []).forEach((val) =>
      list.push({
        id: `ua-${val}`,
        category: 'user_agents',
        categoryLabel: TYPE_CONFIG.user_agents.label,
        value: val,
      })
    );

    return list;
  }, [whitelist]);

  const filteredExceptions = useMemo(() => {
    const q = exceptionSearch.trim().toLowerCase();
    return unifiedExceptions.filter((item) => {
      if (exceptionCategoryFilter !== 'all' && item.category !== exceptionCategoryFilter) {
        return false;
      }
      if (q && !item.value.toLowerCase().includes(q) && !item.categoryLabel.toLowerCase().includes(q)) {
        return false;
      }
      return true;
    });
  }, [unifiedExceptions, exceptionSearch, exceptionCategoryFilter]);

  const handleAddException = () => {
    let val = newValue.trim();
    if (!val) return;

    if (newType === 'paths') {
      if (!val.startsWith('/')) {
        val = `/${val}`;
      }
    } else if (newType === 'methods') {
      val = val.toUpperCase();
      const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
      if (!validMethods.includes(val)) {
        setNotification({
          kind: 'error',
          message: `Invalid HTTP method "${val}". Allowed: ${validMethods.join(', ')}`,
        });
        return;
      }
    } else if (newType === 'ips') {
      const isIpOrCidr = /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/.test(val) ||
        /^[0-9a-fA-F:]+(\/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8]))?$/.test(val);
      if (!isIpOrCidr) {
        setNotification({
          kind: 'error',
          message: `Invalid IP address or CIDR notation "${val}".`,
        });
        return;
      }
    } else if (newType === 'headers') {
      if (!val.includes(':') && !val.includes('=')) {
        setNotification({
          kind: 'error',
          message: 'Header exception should be in Key:Value or Key format (e.g., X-Internal:true).',
        });
        return;
      }
    }

    if (whitelist[newType].includes(val)) {
      setNotification({
        kind: 'info',
        message: `Exception "${val}" is already configured.`,
      });
      return;
    }

    setWhitelist((prev) => ({
      ...prev,
      [newType]: [...prev[newType], val],
    }));
    setNewValue('');
    setAddModalOpen(false);
    markDirty();
    setNotification({
      kind: 'info',
      message: `Added "${val}". Remember to save changes.`,
    });
  };

  const handleRemoveException = (cat: ExceptionCategory, val: string) => {
    setWhitelist((prev) => ({
      ...prev,
      [cat]: prev[cat].filter((item) => item !== val),
    }));
    markDirty();
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const payload: Partial<AntibotFullConfig> = {
        ...(initialConfig || {}),
        whitelist,
      };

      const res = await apiService.saveAntibotConfig(payload);
      if (res && res.success === false) {
        setNotification({ kind: 'error', message: res.error || 'Failed to save policies.' });
        return;
      }
      setInitialConfig({ ...(initialConfig || {}), ...payload } as AntibotFullConfig);
      setIsDirty(false);
      setNotification({ kind: 'success', message: 'Exception policies saved successfully.' });
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to save policies.' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ padding: '32px 32px 100px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Bot defense"
        title="Exceptions"
        icon={Security}
        action={
          <Button
            kind="primary"
            size="md"
            renderIcon={Add}
            onClick={() => {
              setNewValue('');
              setAddModalOpen(true);
            }}
            style={{ borderRadius: 0 }}
          >
            Add Exception
          </Button>
        }
      />

      {notification && (
        <div style={{ marginBottom: '24px' }}>
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        </div>
      )}

      <SectionCard
        title={`Configured Exceptions (${unifiedExceptions.length})`}
      >
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '240px' }}>
            <Search
              id="search-exceptions"
              labelText="Exceptions"
              placeholder="Search exceptions by value or type..."
              value={exceptionSearch}
              onChange={(e) => setExceptionSearch(e.target.value)}
              size="sm"
            />
          </div>
          <div style={{ width: '220px' }}>
            <Select
              id="filter-category"
              labelText="Filter category"
              hideLabel
              value={exceptionCategoryFilter}
              onChange={(e) => setExceptionCategoryFilter(e.target.value)}
              size="sm"
            >
              <SelectItem value="all" text="All Categories" />
              <SelectItem value="ips" text="IPs & CIDRs" />
              <SelectItem value="paths" text="Request Paths" />
              <SelectItem value="methods" text="HTTP Methods" />
              <SelectItem value="headers" text="Header Pairs" />
              <SelectItem value="user_agents" text="User Agents" />
            </Select>
          </div>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={Add}
            onClick={() => {
              setNewValue('');
              setAddModalOpen(true);
            }}
            style={{ borderRadius: 0 }}
          >
            Add Exception
          </Button>
        </div>

        <Table aria-label="Exceptions Table" size="md">
          <TableHead>
            <TableRow>
              <TableHeader style={{ width: '60px' }}>#</TableHeader>
              <TableHeader style={{ width: '200px' }}>Type</TableHeader>
              <TableHeader>Value</TableHeader>
              <TableHeader style={{ textAlign: 'right', width: '80px' }}>Action</TableHeader>
            </TableRow>
          </TableHead>
          <TableBody>
            {filteredExceptions.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} style={{ textAlign: 'center', padding: '48px 16px' }}>
                  <Filter size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                  <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--cds-text-primary)' }}>
                    {exceptionSearch || exceptionCategoryFilter !== 'all'
                      ? 'No matching exceptions'
                      : 'No exceptions configured'}
                  </div>
                  <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                    {exceptionSearch || exceptionCategoryFilter !== 'all'
                      ? 'No exceptions match the selected filter.'
                      : 'Add trusted IPs, paths, methods, or headers to bypass bot mitigation.'}
                  </div>
                  {!exceptionSearch && exceptionCategoryFilter === 'all' && (
                    <Button
                      kind="primary"
                      size="sm"
                      renderIcon={Add}
                      onClick={() => {
                        setNewValue('');
                        setAddModalOpen(true);
                      }}
                      style={{ borderRadius: 0 }}
                    >
                      Add Exception
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ) : (
              filteredExceptions.map((item, index) => {
                const conf = TYPE_CONFIG[item.category] || TYPE_CONFIG.paths;
                return (
                  <TableRow key={item.id}>
                    <TableCell style={{ color: 'var(--cds-text-secondary)', fontWeight: 600, fontSize: '13px' }}>
                      {index + 1}
                    </TableCell>
                    <TableCell>
                      <Tag type={conf.tagType} size="sm" style={{ margin: 0 }}>
                        {item.categoryLabel}
                      </Tag>
                    </TableCell>
                    <TableCell>
                      <code style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontWeight: 600, fontSize: '13px' }}>
                        {item.value}
                      </code>
                    </TableCell>
                    <TableCell style={{ textAlign: 'right' }}>
                      <Button
                        kind="danger--ghost"
                        size="sm"
                        hasIconOnly
                        renderIcon={TrashCan}
                        iconDescription="Remove exception"
                        onClick={() => handleRemoveException(item.category, item.value)}
                        style={{ borderRadius: 0 }}
                      />
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </SectionCard>

      <Modal
        open={addModalOpen}
        modalHeading="Add Exception"
        modalLabel="Bot Protection: Exceptions"
        primaryButtonText="Add Exception"
        secondaryButtonText="Cancel"
        primaryButtonDisabled={!newValue.trim()}
        onRequestClose={() => {
          setAddModalOpen(false);
          setNewValue('');
        }}
        onRequestSubmit={handleAddException}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          <Select
            id="select-type"
            labelText="Type"
            value={newType}
            onChange={(e) => setNewType(e.target.value as ExceptionCategory)}
          >
            <SelectItem value="paths" text="Request Path (e.g. /health, /api/webhooks/stripe)" />
            <SelectItem value="ips" text="IP Address or CIDR (e.g. 203.0.113.10, 198.51.100.0/24)" />
            <SelectItem value="methods" text="HTTP Method (e.g. OPTIONS, HEAD)" />
            <SelectItem value="headers" text="Header Pair (e.g. X-Internal-Check:true)" />
            <SelectItem value="user_agents" text="User Agent (e.g. UptimeRobot, Datadog-Agent)" />
          </Select>
          <TextInput
            id="input-val"
            labelText="Value"
            placeholder={TYPE_CONFIG[newType]?.placeholder || 'Enter exception value'}
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
          />
        </div>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={loadData}
        onSave={handleSave}
      />
    </div>
  );
};

export default BotExceptionsPage;
