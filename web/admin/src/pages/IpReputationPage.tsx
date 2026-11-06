import React, { useState, useEffect, useCallback } from 'react';
import {
  Grid,
  Column,
  Tile,
  TileGroup,
  RadioTile,
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
  TextInput,
  NumberInput,
  Slider,
  Toggle,
  Modal,
  Form,
  Stack,
  InlineNotification,
  DataTableSkeleton,
} from '@carbon/react';
import {
  Security,
  Add,
  TrashCan,
  Renew,
  ArrowRight,
  DataBaseAlt,
  Misuse,
  BareMetalServer,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey } from '../types';
import './IpReputationPage.scss';

export interface ReputationRule {
  id: string;
  ip_or_cidr: string;
  action: 'allow' | 'block' | 'challenge' | 'bypass';
  score: number;
  comment?: string;
}

export interface UnifiedThreatFeedData {
  status?: string;
  total_indicators?: number;
  sources?: {
    cti?: {
      enabled?: boolean;
      url?: string;
      status?: {
        last_error?: string;
        failures?: number;
      };
    };
  };
  indicators?: Array<{
    indicator: string;
    score: number;
    severity: string;
    category: string;
  }>;
}

interface IpReputationPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

function isValidIpOrCidr(entry: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const cidrV4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[12][0-9]|3[0-2])$/;
  const cidrV6Regex = /^([0-9a-fA-F:]+)\/([0-9]{1,3})$/;
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$|^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}$|^(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}$|^(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}$|^[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^::$/;

  const trimmed = entry.trim();
  if (!trimmed) return false;
  const match6 = cidrV6Regex.exec(trimmed);
  const isValidCidrV6 = Boolean(match6 && Number.parseInt(match6[2], 10) >= 1 && Number.parseInt(match6[2], 10) <= 128);

  return cidrV4Regex.test(trimmed) || isValidCidrV6 || ipv4Regex.test(trimmed) || ipv6Regex.test(trimmed);
}

function getActionTagType(action: string): 'red' | 'blue' | 'green' | 'purple' | 'cool-gray' {
  switch (action.toLowerCase()) {
    case 'block':
      return 'red';
    case 'challenge':
      return 'blue';
    case 'allow':
      return 'green';
    case 'bypass':
      return 'purple';
    default:
      return 'cool-gray';
  }
}

export const IpReputationPage: React.FC<IpReputationPageProps> = ({ onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [isEngineToggling, setIsEngineToggling] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'info'; message: string } | null>(null);

  const [enabled, setEnabled] = useState(true);
  const [sensitivity, setSensitivity] = useState(80);
  const [cacheTtl, setCacheTtl] = useState('1h');
  const [action, setAction] = useState<'block' | 'challenge'>('block');
  const [blockTor, setBlockTor] = useState(false);
  const [blockDatacenter, setBlockDatacenter] = useState(false);
  const [ctiEnabled, setCtiEnabled] = useState(true);
  const [ctiUrl, setCtiUrl] = useState('http://localhost:8090');
  const [ctiMinScore, setCtiMinScore] = useState(60);
  const [rules, setRules] = useState<ReputationRule[]>([]);

  const [overridesExpanded, setOverridesExpanded] = useState(false);

  const [feedData, setFeedData] = useState<UnifiedThreatFeedData | null>(null);
  const [feedLoading, setFeedLoading] = useState(false);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalTarget, setModalTarget] = useState('');
  const [modalAction, setModalAction] = useState<'allow' | 'block' | 'challenge' | 'bypass'>('allow');
  const [modalScore, setModalScore] = useState<number>(100);
  const [modalComment, setModalComment] = useState('');
  const [modalError, setModalError] = useState<string | null>(null);

  const [initialConfig, setInitialConfig] = useState<any>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [repCfg, feed] = await Promise.all([
        apiService.getReputationConfig(),
        apiService.getThreatFeed().catch(() => null),
      ]);

      const loadedSensitivity = Number(repCfg?.sensitivity);
      const initialSensitivity = Number.isFinite(loadedSensitivity) && loadedSensitivity > 0 ? loadedSensitivity : 80;
      const loadedCtiUrl = repCfg?.cti?.url || 'http://localhost:8090';
      const loadedCtiMinScore = repCfg?.cti?.min_score ?? 60;

      const normalizedRules: ReputationRule[] = (repCfg?.rules || []).map((r: any, idx: number) => ({
        id: r.id || `rule-${idx}`,
        ip_or_cidr: r.ip_or_cidr || r.target || '',
        action: r.action || 'allow',
        score: typeof r.score === 'number' ? r.score : 100,
        comment: r.comment || r.note || '',
      }));

      setEnabled(repCfg?.enabled !== false);
      setSensitivity(initialSensitivity);
      setCacheTtl(repCfg?.cache_ttl || '1h');
      setAction(repCfg?.action === 'challenge' ? 'challenge' : 'block');
      setBlockTor(Boolean(repCfg?.block_tor));
      setBlockDatacenter(Boolean(repCfg?.block_datacenter));
      setCtiEnabled(repCfg?.cti?.enabled !== false);
      setCtiUrl(loadedCtiUrl);
      setCtiMinScore(loadedCtiMinScore);
      setRules(normalizedRules);
      setFeedData(feed);

      setInitialConfig({
        enabled: repCfg?.enabled !== false,
        sensitivity: initialSensitivity,
        cache_ttl: repCfg?.cache_ttl || '1h',
        action: repCfg?.action === 'challenge' ? 'challenge' : 'block',
        block_tor: Boolean(repCfg?.block_tor),
        block_datacenter: Boolean(repCfg?.block_datacenter),
        ctiEnabled: repCfg?.cti?.enabled !== false,
        ctiUrl: loadedCtiUrl,
        ctiMinScore: loadedCtiMinScore,
        rules: normalizedRules,
      });
      setHasChanges(false);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load IP reputation configuration.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleRefreshFeed = async () => {
    setFeedLoading(true);
    try {
      const refreshed = await apiService.refreshThreatFeed().catch(() => null);
      if (refreshed) {
        setFeedData(refreshed);
      } else {
        const direct = await apiService.getThreatFeed().catch(() => null);
        if (direct) setFeedData(direct);
      }
      setNotification({ kind: 'success', message: 'Threat intelligence feed synchronized successfully.' });
    } catch {
      setNotification({ kind: 'error', message: 'Failed to synchronize threat feed.' });
    } finally {
      setFeedLoading(false);
    }
  };

  const markDirty = () => {
    setHasChanges(true);
  };

  const handleToggleEngine = async (checked: boolean) => {
    setIsEngineToggling(true);
    const prev = enabled;
    setEnabled(checked);
    try {
      const payload = {
        ...(initialConfig || {}),
        enabled: checked,
        sensitivity,
        cache_ttl: cacheTtl.trim() || '1h',
        action,
        block_tor: blockTor,
        block_datacenter: blockDatacenter,
        cti: {
          enabled: ctiEnabled,
          url: ctiUrl,
          min_score: ctiMinScore,
        },
        allowed_ips: rules.filter((r) => r.action === 'allow').map((r) => r.ip_or_cidr),
        blocked_ips: rules.filter((r) => r.action === 'block').map((r) => r.ip_or_cidr),
        rules,
      };

      const ok = await apiService.saveReputationConfig(payload);
      if (ok) {
        setNotification({ kind: 'success', message: `IP reputation ${checked ? 'enabled' : 'disabled'}.` });
        setInitialConfig((prevCfg: any) => ({ ...(prevCfg || {}), enabled: checked }));
      } else {
        throw new Error('Failed to update engine status');
      }
    } catch (err: any) {
      setEnabled(prev);
      setNotification({ kind: 'error', message: err?.message || 'Failed to update engine status' });
    } finally {
      setIsEngineToggling(false);
    }
  };

  const handleSaveConfig = async () => {
    setSaving(true);
    try {
      const payload = {
        enabled,
        sensitivity,
        cache_ttl: cacheTtl.trim() || '1h',
        action,
        block_tor: blockTor,
        block_datacenter: blockDatacenter,
        cti: {
          enabled: ctiEnabled,
          url: ctiUrl,
          min_score: ctiMinScore,
        },
        allowed_ips: rules.filter((r) => r.action === 'allow').map((r) => r.ip_or_cidr),
        blocked_ips: rules.filter((r) => r.action === 'block').map((r) => r.ip_or_cidr),
        rules,
      };

      const success = await apiService.saveReputationConfig(payload);
      if (success) {
        setNotification({ kind: 'success', message: 'IP reputation configuration saved successfully.' });
        setHasChanges(false);
        setInitialConfig({
          enabled,
          sensitivity,
          cache_ttl: cacheTtl.trim() || '1h',
          action,
          block_tor: blockTor,
          block_datacenter: blockDatacenter,
          ctiEnabled,
          ctiUrl,
          ctiMinScore,
          rules,
        });
      } else {
        setNotification({ kind: 'error', message: 'Failed to save configuration.' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'An error occurred while saving configuration.' });
    } finally {
      setSaving(false);
    }
  };

  const handleResetConfig = () => {
    if (!initialConfig) return;
    setEnabled(initialConfig.enabled);
    setSensitivity(initialConfig.sensitivity);
    setCacheTtl(initialConfig.cache_ttl);
    setAction(initialConfig.action);
    setBlockTor(initialConfig.block_tor);
    setBlockDatacenter(initialConfig.block_datacenter);
    setCtiEnabled(initialConfig.ctiEnabled);
    setCtiUrl(initialConfig.ctiUrl || 'http://localhost:8090');
    setCtiMinScore(initialConfig.ctiMinScore ?? 60);
    setRules(initialConfig.rules);
    setHasChanges(false);
    setNotification({ kind: 'info', message: 'Pending changes reverted.' });
  };

  const handleOpenAddModal = () => {
    setModalTarget('');
    setModalAction('allow');
    setModalScore(100);
    setModalComment('');
    setModalError(null);
    setIsModalOpen(true);
    setOverridesExpanded(true);
  };

  const handleSaveModalRule = () => {
    const target = modalTarget.trim();
    if (!target) {
      setModalError('Enter an IP address or CIDR.');
      return;
    }

    if (!isValidIpOrCidr(target)) {
      setModalError('Enter a valid IPv4/IPv6 address or CIDR subnet.');
      return;
    }

    const newRule: ReputationRule = {
      id: `rule-${Date.now()}`,
      ip_or_cidr: target,
      action: modalAction,
      score: Number.isFinite(modalScore) ? Math.max(0, Math.min(100, modalScore)) : 100,
      comment: modalComment.trim() || undefined,
    };

    setRules((prev) => [...prev, newRule]);
    setIsModalOpen(false);
    setOverridesExpanded(true);
    markDirty();
  };

  const handleDeleteRule = (ruleId: string) => {
    setRules((prev) => prev.filter((r) => r.id !== ruleId));
    markDirty();
  };

  const totalCount = feedData?.total_indicators ?? (feedData?.indicators?.length || 0);

  return (
    <main className="ip-reputation-page" id="main-content">
      {notification && (
        <InlineNotification
          kind={notification.kind}
          title={notification.message}
          onClose={() => setNotification(null)}
          onCloseButtonClick={() => setNotification(null)}
        />
      )}

      <PageHeader
        title="IP reputation"
        icon={Security}
        action={
          <HeaderSwitcher
            id="ip-reputation-engine-toggle"
            ariaLabel="IP reputation status"
            toggled={enabled}
            onToggle={handleToggleEngine}
            disabled={isEngineToggling}
          />
        }
      />

      <SectionCard
        title="Protection controls"
        padded={false}
      >
        <div className="ip-rep-control-row">
          <div className="ip-rep-control-left">
            <Misuse size={20} className="ip-rep-control-icon" />
            <div>
              <div className="ip-rep-control-title">Tor exit nodes</div>
              <div className="ip-rep-control-desc">
                Block traffic originating from Tor relays and exit nodes.
              </div>
            </div>
          </div>
          <Toggle
            id="tor-toggle"
            labelText=""
            hideLabel
            size="md"
            toggled={blockTor}
            onToggle={(checked) => {
              setBlockTor(checked);
              markDirty();
            }}
            aria-label="Tor exit node blocking"
          />
        </div>

        <div className="ip-rep-control-row">
          <div className="ip-rep-control-left">
            <BareMetalServer size={20} className="ip-rep-control-icon" />
            <div>
              <div className="ip-rep-control-title">Datacenter traffic</div>
              <div className="ip-rep-control-desc">
                Filter traffic from cloud hosts and hosting providers.
              </div>
            </div>
          </div>
          <Toggle
            id="datacenter-toggle"
            labelText=""
            hideLabel
            size="md"
            toggled={blockDatacenter}
            onToggle={(checked) => {
              setBlockDatacenter(checked);
              markDirty();
            }}
            aria-label="Datacenter traffic filtering"
          />
        </div>

        <div className="ip-rep-control-row">
          <div className="ip-rep-control-left">
            <DataBaseAlt size={20} className="ip-rep-control-icon" />
            <div>
              <div className="ip-rep-control-title">Threat feed sync</div>
              <div className="ip-rep-control-desc">
                Synchronize threat intelligence indicators automatically.
              </div>
            </div>
          </div>
          <Toggle
            id="cti-toggle"
            labelText=""
            hideLabel
            size="md"
            toggled={ctiEnabled}
            onToggle={(checked) => {
              setCtiEnabled(checked);
              markDirty();
            }}
            aria-label="Threat feed synchronization"
          />
        </div>
      </SectionCard>

      <SectionCard
        title="Decision policy"
        padded={true}
      >
        <Grid fullWidth narrow className="ip-rep-grid-flush">
          <Column lg={8} md={8} sm={4}>
            <Tile className="ip-rep-decision-tile">
              <div>
                <Slider
                  id="reputation-min-score"
                  labelText="Minimum trust score"
                  min={0}
                  max={100}
                  step={5}
                  value={sensitivity}
                  onChange={({ value }) => {
                    setSensitivity(value);
                    markDirty();
                  }}
                />
                <div className="ip-rep-slider-helper">
                  Requests scoring below {sensitivity} are {action === 'challenge' ? 'challenged' : 'blocked'}.
                </div>
              </div>

              <div>
                <TextInput
                  id="reputation-cache-ttl"
                  labelText="Cache TTL"
                  value={cacheTtl}
                  placeholder="1h"
                  helperText="Retention duration (e.g. 1h, 24h)."
                  onChange={(e) => {
                    setCacheTtl(e.target.value);
                    markDirty();
                  }}
                />
              </div>
            </Tile>
          </Column>

          <Column lg={8} md={8} sm={4}>
            <Tile className="ip-rep-decision-tile">
              <TileGroup
                name="reputation-action"
                legend="Low trust response"
                valueSelected={action}
                onChange={(val) => {
                  setAction(val as 'block' | 'challenge');
                  markDirty();
                }}
                className="ip-rep-tile-group"
              >
                <RadioTile id="action-block" value="block">
                  <div className="ip-rep-radio-title">
                    Block
                  </div>
                  <div className="ip-rep-radio-desc">
                    Drop requests with HTTP 403 Forbidden.
                  </div>
                </RadioTile>

                <RadioTile id="action-challenge" value="challenge">
                  <div className="ip-rep-radio-title">
                    Challenge
                  </div>
                  <div className="ip-rep-radio-desc">
                    Require verification challenge before allowing access.
                  </div>
                </RadioTile>
              </TileGroup>
            </Tile>
          </Column>
        </Grid>
      </SectionCard>

      <SectionCard
        title="DivineLab CTI Intelligence Feed"
        padded={true}
      >
        <Tile className="ip-rep-feed-tile">
          <div className="ip-rep-feed-left">
            <DataBaseAlt size={20} className="ip-rep-feed-icon" />
            <div>
              <div className="ip-rep-feed-title">
                Threat indicators
              </div>
              <div className="ip-rep-feed-desc">
                {Number(totalCount).toLocaleString()} indicators synchronized.
              </div>
            </div>
          </div>
          <div className="ip-rep-feed-actions">
            <Button
              kind="tertiary"
              size="sm"
              renderIcon={Renew}
              disabled={feedLoading}
              onClick={handleRefreshFeed}
            >
              {feedLoading ? 'Refreshing...' : 'Refresh'}
            </Button>
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowRight}
              onClick={() => {
                if (onNavigate) onNavigate('modules');
                window.location.hash = '#modules-reputation';
              }}
            >
              View in modules
            </Button>
          </div>
        </Tile>
      </SectionCard>

      <SectionCard
        title="Custom overrides"
        collapsible
        expanded={overridesExpanded}
        onToggleExpanded={setOverridesExpanded}
        padded={false}
        bodyStyle={{ padding: '0' }}
        action={
          <Button
            kind="primary"
            size="sm"
            renderIcon={Add}
            onClick={handleOpenAddModal}
          >
            Add rule
          </Button>
        }
      >
        {loading ? (
          <DataTableSkeleton columnCount={5} rowCount={6} showHeader={false} showToolbar={false} />
        ) : (
          <div className="ip-rep-table-wrapper">
            <Table size="md" aria-label="IP reputation override rules table">
              <TableHead>
                <TableRow>
                  <TableHeader className="ip-rep-table-col-target">Target</TableHeader>
                  <TableHeader className="ip-rep-table-col-action">Action</TableHeader>
                  <TableHeader className="ip-rep-table-col-score">Score</TableHeader>
                  <TableHeader>Description</TableHeader>
                  <TableHeader className="ip-rep-table-col-actions">Actions</TableHeader>
                </TableRow>
              </TableHead>
              <TableBody>
                {rules.length === 0 ? (
                  <TableRow className="ip-rep-empty-row">
                    <TableCell colSpan={5} className="ip-rep-empty-state">
                      <div className="ip-rep-empty-content">
                        <Security size={36} className="ip-rep-empty-icon" />
                        <div className="ip-rep-empty-title">
                          No overrides configured
                        </div>
                        <div className="ip-rep-empty-subtitle">
                          Add a rule to allow or block specific IP addresses or subnets.
                        </div>
                        <Button
                          kind="tertiary"
                          size="sm"
                          renderIcon={Add}
                          onClick={handleOpenAddModal}
                        >
                          Add rule
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  rules.map((rule) => (
                    <TableRow key={rule.id}>
                      <TableCell>
                        <span className="ip-rep-mono-text">
                          {rule.ip_or_cidr}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Tag type={getActionTagType(rule.action)} size="sm">
                          {rule.action.toUpperCase()}
                        </Tag>
                      </TableCell>
                      <TableCell>
                        <span className="ip-rep-mono-text">
                          {rule.score ?? '—'}
                        </span>
                      </TableCell>
                      <TableCell className="ip-rep-table-desc">
                        {rule.comment || '—'}
                      </TableCell>
                      <TableCell className="ip-rep-actions-cell">
                        <Button
                          kind="ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={TrashCan}
                          iconDescription="Delete override rule"
                          onClick={() => handleDeleteRule(rule.id)}
                        />
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        )}
      </SectionCard>

      <SaveActionBar
        isDirty={hasChanges}
        isSaving={saving}
        onReset={handleResetConfig}
        onSave={handleSaveConfig}
        saveLabel="Save Changes"
        resetLabel="Cancel"
        message="Unsaved changes"
      />

      <Modal
        open={isModalOpen}
        modalHeading="Add rule"
        primaryButtonText="Add rule"
        secondaryButtonText="Cancel"
        onRequestClose={() => setIsModalOpen(false)}
        onRequestSubmit={handleSaveModalRule}
        size="sm"
      >
        <Form
          onSubmit={(e) => {
            e.preventDefault();
            handleSaveModalRule();
          }}
        >
          <Stack gap={6} style={{ marginTop: '16px', marginBottom: '8px' }}>
            <TextInput
              id="modal-rule-target"
              labelText="IP or CIDR"
              placeholder="198.51.100.1 or 203.0.113.0/24"
              value={modalTarget}
              onChange={(e) => {
                setModalTarget(e.target.value);
                if (modalError) setModalError(null);
              }}
              invalid={Boolean(modalError)}
              invalidText={modalError || ''}
            />

            <Select
              id="modal-rule-action"
              labelText="Action"
              value={modalAction}
              onChange={(e) => setModalAction(e.target.value as any)}
            >
              <SelectItem value="allow" text="Allow" />
              <SelectItem value="block" text="Block" />
              <SelectItem value="challenge" text="Challenge" />
              <SelectItem value="bypass" text="Bypass" />
            </Select>

            <NumberInput
              id="modal-rule-score"
              label="Trust score (0–100)"
              min={0}
              max={100}
              step={5}
              value={modalScore}
              onChange={(_e, { value }) => setModalScore(Number(value) || 0)}
            />

            <TextInput
              id="modal-rule-comment"
              labelText="Description"
              placeholder="Optional description"
              value={modalComment}
              onChange={(e) => setModalComment(e.target.value)}
            />
          </Stack>
        </Form>
      </Modal>
    </main>
  );
};
