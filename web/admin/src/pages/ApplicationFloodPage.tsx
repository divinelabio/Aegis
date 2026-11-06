import React, { useState, useEffect } from 'react';
import {
  Tile,
  Layer,
  Button,
  Select,
  SelectItem,
  TextInput,
  Modal,
  InlineNotification,
  IconButton,
  Slider,
  NumberInput,
} from '@carbon/react';
import {
  Add,
  TrashCan,
  Information,
  Security,
  Misuse,
  Flash,
} from '@carbon/icons-react';
import { PageHeader, SectionCard, StatusToggle, HeaderSwitcher, SaveActionBar, RadioCardGroup } from '../components/common';
import { apiService } from '../services/api';
import type { NavItemKey } from '../types';

export interface FloodProtectedObject {
  id: string;
  hosts?: string[];
  methods?: string[];
  path: string;
  path_match: 'exact' | 'prefix' | 'glob';
  max_rps: number;
  max_concurrency: number;
  burst_multiplier: number;
  action: 'block' | 'challenge' | 'http_reject';
  verified_grace_multiplier?: number;
}

export interface ApplicationFloodConfig {
  enabled?: boolean;
  action?: 'challenge' | 'block' | 'http_reject';
  max_rps?: number;
  max_connections?: number;
  burst_multiplier?: number;
  auto_ban?: boolean;
  ban_duration?: number;
  objects?: FloodProtectedObject[];
}

interface ApplicationFloodPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

export const ApplicationFloodPage: React.FC<ApplicationFloodPageProps> = () => {
  const [_loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enabled, setEnabled] = useState(true);
  const [isEngineToggling, setIsEngineToggling] = useState(false);
  const [hasChanges, setHasChanges] = useState(false);
  const [notification, setNotification] = useState<{ kind: 'success' | 'error' | 'info'; message: string } | null>(null);

  const [action, setAction] = useState<'challenge' | 'block' | 'http_reject'>('challenge');
  const [maxRps, setMaxRps] = useState<number>(100);
  const [maxConnections, setMaxConnections] = useState<number>(50);
  const [burstMultiplier, setBurstMultiplier] = useState<number>(2.0);
  const [autoBan, setAutoBan] = useState<boolean>(false);
  const [banDuration, setBanDuration] = useState<number>(60);
  const [objects, setObjects] = useState<FloodProtectedObject[]>([]);

  const [initialConfig, setInitialConfig] = useState<ApplicationFloodConfig | null>(null);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalId, setModalId] = useState('');
  const [modalMethods, setModalMethods] = useState('POST');
  const [modalHost, setModalHost] = useState('');
  const [modalPath, setModalPath] = useState('/');
  const [modalMatch, setModalMatch] = useState<'exact' | 'prefix' | 'glob'>('prefix');
  const [modalAction, setModalAction] = useState<'block' | 'challenge' | 'http_reject'>('block');
  const [modalRate, setModalRate] = useState<number>(100);
  const [modalConcurrency, setModalConcurrency] = useState<number>(50);
  const [modalBurst, setModalBurst] = useState<number>(2.0);

  const loadData = async () => {
    setLoading(true);
    try {
      const cfg = await apiService.getApplicationFloodConfig();
      const loadedEnabled = cfg.enabled !== false;
      const loadedAction = cfg.action || 'challenge';
      const loadedRps = cfg.max_rps ?? 100;
      const loadedConn = cfg.max_connections ?? 50;
      const loadedBurst = cfg.burst_multiplier ?? 2.0;
      const loadedAutoBan = Boolean(cfg.auto_ban);
      const loadedBanDur = cfg.ban_duration ?? 60;
      const loadedObjects = Array.isArray(cfg.objects) ? cfg.objects : [];

      setEnabled(loadedEnabled);
      setAction(loadedAction);
      setMaxRps(loadedRps);
      setMaxConnections(loadedConn);
      setBurstMultiplier(loadedBurst);
      setAutoBan(loadedAutoBan);
      setBanDuration(loadedBanDur);
      setObjects(loadedObjects);

      setInitialConfig({
        enabled: loadedEnabled,
        action: loadedAction,
        max_rps: loadedRps,
        max_connections: loadedConn,
        burst_multiplier: loadedBurst,
        auto_ban: loadedAutoBan,
        ban_duration: loadedBanDur,
        objects: loadedObjects,
      });
      setHasChanges(false);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load application flood configuration' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const markDirty = () => {
    setHasChanges(true);
  };

  const handleToggleEngine = async (checked: boolean) => {
    setIsEngineToggling(true);
    const prev = enabled;
    setEnabled(checked);
    try {
      const payload: ApplicationFloodConfig = {
        enabled: checked,
        action,
        max_rps: maxRps,
        max_connections: maxConnections,
        burst_multiplier: burstMultiplier,
        auto_ban: autoBan,
        ban_duration: banDuration,
        objects,
      };
      const ok = await apiService.saveApplicationFloodConfig(payload);
      if (ok) {
        setNotification({
          kind: 'success',
          message: `Application flood protection ${checked ? 'enabled' : 'disabled'}.`,
        });
        setInitialConfig((prevCfg) => ({ ...(prevCfg || {}), enabled: checked }));
      } else {
        throw new Error('Failed to update engine status');
      }
    } catch (err: any) {
      setEnabled(prev);
      setNotification({
        kind: 'error',
        message: err?.message || 'Failed to update engine status',
      });
    } finally {
      setIsEngineToggling(false);
    }
  };

  const handleSaveConfig = async () => {
    setSaving(true);
    try {
      const payload: ApplicationFloodConfig = {
        enabled,
        action,
        max_rps: maxRps,
        max_connections: maxConnections,
        burst_multiplier: burstMultiplier,
        auto_ban: autoBan,
        ban_duration: banDuration,
        objects,
      };

      const success = await apiService.saveApplicationFloodConfig(payload);
      if (success) {
        setNotification({ kind: 'success', message: 'Application flood protection configuration saved successfully' });
        setHasChanges(false);
        setInitialConfig({
          enabled,
          action,
          max_rps: maxRps,
          max_connections: maxConnections,
          burst_multiplier: burstMultiplier,
          auto_ban: autoBan,
          ban_duration: banDuration,
          objects,
        });
      } else {
        setNotification({ kind: 'error', message: 'Failed to save configuration' });
      }
    } catch {
      setNotification({ kind: 'error', message: 'An error occurred while saving' });
    } finally {
      setSaving(false);
    }
  };

  const handleResetConfig = () => {
    if (!initialConfig) return;
    setEnabled(initialConfig.enabled !== false);
    setAction(initialConfig.action || 'challenge');
    setMaxRps(initialConfig.max_rps ?? 100);
    setMaxConnections(initialConfig.max_connections ?? 50);
    setBurstMultiplier(initialConfig.burst_multiplier ?? 2.0);
    setAutoBan(Boolean(initialConfig.auto_ban));
    setBanDuration(initialConfig.ban_duration ?? 60);
    setObjects(initialConfig.objects || []);
    setHasChanges(false);
    setNotification({ kind: 'info', message: 'Changes reverted to last saved state' });
  };

  const handleOpenAddModal = () => {
    setModalId('');
    setModalMethods('POST');
    setModalHost('');
    setModalPath('/');
    setModalMatch('prefix');
    setModalAction('block');
    setModalRate(100);
    setModalConcurrency(50);
    setModalBurst(2.0);
    setIsModalOpen(true);
  };

  const handleSaveModalObject = () => {
    const id = modalId.trim().toLowerCase();
    const path = modalPath.trim();
    const rate = Number(modalRate);
    const concurrency = Number(modalConcurrency);
    const burst = Number(modalBurst);

    if (
      !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(id) ||
      id === 'default' ||
      !path.startsWith('/') ||
      !Number.isFinite(rate) ||
      rate < 1 ||
      !Number.isFinite(concurrency) ||
      concurrency < 1 ||
      !Number.isFinite(burst) ||
      burst < 1
    ) {
      setNotification({
        kind: 'error',
        message: 'Provide a valid non-default ID, path starting with "/", positive rate, in-flight limit, and burst multiplier.',
      });
      return;
    }

    if (objects.some((obj) => obj.id === id)) {
      setNotification({ kind: 'error', message: 'Object IDs must be unique.' });
      return;
    }

    const splitMethods = modalMethods
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);

    const newObj: FloodProtectedObject = {
      id,
      hosts: modalHost.trim() ? [modalHost.trim()] : [],
      methods: splitMethods.length ? splitMethods : ['ANY'],
      path,
      path_match: modalMatch,
      max_rps: rate,
      max_concurrency: concurrency,
      burst_multiplier: burst,
      action: modalAction,
      verified_grace_multiplier: 2,
    };

    setObjects((prev) => [...prev, newObj]);
    setIsModalOpen(false);
    markDirty();
    setNotification({ kind: 'info', message: `Staged protected object ${id}` });
  };

  const handleRemoveObject = (id: string) => {
    setObjects((prev) => prev.filter((o) => o.id !== id));
    markDirty();
    setNotification({ kind: 'info', message: 'Protected object removal staged' });
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
        title="Flood defense"
        icon={Security}
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <Button
              kind="primary"
              size="sm"
              renderIcon={Add}
              onClick={handleOpenAddModal}
            >
              Add Protected Endpoint
            </Button>
            <HeaderSwitcher
              id="flood-engine-toggle"
              ariaLabel="Flood Defense Engine Status"
              toggled={enabled}
              onToggle={handleToggleEngine}
              disabled={isEngineToggling}
            />
          </div>
        }
      />

      <SectionCard
        kicker="GLOBAL THRESHOLDS"
        title="Global Thresholds"
        description="Default request rates and connection limits applied across all endpoints."
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem', marginBottom: '1.5rem' }}>
          <Layer>
            <Tile
              style={{
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, fontSize: '12px' }}>
                  HTTP flood threshold
                  <IconButton
                    label="Maximum requests per second allowed from a single client IP."
                    kind="ghost"
                    size="sm"
                    style={{ minHeight: 'unset', width: 'auto', padding: 0 }}
                  >
                    <Information size={14} style={{ color: 'var(--cds-text-secondary)' }} />
                  </IconButton>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <NumberInput
                    id="max-rps-num"
                    min={10}
                    max={5000}
                    step={10}
                    value={maxRps}
                    hideLabel
                    label="HTTP flood threshold in requests per second"
                    size="sm"
                    style={{ width: '120px' }}
                    onChange={(_, { value }) => {
                      if (typeof value === 'number') {
                        setMaxRps(value);
                        markDirty();
                      }
                    }}
                  />
                  <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>req/s</span>
                </div>
              </div>

              <Slider
                id="max-rps-slider"
                min={10}
                max={5000}
                step={10}
                value={maxRps}
                hideTextInput
                hideLabel
                labelText="HTTP flood threshold slider"
                ariaLabelInput="HTTP flood threshold slider"
                onChange={({ value }) => {
                  setMaxRps(value);
                  markDirty();
                }}
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--cds-text-secondary)', fontFamily: 'monospace' }}>
                <span>10 req/s</span>
                <span>1,000</span>
                <span>2,500</span>
                <span>5,000 req/s</span>
              </div>
            </Tile>
          </Layer>

          <Layer>
            <Tile
              style={{
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, fontSize: '12px' }}>
                  In-flight connection ceiling
                  <IconButton
                    label="Maximum simultaneous concurrent HTTP requests allowed from a single client IP."
                    kind="ghost"
                    size="sm"
                    style={{ minHeight: 'unset', width: 'auto', padding: 0 }}
                  >
                    <Information size={14} style={{ color: 'var(--cds-text-secondary)' }} />
                  </IconButton>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <NumberInput
                    id="max-connections-num"
                    min={5}
                    max={1000}
                    step={5}
                    value={maxConnections}
                    hideLabel
                    label="In-flight connection ceiling"
                    size="sm"
                    style={{ width: '120px' }}
                    onChange={(_, { value }) => {
                      if (typeof value === 'number') {
                        setMaxConnections(value);
                        markDirty();
                      }
                    }}
                  />
                  <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>in-flight</span>
                </div>
              </div>

              <Slider
                id="max-connections-slider"
                min={5}
                max={1000}
                step={5}
                value={maxConnections}
                hideTextInput
                hideLabel
                labelText="In-flight connection ceiling slider"
                ariaLabelInput="In-flight connection ceiling slider"
                onChange={({ value }) => {
                  setMaxConnections(value);
                  markDirty();
                }}
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--cds-text-secondary)', fontFamily: 'monospace' }}>
                <span>5 in-flight</span>
                <span>250</span>
                <span>500</span>
                <span>1,000 in-flight</span>
              </div>
            </Tile>
          </Layer>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem' }}>
          <Layer>
            <Tile
              style={{
                padding: '1.25rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 700, fontSize: '12px' }}>
                Burst capacity multiplier
                <IconButton
                  label="Spike headroom factor above the base rate threshold before rate-limiting activates."
                  kind="ghost"
                  size="sm"
                  style={{ minHeight: 'unset', width: 'auto', padding: 0 }}
                >
                  <Information size={14} style={{ color: 'var(--cds-text-secondary)' }} />
                </IconButton>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <NumberInput
                  id="burst-multiplier-num"
                  min={1}
                  max={10}
                  step={0.1}
                  value={burstMultiplier}
                  hideLabel
                  label="Burst capacity multiplier"
                  size="sm"
                  style={{ width: '110px' }}
                  onChange={(_, { value }) => {
                    if (typeof value === 'number') {
                      setBurstMultiplier(value);
                      markDirty();
                    }
                  }}
                />
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)' }}>&times; rate</span>
              </div>
            </Tile>
          </Layer>

          <Layer>
            <Tile
              style={{
                padding: '1.25rem',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.75rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <StatusToggle
                  id="auto-ban-toggle"
                  label="Temporary Ban on Threshold Breach"
                  description="Automatically ban client IPs that repeatedly exceed rate or concurrency ceilings."
                  toggled={autoBan}
                  onToggle={(checked) => {
                    setAutoBan(checked);
                    markDirty();
                  }}
                />
              </div>
              {autoBan && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'flex-end', paddingTop: '4px' }}>
                  <NumberInput
                    id="ban-duration-num"
                    min={1}
                    max={1440}
                    step={1}
                    value={banDuration}
                    hideLabel
                    label="Ban duration in minutes"
                    size="sm"
                    style={{ width: '110px' }}
                    onChange={(_, { value }) => {
                      if (typeof value === 'number') {
                        setBanDuration(value);
                        markDirty();
                      }
                    }}
                  />
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)' }}>minutes</span>
                </div>
              )}
            </Tile>
          </Layer>
        </div>
      </SectionCard>

      <SectionCard
        kicker="RESPONSE STRATEGY"
        title="Default Mitigation Action"
        description="Action taken when request rate or connection limits are breached."
      >
        <RadioCardGroup
          name="application-flood-action"
          valueSelected={action}
          onChange={(val) => {
            setAction(val as 'challenge' | 'block' | 'http_reject');
            markDirty();
          }}
          options={[
            {
              value: 'challenge',
              title: 'Browser challenge',
              description: 'Verify likely browsers before allowing traffic.',
              icon: Security,
            },
            {
              value: 'block',
              title: 'Immediate block',
              description: 'Reject abusive requests with a forbidden response.',
              icon: Misuse,
            },
            {
              value: 'http_reject',
              title: 'HTTP service rejection',
              description: 'Return an explicit temporary-unavailable response. No TCP drop is attempted.',
              icon: Flash,
            },
          ]}
        />
      </SectionCard>

      <SectionCard
        kicker="SCOPED ENFORCEMENT"
        title="Protected Endpoints"
        description="Override global limits for sensitive routes (e.g. /login, /checkout)."
        action={
          <Button
            kind="primary"
            size="sm"
            renderIcon={Add}
            onClick={handleOpenAddModal}
          >
            Add endpoint
          </Button>
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {objects.length > 0 ? (
            objects.map((obj) => (
              <Layer key={obj.id}>
                <Tile
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '1rem 1.25rem',
                    flexWrap: 'wrap',
                    gap: '1rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                    <Security size={18} style={{ color: 'var(--cds-text-secondary)' }} />
                    <div>
                      <strong style={{ fontSize: '14px', fontFamily: 'monospace' }}>{obj.id}</strong>
                      <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px', fontFamily: 'monospace' }}>
                        {(obj.methods || ['ANY']).join(', ')} {obj.path_match || 'prefix'} {obj.path || '/'}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem' }}>
                    <span style={{ fontSize: '13px', fontWeight: 600, fontFamily: 'monospace' }}>
                      {(obj.max_rps || 100).toLocaleString()} req/s
                    </span>
                    <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', fontFamily: 'monospace' }}>
                      {(obj.max_concurrency || 50).toLocaleString()} in-flight
                    </span>
                    <Button
                      kind="ghost"
                      size="sm"
                      hasIconOnly
                      renderIcon={TrashCan}
                      iconDescription={`Remove protected object ${obj.id}`}
                      onClick={() => handleRemoveObject(obj.id)}
                    />
                  </div>
                </Tile>
              </Layer>
            ))
          ) : (
            <Layer>
              <Tile
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  padding: '2.5rem',
                  textAlign: 'center',
                  gap: '0.5rem',
                  borderStyle: 'dashed',
                }}
              >
                <Security size={32} style={{ color: 'var(--cds-text-secondary)', marginBottom: '4px' }} />
                <strong style={{ fontSize: '14px' }}>Default policy applies to all requests</strong>
                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                  Add a protected object only when an endpoint needs stricter limits than the default.
                </span>
              </Tile>
            </Layer>
          )}
        </div>
      </SectionCard>

      <SaveActionBar
        isDirty={hasChanges}
        isSaving={saving}
        onReset={handleResetConfig}
        onSave={handleSaveConfig}
        saveLabel="Save Changes"
        resetLabel="Cancel"
        message="Unsaved changes in Application Flood policy"
      />

      <Modal
        open={isModalOpen}
        modalHeading="Add protected HTTP object"
        primaryButtonText="Add object"
        secondaryButtonText="Cancel"
        onRequestClose={() => setIsModalOpen(false)}
        onRequestSubmit={handleSaveModalObject}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '1rem 0' }}>
          <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
            <strong>Scoped policy:</strong> object matching is deterministic by priority, then ID. Use the narrowest host, method, and path that protects the endpoint.
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <TextInput
              id="flood-object-id"
              labelText="Object ID"
              placeholder="checkout-payments"
              value={modalId}
              onChange={(e) => setModalId(e.target.value)}
              required
            />
            <TextInput
              id="flood-object-methods"
              labelText="Methods (comma separated)"
              placeholder="POST, PUT"
              value={modalMethods}
              onChange={(e) => setModalMethods(e.target.value)}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <TextInput
              id="flood-object-host"
              labelText="Host (optional)"
              placeholder="shop.example.com"
              value={modalHost}
              onChange={(e) => setModalHost(e.target.value)}
            />
            <TextInput
              id="flood-object-path"
              labelText="Path"
              placeholder="/checkout/pay"
              value={modalPath}
              onChange={(e) => setModalPath(e.target.value)}
              required
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <Select
              id="flood-object-match"
              labelText="Path matching"
              value={modalMatch}
              onChange={(e) => setModalMatch(e.target.value as any)}
            >
              <SelectItem value="exact" text="Exact" />
              <SelectItem value="prefix" text="Prefix" />
              <SelectItem value="glob" text="Glob" />
            </Select>

            <Select
              id="flood-object-action"
              labelText="Action"
              value={modalAction}
              onChange={(e) => setModalAction(e.target.value as any)}
            >
              <SelectItem value="block" text="HTTP 429 block" />
              <SelectItem value="challenge" text="Browser challenge" />
              <SelectItem value="http_reject" text="HTTP 503 reject" />
            </Select>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1rem' }}>
            <NumberInput
              id="flood-object-rate"
              label="Rate / second"
              min={1}
              value={modalRate}
              onChange={(_e, { value }) => setModalRate(Number(value) || 1)}
            />
            <NumberInput
              id="flood-object-concurrency"
              label="In-flight limit"
              min={1}
              value={modalConcurrency}
              onChange={(_e, { value }) => setModalConcurrency(Number(value) || 1)}
            />
            <NumberInput
              id="flood-object-burst"
              label="Burst multiplier"
              min={1}
              step={0.1}
              value={modalBurst}
              onChange={(_e, { value }) => setModalBurst(Number(value) || 1)}
            />
          </div>
        </div>
      </Modal>
    </div>
  );
};
