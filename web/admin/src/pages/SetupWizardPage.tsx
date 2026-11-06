import React, { useState } from 'react';
import {
  ProgressIndicator,
  ProgressStep,
  Stack,
  TextInput,
  PasswordInput,
  NumberInput,
  Select,
  SelectItem,
  Toggle,
  Button,
  InlineNotification,
  Layer,
  Grid,
  Column,
  Tag,
} from '@carbon/react';
import {
  CheckmarkOutline,
  ArrowRight,
  ArrowLeft,
  Security,
  Datastore,
  Analytics,
  UserAdmin,
  Certificate,
  Renew,
} from '@carbon/icons-react';
import { apiService } from '../services/api';
import type {
  PostgreSQLPreflightRequest,
  PostgreSQLControlPendingRequest,
  ClickHousePreflightRequest,
  ClickHouseAnalyticsPendingRequest,
  SetupFirstAdminRequest,
} from '../types';

interface SetupWizardPageProps {
  onComplete?: () => void;
}

export const SetupWizardPage: React.FC<SetupWizardPageProps> = ({ onComplete }) => {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [stepError, setStepError] = useState<string | null>(null);
  const [stepSuccess, setStepSuccess] = useState<string | null>(null);

  const [pgHost, setPgHost] = useState<string>('127.0.0.1');
  const [pgPort, setPgPort] = useState<number>(5432);
  const [pgDatabase, setPgDatabase] = useState<string>('aegis');
  const [pgUsername, setPgUsername] = useState<string>('aegis');
  const [pgPassword, setPgPassword] = useState<string>('');
  const [pgSSLMode, setPgSSLMode] = useState<string>('disable');
  const [_pgTested, setPgTested] = useState<boolean>(false);

  const [analyticsDriver, setAnalyticsDriver] = useState<'postgresql' | 'clickhouse'>('postgresql');
  const [analyticsRetentionDays, setAnalyticsRetentionDays] = useState<number>(30);
  const [chMode, setChMode] = useState<'optional' | 'required' | 'disabled'>('optional');
  const [chHost, setChHost] = useState<string>('127.0.0.1');
  const [chPort, setChPort] = useState<number>(9000);
  const [chDatabase, setChDatabase] = useState<string>('aegis_analytics');
  const [chUsername, setChUsername] = useState<string>('default');
  const [chPassword, setChPassword] = useState<string>('');
  const [chSecure, setChSecure] = useState<boolean>(false);
  const [_chTested, setChTested] = useState<boolean>(false);

  const [adminUsername, setAdminUsername] = useState<string>('admin');
  const [adminEmail, setAdminEmail] = useState<string>('admin@example.com');
  const [adminPassword, setAdminPassword] = useState<string>('');
  const [adminConfirmPassword, setAdminConfirmPassword] = useState<string>('');
  const [adminCreated, setAdminCreated] = useState<boolean>(false);

  const [licenseKey, setLicenseKey] = useState<string>('');
  const [activatedTier, setActivatedTier] = useState<string>('Community');
  const [licenseActivated, setLicenseActivated] = useState<boolean>(false);

  const [setupFinished, setSetupFinished] = useState<boolean>(false);

  const handleTestPostgres = async () => {
    setLoading(true);
    setStepError(null);
    setStepSuccess(null);
    try {
      const payload: PostgreSQLPreflightRequest = {
        host: pgHost.trim(),
        port: Number(pgPort),
        database: pgDatabase.trim(),
        username: pgUsername.trim(),
        password: pgPassword,
        ssl_mode: pgSSLMode,
      };
      const res = await apiService.preflightSetupStoragePostgreSQL(payload);
      if (res.status === 'ok') {
        setPgTested(true);
        setStepSuccess('PostgreSQL connection verified successfully.');
      } else {
        setStepError(typeof res.error === 'string' ? res.error : 'PostgreSQL connection failed. Check host, credentials, and SSL mode.');
      }
    } catch (err: any) {
      setStepError(err?.message || 'Error testing PostgreSQL connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleSavePostgres = async () => {
    setLoading(true);
    setStepError(null);
    try {
      const payload: PostgreSQLControlPendingRequest = {
        host: pgHost.trim(),
        port: Number(pgPort),
        database: pgDatabase.trim(),
        username: pgUsername.trim(),
        password_secret_ref: pgPassword ? `env:AEGIS_DB_PASSWORD` : '',
        ssl_mode: pgSSLMode,
      };
      await apiService.saveSetupStoragePostgreSQLPending(payload);
      setStepError(null);
      setStepSuccess(null);
      setCurrentStep(1);
    } catch (err: any) {
      setStepError(err?.message || 'Failed to save PostgreSQL configuration.');
    } finally {
      setLoading(false);
    }
  };

  const handleTestClickHouse = async () => {
    if (chMode === 'disabled') {
      setStepSuccess('Analytics engine is disabled.');
      setChTested(true);
      return;
    }
    if (analyticsDriver === 'postgresql') {
      setStepSuccess('PostgreSQL analytics uses the control-plane PostgreSQL database (30-day max retention).');
      setChTested(true);
      return;
    }
    setLoading(true);
    setStepError(null);
    setStepSuccess(null);
    try {
      const payload: ClickHousePreflightRequest = {
        host: chHost.trim(),
        port: Number(chPort),
        database: chDatabase.trim(),
        username: chUsername.trim(),
        password: chPassword,
        secure: chSecure,
      };
      const res = await apiService.preflightSetupStorageClickHouse(payload);
      if (res.status === 'ok') {
        setChTested(true);
        setStepSuccess('ClickHouse connection verified successfully.');
      } else {
        setStepError(typeof res.error === 'string' ? res.error : 'ClickHouse connection failed. Check host, port, and credentials.');
      }
    } catch (err: any) {
      setStepError(err?.message || 'Error testing ClickHouse connection.');
    } finally {
      setLoading(false);
    }
  };

  const handleSaveClickHouse = async () => {
    setLoading(true);
    setStepError(null);
    try {
      const retention = Math.min(30, Math.max(1, Number(analyticsRetentionDays) || 30));
      if (chMode !== 'disabled') {
        const payload: ClickHouseAnalyticsPendingRequest =
          analyticsDriver === 'postgresql'
            ? {
                mode: chMode,
                driver: 'postgresql',
                host: pgHost.trim(),
                port: Number(pgPort) || 5432,
                database: pgDatabase.trim(),
                username: pgUsername.trim(),
                password_secret_ref: pgPassword ? 'env:AEGIS_CONTROL_DB_PASSWORD' : '',
                secure: false,
                retention_days: retention,
              }
            : {
                mode: chMode,
                driver: 'clickhouse',
                host: chHost.trim(),
                port: Number(chPort) || 9000,
                database: chDatabase.trim(),
                username: chUsername.trim(),
                password_secret_ref: chPassword ? 'env:AEGIS_ANALYTICS_DB_PASSWORD' : '',
                secure: chSecure,
                retention_days: retention,
              };
        await apiService.saveSetupStorageClickHousePending(payload);
      }
      setStepError(null);
      setStepSuccess(null);
      setCurrentStep(2);
    } catch (err: any) {
      setStepError(err?.message || 'Failed to save analytics configuration.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateAdmin = async () => {
    if (!adminUsername.trim() || !adminEmail.trim()) {
      setStepError('Username and email are required.');
      return;
    }
    if (adminPassword.length < 8) {
      setStepError('Password must be at least 8 characters long.');
      return;
    }
    if (adminPassword !== adminConfirmPassword) {
      setStepError('Passwords do not match.');
      return;
    }
    setLoading(true);
    setStepError(null);
    try {
      const payload: SetupFirstAdminRequest = {
        username: adminUsername.trim(),
        email: adminEmail.trim(),
        password: adminPassword,
      };
      await apiService.createSetupFirstAdmin(payload);
      setAdminCreated(true);
      setStepError(null);
      setStepSuccess('Super administrator account created.');
      setCurrentStep(3);
    } catch (err: any) {
      setStepError(err?.message || 'Failed to create super administrator account.');
    } finally {
      setLoading(false);
    }
  };

  const handleActivateLicense = async () => {
    if (!licenseKey.trim()) {
      setStepError('Please enter a license key to activate.');
      return;
    }
    setLoading(true);
    setStepError(null);
    try {
      const res = await apiService.activateLicense(licenseKey.trim());
      if (res.success) {
        const tier = res.license?.effective_tier || res.license?.licensed_tier || 'Enterprise';
        setActivatedTier(tier.toUpperCase());
        setLicenseActivated(true);
        setStepSuccess(`License activated successfully (${tier.toUpperCase()}).`);
      } else {
        setStepError(res.error || 'Failed to activate license key.');
      }
    } catch (err: any) {
      setStepError(err?.message || 'License activation failed.');
    } finally {
      setLoading(false);
    }
  };

  const handleSkipLicense = () => {
    setStepError(null);
    setStepSuccess(null);
    setCurrentStep(4);
  };

  const handleCompleteSetup = async () => {
    setLoading(true);
    setStepError(null);
    try {
      await apiService.completeSetup();
      setSetupFinished(true);
    } catch (err: any) {
      setStepError(err?.message || 'Failed to complete first-run setup.');
    } finally {
      setLoading(false);
    }
  };

  const handleFinalRedirect = () => {
    if (onComplete) {
      onComplete();
    } else {
      window.location.hash = '#security-events';
      window.location.reload();
    }
  };

  return (
    <div
      style={{
        minHeight: '100vh',
        backgroundColor: 'var(--cds-background, #161616)',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        padding: '3rem 1.5rem',
      }}
    >
      <div style={{ maxWidth: '840px', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '2.5rem' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
            <Security size={32} />
            <span style={{ fontSize: '1.75rem', fontWeight: 600, letterSpacing: '-0.5px' }}>
              AEGIS DEFENDER
            </span>
          </div>
          <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '1rem', margin: 0 }}>
            First-Run System Deployment &amp; Initial Configuration Wizard
          </p>
        </div>

        <div style={{ marginBottom: '2.5rem' }}>
          <ProgressIndicator currentIndex={currentStep}>
            <ProgressStep label="Control Storage" description="PostgreSQL" />
            <ProgressStep label="Analytics Engine" description={analyticsDriver === 'postgresql' ? 'PostgreSQL (30d)' : 'ClickHouse'} />
            <ProgressStep label="Administrator" description="Super Admin" />
            <ProgressStep label="License" description="Tier Activation" />
            <ProgressStep label="Review & Finish" description="Summary" />
          </ProgressIndicator>
        </div>

        {stepError && (
          <InlineNotification
            kind="error"
            lowContrast
            title="Setup Error"
            subtitle={stepError}
            onCloseButtonClick={() => setStepError(null)}
            style={{ marginBottom: '1.5rem', width: '100%' }}
          />
        )}
        {stepSuccess && (
          <InlineNotification
            kind="success"
            lowContrast
            title="Success"
            subtitle={stepSuccess}
            onCloseButtonClick={() => setStepSuccess(null)}
            style={{ marginBottom: '1.5rem', width: '100%' }}
          />
        )}

        <Layer
          level={1}
          style={{
            padding: '2rem',
            borderRadius: '6px',
            border: '1px solid var(--cds-border-subtle, #393939)',
            backgroundColor: 'var(--cds-layer-01, #262626)',
          }}
        >
          {currentStep === 0 && (
            <Stack gap={6}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <Datastore size={24} />
                  <h3 style={{ margin: 0 }}>Step 1: PostgreSQL Control Plane Storage</h3>
                </div>
                <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '0.875rem' }}>
                  The control plane stores configuration policies, users, certificates, and operational state.
                </p>
              </div>

              <Grid fullWidth style={{ padding: 0 }}>
                <Column lg={8} md={4} sm={4}>
                  <TextInput
                    id="pg-host"
                    labelText="Database Host"
                    value={pgHost}
                    onChange={(e) => setPgHost(e.target.value)}
                    placeholder="127.0.0.1 or db.internal"
                    required
                  />
                </Column>
                <Column lg={4} md={4} sm={4}>
                  <NumberInput
                    id="pg-port"
                    label="Port"
                    min={1}
                    max={65535}
                    value={pgPort}
                    onChange={(_, { value }) => setPgPort(Number(value) || 5432)}
                  />
                </Column>
              </Grid>

              <Grid fullWidth style={{ padding: 0 }}>
                <Column lg={6} md={4} sm={4}>
                  <TextInput
                    id="pg-db"
                    labelText="Database Name"
                    value={pgDatabase}
                    onChange={(e) => setPgDatabase(e.target.value)}
                    required
                  />
                </Column>
                <Column lg={6} md={4} sm={4}>
                  <TextInput
                    id="pg-user"
                    labelText="Username"
                    value={pgUsername}
                    onChange={(e) => setPgUsername(e.target.value)}
                    required
                  />
                </Column>
              </Grid>

              <Grid fullWidth style={{ padding: 0 }}>
                <Column lg={6} md={4} sm={4}>
                  <PasswordInput
                    id="pg-pass"
                    labelText="Password"
                    value={pgPassword}
                    onChange={(e) => setPgPassword(e.target.value)}
                    placeholder="••••••••"
                  />
                </Column>
                <Column lg={6} md={4} sm={4}>
                  <Select
                    id="pg-ssl"
                    labelText="SSL / TLS Mode"
                    value={pgSSLMode}
                    onChange={(e) => setPgSSLMode(e.target.value)}
                  >
                    <SelectItem value="disable" text="Disable (local / development)" />
                    <SelectItem value="require" text="Require (encrypted, standard)" />
                    <SelectItem value="verify-ca" text="Verify CA (signed certificate)" />
                    <SelectItem value="verify-full" text="Verify Full (hostname + CA match)" />
                  </Select>
                </Column>
              </Grid>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--cds-border-subtle, #393939)' }}>
                <Button
                  kind="tertiary"
                  renderIcon={Renew}
                  onClick={handleTestPostgres}
                  disabled={loading}
                >
                  {loading ? 'Testing...' : 'Test Connection'}
                </Button>
                <Button
                  kind="primary"
                  renderIcon={ArrowRight}
                  onClick={handleSavePostgres}
                  disabled={loading}
                >
                  Save &amp; Continue
                </Button>
              </div>
            </Stack>
          )}

          {currentStep === 1 && (
            <Stack gap={6}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <Analytics size={24} />
                  <h3 style={{ margin: 0 }}>Step 2: Analytics Storage Engine</h3>
                </div>
                <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '0.875rem' }}>
                  Security event and telemetry persistence. Defaults to PostgreSQL (30-day rolling retention, reusing the control-plane database); ClickHouse is optional.
                </p>
              </div>

              <Grid fullWidth style={{ padding: 0 }}>
                <Column lg={6} md={4} sm={4}>
                  <Select
                    id="ch-mode"
                    labelText="Analytics Storage Mode"
                    value={chMode}
                    onChange={(e) => setChMode(e.target.value as any)}
                  >
                    <SelectItem value="optional" text="Optional (Recommended - log if available)" />
                    <SelectItem value="required" text="Required (Strict high-security cluster)" />
                    <SelectItem value="disabled" text="Disabled (Skip analytics engine)" />
                  </Select>
                </Column>
                {chMode !== 'disabled' && (
                  <Column lg={6} md={4} sm={4}>
                    <Select
                      id="analytics-driver"
                      labelText="Analytics Database Driver"
                      value={analyticsDriver}
                      onChange={(e) => setAnalyticsDriver(e.target.value as 'postgresql' | 'clickhouse')}
                    >
                      <SelectItem value="postgresql" text="PostgreSQL (Default — shared with Control DB)" />
                      <SelectItem value="clickhouse" text="ClickHouse (Optional external engine)" />
                    </Select>
                  </Column>
                )}
              </Grid>

              {chMode !== 'disabled' && (
                <NumberInput
                  id="analytics-retention-days"
                  label="Retention Window (Days, max 30)"
                  min={1}
                  max={30}
                  value={analyticsRetentionDays}
                  onChange={(_, { value }) => setAnalyticsRetentionDays(Math.min(30, Math.max(1, Number(value) || 30)))}
                  helperText="Events older than this window are automatically pruned."
                />
              )}

              {chMode !== 'disabled' && analyticsDriver === 'clickhouse' && (
                <>
                  <Grid fullWidth style={{ padding: 0 }}>
                    <Column lg={8} md={4} sm={4}>
                      <TextInput
                        id="ch-host"
                        labelText="ClickHouse Host"
                        value={chHost}
                        onChange={(e) => setChHost(e.target.value)}
                        placeholder="127.0.0.1 or ch.internal"
                      />
                    </Column>
                    <Column lg={4} md={4} sm={4}>
                      <NumberInput
                        id="ch-port"
                        label="Native Port"
                        min={1}
                        max={65535}
                        value={chPort}
                        onChange={(_, { value }) => setChPort(Number(value) || 9000)}
                      />
                    </Column>
                  </Grid>

                  <Grid fullWidth style={{ padding: 0 }}>
                    <Column lg={6} md={4} sm={4}>
                      <TextInput
                        id="ch-db"
                        labelText="Database Name"
                        value={chDatabase}
                        onChange={(e) => setChDatabase(e.target.value)}
                      />
                    </Column>
                    <Column lg={6} md={4} sm={4}>
                      <TextInput
                        id="ch-user"
                        labelText="Username"
                        value={chUsername}
                        onChange={(e) => setChUsername(e.target.value)}
                      />
                    </Column>
                  </Grid>

                  <Grid fullWidth style={{ padding: 0 }}>
                    <Column lg={6} md={4} sm={4}>
                      <PasswordInput
                        id="ch-pass"
                        labelText="Password"
                        value={chPassword}
                        onChange={(e) => setChPassword(e.target.value)}
                        placeholder="••••••••"
                      />
                    </Column>
                    <Column lg={6} md={4} sm={4} style={{ display: 'flex', alignItems: 'center', paddingTop: '1.5rem' }}>
                      <Toggle
                        id="ch-secure"
                        labelText="TLS Encryption"
                        labelA="Insecure"
                        labelB="Secure"
                        toggled={chSecure}
                        onToggle={(checked) => setChSecure(checked)}
                      />
                    </Column>
                  </Grid>
                </>
              )}

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--cds-border-subtle, #393939)' }}>
                <Button
                  kind="secondary"
                  renderIcon={ArrowLeft}
                  onClick={() => setCurrentStep(0)}
                  disabled={loading}
                >
                  Back
                </Button>
                <div style={{ display: 'flex', gap: '0.75rem' }}>
                  {chMode !== 'disabled' && analyticsDriver === 'clickhouse' && (
                    <Button
                      kind="tertiary"
                      renderIcon={Renew}
                      onClick={handleTestClickHouse}
                      disabled={loading}
                    >
                      {loading ? 'Testing...' : 'Test Connection'}
                    </Button>
                  )}
                  <Button
                    kind="primary"
                    renderIcon={ArrowRight}
                    onClick={handleSaveClickHouse}
                    disabled={loading}
                  >
                    Save &amp; Continue
                  </Button>
                </div>
              </div>
            </Stack>
          )}

          {currentStep === 2 && (
            <Stack gap={6}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <UserAdmin size={24} />
                  <h3 style={{ margin: 0 }}>Step 3: First Super Administrator Account</h3>
                </div>
                <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '0.875rem' }}>
                  Create the master administrator account for this Aegis deployment.
                </p>
              </div>

              <TextInput
                id="admin-username"
                labelText="Super Administrator Username"
                value={adminUsername}
                onChange={(e) => setAdminUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
              />

              <TextInput
                id="admin-email"
                labelText="Email Address"
                type="email"
                value={adminEmail}
                onChange={(e) => setAdminEmail(e.target.value)}
                placeholder="admin@company.com"
                required
              />

              <Grid fullWidth style={{ padding: 0 }}>
                <Column lg={6} md={4} sm={4}>
                  <PasswordInput
                    id="admin-pass"
                    labelText="Password"
                    value={adminPassword}
                    onChange={(e) => setAdminPassword(e.target.value)}
                    helperText="Minimum 8 characters."
                    required
                  />
                </Column>
                <Column lg={6} md={4} sm={4}>
                  <PasswordInput
                    id="admin-confirm-pass"
                    labelText="Confirm Password"
                    value={adminConfirmPassword}
                    onChange={(e) => setAdminConfirmPassword(e.target.value)}
                    required
                  />
                </Column>
              </Grid>

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--cds-border-subtle, #393939)' }}>
                <Button
                  kind="secondary"
                  renderIcon={ArrowLeft}
                  onClick={() => setCurrentStep(1)}
                  disabled={loading || adminCreated}
                >
                  Back
                </Button>
                <Button
                  kind="primary"
                  renderIcon={ArrowRight}
                  onClick={handleCreateAdmin}
                  disabled={loading || adminPassword.length < 8 || adminPassword !== adminConfirmPassword}
                >
                  {loading ? 'Creating...' : 'Create Account &amp; Proceed'}
                </Button>
              </div>
            </Stack>
          )}

          {currentStep === 3 && (
            <Stack gap={6}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                  <Certificate size={24} />
                  <h3 style={{ margin: 0 }}>Step 4: License Key Activation</h3>
                </div>
                <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '0.875rem' }}>
                  Enter your commercial license key to unlock Enterprise or Professional features, or skip to use Community Edition.
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '1rem', backgroundColor: 'var(--cds-layer-02, #393939)', borderRadius: '4px' }}>
                <span style={{ fontWeight: 600 }}>Active Tier:</span>
                <Tag type={licenseActivated ? 'purple' : 'blue'} size="md">
                  {activatedTier}
                </Tag>
              </div>

              <TextInput
                id="license-key"
                labelText="Enterprise / Professional License Key (Optional)"
                placeholder="AEGIS-XXXX-XXXX-XXXX-XXXX"
                value={licenseKey}
                onChange={(e) => setLicenseKey(e.target.value)}
                helperText="Can be added or updated at any time in System Settings."
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--cds-border-subtle, #393939)' }}>
                <Button
                  kind="ghost"
                  onClick={handleSkipLicense}
                >
                  Skip for Now (Community Edition)
                </Button>

                <div style={{ display: 'flex', gap: '0.75rem' }}>
                  {licenseKey && (
                    <Button
                      kind="tertiary"
                      renderIcon={CheckmarkOutline}
                      onClick={handleActivateLicense}
                      disabled={loading || !licenseKey.trim()}
                    >
                      {loading ? 'Activating...' : 'Activate Key'}
                    </Button>
                  )}
                  <Button
                    kind="primary"
                    renderIcon={ArrowRight}
                    onClick={() => setCurrentStep(4)}
                  >
                    Continue
                  </Button>
                </div>
              </div>
            </Stack>
          )}

          {currentStep === 4 && (
            <Stack gap={6}>
              {!setupFinished ? (
                <>
                  <div>
                    <h3 style={{ margin: '0 0 0.5rem 0' }}>Step 5: Review &amp; Complete Setup</h3>
                    <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', fontSize: '0.875rem', margin: 0 }}>
                      Review your initial deployment configuration before committing.
                    </p>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                    <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer-02, #393939)', borderRadius: '4px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Control Plane Storage</div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--cds-text-secondary, #c6c6c6)' }}>
                        Host: {pgHost}:{pgPort}<br />
                        Database: {pgDatabase}<br />
                        User: {pgUsername}<br />
                        SSL Mode: {pgSSLMode}
                      </div>
                    </div>

                    <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer-02, #393939)', borderRadius: '4px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Analytics Engine</div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--cds-text-secondary, #c6c6c6)' }}>
                        Mode: {chMode}<br />
                        {chMode !== 'disabled' && (
                          analyticsDriver === 'postgresql' ? (
                            <>
                              Driver: PostgreSQL (Shared Control DB)<br />
                              Retention: {analyticsRetentionDays} days
                            </>
                          ) : (
                            <>
                              Driver: ClickHouse<br />
                              Host: {chHost}:{chPort}<br />
                              Database: {chDatabase}<br />
                              Retention: {analyticsRetentionDays} days
                            </>
                          )
                        )}
                      </div>
                    </div>

                    <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer-02, #393939)', borderRadius: '4px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Primary Administrator</div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--cds-text-secondary, #c6c6c6)' }}>
                        Username: {adminUsername}<br />
                        Email: {adminEmail}<br />
                        Role: super_admin
                      </div>
                    </div>

                    <div style={{ padding: '1rem', backgroundColor: 'var(--cds-layer-02, #393939)', borderRadius: '4px' }}>
                      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>Active Edition</div>
                      <div style={{ fontSize: '0.875rem', color: 'var(--cds-text-secondary, #c6c6c6)' }}>
                        Tier: {activatedTier}<br />
                        License: {licenseActivated ? 'Activated' : 'Community Standard'}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--cds-border-subtle, #393939)' }}>
                    <Button
                      kind="secondary"
                      renderIcon={ArrowLeft}
                      onClick={() => setCurrentStep(3)}
                      disabled={loading}
                    >
                      Back
                    </Button>
                    <Button
                      kind="primary"
                      renderIcon={CheckmarkOutline}
                      onClick={handleCompleteSetup}
                      disabled={loading}
                      size="lg"
                    >
                      {loading ? 'Finalizing Setup...' : 'Complete Setup &amp; Launch'}
                    </Button>
                  </div>
                </>
              ) : (
                <div style={{ textAlign: 'center', padding: '2rem 1rem' }}>
                  <CheckmarkOutline size={64} style={{ color: 'var(--cds-support-success, #24a148)', marginBottom: '1rem' }} />
                  <h2 style={{ marginBottom: '0.75rem' }}>Aegis Setup Complete!</h2>
                  <p style={{ color: 'var(--cds-text-secondary, #8d8d8d)', maxWidth: '520px', margin: '0 auto 2rem auto' }}>
                    Your control plane and security policies are active. You can now access the full management console.
                  </p>
                  <Button
                    kind="primary"
                    size="lg"
                    renderIcon={ArrowRight}
                    onClick={handleFinalRedirect}
                  >
                    Go to Admin Console
                  </Button>
                </div>
              )}
            </Stack>
          )}
        </Layer>
      </div>
    </div>
  );
};

export default SetupWizardPage;
