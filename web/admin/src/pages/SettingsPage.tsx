import React, { useEffect, useState, useMemo, useRef } from 'react';
import {
  Tile,
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  TextInput,
  PasswordInput,
  NumberInput,
  Select,
  SelectItem,
  InlineNotification,
  Grid,
  Column,
  Button,
  Modal,
} from '@carbon/react';
import {
  Settings,
  Datastore,
  Activity,
  Network_3,
  Document,
  Download,
  Upload,
  Reset,
  Renew,
  Enterprise,
  Launch,
} from '@carbon/icons-react';
import type {
  SystemSettings,
  LicenseSnapshot,
  StorageStatusResponse,
  PostgreSQLPreflightRequest,
  PostgreSQLControlPendingRequest,
  ClickHousePreflightRequest,
  ClickHouseAnalyticsPendingRequest,
  UpstreamSettings,
  SystemUpdateStatus,
} from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard, StatusToggle } from '../components/common';

export const SettingsPage: React.FC = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [selectedTab, setSelectedTab] = useState<number>(() => {
    const hash = window.location.hash.toLowerCase();
    if (hash.includes('storage') || hash.includes('database')) return 1;
    if (hash.includes('telemetry') || hash.includes('advanced')) return 2;
    if (hash.includes('origin') || hash.includes('upstream')) return 3;
    if (hash.includes('backup')) return 4;
    if (hash.includes('licence') || hash.includes('license')) return 5;
    return 0;
  });

  const [initialSettings, setInitialSettings] = useState<SystemSettings | null>(null);

  const [publicProxyPort, setPublicProxyPort] = useState<number>(8080);
  const [adminHost, setAdminHost] = useState<string>('127.0.0.1');
  const [adminPort, setAdminPort] = useState<number>(8081);
  const [savingGeneral, setSavingGeneral] = useState<boolean>(false);

  const isLoopbackHost = (host: string): boolean => {
    const normalized = host.trim().replace(/^\[|\]$/g, '').toLowerCase();
    return normalized === 'localhost' || normalized.startsWith('127.') || normalized === '::1';
  };

  const [_storageStatus, setStorageStatus] = useState<StorageStatusResponse | null>(null);
  const [pgHost, setPgHost] = useState<string>('localhost');
  const [pgPort, setPgPort] = useState<number>(5432);
  const [pgDatabase, setPgDatabase] = useState<string>('aegis');
  const [pgUsername, setPgUsername] = useState<string>('aegis');
  const [pgPassword, setPgPassword] = useState<string>('');
  const [pgSecretRef, setPgSecretRef] = useState<string>('env:AEGIS_CONTROL_DB_PASSWORD');
  const [pgSslMode, setPgSslMode] = useState<string>('disable');
  const [pgTesting, setPgTesting] = useState<boolean>(false);
  const [pgSaving, setPgSaving] = useState<boolean>(false);

  const [analyticsDriver, setAnalyticsDriver] = useState<'postgresql' | 'clickhouse'>('postgresql');
  const [analyticsRetentionDays, setAnalyticsRetentionDays] = useState<number>(30);
  const [chMode, setChMode] = useState<'required' | 'optional' | 'disabled'>('optional');
  const [chHost, setChHost] = useState<string>('localhost');
  const [chPort, setChPort] = useState<number>(9000);
  const [chDatabase, setChDatabase] = useState<string>('aegis');
  const [chUsername, setChUsername] = useState<string>('default');
  const [chPassword, setChPassword] = useState<string>('');
  const [chSecretRef, setChSecretRef] = useState<string>('env:AEGIS_ANALYTICS_DB_PASSWORD');
  const [chSecure, setChSecure] = useState<boolean>(false);
  const [chTesting, setChTesting] = useState<boolean>(false);
  const [chSaving, setChSaving] = useState<boolean>(false);

  const [prometheusEnabled, setPrometheusEnabled] = useState<boolean>(true);
  const [prometheusPath, setPrometheusPath] = useState<string>('/metrics');
  const [prometheusToken, setPrometheusToken] = useState<string>('');
  const [clearPrometheusToken, setClearPrometheusToken] = useState<boolean>(false);
  const [requestLogging, setRequestLogging] = useState<boolean>(true);
  const [savingTelemetry, setSavingTelemetry] = useState<boolean>(false);

  const [_upstreamAvailability, setUpstreamAvailability] = useState<string>('available');
  const [initialUpstream, setInitialUpstream] = useState<UpstreamSettings | null>(null);
  const [upstreamTarget, setUpstreamTarget] = useState<string>('');
  const [maxIdleConns, setMaxIdleConns] = useState<number>(1000);
  const [maxIdleConnsPerHost, setMaxIdleConnsPerHost] = useState<number>(20);
  const [maxConnsPerHost, setMaxConnsPerHost] = useState<number>(100);
  const [idleTimeout, setIdleTimeout] = useState<string>('90s');
  const [tlsTimeout, setTlsTimeout] = useState<string>('10s');
  const [healthConcurrency, setHealthConcurrency] = useState<number>(32);
  const [insecureSkipVerify, setInsecureSkipVerify] = useState<boolean>(false);
  const [upstreamSaving, setUpstreamSaving] = useState<boolean>(false);

  const [isResetModalOpen, setIsResetModalOpen] = useState<boolean>(false);
  const [resetting, setResetting] = useState<boolean>(false);
  const [downloadingBackup, setDownloadingBackup] = useState<boolean>(false);
  const [exportingConfig, setExportingConfig] = useState<boolean>(false);
  const [importingFile, setImportingFile] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const [license, setLicense] = useState<LicenseSnapshot | null>(null);
  const [licenseKeyInput, setLicenseKeyInput] = useState<string>('');
  const [activatingLicense, setActivatingLicense] = useState<boolean>(false);
  const [refreshingLicense, setRefreshingLicense] = useState<boolean>(false);
  const [isDeactivateModalOpen, setIsDeactivateModalOpen] = useState<boolean>(false);
  const [deactivatingLicense, setDeactivatingLicense] = useState<boolean>(false);
  const [upgradingLicense, setUpgradingLicense] = useState<boolean>(false);
  const [isUpdateModalOpen, setIsUpdateModalOpen] = useState<boolean>(false);
  const [updateStatus, setUpdateStatus] = useState<SystemUpdateStatus | null>(null);
  const [checkingUpdates, setCheckingUpdates] = useState<boolean>(false);
  const [applyingUpdate, setApplyingUpdate] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [
        fetchedSettings,
        fetchedConfig,
        fetchedStorage,
        fetchedUpstreamResult,
        fetchedLicense,
      ] = await Promise.all([
        apiService.getSystemSettings().catch(() => null),
        apiService.getFullConfig().catch(() => null),
        apiService.getStorageStatus().catch(() => null),
        apiService.getUpstreamSettings().catch(() => ({ data: null, availability: 'unavailable' as const })),
        apiService.getLicense().catch(() => null),
      ]);

      if (fetchedStorage) {
        setStorageStatus(fetchedStorage);
      }

      if (fetchedSettings) {
        const mergedSettings: SystemSettings = {
          ...fetchedSettings,
          admin_host: fetchedConfig?.server?.admin?.host || fetchedSettings.admin_host || '127.0.0.1',
          request_logging: fetchedConfig?.telemetry?.request_logging !== undefined ? fetchedConfig.telemetry.request_logging : (fetchedSettings.request_logging ?? false),
          prometheus_token: fetchedConfig?.telemetry?.prometheus_token || fetchedSettings.prometheus_token || '',
        };
        setInitialSettings(mergedSettings);
        setPublicProxyPort(mergedSettings.http_port || 8080);
        setAdminPort(mergedSettings.admin_port || 8081);
        setAdminHost(mergedSettings.admin_host || '127.0.0.1');
        setPrometheusEnabled(mergedSettings.prometheus_enabled ?? true);
        setPrometheusPath(mergedSettings.prometheus_path || '/metrics');
        setRequestLogging(mergedSettings.request_logging ?? false);
        setPrometheusToken(mergedSettings.prometheus_token || '');
      }

      if (fetchedConfig) {
        if (fetchedConfig.server?.admin?.host) {
          setAdminHost(fetchedConfig.server.admin.host);
        }
        if (fetchedConfig.telemetry?.request_logging !== undefined) {
          setRequestLogging(fetchedConfig.telemetry.request_logging);
        }
        if (fetchedConfig.storage?.control) {
          const ctrl = fetchedConfig.storage.control;
          if (ctrl.host) setPgHost(ctrl.host);
          if (ctrl.port) setPgPort(ctrl.port);
          if (ctrl.database) setPgDatabase(ctrl.database);
          if (ctrl.username) setPgUsername(ctrl.username);
          if (ctrl.ssl_mode) setPgSslMode(ctrl.ssl_mode);
          if (ctrl.password_secret_ref && ctrl.password_secret_ref !== '[REDACTED]') {
            setPgSecretRef(ctrl.password_secret_ref);
          }
        }
        if (fetchedConfig.storage?.analytics) {
          const an = fetchedConfig.storage.analytics;
          if (an.driver === 'clickhouse' || an.driver === 'postgresql') {
            setAnalyticsDriver(an.driver);
          } else {
            setAnalyticsDriver('postgresql');
          }
          if (an.retention_days && Number(an.retention_days) >= 1 && Number(an.retention_days) <= 30) {
            setAnalyticsRetentionDays(Number(an.retention_days));
          } else {
            setAnalyticsRetentionDays(30);
          }
          if (an.mode) setChMode(an.mode);
          if (an.host) setChHost(an.host);
          if (an.port) setChPort(an.port);
          if (an.database) setChDatabase(an.database);
          if (an.username) setChUsername(an.username);
          if (an.secure !== undefined) setChSecure(an.secure);
          if (an.password_secret_ref && an.password_secret_ref !== '[REDACTED]') {
            setChSecretRef(an.password_secret_ref);
          }
        }
      }

      if (fetchedUpstreamResult) {
        setUpstreamAvailability(fetchedUpstreamResult.availability);
        if (fetchedUpstreamResult.data) {
          const up = fetchedUpstreamResult.data;
          setInitialUpstream(up);
          setUpstreamTarget(up.target || '');
          setMaxIdleConns(up.max_idle_conns || 1000);
          setMaxIdleConnsPerHost(up.max_idle_conns_per_host || 20);
          setMaxConnsPerHost(up.max_conns_per_host || 100);
          setIdleTimeout(up.idle_timeout || '90s');
          setTlsTimeout(up.tls_timeout || '10s');
          setHealthConcurrency(up.health_check_concurrency || 32);
          setInsecureSkipVerify(up.insecure_skip_verify || false);
        }
      }

      if (fetchedLicense) {
        setLicense(fetchedLicense);
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load system settings' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const isGeneralDirty = useMemo(() => {
    if (!initialSettings) return false;
    return (
      Number(publicProxyPort) !== Number(initialSettings.http_port || 8080) ||
      adminHost.trim() !== (initialSettings.admin_host || '127.0.0.1').trim() ||
      Number(adminPort) !== Number(initialSettings.admin_port || 8081)
    );
  }, [initialSettings, publicProxyPort, adminHost, adminPort]);

  const isTelemetryDirty = useMemo(() => {
    if (!initialSettings) return false;
    return (
      prometheusEnabled !== (initialSettings.prometheus_enabled ?? true) ||
      prometheusPath.trim() !== (initialSettings.prometheus_path || '/metrics').trim() ||
      prometheusToken.trim() !== (initialSettings.prometheus_token || '').trim() ||
      clearPrometheusToken ||
      requestLogging !== (initialSettings.request_logging ?? false)
    );
  }, [
    initialSettings,
    prometheusEnabled,
    prometheusPath,
    prometheusToken,
    clearPrometheusToken,
    requestLogging,
  ]);

  const isUpstreamDirty = useMemo(() => {
    if (!initialUpstream) return false;
    return (
      upstreamTarget.trim() !== (initialUpstream.target || '').trim() ||
      Number(maxIdleConns) !== Number(initialUpstream.max_idle_conns || 1000) ||
      Number(maxIdleConnsPerHost) !== Number(initialUpstream.max_idle_conns_per_host || 20) ||
      Number(maxConnsPerHost) !== Number(initialUpstream.max_conns_per_host || 100) ||
      idleTimeout.trim() !== (initialUpstream.idle_timeout || '90s').trim() ||
      tlsTimeout.trim() !== (initialUpstream.tls_timeout || '10s').trim() ||
      Number(healthConcurrency) !== Number(initialUpstream.health_check_concurrency || 32) ||
      insecureSkipVerify !== (initialUpstream.insecure_skip_verify || false)
    );
  }, [
    initialUpstream,
    upstreamTarget,
    maxIdleConns,
    maxIdleConnsPerHost,
    maxConnsPerHost,
    idleTimeout,
    tlsTimeout,
    healthConcurrency,
    insecureSkipVerify,
  ]);

  const handleSaveGeneral = async () => {
    const portNum = Number(publicProxyPort);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      setNotification({ kind: 'error', message: 'Enter a valid public proxy port (1–65535).' });
      return;
    }
    if (!adminHost.trim()) {
      setNotification({ kind: 'error', message: 'Enter an admin listener host.' });
      return;
    }
    const adminPortNum = Number(adminPort);
    if (!Number.isInteger(adminPortNum) || adminPortNum < 1 || adminPortNum > 65535) {
      setNotification({ kind: 'error', message: 'Enter a valid admin listener port (1–65535).' });
      return;
    }

    setSavingGeneral(true);
    const updates: Record<string, unknown> = {
      'server.port': portNum,
      'server.admin.host': adminHost.trim(),
      'server.admin.port': adminPortNum,
    };

    const ok = await apiService.saveConfigUpdates(updates);
    setSavingGeneral(false);
    if (ok) {
      setInitialSettings((prev) =>
        prev
          ? {
              ...prev,
              http_port: portNum,
              admin_host: adminHost.trim(),
              admin_port: adminPortNum,
            }
          : null
      );
      setNotification({
        kind: 'success',
        message: 'Listener configuration saved. Restart Aegis to apply it.',
      });
    } else {
      setNotification({ kind: 'error', message: 'Failed to save listener configuration.' });
    }
  };

  const handleResetGeneral = () => {
    if (!initialSettings) return;
    setPublicProxyPort(initialSettings.http_port || 8080);
    setAdminHost(initialSettings.admin_host || '127.0.0.1');
    setAdminPort(initialSettings.admin_port || 8081);
    setNotification(null);
  };

  const handleSaveTelemetry = async () => {
    if (prometheusPath.trim() === '' || !prometheusPath.startsWith('/')) {
      setNotification({ kind: 'error', message: 'Metrics scrape path must start with / (e.g. /metrics).' });
      return;
    }
    setSavingTelemetry(true);
    const updates: Record<string, unknown> = {
      'telemetry.prometheus_enabled': prometheusEnabled,
      'telemetry.prometheus_path': prometheusPath.trim(),
      'telemetry.request_logging': requestLogging,
    };
    if (prometheusToken.trim()) {
      updates['telemetry.prometheus_token'] = prometheusToken.trim();
    }
    if (clearPrometheusToken) {
      updates['telemetry.prometheus_token'] = '';
    }

    const ok = await apiService.saveConfigUpdates(updates);
    setSavingTelemetry(false);
    if (ok) {
      setInitialSettings((prev) =>
        prev
          ? {
              ...prev,
              prometheus_enabled: prometheusEnabled,
              prometheus_path: prometheusPath.trim(),
              request_logging: requestLogging,
              prometheus_token: clearPrometheusToken ? '' : (prometheusToken.trim() || prev.prometheus_token || ''),
            }
          : null
      );
      setClearPrometheusToken(false);
      setNotification({
        kind: 'success',
        message: 'Telemetry settings saved.',
      });
    } else {
      setNotification({ kind: 'error', message: 'Failed to save telemetry settings.' });
    }
  };

  const handleResetTelemetry = () => {
    if (!initialSettings) return;
    setPrometheusEnabled(initialSettings.prometheus_enabled ?? true);
    setPrometheusPath(initialSettings.prometheus_path || '/metrics');
    setRequestLogging(initialSettings.request_logging ?? false);
    setClearPrometheusToken(false);
    setPrometheusToken(initialSettings.prometheus_token || '');
    setNotification(null);
  };

  const handleTestPostgres = async () => {
    if (!pgHost.trim() || !pgDatabase.trim() || !pgUsername.trim()) {
      setNotification({ kind: 'error', message: 'Please provide host, database, and username for PostgreSQL test.' });
      return;
    }
    if (!pgPassword) {
      setNotification({ kind: 'error', message: 'Enter temporary test password for PostgreSQL preflight test.' });
      return;
    }
    setPgTesting(true);
    const req: PostgreSQLPreflightRequest = {
      host: pgHost.trim(),
      port: Number(pgPort) || 5432,
      database: pgDatabase.trim(),
      username: pgUsername.trim(),
      password: pgPassword,
      ssl_mode: pgSslMode,
    };
    const res = await apiService.testPostgreSQLControl(req);
    setPgTesting(false);
    setPgPassword('');
    if (res.success) {
      setNotification({ kind: 'success', message: 'PostgreSQL connection test succeeded! Preflight handshake verified.' });
    } else {
      setNotification({ kind: 'error', message: res.error || 'PostgreSQL connection test failed.' });
    }
  };

  const handleSavePostgresPending = async () => {
    if (!pgHost.trim() || !pgDatabase.trim() || !pgUsername.trim() || !pgSecretRef.trim()) {
      setNotification({ kind: 'error', message: 'Please provide all required PostgreSQL connection parameters.' });
      return;
    }
    if (!/^env:[A-Z_][A-Z0-9_]*$/.test(pgSecretRef.trim())) {
      setNotification({ kind: 'error', message: 'Secret reference must be in the format env:AEGIS_CONTROL_DB_PASSWORD' });
      return;
    }
    setPgSaving(true);
    const req: PostgreSQLControlPendingRequest = {
      host: pgHost.trim(),
      port: Number(pgPort) || 5432,
      database: pgDatabase.trim(),
      username: pgUsername.trim(),
      password_secret_ref: pgSecretRef.trim(),
      ssl_mode: pgSslMode,
    };
    const res = await apiService.savePostgreSQLControlPending(req);
    setPgSaving(false);
    if (res.success) {
      setNotification({
        kind: 'success',
        message: 'PostgreSQL configuration staged as pending. Restart Aegis to activate this storage backend.',
      });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to stage PostgreSQL configuration.' });
    }
  };

  const handleTestClickHouse = async () => {
    if (!chHost.trim() || !chDatabase.trim() || !chUsername.trim()) {
      setNotification({ kind: 'error', message: 'Please provide host, database, and username for ClickHouse test.' });
      return;
    }
    setChTesting(true);
    const req: ClickHousePreflightRequest = {
      host: chHost.trim(),
      port: Number(chPort) || 9000,
      database: chDatabase.trim(),
      username: chUsername.trim(),
      password: chPassword,
      secure: chSecure,
    };
    const res = await apiService.testClickHouseAnalytics(req);
    setChTesting(false);
    setChPassword('');
    if (res.success) {
      setNotification({ kind: 'success', message: 'ClickHouse analytics storage connection test succeeded!' });
    } else {
      setNotification({ kind: 'error', message: res.error || 'ClickHouse connection test failed.' });
    }
  };

  const handleSaveClickHousePending = async () => {
    const retention = Math.min(30, Math.max(1, Number(analyticsRetentionDays) || 30));
    if (analyticsDriver === 'clickhouse') {
      if (!chHost.trim() || !chDatabase.trim() || !chUsername.trim() || !chSecretRef.trim()) {
        setNotification({ kind: 'error', message: 'Please provide all required ClickHouse connection parameters.' });
        return;
      }
      if (!/^env:[A-Z_][A-Z0-9_]*$/.test(chSecretRef.trim())) {
        setNotification({ kind: 'error', message: 'Secret reference must be in the format env:AEGIS_ANALYTICS_DB_PASSWORD' });
        return;
      }
    }
    setChSaving(true);
    const req: ClickHouseAnalyticsPendingRequest =
      analyticsDriver === 'postgresql'
        ? {
            mode: chMode || 'optional',
            driver: 'postgresql',
            host: '',
            port: 0,
            database: '',
            username: '',
            password_secret_ref: '',
            secure: false,
            retention_days: retention,
          }
        : {
            mode: chMode || 'optional',
            driver: 'clickhouse',
            host: chHost.trim(),
            port: Number(chPort) || 9000,
            database: chDatabase.trim(),
            username: chUsername.trim(),
            password_secret_ref: chSecretRef.trim(),
            secure: chSecure,
            retention_days: retention,
          };
    const res = await apiService.saveClickHouseAnalyticsPending(req);
    setChSaving(false);
    if (res.success) {
      setAnalyticsRetentionDays(retention);
      try {
        const refreshedStorage = await apiService.getStorageStatus();
        if (refreshedStorage) {
          setStorageStatus(refreshedStorage);
        }
      } catch {
      }
      setNotification({
        kind: 'success',
        message: res.restart_required
          ? `${analyticsDriver === 'postgresql' ? 'PostgreSQL' : 'ClickHouse'} analytics storage configuration (${retention}-day retention) staged. Restart Aegis to activate.`
          : `${analyticsDriver === 'postgresql' ? 'PostgreSQL' : 'ClickHouse'} analytics storage configuration (${retention}-day retention) saved and activated.`,
      });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to stage analytics storage configuration.' });
    }
  };

  const handleSaveUpstream = async () => {
    setUpstreamSaving(true);
    const settings: UpstreamSettings = {
      target: upstreamTarget.trim(),
      max_idle_conns: Number(maxIdleConns) || 1000,
      max_idle_conns_per_host: Number(maxIdleConnsPerHost) || 20,
      max_conns_per_host: Number(maxConnsPerHost) || 100,
      idle_timeout: idleTimeout.trim() || '90s',
      tls_timeout: tlsTimeout.trim() || '10s',
      health_check_concurrency: Number(healthConcurrency) || 32,
      insecure_skip_verify: insecureSkipVerify,
    };
    const res = await apiService.saveUpstreamSettings(settings);
    setUpstreamSaving(false);
    if (res.success && res.data) {
      setInitialUpstream(res.data);
      setNotification({ kind: 'success', message: 'Origin settings applied and active for new requests.' });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to save Origin settings.' });
    }
  };

  const handleDownloadBackup = async () => {
    setDownloadingBackup(true);
    try {
      const res = await apiService.downloadConfigBackup();
      if (!res.ok) {
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to download backup archive.',
        });
        return;
      }
      if (res.blob && res.filename) {
        const url = window.URL.createObjectURL(res.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        setNotification({
          kind: 'success',
          message: `Backup archive ${res.filename} downloaded successfully.`,
        });
      }
    } catch (err: any) {
      setNotification({
        kind: 'error',
        message: err?.message || 'Error downloading backup archive.',
      });
    } finally {
      setDownloadingBackup(false);
    }
  };

  const handleExportConfig = async () => {
    setExportingConfig(true);
    try {
      const res = await apiService.downloadConfigExport();
      if (!res.ok) {
        setNotification({
          kind: 'error',
          message: res.error || 'Failed to export configuration.',
        });
        return;
      }
      if (res.blob && res.filename) {
        const url = window.URL.createObjectURL(res.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = res.filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        setNotification({
          kind: 'success',
          message: `Configuration exported successfully as ${res.filename}.`,
        });
      }
    } catch (err: any) {
      setNotification({
        kind: 'error',
        message: err?.message || 'Error exporting configuration.',
      });
    } finally {
      setExportingConfig(false);
    }
  };

  const handleImportFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportingFile(true);
    const res = await apiService.importConfigFile(file);
    setImportingFile(false);
    if (e.target) e.target.value = '';
    if (res.success) {
      setNotification({
        kind: 'success',
        message: 'Configuration import is staged. Restart Aegis to apply the restored configuration.',
      });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to import configuration file.' });
    }
  };

  const handleFactoryResetConfirm = async () => {
    setResetting(true);
    const res = await apiService.factoryReset();
    setResetting(false);
    setIsResetModalOpen(false);
    if (res.success) {
      setNotification({
        kind: 'success',
        message: 'Factory reset staged. Restart Aegis to revert config.yaml to pristine defaults.',
      });
    } else {
      setNotification({ kind: 'error', message: res.error || 'Factory reset failed.' });
    }
  };

  const handleActivateLicense = async () => {
    const key = licenseKeyInput.trim();
    if (!key) {
      setNotification({ kind: 'error', message: 'Please enter a valid license key.' });
      return;
    }
    setActivatingLicense(true);
    const result = await apiService.activateLicense(key);
    setActivatingLicense(false);
    if (result.success) {
      setLicenseKeyInput('');
      setNotification({ kind: 'success', message: 'Commercial license activated successfully!' });
      const updated = await apiService.getLicense();
      if (updated) {
        setLicense(updated);
        window.dispatchEvent(new CustomEvent('aegis:license-changed'));
      }
    } else {
      setNotification({ kind: 'error', message: result.error || 'License activation failed.' });
    }
  };

  const handleRefreshLicense = async () => {
    setRefreshingLicense(true);
    const updated = await apiService.refreshLicense();
    setRefreshingLicense(false);
    if (updated) {
      setLicense(updated);
      window.dispatchEvent(new CustomEvent('aegis:license-changed'));
      setNotification({ kind: 'success', message: 'License status refreshed successfully.' });
    } else {
      setNotification({ kind: 'error', message: 'Failed to refresh license lease.' });
    }
  };

  const handleDeactivateConfirm = async () => {
    setDeactivatingLicense(true);
    const updated = await apiService.deactivateLicense();
    setDeactivatingLicense(false);
    setIsDeactivateModalOpen(false);
    if (updated) {
      setLicense(updated);
      window.dispatchEvent(new CustomEvent('aegis:license-changed'));
      setNotification({ kind: 'info', message: 'License deactivated and activation slot released.' });
    } else {
      setNotification({ kind: 'error', message: 'License deactivation request failed.' });
    }
  };

  const handleCheckUpdates = async () => {
    setCheckingUpdates(true);
    const status = await apiService.checkSystemUpdates(true);
    setCheckingUpdates(false);
    if (status) {
      setUpdateStatus(status);
      setIsUpdateModalOpen(true);
    } else {
      setNotification({ kind: 'warning', message: 'Could not reach update server. Check edge connectivity.' });
    }
  };

  const handleApplyUpdate = async () => {
    if (!updateStatus) return;
    setApplyingUpdate(true);
    const res = await apiService.applySystemUpdate(updateStatus.latest_version);
    setApplyingUpdate(false);
    if (res.ok) {
      setNotification({
        kind: 'success',
        message: 'System upgrade initiated. Aegis updater is applying changes and restarting.',
      });
      setIsUpdateModalOpen(false);
    } else {
      setNotification({
        kind: 'error',
        message: res.error || 'Failed to apply system update.',
      });
    }
  };

  const handleApplyLicenseUpgrade = async () => {
    setUpgradingLicense(true);
    const res = await apiService.applyLicenseUpgrade();
    setUpgradingLicense(false);
    if (res.ok) {
      setNotification({
        kind: 'success',
        message: res.message || 'Commercial license upgrade initiated. Aegis is restarting...',
      });
    } else {
      setNotification({
        kind: 'error',
        message: res.error || 'Failed to apply commercial upgrade.',
      });
    }
  };

  const formatLicenseDate = (val?: string) => {
    if (!val || val.startsWith('0001-')) return '—';
    const d = new Date(val);
    return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
  };

  const formatLicenseLabel = (value?: string) => {
    if (!value) return 'Community';
    return value.replace(/[_-]+/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        padding: '32px 32px 80px',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      <PageHeader
        title="Settings"
        icon={Settings}
        action={
          <Button
            kind="ghost"
            size="md"
            renderIcon={Activity}
            onClick={() => {
              window.location.hash = '#dashboard';
            }}
          >
            System health
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

      <Tabs selectedIndex={selectedTab} onChange={({ selectedIndex }) => setSelectedTab(selectedIndex)}>
        <TabList aria-label="System Administration Tabs">
          <Tab renderIcon={Settings}>General</Tab>
          <Tab renderIcon={Datastore}>Storage</Tab>
          <Tab renderIcon={Activity}>Telemetry</Tab>
          <Tab renderIcon={Network_3}>Origin settings</Tab>
          <Tab renderIcon={Download}>Backups</Tab>
          <Tab renderIcon={Enterprise}>License</Tab>
        </TabList>

        <TabPanels>
          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Listener configuration">
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '20px',
                    }}
                  >
                    <NumberInput
                      id="set-server-port"
                      label="Public proxy port"
                      min={1}
                      max={65535}
                      value={publicProxyPort}
                      onChange={(_, { value }) => setPublicProxyPort(Number(value) || 8080)}
                    />

                    <TextInput
                      id="set-admin-host"
                      labelText="Admin listener host"
                      value={adminHost}
                      onChange={(e) => setAdminHost(e.target.value)}
                      placeholder="127.0.0.1"
                      helperText={isLoopbackHost(adminHost) ? undefined : 'External access requires HTTPS.'}
                    />

                    <NumberInput
                      id="set-admin-port"
                      label="Admin management port"
                      min={1}
                      max={65535}
                      value={adminPort}
                      onChange={(_, { value }) => setAdminPort(Number(value) || 8081)}
                    />
                  </div>

                  <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                    <Button
                      kind="primary"
                      size="md"
                      disabled={savingGeneral || !isGeneralDirty}
                      onClick={handleSaveGeneral}
                    >
                      {savingGeneral ? 'Saving...' : 'Save for next restart'}
                    </Button>
                    {isGeneralDirty && (
                      <Button
                        kind="ghost"
                        size="md"
                        onClick={handleResetGeneral}
                      >
                        Reset
                      </Button>
                    )}
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16}>
                <Tile style={{ padding: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--cds-layer-01)', border: '1px solid var(--cds-border-subtle)', borderRadius: 0 }}>
                  <div>
                    <h4 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 4px' }}>Administrator accounts</h4>
                    <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                      Manage users, roles, and permissions.
                    </p>
                  </div>
                  <Button
                    kind="tertiary"
                    renderIcon={Launch}
                    onClick={() => {
                      window.location.hash = '#access-roles';
                    }}
                  >
                    Open roles &amp; permissions
                  </Button>
                </Tile>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="PostgreSQL">
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '20px',
                    }}
                  >
                    <TextInput
                      id="set-pg-host"
                      labelText="Host"
                      value={pgHost}
                      onChange={(e) => setPgHost(e.target.value)}
                      placeholder="localhost"
                    />

                    <NumberInput
                      id="set-pg-port"
                      label="Port"
                      min={1}
                      max={65535}
                      value={pgPort}
                      onChange={(_, { value }) => setPgPort(Number(value) || 5432)}
                    />

                    <TextInput
                      id="set-pg-database"
                      labelText="Database name"
                      value={pgDatabase}
                      onChange={(e) => setPgDatabase(e.target.value)}
                      placeholder="aegis"
                    />

                    <TextInput
                      id="set-pg-username"
                      labelText="Username"
                      value={pgUsername}
                      onChange={(e) => setPgUsername(e.target.value)}
                      placeholder="aegis"
                    />

                    <PasswordInput
                      id="set-pg-password"
                      labelText="Temporary test password"
                      value={pgPassword}
                      onChange={(e) => setPgPassword(e.target.value)}
                      placeholder="Enter password for preflight"
                    />

                    <TextInput
                      id="set-pg-secret-ref"
                      labelText="Password secret reference"
                      value={pgSecretRef}
                      onChange={(e) => setPgSecretRef(e.target.value)}
                      placeholder="env:AEGIS_CONTROL_DB_PASSWORD"
                    />

                    <Select
                      id="set-pg-ssl-mode"
                      labelText="TLS mode"
                      value={pgSslMode}
                      onChange={(e) => setPgSslMode(e.target.value)}
                    >
                      <SelectItem value="disable" text="Disable" />
                      <SelectItem value="allow" text="Allow" />
                      <SelectItem value="prefer" text="Prefer" />
                      <SelectItem value="require" text="Require" />
                      <SelectItem value="verify-ca" text="Verify-CA" />
                      <SelectItem value="verify-full" text="Verify-Full" />
                    </Select>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                    <Button
                      kind="secondary"
                      size="md"
                      disabled={pgTesting}
                      onClick={handleTestPostgres}
                    >
                      {pgTesting ? 'Testing connection...' : 'Test connection'}
                    </Button>
                    <Button
                      kind="primary"
                      size="md"
                      disabled={pgSaving}
                      onClick={handleSavePostgresPending}
                    >
                      {pgSaving ? 'Saving...' : 'Save for next restart'}
                    </Button>
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16}>
                <SectionCard title="Event & analytics storage">
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '20px',
                    }}
                  >
                    <Select
                      id="set-analytics-driver"
                      labelText="Analytics storage engine"
                      value={analyticsDriver}
                      onChange={(e) => setAnalyticsDriver(e.target.value as 'postgresql' | 'clickhouse')}
                    >
                      <SelectItem value="postgresql" text="PostgreSQL (default)" />
                      <SelectItem value="clickhouse" text="ClickHouse (external)" />
                    </Select>

                    <Select
                      id="set-ch-mode"
                      labelText="Analytics mode"
                      value={chMode}
                      onChange={(e) => setChMode(e.target.value as any)}
                    >
                      <SelectItem value="optional" text="Optional" />
                      <SelectItem value="required" text="Required" />
                      <SelectItem value="disabled" text="Disabled" />
                    </Select>

                    <NumberInput
                      id="set-analytics-retention-days"
                      label="Event retention duration (days)"
                      min={1}
                      max={30}
                      value={analyticsRetentionDays}
                      onChange={(_, { value }) => setAnalyticsRetentionDays(Math.min(30, Math.max(1, Number(value) || 30)))}
                    />

                    {analyticsDriver === 'clickhouse' && (
                      <>
                        <TextInput
                          id="set-ch-host"
                          labelText="ClickHouse host"
                          value={chHost}
                          onChange={(e) => setChHost(e.target.value)}
                          placeholder="localhost"
                        />

                        <NumberInput
                          id="set-ch-port"
                          label="ClickHouse port"
                          min={1}
                          max={65535}
                          value={chPort}
                          onChange={(_, { value }) => setChPort(Number(value) || 9000)}
                        />

                        <TextInput
                          id="set-ch-database"
                          labelText="Database name"
                          value={chDatabase}
                          onChange={(e) => setChDatabase(e.target.value)}
                          placeholder="aegis"
                        />

                        <TextInput
                          id="set-ch-username"
                          labelText="Username"
                          value={chUsername}
                          onChange={(e) => setChUsername(e.target.value)}
                          placeholder="default"
                        />

                        <PasswordInput
                          id="set-ch-password"
                          labelText="Temporary test password"
                          value={chPassword}
                          onChange={(e) => setChPassword(e.target.value)}
                          placeholder="Enter password for preflight"
                        />

                        <TextInput
                          id="set-ch-secret-ref"
                          labelText="Password secret reference"
                          value={chSecretRef}
                          onChange={(e) => setChSecretRef(e.target.value)}
                          placeholder="env:AEGIS_ANALYTICS_DB_PASSWORD"
                        />
                      </>
                    )}
                  </div>

                  {analyticsDriver !== 'postgresql' && (
                    <div style={{ marginTop: '20px' }}>
                      <StatusToggle
                        id="toggle-ch-secure"
                        label="TLS encryption"
                        toggled={chSecure}
                        onToggle={(checked) => setChSecure(checked)}
                      />
                    </div>
                  )}

                  <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                    {analyticsDriver === 'clickhouse' && (
                      <Button
                        kind="secondary"
                        size="md"
                        disabled={chTesting}
                        onClick={handleTestClickHouse}
                      >
                        {chTesting ? 'Testing connection...' : 'Test connection'}
                      </Button>
                    )}
                    <Button
                      kind="primary"
                      size="md"
                      disabled={chSaving}
                      onClick={handleSaveClickHousePending}
                    >
                      {chSaving ? 'Saving...' : 'Save for next restart'}
                    </Button>
                  </div>
                </SectionCard>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Prometheus metrics exporter">
                  <div style={{ marginBottom: '20px' }}>
                    <StatusToggle
                      id="toggle-telemetry-prometheus"
                      label="Prometheus metrics exporter"
                      toggled={prometheusEnabled}
                      onToggle={(checked) => setPrometheusEnabled(checked)}
                    />
                  </div>

                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '20px',
                    }}
                  >
                    <TextInput
                      id="telemetry-scrape-path"
                      labelText="Metrics scrape path"
                      value={prometheusPath}
                      onChange={(e) => setPrometheusPath(e.target.value)}
                      disabled={!prometheusEnabled}
                      placeholder="/metrics"
                    />

                    <PasswordInput
                      id="telemetry-bearer-token"
                      labelText="Scrape bearer token"
                      value={prometheusToken}
                      onChange={(e) => setPrometheusToken(e.target.value)}
                      placeholder="Bearer token"
                      disabled={!prometheusEnabled}
                    />
                  </div>

                  <div style={{ marginTop: '16px' }}>
                    <StatusToggle
                      id="toggle-clear-token"
                      label="Clear bearer token"
                      toggled={clearPrometheusToken}
                      onToggle={(checked) => setClearPrometheusToken(checked)}
                      disabled={!prometheusEnabled}
                    />
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16}>
                <SectionCard title="Detailed request logging">
                  <StatusToggle
                    id="toggle-request-logging"
                    label="Detailed request logging"
                    toggled={requestLogging}
                    onToggle={(checked) => setRequestLogging(checked)}
                  />

                  <div style={{ display: 'flex', gap: '12px', marginTop: '24px' }}>
                    <Button
                      kind="primary"
                      size="md"
                      disabled={savingTelemetry || !isTelemetryDirty}
                      onClick={handleSaveTelemetry}
                    >
                      {savingTelemetry ? 'Saving...' : 'Save changes'}
                    </Button>
                    {isTelemetryDirty && (
                      <Button
                        kind="ghost"
                        size="md"
                        onClick={handleResetTelemetry}
                      >
                        Reset
                      </Button>
                    )}
                  </div>
                </SectionCard>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Fallback delivery">
                  <TextInput
                    id="set-upstream-target"
                    labelText="Fallback backend URL"
                    value={upstreamTarget}
                    onChange={(e) => setUpstreamTarget(e.target.value)}
                    placeholder="http://127.0.0.1:9090"
                  />
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Connection capacity & pool tuning">
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                      gap: '20px',
                      marginBottom: '20px',
                    }}
                  >
                    <NumberInput
                      id="set-max-idle"
                      label="Max idle connections"
                      min={1}
                      max={10000}
                      value={maxIdleConns}
                      onChange={(_, { value }) => setMaxIdleConns(Number(value) || 1000)}
                    />

                    <NumberInput
                      id="set-max-idle-per-host"
                      label="Max idle per origin"
                      min={1}
                      max={2000}
                      value={maxIdleConnsPerHost}
                      onChange={(_, { value }) => setMaxIdleConnsPerHost(Number(value) || 20)}
                    />

                    <NumberInput
                      id="set-max-conns-per-host"
                      label="Max connections per origin"
                      min={1}
                      max={10000}
                      value={maxConnsPerHost}
                      onChange={(_, { value }) => setMaxConnsPerHost(Number(value) || 100)}
                    />

                    <TextInput
                      id="set-idle-timeout"
                      labelText="Idle timeout"
                      value={idleTimeout}
                      onChange={(e) => setIdleTimeout(e.target.value)}
                      placeholder="90s"
                    />

                    <TextInput
                      id="set-tls-timeout"
                      labelText="TLS timeout"
                      value={tlsTimeout}
                      onChange={(e) => setTlsTimeout(e.target.value)}
                      placeholder="10s"
                    />

                    <NumberInput
                      id="set-health-concurrency"
                      label="Health check concurrency"
                      min={1}
                      max={256}
                      value={healthConcurrency}
                      onChange={(_, { value }) => setHealthConcurrency(Number(value) || 32)}
                    />
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Transport verification">
                  <StatusToggle
                    id="set-skip-verify"
                    label="Skip TLS certificate verification"
                    toggled={insecureSkipVerify}
                    onToggle={(checked) => setInsecureSkipVerify(checked)}
                  />
                  <p style={{ marginTop: '8px', fontSize: '12px', color: 'var(--cds-support-error, #da1e28)' }}>
                    Only for internal backends with trusted certificates.
                  </p>

                  <div style={{ marginTop: '24px' }}>
                    <Button
                      kind="primary"
                      size="md"
                      disabled={upstreamSaving || !isUpstreamDirty}
                      onClick={handleSaveUpstream}
                    >
                      {upstreamSaving ? 'Saving...' : 'Save changes'}
                    </Button>
                  </div>
                </SectionCard>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Backup & export">
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
                      gap: '16px',
                    }}
                  >
                    <Tile style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', background: 'var(--cds-layer-01)', border: '1px solid var(--cds-border-subtle)', borderRadius: 0 }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                          <Download size={20} />
                          <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>Configuration archive</h4>
                        </div>
                        <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                          Snapshot of configurations, policies, and rules. Secrets excluded.
                        </p>
                      </div>
                      <div style={{ marginTop: '20px' }}>
                        <Button kind="secondary" size="md" disabled={downloadingBackup} renderIcon={Download} onClick={handleDownloadBackup}>
                          {downloadingBackup ? 'Downloading...' : 'Download archive'}
                        </Button>
                      </div>
                    </Tile>

                    <Tile style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', background: 'var(--cds-layer-01)', border: '1px solid var(--cds-border-subtle)', borderRadius: 0 }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                          <Document size={20} />
                          <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600 }}>Sanitized configuration</h4>
                        </div>
                        <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                          Configuration with secrets and credentials removed.
                        </p>
                      </div>
                      <div style={{ marginTop: '20px' }}>
                        <Button kind="secondary" size="md" disabled={exportingConfig} renderIcon={Launch} onClick={handleExportConfig}>
                          {exportingConfig ? 'Exporting...' : 'Export config'}
                        </Button>
                      </div>
                    </Tile>
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Restore backup">
                  <div style={{ maxWidth: '500px' }}>
                    <p style={{ margin: '0 0 16px', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                      Upload a <code>.yaml</code> or <code>.tar.gz</code> archive.
                    </p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".yaml,.yml,.tar.gz,.tgz,application/gzip"
                      style={{ display: 'none' }}
                      onChange={handleImportFile}
                    />
                    <Button
                      kind="tertiary"
                      size="md"
                      renderIcon={Upload}
                      disabled={importingFile}
                      onClick={() => fileInputRef.current?.click()}
                    >
                      {importingFile ? 'Importing file...' : 'Import archive'}
                    </Button>
                  </div>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16}>
                <Tile
                  style={{
                    padding: '24px',
                    background: 'var(--cds-layer-01)',
                    border: '1px solid var(--cds-support-error, #da1e28)',
                    borderRadius: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '16px',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <Reset size={20} style={{ fill: 'var(--cds-support-error, #da1e28)' }} />
                      <h4 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: 'var(--cds-support-error, #da1e28)' }}>
                        Factory reset
                      </h4>
                    </div>
                    <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                      Reset configuration to defaults on restart. Preserves databases, certificates, and accounts.
                    </p>
                  </div>
                  <Button kind="danger" size="md" onClick={() => setIsResetModalOpen(true)}>
                    Factory reset
                  </Button>
                </Tile>
              </Column>
            </Grid>
          </TabPanel>

          <TabPanel style={{ padding: '24px 0' }}>
            <Grid narrow fullWidth style={{ padding: 0 }}>
              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <Tile
                  style={{
                    padding: '24px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '16px',
                    background: 'var(--cds-layer-01)',
                    border: '1px solid var(--cds-border-subtle)',
                    borderRadius: 0,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div
                      style={{
                        width: '48px',
                        height: '48px',
                        borderRadius: '50%',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        background: 'var(--cds-layer-02)',
                        color: 'var(--cds-interactive, #ff832b)',
                      }}
                    >
                      <Enterprise size={28} />
                    </div>
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                        <h3 style={{ fontSize: '18px', fontWeight: 600, margin: 0 }}>
                          License
                        </h3>
                        {!['community', 'unlicensed'].includes((license?.status || '').toLowerCase()) && license?.status && (
                          <span style={{ fontSize: '12px', fontWeight: 600, color: ['active', 'grace'].includes((license.status).toLowerCase()) ? 'var(--cds-support-success, #24a148)' : 'var(--cds-text-secondary)' }}>
                            ● {license.status.toUpperCase()}
                          </span>
                        )}
                      </div>
                      <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
                        {!['community', 'unlicensed'].includes((license?.effective_tier || '').toLowerCase())
                          ? 'Commercial enterprise security engine active.'
                          : 'Activate advanced features with a commercial license key.'}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', gap: '24px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase' }}>
                        Licensed plan
                      </div>
                      <div style={{ fontWeight: 600, fontSize: '14px' }}>
                        {formatLicenseLabel(license?.licensed_tier || 'Community')}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase' }}>
                        Effective plan
                      </div>
                      <div style={{ fontWeight: 600, fontSize: '14px' }}>
                        {formatLicenseLabel(license?.effective_tier || 'Community')}
                      </div>
                    </div>
                    {!['community', 'unlicensed'].includes((license?.effective_tier || '').toLowerCase()) && (
                      <>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase' }}>
                            Lease expires
                          </div>
                          <div style={{ fontWeight: 600, fontSize: '14px' }}>
                            {formatLicenseDate(license?.expires_at)}
                          </div>
                        </div>
                        <div>
                          <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', textTransform: 'uppercase' }}>
                            Last checked
                          </div>
                          <div style={{ fontWeight: 600, fontSize: '14px' }}>
                            {formatLicenseDate(license?.last_refresh)}
                          </div>
                        </div>
                      </>
                    )}
                  </div>
                </Tile>
              </Column>

              {license?.upgrade?.required && (
                <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                  <InlineNotification
                    kind="warning"
                    title={license.upgrade.available ? 'Commercial upgrade ready' : 'Release awaiting'}
                    subtitle={license.upgrade.reason || 'An engine release update is available for this installation.'}
                  />
                  {license.upgrade.available && (
                    <div style={{ marginTop: '12px' }}>
                      <Button
                        kind="primary"
                        size="sm"
                        disabled={upgradingLicense}
                        onClick={handleApplyLicenseUpgrade}
                      >
                        {upgradingLicense ? 'Upgrading...' : 'Apply commercial upgrade'}
                      </Button>
                    </div>
                  )}
                </Column>
              )}

              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="Software updates">
                  <Button
                    kind="tertiary"
                    size="md"
                    renderIcon={Renew}
                    disabled={checkingUpdates}
                    onClick={handleCheckUpdates}
                  >
                    {checkingUpdates ? 'Checking for updates...' : 'Check for updates'}
                  </Button>
                </SectionCard>
              </Column>

              <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
                <SectionCard title="License management">
                  <div style={{ maxWidth: '600px' }}>
                    <TextInput
                      id="commercial-license-key-input"
                      labelText="License key"
                      placeholder="AEGIS-ENT-..."
                      value={licenseKeyInput}
                      onChange={(e) => setLicenseKeyInput(e.target.value)}
                      style={{ fontFamily: 'var(--cds-font-mono, monospace)', marginBottom: '16px' }}
                    />
                    <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                      <Button
                        kind="primary"
                        size="md"
                        disabled={activatingLicense || !licenseKeyInput.trim() || Boolean(license?.activation_id)}
                        onClick={handleActivateLicense}
                      >
                        {activatingLicense ? 'Activating...' : 'Activate license'}
                      </Button>
                      {license?.activation_id && (
                        <>
                          <Button
                            kind="secondary"
                            size="md"
                            renderIcon={Renew}
                            disabled={refreshingLicense}
                            onClick={handleRefreshLicense}
                          >
                            {refreshingLicense ? 'Refreshing...' : 'Refresh lease'}
                          </Button>
                          <Button
                            kind="danger--tertiary"
                            size="md"
                            onClick={() => setIsDeactivateModalOpen(true)}
                          >
                            Deactivate installation
                          </Button>
                        </>
                      )}
                    </div>
                  </div>
                </SectionCard>
              </Column>

            </Grid>
          </TabPanel>
        </TabPanels>
      </Tabs>

      <Modal
        open={isResetModalOpen}
        modalHeading="Factory reset"
        primaryButtonText={resetting ? 'Resetting...' : 'Factory reset'}
        secondaryButtonText="Cancel"
        danger
        onRequestClose={() => setIsResetModalOpen(false)}
        onRequestSubmit={handleFactoryResetConfirm}
      >
        <p style={{ margin: '0 0 12px' }}>
          Replace configuration with Aegis defaults?
        </p>
        <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '13px' }}>
          Database data, certificates, and user accounts are retained. Requires a system restart.
        </p>
      </Modal>

      <Modal
        open={isDeactivateModalOpen}
        modalHeading="Deactivate license"
        primaryButtonText={deactivatingLicense ? 'Deactivating...' : 'Deactivate'}
        secondaryButtonText="Cancel"
        danger
        onRequestClose={() => setIsDeactivateModalOpen(false)}
        onRequestSubmit={handleDeactivateConfirm}
      >
        <p style={{ margin: 0 }}>
          Deactivate this installation? Commercial features will revert to the community tier.
        </p>
      </Modal>

      <Modal
        open={isUpdateModalOpen}
        modalHeading="Software updates"
        passiveModal
        onRequestClose={() => setIsUpdateModalOpen(false)}
      >
        {updateStatus ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
              <span style={{ fontSize: '13px', fontWeight: 600, color: updateStatus.update_available ? 'var(--cds-support-success, #24a148)' : 'var(--cds-interactive, #ff832b)' }}>
                ● {updateStatus.update_available ? 'Update available' : 'Up to date'}
              </span>
              <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                Current version: <strong>{updateStatus.current_version}</strong>
              </span>
            </div>

            {updateStatus.update_available ? (
              <div>
                <h4 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 8px' }}>
                  Aegis {updateStatus.latest_version || updateStatus.target_tier}
                </h4>
                <p style={{ margin: '0 0 16px', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  {updateStatus.title || 'A new official release is ready for installation.'}
                </p>
                <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                  <Button
                    kind="primary"
                    size="md"
                    disabled={applyingUpdate}
                    onClick={handleApplyUpdate}
                  >
                    {applyingUpdate ? 'Installing...' : 'Install & restart'}
                  </Button>
                  {updateStatus.download_url && (
                    <Button
                      kind="tertiary"
                      size="md"
                      renderIcon={Launch}
                      onClick={() => {
                        if (updateStatus.download_url) window.open(updateStatus.download_url, '_blank');
                      }}
                    >
                      View release on GitHub
                    </Button>
                  )}
                </div>
              </div>
            ) : (
              <p style={{ margin: 0, color: 'var(--cds-text-secondary)', fontSize: '14px' }}>
                Running the latest version ({updateStatus.current_version}).
              </p>
            )}
          </div>
        ) : null}
      </Modal>
    </div>
  );
};
