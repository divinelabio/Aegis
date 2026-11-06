import React, { useEffect, useState, useMemo } from 'react';
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
  Modal,
  TextInput,
  TextArea,
  Select,
  SelectItem,
  InlineNotification,
  DataTableSkeleton,
  ContentSwitcher,
  Switch,
} from '@carbon/react';
import { Add, TrashCan, Renew, Certificate } from '@carbon/icons-react';
import type { CertificateRecord, TLSConfigState } from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard, StatusToggle, SaveActionBar } from '../components/common';

export const SslPage: React.FC = () => {
  const [certs, setCerts] = useState<CertificateRecord[]>([]);
  const [tlsConfig, setTlsConfig] = useState<TLSConfigState | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [uploadModalOpen, setUploadModalOpen] = useState<boolean>(false);
  const [uploadMode, setUploadMode] = useState<'files' | 'paste'>('files');
  const [uploadDomain, setUploadDomain] = useState<string>('');
  const [uploadCertPem, setUploadCertPem] = useState<string>('');
  const [uploadKeyPem, setUploadKeyPem] = useState<string>('');
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [certToDelete, setCertToDelete] = useState<CertificateRecord | null>(null);

  const [httpsEnabled, setHttpsEnabled] = useState<boolean>(true);
  const [listenerMode, setListenerMode] = useState<'http' | 'https'>('https');

  const [autoRenew, setAutoRenew] = useState<boolean>(true);
  const [managedDomains, setManagedDomains] = useState<string[]>([]);
  const [newDomainInput, setNewDomainInput] = useState<string>('');
  const [domainInputError, setDomainInputError] = useState<string | null>(null);
  const [acmeEmail, setAcmeEmail] = useState<string>('');
  const [acmeChallenge, setAcmeChallenge] = useState<string>('http-01');
  const [savingTls, setSavingTls] = useState<boolean>(false);

  const loadData = async () => {
    setLoading(true);
    try {
      const [fetchedCerts, fetchedConfig] = await Promise.all([
        apiService.getCertificates(),
        apiService.getTLSConfig(),
      ]);
      setCerts(fetchedCerts);
      setTlsConfig(fetchedConfig);
      setHttpsEnabled(Boolean(fetchedConfig.enabled));
      setAutoRenew(Boolean(fetchedConfig.auto));
      setManagedDomains(fetchedConfig.domains || []);
      setAcmeEmail(fetchedConfig.email || '');
      setAcmeChallenge(fetchedConfig.challenge || 'http-01');
      setListenerMode(fetchedConfig.listener_mode || 'https');
    } catch (err: any) {
      console.error('[SslPage] Failed to load SSL certificates or TLS config:', err);
      setNotification({ kind: 'error', message: err?.message || 'Failed to load SSL certificates or TLS config' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const isDirty = useMemo(() => {
    if (!tlsConfig) return false;
    const origDomains = (tlsConfig.domains || []).slice().sort().join(',');
    const currDomains = managedDomains.slice().sort().join(',');
    return (
      httpsEnabled !== Boolean(tlsConfig.enabled) ||
      autoRenew !== Boolean(tlsConfig.auto) ||
      origDomains !== currDomains ||
      acmeEmail.trim() !== (tlsConfig.email || '').trim() ||
      acmeChallenge !== (tlsConfig.challenge || 'http-01') ||
      listenerMode !== (tlsConfig.listener_mode || 'https')
    );
  }, [tlsConfig, httpsEnabled, autoRenew, managedDomains, acmeEmail, acmeChallenge, listenerMode]);

  const handleResetTls = () => {
    if (!tlsConfig) return;
    setHttpsEnabled(Boolean(tlsConfig.enabled));
    setAutoRenew(Boolean(tlsConfig.auto));
    setManagedDomains(tlsConfig.domains || []);
    setNewDomainInput('');
    setDomainInputError(null);
    setAcmeEmail(tlsConfig.email || '');
    setAcmeChallenge(tlsConfig.challenge || 'http-01');
    setListenerMode(tlsConfig.listener_mode || 'https');
    setNotification(null);
  };

  const normalizeDomain = (value: string): string => {
    const input = value.trim().replace(/\.$/, '');
    if (!input || /[:/\\*@?#]/u.test(input)) return '';
    try {
      const d = new URL(`https://${input}`).hostname.toLowerCase();
      if (d.length > 253 || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d)) {
        return '';
      }
      return d;
    } catch {
      return '';
    }
  };

  const handleAddDomain = () => {
    const norm = normalizeDomain(newDomainInput);
    if (!norm) {
      setDomainInputError('Enter a valid domain name (e.g. example.com)');
      return;
    }
    if (managedDomains.includes(norm)) {
      setDomainInputError('This domain is already managed');
      return;
    }
    setManagedDomains((prev) => [...prev, norm]);
    setNewDomainInput('');
    setDomainInputError(null);
  };

  const handleRemoveDomain = (domainToRemove: string) => {
    setManagedDomains((prev) => prev.filter((d) => d !== domainToRemove));
  };

  const handleUploadCert = async () => {
    if (uploadMode === 'files') {
      if (!certFile || !keyFile) {
        setNotification({ kind: 'error', message: 'Please select both certificate and private key files' });
        return;
      }
      if (certFile.size > 1024 * 1024 || keyFile.size > 1024 * 1024) {
        setNotification({ kind: 'error', message: 'Certificate and key files must each be 1 MiB or smaller' });
        return;
      }
    } else {
      if (!uploadCertPem.trim() || !uploadKeyPem.trim()) {
        setNotification({ kind: 'error', message: 'Certificate PEM and Private Key PEM are required' });
        return;
      }
    }

    const res = await apiService.uploadCertificate({
      domain: uploadDomain.trim() || undefined,
      certFile: uploadMode === 'files' ? (certFile || undefined) : undefined,
      keyFile: uploadMode === 'files' ? (keyFile || undefined) : undefined,
      certPem: uploadMode === 'paste' ? uploadCertPem.trim() : undefined,
      keyPem: uploadMode === 'paste' ? uploadKeyPem.trim() : undefined,
    });

    if (res.success) {
      setUploadModalOpen(false);
      setUploadDomain('');
      setUploadCertPem('');
      setUploadKeyPem('');
      setCertFile(null);
      setKeyFile(null);
      const warningSuffix = res.warnings?.length ? ` ${res.warnings.join(' ')}` : '';
      setNotification({
        kind: res.restart_required || res.warnings?.length ? 'warning' : 'success',
        message: res.restart_required
          ? `Certificate uploaded. Restart Aegis to activate it.${warningSuffix}`
          : `Certificate ${uploadDomain ? `for "${uploadDomain}" ` : ''}uploaded and validated successfully.${warningSuffix}`,
      });
      await loadData();
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to upload certificate' });
    }
  };

  const handleSaveTlsConfig = async () => {
    if (!tlsConfig) return;

    if (httpsEnabled && autoRenew && managedDomains.length === 0) {
      setNotification({ kind: 'error', message: 'Auto-TLS requires at least one managed domain' });
      return;
    }

    setSavingTls(true);
    const updated: TLSConfigState = {
      ...tlsConfig,
      enabled: httpsEnabled,
      auto: autoRenew,
      domains: managedDomains,
      email: acmeEmail.trim(),
      challenge: acmeChallenge,
      listener_mode: listenerMode,
    };
    const res = await apiService.saveTLSConfig(updated);
    setSavingTls(false);
    if (res.success) {
      setTlsConfig(updated);
      setNotification({
        kind: res.restart_required ? 'warning' : 'success',
        message: res.restart_required
          ? 'Configuration saved. Restart Aegis to apply changes.'
          : 'TLS configuration saved successfully.',
      });
      await loadData();
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to save TLS settings' });
    }
  };

  const confirmDelete = (cert: CertificateRecord) => {
    setCertToDelete(cert);
    setDeleteConfirmOpen(true);
  };

  const handleDelete = async () => {
    if (!certToDelete?.id) return;
    const res = await apiService.deleteCertificate(certToDelete.id);
    if (res.success) {
      setCerts((prev) => prev.filter((c) => c.id !== certToDelete.id));
      setNotification({ kind: 'success', message: `Certificate for "${certToDelete.domain || certToDelete.cn}" removed` });
      await loadData();
    } else {
      setNotification({ kind: 'error', message: res.error || 'Failed to delete certificate' });
    }
    setDeleteConfirmOpen(false);
    setCertToDelete(null);
  };

  const formatCertDate = (value?: string) => {
    if (!value) return null;
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleDateString();
  };

  const headers = [
    { key: 'domain', header: 'Domain Name' },
    { key: 'sans', header: 'SANs' },
    { key: 'issuer', header: 'Issuer' },
    { key: 'status', header: 'Status' },
    { key: 'expires', header: 'Expires' },
    { key: 'managed', header: 'Auto Renew' },
    { key: 'actions', header: 'Actions' },
  ];

  const tableRows = certs.map((c, idx) => ({
    id: c.id || c.domain || `cert-${idx}`,
    domain: c.domain || c.cn || 'Unknown',
    sans: (c.sans || []).join(', ') || '-',
    issuer: c.issuer || (c.managed ? 'Auto-managed' : '—'),
    status: c.status || 'valid',
    expires: c.days_remaining !== undefined ? c.days_remaining : '—',
    managed: Boolean(c.auto_renew ?? c.managed),
    deletable: c.deletable !== false,
  }));

  const certsMap = new Map(certs.map((c, idx) => [c.id || c.domain || `cert-${idx}`, c]));

  const getStatusBadge = (cert: CertificateRecord) => {
    if (cert.status === 'not_yet_valid') {
      return <Tag type="purple" size="sm">Not Yet Valid</Tag>;
    }
    if (cert.status === 'expired' || cert.valid === false) {
      return <Tag type="red" size="sm">Expired</Tag>;
    }
    if (cert.status === 'expiring' || (cert.days_remaining !== undefined && cert.days_remaining < 15)) {
      return <Tag type="magenta" size="sm">Urgent</Tag>;
    }
    if (cert.days_remaining !== undefined && cert.days_remaining < 30) {
      return <Tag type="warm-gray" size="sm">Expiring Soon</Tag>;
    }
    if (cert.auto_renew) {
      return <Tag type="green" size="sm">Auto-renewed</Tag>;
    }
    return <Tag type="green" size="sm">Valid</Tag>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="Network"
        title="SSL certificates"
        icon={Certificate}
        action={
          <Button kind="primary" renderIcon={Add} size="md" onClick={() => setUploadModalOpen(true)}>
            Upload Certificate
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

      <SectionCard
        title="HTTPS"
        action={
          <StatusToggle
            id="toggle-enable-https"
            hideLabel
            ariaLabel="Enable HTTPS"
            toggled={httpsEnabled}
            onToggle={(checked) => setHttpsEnabled(checked)}
          />
        }
      >
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', alignItems: 'flex-start' }}>
          <Select
            id="listener-mode"
            labelText="HTTPS Enforcement"
            value={listenerMode}
            onChange={(e) => setListenerMode(e.target.value as 'http' | 'https')}
            disabled={!httpsEnabled}
          >
            <SelectItem value="https" text="Force HTTPS (Redirect HTTP to HTTPS)" />
            <SelectItem value="http" text="Dual Port (Allow HTTP & HTTPS)" />
          </Select>
        </div>
      </SectionCard>

      <SectionCard
        title="Automated ACME TLS (Let's Encrypt)"
        action={
          <StatusToggle
            id="toggle-auto-tls"
            hideLabel
            ariaLabel="Automated ACME TLS"
            toggled={autoRenew}
            onToggle={(checked) => setAutoRenew(checked)}
            disabled={!httpsEnabled}
          />
        }
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', alignItems: 'flex-start', opacity: autoRenew && httpsEnabled ? 1 : 0.6 }}>
            <TextInput
              id="acme-email"
              labelText="Contact Email"
              placeholder="admin@example.com"
              value={acmeEmail}
              onChange={(e) => setAcmeEmail(e.target.value)}
              disabled={!autoRenew || !httpsEnabled}
              helperText="Certificate expiration and security notices"
            />
            <Select
              id="acme-challenge"
              labelText="Verification Challenge"
              value={acmeChallenge}
              onChange={(e) => setAcmeChallenge(e.target.value)}
              disabled={!autoRenew || !httpsEnabled}
              helperText="Challenge method for automated domain validation"
            >
              <SelectItem value="http-01" text="HTTP-01 Challenge (Port 80)" />
              <SelectItem value="tls-alpn-01" text="TLS-ALPN-01 (Port 443)" />
              <SelectItem value="dns-01" text="DNS-01 Challenge" />
            </Select>
          </div>

          <div style={{ borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px', opacity: autoRenew && httpsEnabled ? 1 : 0.6 }}>
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '2px' }}>Managed Domains</div>
            </div>

            <div style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', maxWidth: '520px', marginBottom: '16px' }}>
              <TextInput
                id="domain-input"
                labelText="New certificate domain name"
                hideLabel
                placeholder="example.com or api.example.com"
                value={newDomainInput}
                onChange={(e) => {
                  setNewDomainInput(e.target.value);
                  if (domainInputError) setDomainInputError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault();
                    handleAddDomain();
                  }
                }}
                disabled={!autoRenew || !httpsEnabled}
                invalid={Boolean(domainInputError)}
                invalidText={domainInputError || ''}
                style={{ flex: 1 }}
              />
              <Button
                kind="tertiary"
                size="md"
                renderIcon={Add}
                onClick={handleAddDomain}
                disabled={!autoRenew || !httpsEnabled || !newDomainInput.trim()}
              >
                Add Domain
              </Button>
            </div>

            {managedDomains.length === 0 ? (
              <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', padding: '16px', background: 'var(--cds-layer-01)', borderRadius: '4px', textAlign: 'center' }}>
                No domains configured. Add a hostname above for automatic certificate issuance.
              </div>
            ) : (
              <div style={{ marginTop: '8px', overflowX: 'auto' }}>
                <Table size="sm" aria-label="Managed Domains Table">
                  <TableHead>
                    <TableRow>
                      <TableHeader>Domain</TableHeader>
                      <TableHeader>Coverage</TableHeader>
                      <TableHeader style={{ width: '80px', textAlign: 'right' }}>Actions</TableHeader>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                  {managedDomains.map((domain) => (
                    <TableRow key={domain}>
                      <TableCell style={{ fontWeight: 600 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <Certificate size={16} />
                          <code style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '13px' }}>{domain}</code>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Tag type="blue" size="sm">Auto-TLS</Tag>
                      </TableCell>
                      <TableCell style={{ textAlign: 'right' }}>
                        <Button
                          kind="danger--ghost"
                          size="sm"
                          hasIconOnly
                          renderIcon={TrashCan}
                          iconDescription="Remove domain"
                          onClick={() => handleRemoveDomain(domain)}
                          disabled={!autoRenew || !httpsEnabled}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title="Managed Certificates"
      >
        {loading ? (
          <DataTableSkeleton headers={headers} rowCount={5} columnCount={headers.length} />
        ) : (
          <DataTable rows={tableRows} headers={headers}>
            {({ rows, headers, getHeaderProps, getRowProps, getTableProps, onInputChange }) => (
              <TableContainer>
                <TableToolbar>
                  <TableToolbarContent>
                    <TableToolbarSearch
                      persistent
                      placeholder="Search certificates by domain..."
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

                <Table {...getTableProps()} size="md" aria-label="Certificates Table">
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
                          <Certificate size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                          <div style={{ fontWeight: 600, marginBottom: '4px' }}>No certificates installed</div>
                          <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                            Upload a custom certificate or configure automated ACME domains above.
                          </div>
                          <Button kind="tertiary" size="sm" renderIcon={Add} onClick={() => setUploadModalOpen(true)}>
                            Upload Certificate
                          </Button>
                        </TableCell>
                      </TableRow>
                    ) : (
                      rows.map((row) => {
                        const raw = certsMap.get(row.id);
                        if (!raw) return null;
                        const { key, ...rowProps } = getRowProps({ row });
                        const formattedExpiry = formatCertDate(raw.not_after);
                        return (
                          <TableRow key={key} {...rowProps}>
                            <TableCell style={{ fontWeight: 600 }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <Certificate size={16} />
                                <span>{raw.domain || raw.cn}</span>
                                {raw.active && <Tag type="cyan" size="sm">Active</Tag>}
                              </div>
                            </TableCell>
                            <TableCell>
                              <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                                {(raw.sans || []).slice(0, 3).join(', ')}
                                {(raw.sans || []).length > 3 ? ` +${raw.sans!.length - 3} more` : ''}
                              </span>
                            </TableCell>
                            <TableCell>{raw.issuer || (raw.managed ? 'Auto-managed' : '—')}</TableCell>
                            <TableCell>{getStatusBadge(raw)}</TableCell>
                            <TableCell>
                              <div style={{ display: 'flex', flexDirection: 'column' }}>
                                <span style={{ fontSize: '13px' }}>
                                  {formattedExpiry || (raw.days_remaining !== undefined ? `${raw.days_remaining} days` : '—')}
                                </span>
                                {formattedExpiry && raw.days_remaining !== undefined && (
                                  <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                                    {raw.days_remaining}d remaining
                                  </span>
                                )}
                              </div>
                            </TableCell>
                            <TableCell>
                              {raw.auto_renew ? (
                                <Tag type="green" size="sm">Auto</Tag>
                              ) : (
                                <Tag type="gray" size="sm">Manual</Tag>
                              )}
                            </TableCell>
                            <TableCell>
                              {raw.deletable === false ? (
                                <span style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', paddingLeft: '8px' }}>—</span>
                              ) : (
                                <Button
                                  kind="danger--ghost"
                                  size="sm"
                                  hasIconOnly
                                  renderIcon={TrashCan}
                                  iconDescription="Delete Certificate"
                                  onClick={() => confirmDelete(raw)}
                                />
                              )}
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
      </SectionCard>

      <Modal
        open={uploadModalOpen}
        modalHeading="Upload SSL/TLS Certificate"
        primaryButtonText="Install Certificate"
        secondaryButtonText="Cancel"
        onRequestClose={() => setUploadModalOpen(false)}
        onRequestSubmit={handleUploadCert}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          <TextInput
            id="cert-domain"
            labelText="Domain (Optional)"
            placeholder="e.g. example.com"
            value={uploadDomain}
            onChange={(e) => setUploadDomain(e.target.value)}
            helperText="Optional hostname verification. Leave empty to detect from certificate."
          />

          <div style={{ marginBottom: '8px' }}>
            <ContentSwitcher
              size="sm"
              selectedIndex={uploadMode === 'files' ? 0 : 1}
              onChange={(e: any) => setUploadMode(e.name as 'files' | 'paste')}
            >
              <Switch name="files" text="Upload Files (.crt, .key)" />
              <Switch name="paste" text="Paste PEM Text" />
            </ContentSwitcher>
          </div>

          {uploadMode === 'files' ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label className="cds--label" style={{ display: 'block', marginBottom: '6px' }}>
                  Certificate File (.crt, .pem, .cer)
                </label>
                <input
                  type="file"
                  id="cert-file"
                  accept=".crt,.pem,.cer"
                  className="cds--text-input"
                  style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
                  onChange={(e) => setCertFile(e.target.files?.[0] || null)}
                />
              </div>
              <div>
                <label className="cds--label" style={{ display: 'block', marginBottom: '6px' }}>
                  Private Key File (.key, .pem)
                </label>
                <input
                  type="file"
                  id="key-file"
                  accept=".key,.pem"
                  className="cds--text-input"
                  style={{ width: '100%', padding: '8px', boxSizing: 'border-box' }}
                  onChange={(e) => setKeyFile(e.target.files?.[0] || null)}
                />
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <TextArea
                id="cert-pem"
                labelText="Certificate PEM (including intermediate chain)"
                rows={4}
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                value={uploadCertPem}
                onChange={(e) => setUploadCertPem(e.target.value)}
                helperText="PEM certificate with optional intermediate chain"
              />
              <TextArea
                id="key-pem"
                labelText="Private Key PEM"
                rows={4}
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                value={uploadKeyPem}
                onChange={(e) => setUploadKeyPem(e.target.value)}
                helperText="PEM private key (RSA or ECDSA, unencrypted)"
              />
            </div>
          )}
        </div>
      </Modal>

      <Modal
        danger
        open={deleteConfirmOpen}
        modalHeading="Delete Certificate"
        primaryButtonText="Delete"
        secondaryButtonText="Cancel"
        onRequestClose={() => setDeleteConfirmOpen(false)}
        onRequestSubmit={handleDelete}
      >
        <p style={{ padding: '16px 0' }}>
          Are you sure you want to delete the TLS certificate for <strong>"{certToDelete?.domain || certToDelete?.cn}"</strong>? Ingress listeners will fall back to the default certificate.
        </p>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={savingTls}
        onReset={handleResetTls}
        onSave={handleSaveTlsConfig}
        saveLabel="Save TLS Policy"
      />
    </div>
  );
};
