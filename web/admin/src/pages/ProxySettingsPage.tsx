import React, { useEffect, useState, useMemo, useRef, useCallback } from 'react';
import {
  Select,
  SelectItem,
  TextInput,
  TextArea,
  InlineNotification,
  Button,
  Modal,
  CodeSnippet,
  Accordion,
  AccordionItem,
} from '@carbon/react';
import { Network_3, Information } from '@carbon/icons-react';
import type {
  InfrastructureSettings,
  DeploymentMode,
  ProxyProvider,
  ProxySettingsResponse,
} from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard, StatusToggle, SaveActionBar } from '../components/common';

const deploymentModeLabels: Record<DeploymentMode, string> = {
  standalone: 'Standalone (Direct)',
  behind_proxy: 'Behind Reverse Proxy',
  sidecar: 'Sidecar',
  kubernetes_ingress: 'Kubernetes Ingress',
};

const proxyProviderLabels: Record<ProxyProvider, string> = {
  nginx: 'NGINX',
  traefik: 'Traefik Proxy',
  caddy: 'Caddy Web Server',
  apache: 'Apache HTTP Server',
};

function getGuideFilename(provider: string): string {
  switch (provider) {
    case 'nginx':
      return 'nginx.conf';
    case 'traefik':
      return 'traefik.yaml';
    case 'caddy':
      return 'Caddyfile';
    case 'apache':
      return 'httpd.conf';
    case 'sidecar':
      return 'sidecar.yaml';
    case 'kubernetes_ingress':
      return 'ingress.yaml';
    default:
      return 'config.yaml';
  }
}

function compactGuide(provider: string, fallbackTitle?: string, fallbackSteps?: string[]): { title: string; steps: string[] } {
  const guides: Record<string, { title: string; steps: string[] }> = {
    standalone: {
      title: 'Standalone',
      steps: [
        'Configure TLS in SSL Certificates.',
        'Define route rules in Routing.',
        'Configure upstream backends in Origins.',
      ],
    },
    nginx: {
      title: 'Nginx in front of Aegis',
      steps: [
        'Configure your Nginx server block with the snippet below.',
        'Forward incoming traffic to your Aegis address.',
        'Add the Nginx server IP or subnet to Trusted proxy CIDRs.',
      ],
    },
    traefik: {
      title: 'Traefik in front of Aegis',
      steps: [
        'Create a router and service pointing to Aegis.',
        'Forward client headers to Aegis.',
        'Add the Traefik IP or subnet to Trusted proxy CIDRs.',
      ],
    },
    caddy: {
      title: 'Caddy in front of Aegis',
      steps: [
        'Add reverse_proxy directive pointing to your Aegis address.',
        'Add the Caddy server IP or subnet to Trusted proxy CIDRs.',
      ],
    },
    apache: {
      title: 'Apache in front of Aegis',
      steps: [
        'Enable mod_proxy and mod_proxy_http.',
        'Configure ProxyPass to forward requests to Aegis.',
        'Add the Apache server IP or subnet to Trusted proxy CIDRs.',
      ],
    },
    sidecar: {
      title: 'Sidecar Container',
      steps: [
        'Route incoming container traffic through the Aegis sidecar.',
        'Add the local pod or container network to Trusted proxy CIDRs.',
      ],
    },
    kubernetes_ingress: {
      title: 'Kubernetes Ingress Controller',
      steps: [
        'Create a Kubernetes Service pointing to your Aegis pods.',
        'Configure an Ingress resource directing traffic to the Service.',
        'Add the ingress controller CIDRs to Trusted proxy CIDRs.',
      ],
    },
  };
  return guides[provider] || {
    title: fallbackTitle || provider.charAt(0).toUpperCase() + provider.slice(1),
    steps:
      fallbackSteps && fallbackSteps.length > 0
        ? fallbackSteps.slice(0, 3)
        : ['Configure proxy routing', 'Forward client identity headers', 'Add upstream IP to trusted CIDRs'],
  };
}

function extractHost(urlStr: string): string {
  try {
    const formatted = urlStr.includes('://') ? urlStr : `https://${urlStr}`;
    const parsed = new URL(formatted);
    if (parsed.host) return parsed.host;
  } catch {}
  return urlStr.replace(/^https?:\/\//, '').split('/')[0] || 'example.com';
}

function getFallbackTemplate(provider: string, host: string, aegisAddress: string): string {
  const safeHost = host || 'example.com';
  const safeAegis = aegisAddress || 'http://127.0.0.1:8080';

  switch (provider) {
    case 'nginx':
      return `server {
    listen 80;
    server_name ${safeHost};

    location / {
        proxy_pass ${safeAegis};
        proxy_set_header Forwarded "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}`;
    case 'traefik':
      return `http:
  routers:
    aegis:
      rule: "Host(\`${safeHost}\`)"
      entryPoints: ["web", "websecure"]
      service: aegis
      middlewares: ["aegis-forwarded-safety"]
  middlewares:
    aegis-forwarded-safety:
      headers:
        customRequestHeaders:
          Forwarded: ""
  services:
    aegis:
      loadBalancer:
        servers:
          - url: "${safeAegis}"`;
    case 'caddy':
      return `${safeHost} {
    reverse_proxy ${safeAegis} {
        header_up -Forwarded
    }
}`;
    case 'apache':
      return `<VirtualHost *:80>
    ServerName ${safeHost}

    RequestHeader unset Forwarded
    ProxyPreserveHost On
    ProxyPass / ${safeAegis}/
    ProxyPassReverse / ${safeAegis}/
</VirtualHost>`;
    case 'sidecar':
      return `apiVersion: v1
kind: Pod
metadata:
  name: app-with-aegis
spec:
  containers:
    - name: aegis-sidecar
      image: aegis:latest
      ports:
        - containerPort: 8080
    - name: app
      image: myapp:latest`;
    case 'kubernetes_ingress':
      return `apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: aegis-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
    - host: ${safeHost}
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: aegis-service
                port:
                  number: 8080`;
    default:
      return '';
  }
}

export const ProxySettingsPage: React.FC = () => {
  const [_loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'warning' | 'error';
    message: string;
  } | null>(null);

  const [initialData, setInitialData] = useState<ProxySettingsResponse | null>(null);

  const [mode, setMode] = useState<DeploymentMode>('standalone');
  const [provider, setProvider] = useState<ProxyProvider>('nginx');
  const [publicUrl, setPublicUrl] = useState<string>('https://example.com');
  const [aegisAddress, setAegisAddress] = useState<string>('http://127.0.0.1:8080');
  const [trustedEnabled, setTrustedEnabled] = useState<boolean>(false);
  const [cidrsText, setCidrsText] = useState<string>('127.0.0.1/32\n::1/128');
  const [sourcesText, setSourcesText] = useState<string>('');
  const [filesText, setFilesText] = useState<string>('');
  const [sourceRoot, setSourceRoot] = useState<string>('./data/trusted-proxies/sources');
  const [combinedList, setCombinedList] = useState<string>('./data/trusted-proxies/combined.list');
  const [realIpsText, setRealIpsText] = useState<string>('X-Forwarded-For, X-Real-IP');
  const [protoHeader, setProtoHeader] = useState<string>('X-Forwarded-Proto');
  const [hostHeader, setHostHeader] = useState<string>('X-Forwarded-Host');
  const [forwardedHeader, setForwardedHeader] = useState<boolean>(false);
  const [recursive, setRecursive] = useState<boolean>(true);

  const [trustedListError, setTrustedListError] = useState<string>('');
  const [trustedListEntries, setTrustedListEntries] = useState<number>(0);
  const [trustedListPath, setTrustedListPath] = useState<string>('');

  const [guideModalOpen, setGuideModalOpen] = useState<boolean>(false);
  const [guideTitle, setGuideTitle] = useState<string>('Standalone');
  const [guideSteps, setGuideSteps] = useState<string[]>([]);
  const [guideTemplate, setGuideTemplate] = useState<string>('');
  const guideAbortRef = useRef<AbortController | null>(null);
  const guideDebounceTimerRef = useRef<number | null>(null);

  const hydrateFromResponse = (response: ProxySettingsResponse) => {
    setInitialData(response);
    const settings = response.settings;
    const trusted = settings.trusted_proxies || ({} as any);

    const resolvedMode = ((settings.mode && String(settings.mode).trim()) as DeploymentMode) || 'standalone';
    const isStandaloneMode = resolvedMode === 'standalone';
    setMode(resolvedMode);
    setProvider(settings.proxy_provider || 'nginx');
    setPublicUrl(settings.public_base_url || 'https://example.com');
    setAegisAddress(settings.aegis_address || 'http://127.0.0.1:8080');
    setTrustedEnabled(isStandaloneMode ? false : (trusted.enabled ?? true));
    setCidrsText((trusted.cidrs || []).join('\n'));
    setSourcesText((trusted.source_urls || []).join('\n'));
    setFilesText((trusted.source_files || []).join('\n'));
    setSourceRoot(trusted.source_root || './data/trusted-proxies/sources');
    setCombinedList(trusted.combined_list || './data/trusted-proxies/combined.list');
    setRealIpsText((trusted.real_ip_headers || []).join(', '));
    setProtoHeader(trusted.proto_header || 'X-Forwarded-Proto');
    setHostHeader(trusted.host_header || 'X-Forwarded-Host');
    setForwardedHeader(trusted.forwarded_header ?? false);
    setRecursive(trusted.recursive ?? true);

    if (response.trusted_list) {
      setTrustedListError(response.trusted_list.error || '');
      setTrustedListEntries(response.trusted_list.entries || 0);
      setTrustedListPath(response.trusted_list.path || '');
    } else {
      setTrustedListError('');
      setTrustedListEntries(0);
      setTrustedListPath('');
    }
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await apiService.getProxySettings();
      hydrateFromResponse(data);
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'Failed to load proxy settings' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const updateGuide = useCallback(
    async (targetMode: DeploymentMode, targetProvider: ProxyProvider, targetUrl: string, targetAegis: string) => {
      if (guideAbortRef.current) {
        guideAbortRef.current.abort();
      }
      const controller = new AbortController();
      guideAbortRef.current = controller;

      const effectiveProvider = targetMode === 'behind_proxy' ? targetProvider : targetMode;
      const host = extractHost(targetUrl);
      const defaultGuide = compactGuide(effectiveProvider);
      const defaultTemplate = getFallbackTemplate(effectiveProvider, host, targetAegis);

      try {
        const guideData = await apiService.getProxyTemplate(
          effectiveProvider,
          targetUrl,
          targetAegis,
          controller.signal
        );

        if (controller.signal.aborted) return;

        const effectiveTitle = guideData.title || defaultGuide.title;
        const effectiveSteps = guideData.steps && guideData.steps.length > 0 ? guideData.steps : defaultGuide.steps;
        const effectiveTemplate = guideData.template !== undefined ? guideData.template : defaultTemplate;

        setGuideTitle(effectiveTitle);
        setGuideSteps(effectiveSteps);
        setGuideTemplate(effectiveTemplate || '');
      } catch (err: any) {
        if (err.name === 'AbortError') return;
        setGuideTitle(defaultGuide.title);
        setGuideSteps(defaultGuide.steps);
        setGuideTemplate(defaultTemplate);
      }
    },
    []
  );

  useEffect(() => {
    if (guideDebounceTimerRef.current) {
      window.clearTimeout(guideDebounceTimerRef.current);
    }
    guideDebounceTimerRef.current = window.setTimeout(() => {
      updateGuide(mode, provider, publicUrl, aegisAddress);
    }, 250);

    return () => {
      if (guideDebounceTimerRef.current) {
        window.clearTimeout(guideDebounceTimerRef.current);
      }
    };
  }, [mode, provider, publicUrl, aegisAddress, updateGuide]);

  const isDirty = useMemo(() => {
    if (!initialData) return false;
    const s = initialData.settings;
    const t = s.trusted_proxies || ({} as any);

    const normList = (txt: string) =>
      txt
        .split(/[,\n]/)
        .map((x) => x.trim())
        .filter(Boolean)
        .join('\n');

    const origCidrs = (t.cidrs || []).join('\n');
    const origSources = (t.source_urls || []).join('\n');
    const origFiles = (t.source_files || []).join('\n');
    const origSourceRoot = t.source_root || './data/trusted-proxies/sources';
    const origRealIp = (t.real_ip_headers || []).join('\n');

    return (
      mode !== (s.mode || 'standalone') ||
      provider !== (s.proxy_provider || 'nginx') ||
      publicUrl.trim() !== (s.public_base_url || 'https://example.com').trim() ||
      aegisAddress.trim() !== (s.aegis_address || 'http://127.0.0.1:8080').trim() ||
      trustedEnabled !== (t.enabled ?? (s.mode !== 'standalone')) ||
      normList(cidrsText) !== origCidrs ||
      normList(sourcesText) !== origSources ||
      normList(filesText) !== origFiles ||
      sourceRoot.trim() !== origSourceRoot.trim() ||
      normList(realIpsText) !== origRealIp ||
      protoHeader.trim() !== (t.proto_header || 'X-Forwarded-Proto').trim() ||
      hostHeader.trim() !== (t.host_header || 'X-Forwarded-Host').trim() ||
      forwardedHeader !== (t.forwarded_header === true) ||
      recursive !== (t.recursive !== false)
    );
  }, [
    initialData,
    mode,
    provider,
    publicUrl,
    aegisAddress,
    trustedEnabled,
    cidrsText,
    sourcesText,
    filesText,
    sourceRoot,
    realIpsText,
    protoHeader,
    hostHeader,
    forwardedHeader,
    recursive,
  ]);

  const handleReset = () => {
    if (!initialData) return;
    hydrateFromResponse(initialData);
    setNotification(null);
  };

  const handleSave = async () => {
    setSaving(true);
    const cidrs = cidrsText
      .split(/[,\n]/)
      .map((c) => c.trim())
      .filter(Boolean);
    const sources = sourcesText
      .split(/[,\n]/)
      .map((s) => s.trim())
      .filter(Boolean);
    const files = filesText
      .split(/[,\n]/)
      .map((f) => f.trim())
      .filter(Boolean);
    const realIpHeaders = realIpsText
      .split(/[,\n]/)
      .map((h) => h.trim())
      .filter(Boolean);

    let formattedPublicUrl = publicUrl.trim();
    if (formattedPublicUrl && !/^https?:\/\//i.test(formattedPublicUrl)) {
      formattedPublicUrl = `https://${formattedPublicUrl}`;
    }
    formattedPublicUrl = formattedPublicUrl.replace(/\/+$/, '');

    let formattedAegis = aegisAddress.trim();
    if (formattedAegis && !/^https?:\/\//i.test(formattedAegis)) {
      formattedAegis = `http://${formattedAegis}`;
    }
    formattedAegis = formattedAegis.replace(/\/+$/, '');

    const isStandaloneMode = mode === 'standalone';

    const payload: InfrastructureSettings = {
      mode,
      proxy_provider: provider,
      public_base_url: formattedPublicUrl || 'https://example.com',
      aegis_address: formattedAegis || 'http://127.0.0.1:8080',
      trusted_proxies: {
        enabled: !isStandaloneMode && trustedEnabled,
        cidrs,
        real_ip_headers: realIpHeaders.length > 0 ? realIpHeaders : ['X-Forwarded-For', 'X-Real-IP'],
        proto_header: protoHeader.trim() || 'X-Forwarded-Proto',
        host_header: hostHeader.trim() || 'X-Forwarded-Host',
        forwarded_header: !isStandaloneMode && forwardedHeader,
        recursive,
        source_urls: sources,
        source_files: files,
        source_root: sourceRoot.trim() || './data/trusted-proxies/sources',
        combined_list: combinedList || './data/trusted-proxies/combined.list',
      },
    };

    const res = await apiService.saveProxySettings(payload);
    setSaving(false);

    if (res.ok) {
      if (res.data) {
        hydrateFromResponse(res.data);
      } else {
        setInitialData({
          settings: payload,
          runtime: {
            applied: !res.restartRequired,
            restart_required: Boolean(res.restartRequired),
            revision: 'saved',
          },
        });
      }

      if (res.restartRequired) {
        setNotification({
          kind: 'warning',
          message: 'Proxy settings saved. Restart Aegis to apply them.',
        });
      } else {
        setNotification({
          kind: 'success',
          message: 'Proxy settings saved and applied live',
        });
      }
    } else {
      setNotification({
        kind: 'error',
        message: res.error || 'Failed to update proxy settings',
      });
    }
  };

  const isStandalone = mode === 'standalone';
  const effectiveProviderKey = mode === 'behind_proxy' ? provider : mode;
  const guideFilename = getGuideFilename(effectiveProviderKey);

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '24px',
        padding: '32px 32px 96px',
        width: '100%',
        boxSizing: 'border-box',
      }}
    >
      <PageHeader
        title="Proxy settings"
        icon={Network_3}
        action={
          <Button
            kind="tertiary"
            size="md"
            renderIcon={Information}
            onClick={() => setGuideModalOpen(true)}
          >
            Deployment guide
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

      <SectionCard title="Deployment topology">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
          <Select
            id="deployment-mode"
            labelText="Mode"
            value={mode}
            onChange={(e) => setMode(e.target.value as DeploymentMode)}
          >
            {Object.entries(deploymentModeLabels).map(([value, label]) => (
              <SelectItem key={value} value={value} text={label} />
            ))}
          </Select>

          {mode === 'behind_proxy' && (
            <Select
              id="proxy-provider"
              labelText="Proxy provider"
              value={provider}
              onChange={(e) => setProvider(e.target.value as ProxyProvider)}
            >
              {Object.entries(proxyProviderLabels).map(([value, label]) => (
                <SelectItem key={value} value={value} text={label} />
              ))}
            </Select>
          )}

          {!isStandalone && (
            <>
              <TextInput
                id="public-base-url"
                labelText="Public URL"
                placeholder="https://example.com"
                value={publicUrl}
                onChange={(e) => setPublicUrl(e.target.value)}
              />

              <TextInput
                id="aegis-address"
                labelText="Listen address"
                placeholder="http://127.0.0.1:8080"
                value={aegisAddress}
                onChange={(e) => setAegisAddress(e.target.value)}
              />
            </>
          )}
        </div>

        {isStandalone && (
          <InlineNotification
            kind="info"
            lowContrast
            title="Standalone mode"
            subtitle="Reverse proxy headers and trusted CIDRs are inactive in standalone mode."
            hideCloseButton
            style={{ marginTop: '16px' }}
          />
        )}
      </SectionCard>

      {!isStandalone && (
        <SectionCard
          title="Trusted proxies & real IP resolution"
          action={
            <StatusToggle
              id="toggle-trusted-proxies"
              hideLabel
              ariaLabel="Trusted proxies status"
              toggled={trustedEnabled}
              onToggle={(checked) => setTrustedEnabled(checked)}
            />
          }
        >
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
              gap: '24px',
              marginTop: '8px',
            }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <TextArea
                id="trusted-cidrs"
                labelText="Trusted proxy CIDRs"
                rows={5}
                value={cidrsText}
                onChange={(e) => setCidrsText(e.target.value)}
                placeholder="10.0.0.0/8&#10;172.16.0.0/12&#10;192.168.0.0/16"
                disabled={!trustedEnabled}
              />

              <TextArea
                id="trusted-sources"
                labelText="Remote proxy lists"
                rows={3}
                value={sourcesText}
                onChange={(e) => setSourcesText(e.target.value)}
                placeholder="https://example.com/ips.txt"
                disabled={!trustedEnabled}
              />

              {trustedListError && (
                <InlineNotification
                  kind="error"
                  lowContrast
                  title="List Sync Error"
                  subtitle={trustedListError}
                  hideCloseButton
                />
              )}

              {trustedListEntries > 0 && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {trustedListEntries} active entries compiled
                  </span>
                  {trustedListPath && (
                    <span
                      style={{
                        fontSize: '12px',
                        color: 'var(--cds-text-secondary)',
                        fontFamily: 'var(--cds-code-01-font-family, monospace)',
                      }}
                    >
                      {trustedListPath}
                    </span>
                  )}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <TextInput
                id="real-ip-headers"
                labelText="Client IP headers"
                value={realIpsText}
                onChange={(e) => setRealIpsText(e.target.value)}
                placeholder="X-Forwarded-For, X-Real-IP, CF-Connecting-IP"
                disabled={!trustedEnabled}
              />

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <TextInput
                  id="proto-header"
                  labelText="Proto Header"
                  value={protoHeader}
                  onChange={(e) => setProtoHeader(e.target.value)}
                  disabled={!trustedEnabled}
                />
                <TextInput
                  id="host-header"
                  labelText="Host Header"
                  value={hostHeader}
                  onChange={(e) => setHostHeader(e.target.value)}
                  disabled={!trustedEnabled}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginTop: '4px' }}>
                <StatusToggle
                  id="toggle-forwarded"
                  label="RFC 7239 Forwarded"
                  description="Parse Forwarded header"
                  toggled={forwardedHeader}
                  onToggle={(c) => setForwardedHeader(c)}
                  disabled={!trustedEnabled}
                />
                <StatusToggle
                  id="toggle-recursive"
                  label="Resolve proxy chains"
                  description="Traverse XFF chain"
                  toggled={recursive}
                  onToggle={(c) => setRecursive(c)}
                  disabled={!trustedEnabled}
                />
              </div>

              <div style={{ marginTop: '4px' }}>
                <Accordion>
                  <AccordionItem title="Local list files and storage">
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '8px' }}>
                      <TextArea
                        id="proxy-trusted-files"
                        labelText="Local list files"
                        placeholder="./data/trusted.list"
                        value={filesText}
                        onChange={(e) => setFilesText(e.target.value)}
                        rows={2}
                        disabled={!trustedEnabled}
                      />
                      <TextInput
                        id="proxy-source-root"
                        labelText="Source root directory"
                        placeholder="./data/trusted-proxies/sources"
                        value={sourceRoot}
                        onChange={(e) => setSourceRoot(e.target.value)}
                        disabled={!trustedEnabled}
                      />
                    </div>
                  </AccordionItem>
                </Accordion>
              </div>
            </div>
          </div>
        </SectionCard>
      )}

      <Modal
        open={guideModalOpen}
        onRequestClose={() => setGuideModalOpen(false)}
        modalHeading={`${guideTitle} guide`}
        primaryButtonText="Close"
        onRequestSubmit={() => setGuideModalOpen(false)}
        passiveModal
        size="lg"
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', padding: '8px 0 16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <span
              style={{
                fontSize: '12px',
                fontWeight: 600,
                color: 'var(--cds-text-secondary)',
                textTransform: 'uppercase',
                letterSpacing: '0.32px',
              }}
            >
              Setup Steps
            </span>
            {guideSteps.map((step, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '12px' }}>
                <span
                  style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    backgroundColor: 'var(--cds-interactive, #ff832b)',
                    color: '#ffffff',
                    fontSize: '12px',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                    marginTop: '1px',
                  }}
                >
                  {idx + 1}
                </span>
                <span
                  style={{
                    fontSize: '14px',
                    lineHeight: '1.45',
                    color: 'var(--cds-text-primary)',
                  }}
                >
                  {step}
                </span>
              </div>
            ))}
          </div>

          {guideTemplate.trim() ? (
            <div style={{ marginTop: '8px' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '8px',
                }}
              >
                <span
                  style={{
                    fontSize: '12px',
                    fontWeight: 600,
                    color: 'var(--cds-text-secondary)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.32px',
                  }}
                >
                  Configuration File
                </span>
                <code
                  style={{
                    fontFamily: 'var(--cds-code-01-font-family, monospace)',
                    fontWeight: 600,
                    fontSize: '12px',
                    backgroundColor: 'var(--cds-layer-02)',
                    padding: '2px 6px',
                    border: '1px solid var(--cds-border-subtle)',
                  }}
                >
                  {guideFilename}
                </code>
              </div>
              <CodeSnippet type="multi" feedback="Copied to clipboard">
                {guideTemplate}
              </CodeSnippet>
            </div>
          ) : null}
        </div>
      </Modal>

      <SaveActionBar
        isDirty={isDirty}
        isSaving={saving}
        onReset={handleReset}
        onSave={handleSave}
      />
    </div>
  );
};
