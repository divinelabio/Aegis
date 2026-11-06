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
  NumberInput,
  Select,
  SelectItem,
  InlineNotification,
  DataTableSkeleton,
  Pagination,
  OverflowMenu,
  OverflowMenuItem,
  Accordion,
  AccordionItem,
} from '@carbon/react';
import {
  Add,
  Renew,
  Network_3,
  ArrowLeft,
  CheckmarkOutline,
  Globe,
} from '@carbon/icons-react';
import type { RouteRecord, OriginPool, NavItemKey, AppV2, RouteBackend } from '../types';
import { apiService } from '../services/api';
import { PageHeader, SectionCard, StatusToggle, PolicyTag } from '../components/common';
import { useAuth } from '../context/AuthContext';
import { FEATURES } from '../utils/features';

interface RoutingPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

type DeliveryMode = 'origin' | 'inline' | 'default';
type PathTransform = 'keep' | 'strip' | 'rewrite';

interface RouteAccessInfo {
  label: 'Public' | 'Protected' | 'Disabled' | 'Misconfigured' | 'Unknown';
  tone: 'magenta' | 'warm-gray' | 'red' | 'gray' | 'cool-gray';
  app: AppV2 | null;
  description: string;
}

export const RoutingPage: React.FC<RoutingPageProps> = ({ onNavigate }) => {
  const { hasFeature, isCommunity, isProfessional } = useAuth();
  const hasAccessControl = !isCommunity && !isProfessional && hasFeature(FEATURES.ACCESS_CONTROL_ALL);

  const [routes, setRoutes] = useState<RouteRecord[]>([]);
  const [origins, setOrigins] = useState<OriginPool[]>([]);
  const [protectedApps, setProtectedApps] = useState<AppV2[]>([]);
  const [protectedAppsAvailable, setProtectedAppsAvailable] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [pageSize, setPageSize] = useState<number>(10);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'warning' | 'info';
    message: string;
  } | null>(null);

  const [isEditing, setIsEditing] = useState<boolean>(false);
  const [editingRoute, setEditingRoute] = useState<RouteRecord | null>(null);
  const [saving, setSaving] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [formName, setFormName] = useState<string>('');
  const [formPriority, setFormPriority] = useState<number>(100);
  const [formEnabled, setFormEnabled] = useState<boolean>(true);
  const [formHosts, setFormHosts] = useState<string>('');
  const [formPaths, setFormPaths] = useState<string>('');
  const [deliveryMode, setDeliveryMode] = useState<DeliveryMode>('origin');
  const [formUpstream, setFormUpstream] = useState<string>('');
  const [formBackends, setFormBackends] = useState<string>('');
  const [formStrategy, setFormStrategy] = useState<string>('round_robin');
  const [pathTransform, setPathTransform] = useState<PathTransform>('keep');
  const [formStripPrefix, setFormStripPrefix] = useState<string>('');
  const [formRewritePath, setFormRewritePath] = useState<string>('');
  const [formTimeout, setFormTimeout] = useState<string>('');
  const [formRetries, setFormRetries] = useState<number>(0);
  const [formPreserveHost, setFormPreserveHost] = useState<boolean>(true);

  const [formMethods, setFormMethods] = useState<string>('');
  const [formSourceCIDRs, setFormSourceCIDRs] = useState<string>('');
  const [formHeadersJSON, setFormHeadersJSON] = useState<string>('');
  const [formQueryJSON, setFormQueryJSON] = useState<string>('');
  const [formFallbackBackends, setFormFallbackBackends] = useState<string>('');
  const [formFallbackStrategy, setFormFallbackStrategy] = useState<string>('round_robin');

  const [formWafCore, setFormWafCore] = useState<boolean>(true);
  const [formTrafficControl, setFormTrafficControl] = useState<boolean>(true);
  const [formHttpSecurity, setFormHttpSecurity] = useState<boolean>(true);
  const [formBotProtection, setFormBotProtection] = useState<boolean>(true);
  const [formApiSecurity, setFormApiSecurity] = useState<boolean>(true);
  const [formAccessControl, setFormAccessControl] = useState<boolean>(false);

  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [routeToDelete, setRouteToDelete] = useState<RouteRecord | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [fetchedRoutes, fetchedOrigins, appsRes] = await Promise.all([
        apiService.getRoutes(),
        apiService.getOrigins(),
        hasAccessControl
          ? apiService.getProtectedApps().catch(() => ({ apps: [], available: false }))
          : Promise.resolve({ apps: [], available: false }),
      ]);

      // Sort routes by numerical priority ascending (lower priority number evaluated first)
      const sortedRoutes = [...fetchedRoutes].sort(
        (a, b) => (a.priority ?? 100) - (b.priority ?? 100)
      );

      setRoutes(sortedRoutes);
      setOrigins(fetchedOrigins);
      setProtectedApps(appsRes.apps || []);
      setProtectedAppsAvailable(appsRes.available);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load routes from backend API.' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [hasAccessControl]);

  const appsByRoute = useMemo(() => {
    const map = new Map<string, AppV2>();
    for (const app of protectedApps) {
      if (app.route_id) {
        map.set(app.route_id, app);
      }
    }
    return map;
  }, [protectedApps]);

  const getRouteAccessInfo = (route: RouteRecord): RouteAccessInfo => {
    const app = (route.id && appsByRoute.get(route.id)) || null;
    const accessFlag = Boolean(route.security?.access_control);

    if (!protectedAppsAvailable) {
      return {
        label: 'Unknown',
        tone: 'cool-gray',
        app: null,
        description: 'Access protection status is temporarily unavailable.',
      };
    }

    if (app) {
      if (app.access_health?.state === 'error' || !app.route) {
        return {
          label: 'Misconfigured',
          tone: 'red',
          app,
          description:
            app.access_health?.reason_codes?.join(', ') ||
            'Protected App references a Route that Routing cannot resolve.',
        };
      }
      if (
        !app.enabled ||
        app.deployment_state !== 'deployed' ||
        route.enabled === false ||
        !accessFlag
      ) {
        return {
          label: 'Disabled',
          tone: 'warm-gray',
          app,
          description: 'Protected App exists, but route or access enforcement is disabled.',
        };
      }
      if (
        accessFlag ||
        ['active', 'deny_only', 'update_available'].includes(app.access_health?.state || '')
      ) {
        return {
          label: 'Protected',
          tone: 'magenta',
          app,
          description: `${app.name} enforces its deployed access policies.`,
        };
      }
      return {
        label: 'Misconfigured',
        tone: 'red',
        app,
        description: 'Protected App exists, but route access enforcement is not enabled.',
      };
    }

    if (accessFlag) {
      return {
        label: 'Misconfigured',
        tone: 'red',
        app: null,
        description: 'Route has access enforcement enabled without a linked Protected App.',
      };
    }

    return {
      label: 'Public',
      tone: 'gray',
      app: null,
      description: 'No Protected App is linked to this route.',
    };
  };

  const openAddEditor = () => {
    setEditingRoute(null);
    setFormError(null);
    setFormName('');
    setFormPriority(100);
    setFormEnabled(true);
    setFormHosts('');
    setFormPaths('');
    setDeliveryMode(origins.length > 0 ? 'origin' : 'inline');
    setFormUpstream(origins[0]?.name || '');
    setFormBackends('');
    setFormStrategy('round_robin');
    setPathTransform('keep');
    setFormStripPrefix('');
    setFormRewritePath('');
    setFormTimeout('');
    setFormRetries(0);
    setFormPreserveHost(true);
    setFormMethods('');
    setFormSourceCIDRs('');
    setFormHeadersJSON('');
    setFormQueryJSON('');
    setFormFallbackBackends('');
    setFormFallbackStrategy('round_robin');
    setFormWafCore(true);
    setFormTrafficControl(true);
    setFormHttpSecurity(true);
    setFormBotProtection(true);
    setFormApiSecurity(true);
    setFormAccessControl(false);
    setIsEditing(true);
  };

  const openEditEditor = (r: RouteRecord) => {
    setEditingRoute(r);
    setFormError(null);
    setFormName(r.name || '');
    setFormPriority(r.priority ?? 100);
    setFormEnabled(r.enabled !== false);
    setFormHosts(r.hosts ? r.hosts.join(', ') : '');
    setFormPaths(r.paths ? r.paths.join(', ') : '');

    const upstream = r.action?.upstream || '';
    const backendsList = r.action?.backends || r.backends || [];
    if (upstream && upstream !== 'default') {
      setDeliveryMode('origin');
      setFormUpstream(upstream);
      setFormFallbackBackends(
        backendsList.map((b) => `${b.url},${b.weight || 1}`).join('\n')
      );
      setFormFallbackStrategy(r.action?.strategy || 'round_robin');
    } else if (backendsList.length > 0) {
      setDeliveryMode('inline');
      setFormBackends(
        backendsList.map((b) => `${b.url},${b.weight || 1}`).join('\n')
      );
      setFormStrategy(r.action?.strategy || r.load_balance || 'round_robin');
    } else {
      setDeliveryMode('default');
    }

    const strip = r.action?.strip_prefix || r.strip_prefix || '';
    const rewrite = r.action?.rewrite_path || '';
    if (rewrite) {
      setPathTransform('rewrite');
      setFormRewritePath(rewrite);
      setFormStripPrefix('');
    } else if (strip) {
      setPathTransform('strip');
      setFormStripPrefix(strip);
      setFormRewritePath('');
    } else {
      setPathTransform('keep');
      setFormStripPrefix('');
      setFormRewritePath('');
    }

    setFormTimeout(r.action?.timeout || '');
    setFormRetries(r.action?.retries ?? 0);
    setFormPreserveHost(r.action?.preserve_host ?? true);

    setFormMethods(r.match?.methods ? r.match.methods.join(', ') : '');
    setFormSourceCIDRs(r.match?.source_cidrs ? r.match.source_cidrs.join(', ') : '');
    setFormHeadersJSON(
      r.match?.headers && Object.keys(r.match.headers).length > 0
        ? JSON.stringify(r.match.headers, null, 2)
        : ''
    );
    setFormQueryJSON(
      r.match?.query && Object.keys(r.match.query).length > 0
        ? JSON.stringify(r.match.query, null, 2)
        : ''
    );

    setFormWafCore(r.security?.waf_core !== false);
    setFormTrafficControl(r.security?.traffic_control !== false);
    setFormHttpSecurity(r.security?.http_security !== false);
    setFormBotProtection(r.security?.bot_protection !== false);
    setFormApiSecurity(r.security?.api_security !== false);
    setFormAccessControl(Boolean(r.security?.access_control));

    setIsEditing(true);
  };

  const parseBackends = (text: string): RouteBackend[] => {
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line, idx) => {
        const comma = line.lastIndexOf(',');
        const url = (comma >= 0 ? line.slice(0, comma) : line).trim();
        const weightText = comma >= 0 ? line.slice(comma + 1).trim() : '1';
        const weight = Number.parseInt(weightText, 10);
        if (!url || !Number.isInteger(weight) || weight < 1 || weight > 1000) {
          throw new Error(
            `Backend line ${idx + 1} must use URL,weight with a weight from 1 to 1000 (e.g. http://10.0.1.10:8080,1).`
          );
        }
        return { url, weight };
      });
  };

  const handleSaveRoute = async () => {
    if (!formName.trim()) {
      setFormError('Route name is required.');
      return;
    }

    const hostsArr = formHosts
      .split(',')
      .map((h) => h.trim())
      .filter(Boolean);
    const pathsArr = formPaths
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    for (const p of pathsArr) {
      if (!p.startsWith('/')) {
        setFormError(`Path pattern "${p}" must start with a forward slash "/" (e.g. /${p.replace(/^\/+/, '')}).`);
        return;
      }
    }

    if (formRetries < 0 || formRetries > 5) {
      setFormError('Retries on 5xx must be between 0 and 5.');
      return;
    }

    if (deliveryMode === 'origin' && !formUpstream) {
      setFormError('Please select a valid Origin pool or choose another delivery target.');
      return;
    }

    let parsedInlineBackends: RouteBackend[] = [];
    if (deliveryMode === 'inline') {
      try {
        parsedInlineBackends = parseBackends(formBackends);
        if (parsedInlineBackends.length === 0) {
          setFormError('Please provide at least one inline backend target URL.');
          return;
        }
      } catch (err: any) {
        setFormError(err.message || 'Invalid backend format. Use URL,weight per line.');
        return;
      }
    }

    let parsedFallbackBackends: RouteBackend[] = [];
    if (deliveryMode === 'origin' && formFallbackBackends.trim()) {
      try {
        parsedFallbackBackends = parseBackends(formFallbackBackends);
      } catch (err: any) {
        setFormError(`Fallback backends: ${err.message}`);
        return;
      }
    }

    let parsedHeaders: Record<string, string[]> = {};
    if (formHeadersJSON.trim()) {
      try {
        const parsed = JSON.parse(formHeadersJSON);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Header matchers must be a JSON map: { "Header-Name": ["value1", "value2"] }');
        }
        for (const [k, v] of Object.entries(parsed)) {
          if (!Array.isArray(v) || !v.every((item) => typeof item === 'string')) {
            throw new Error(`Header "${k}" must have an array of string values.`);
          }
          parsedHeaders[k] = v;
        }
      } catch (err: any) {
        setFormError(err.message || 'Header matchers must be valid JSON.');
        return;
      }
    }

    let parsedQuery: Record<string, string[]> = {};
    if (formQueryJSON.trim()) {
      try {
        const parsed = JSON.parse(formQueryJSON);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('Query matchers must be a JSON map: { "param": ["value1"] }');
        }
        for (const [k, v] of Object.entries(parsed)) {
          if (!Array.isArray(v) || !v.every((item) => typeof item === 'string')) {
            throw new Error(`Query parameter "${k}" must have an array of string values.`);
          }
          parsedQuery[k] = v;
        }
      } catch (err: any) {
        setFormError(err.message || 'Query matchers must be valid JSON.');
        return;
      }
    }

    const methodsArr = formMethods
      .split(',')
      .map((m) => m.trim().toUpperCase())
      .filter(Boolean);
    const cidrsArr = formSourceCIDRs
      .split(',')
      .map((c) => c.trim())
      .filter(Boolean);

    setSaving(true);
    setFormError(null);

    const backendsToSave =
      deliveryMode === 'origin'
        ? parsedFallbackBackends
        : deliveryMode === 'inline'
        ? parsedInlineBackends
        : [];

    const strategyToSave =
      deliveryMode === 'origin'
        ? formFallbackStrategy
        : deliveryMode === 'inline'
        ? formStrategy
        : 'round_robin';

    const routeData: RouteRecord = {
      id: editingRoute?.id || undefined,
      name: formName.trim(),
      priority: Number(formPriority) || 100,
      hosts: hostsArr.length > 0 ? hostsArr : ['*'],
      paths: pathsArr.length > 0 ? pathsArr : ['/*'],
      match: {
        hosts: hostsArr.length > 0 ? hostsArr : ['*'],
        paths: pathsArr.length > 0 ? pathsArr : ['/*'],
        methods: methodsArr,
        source_cidrs: cidrsArr,
        headers: parsedHeaders,
        query: parsedQuery,
      },
      action: {
        upstream: deliveryMode === 'origin' ? formUpstream : '',
        backends: backendsToSave,
        strategy: strategyToSave,
        strip_prefix: pathTransform === 'strip' ? formStripPrefix.trim() : '',
        rewrite_path: pathTransform === 'rewrite' ? formRewritePath.trim() : '',
        preserve_host: formPreserveHost,
        timeout: formTimeout.trim(),
        retries: Number(formRetries) || 0,
      },
      backends: backendsToSave,
      enabled: formEnabled,
      security: {
        waf_core: formWafCore,
        traffic_control: formTrafficControl,
        http_security: formHttpSecurity,
        bot_protection: formBotProtection,
        api_security: formApiSecurity,
        access_control: hasAccessControl ? formAccessControl : false,
      },
    };

    const res = await apiService.saveRoute(routeData);
    setSaving(false);
    if (res.success) {
      setIsEditing(false);
      setNotification({
        kind: 'success',
        message: editingRoute
          ? `Route "${routeData.name}" updated successfully.`
          : `Route "${routeData.name}" created successfully.`,
      });
      await loadData();
    } else {
      setFormError(res.error || 'Failed to save route. Please check server logs.');
    }
  };

  const handleToggleRoute = async (r: RouteRecord, enabled: boolean) => {
    const updated: RouteRecord = { ...r, enabled };
    setRoutes((prev) => prev.map((item) => (item.id === r.id ? updated : item)));
    const res = await apiService.saveRoute(updated);
    if (res.success) {
      setNotification({
        kind: 'success',
        message: `Route "${r.name}" ${enabled ? 'enabled' : 'disabled'}.`,
      });
    } else {
      setNotification({ kind: 'error', message: res.error || `Failed to update status for "${r.name}".` });
      await loadData();
    }
  };

  const confirmDelete = (r: RouteRecord) => {
    setRouteToDelete(r);
    setDeleteConfirmOpen(true);
  };

  const handleDelete = async () => {
    if (!routeToDelete?.id) return;
    const res = await apiService.deleteRoute(routeToDelete.id);
    if (res.success) {
      setRoutes((prev) => prev.filter((item) => item.id !== routeToDelete.id));
      setNotification({ kind: 'success', message: `Route "${routeToDelete.name}" deleted.` });
    } else {
      setNotification({ kind: 'error', message: res.error || `Failed to delete route "${routeToDelete.name}".` });
    }
    setDeleteConfirmOpen(false);
    setRouteToDelete(null);
  };

  const formatStrategy = (strat = 'round_robin') => {
    const map: Record<string, string> = {
      round_robin: 'Round robin',
      weighted_rr: 'Weighted round robin',
      least_conn: 'Least connections',
      ip_hash: 'IP hash',
    };
    return map[strat] || strat.replace(/_/g, ' ');
  };

  const filteredRoutes = useMemo(() => {
    if (!searchQuery.trim()) return routes;
    const q = searchQuery.toLowerCase();
    return routes.filter((r) => {
      const nameMatch = (r.name || '').toLowerCase().includes(q);
      const hostsMatch = (r.hosts || []).some((h) => h.toLowerCase().includes(q));
      const pathsMatch = (r.paths || []).some((p) => p.toLowerCase().includes(q));
      const upstreamMatch = (r.action?.upstream || '').toLowerCase().includes(q);
      const backendsMatch = (r.action?.backends || r.backends || []).some((b) =>
        b.url.toLowerCase().includes(q)
      );
      return nameMatch || hostsMatch || pathsMatch || upstreamMatch || backendsMatch;
    });
  }, [routes, searchQuery]);

  const routesById = useMemo(() => {
    const map = new Map<string, RouteRecord>();
    routes.forEach((r, idx) => {
      map.set(r.id || r.name || `route-${idx}`, r);
    });
    return map;
  }, [routes]);

  const paginatedRoutes = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredRoutes.slice(start, start + pageSize);
  }, [filteredRoutes, currentPage, pageSize]);

  const headers = useMemo(() => {
    const cols = [
      { key: 'route', header: 'Route' },
      { key: 'priority', header: 'Priority' },
      { key: 'paths', header: 'Path patterns' },
      { key: 'destination', header: 'Destination' },
      { key: 'policy', header: 'Origin policy' },
    ];
    if (hasAccessControl) {
      cols.push({ key: 'access', header: 'Access' });
    }
    cols.push({ key: 'status', header: 'Status' });
    cols.push({ key: 'actions', header: 'Actions' });
    return cols;
  }, [hasAccessControl]);

  const tableRows = useMemo(() => {
    return paginatedRoutes.map((r, idx) => {
      const access = getRouteAccessInfo(r);
      const hosts = (r.hosts || ['*']).join(', ');
      const paths = (r.paths || ['/*']).join(' ');
      const destination = r.action?.upstream
        ? `Origin: ${r.action.upstream}`
        : (r.action?.backends || r.backends || []).map((b) => b.url).join(' ') || 'Default proxy';

      let policy = formatStrategy(r.action?.strategy || r.load_balance);
      if (r.action?.upstream && r.action.upstream !== 'default') {
        const pool = origins.find((o) => o.name === r.action!.upstream);
        policy = pool ? formatStrategy(pool.strategy) : 'Origin pool';
      }

      return {
        id: r.id || r.name || `route-${idx}`,
        route: r.name || 'Unnamed route',
        hosts,
        priority: `P${r.priority ?? 100}`,
        paths,
        destination,
        policy,
        access: access.label,
        status: r.enabled !== false ? 'Active' : 'Disabled',
        routeRaw: r,
      };
    });
  }, [paginatedRoutes, origins, protectedApps, protectedAppsAvailable]);

  const appBlockingDelete = useMemo(() => {
    if (!hasAccessControl || !routeToDelete?.id) return null;
    return appsByRoute.get(routeToDelete.id) || null;
  }, [hasAccessControl, routeToDelete, appsByRoute]);

  const knownOriginNames = useMemo(() => origins.map((o) => o.name), [origins]);

  if (isEditing) {
    const accessContext = (hasAccessControl && editingRoute) ? getRouteAccessInfo(editingRoute) : null;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
        <div>
          <Button
            kind="ghost"
            size="sm"
            renderIcon={ArrowLeft}
            onClick={() => setIsEditing(false)}
          >
            Back to routes
          </Button>
        </div>

        <PageHeader
          title={editingRoute ? `Edit route: ${editingRoute.name || 'Unnamed'}` : 'Add route'}
          icon={Globe}
          badge={
            editingRoute ? (
              <Tag type={formEnabled ? 'green' : 'cool-gray'} size="sm">
                {formEnabled ? 'Active' : 'Disabled'}
              </Tag>
            ) : undefined
          }
        />

        {formError && (
          <InlineNotification
            kind="error"
            title="Validation error"
            subtitle={formError}
            onCloseButtonClick={() => setFormError(null)}
          />
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', width: '100%' }}>
          <SectionCard
            title="Route details"
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '20px', alignItems: 'center' }}>
              <TextInput
                id="route-name"
                labelText="Route name"
                placeholder="e.g. API Gateway, Customer Portal"
                value={formName}
                onChange={(e) => setFormName(e.target.value)}
                required
              />
              <NumberInput
                id="route-priority"
                label="Priority"
                min={1}
                max={10000}
                step={1}
                value={formPriority}
                onChange={(_, { value }) => setFormPriority(Number(value) || 100)}
                helperText="Lower numbers evaluated first"
              />
              <StatusToggle
                id="route-enabled-toggle"
                label="Route status"
                description="Active traffic matching"
                toggled={formEnabled}
                onToggle={(checked) => setFormEnabled(checked)}
              />
            </div>
          </SectionCard>

          <SectionCard
            title="Traffic matching"
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
              <TextInput
                id="route-hosts"
                labelText="Hosts"
                placeholder="example.com, *.example.com"
                value={formHosts}
                onChange={(e) => setFormHosts(e.target.value)}
                helperText="Leave blank for all hosts (*)"
              />
              <TextInput
                id="route-paths"
                labelText="Path patterns"
                placeholder="/api/*, /v1/*"
                value={formPaths}
                onChange={(e) => setFormPaths(e.target.value)}
                helperText="Leave blank for all paths (/*)"
              />
            </div>
          </SectionCard>

          <SectionCard
            title="Destination"
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
                <Select
                  id="route-delivery-mode"
                  labelText="Target"
                  value={deliveryMode}
                  onChange={(e) => setDeliveryMode(e.target.value as DeliveryMode)}
                >
                  <SelectItem value="origin" text="Origin pool (Recommended)" />
                  <SelectItem value="inline" text="Inline backend targets" />
                  <SelectItem value="default" text="Default proxy target" />
                </Select>

                {deliveryMode === 'origin' && (
                  <Select
                    id="route-upstream"
                    labelText="Origin pool"
                    value={formUpstream}
                    onChange={(e) => setFormUpstream(e.target.value)}
                    helperText={origins.length === 0 ? 'No origin pools configured. Add pools in Origins.' : undefined}
                  >
                    {formUpstream && !knownOriginNames.includes(formUpstream) && (
                      <SelectItem value={formUpstream} text={`${formUpstream} (External/Custom)`} />
                    )}
                    {origins.map((origin) => (
                      <SelectItem key={origin.id || origin.name} value={origin.name} text={origin.name} />
                    ))}
                    {origins.length === 0 && !formUpstream && (
                      <SelectItem value="" text="No origins configured" />
                    )}
                  </Select>
                )}
              </div>

              {deliveryMode === 'origin' && (
                <div style={{ borderTop: '1px solid var(--cds-border-subtle)', paddingTop: '16px' }}>
                  <div style={{ marginBottom: '12px' }}>
                    <div style={{ fontWeight: 600, fontSize: '14px' }}>
                      Fallback backend (optional)
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                      Used if origin pool targets are unhealthy.
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                    <TextArea
                      id="route-fallback-backends"
                      labelText="Fallback targets"
                      placeholder="http://10.0.99.10:8080&#10;http://10.0.99.11:8080,2"
                      rows={3}
                      value={formFallbackBackends}
                      onChange={(e) => setFormFallbackBackends(e.target.value)}
                      helperText="One target per line (URL,weight)"
                    />
                    <Select
                      id="route-fallback-strategy"
                      labelText="Fallback strategy"
                      value={formFallbackStrategy}
                      onChange={(e) => setFormFallbackStrategy(e.target.value)}
                    >
                      <SelectItem value="round_robin" text="Round robin" />
                      <SelectItem value="weighted_rr" text="Weighted round robin" />
                      <SelectItem value="least_conn" text="Least connections" />
                      <SelectItem value="ip_hash" text="IP hash" />
                    </Select>
                  </div>
                </div>
              )}

              {deliveryMode === 'inline' && (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', padding: '16px', background: 'var(--cds-layer-01)', borderRadius: '4px' }}>
                  <TextArea
                    id="route-backends"
                    labelText="Backend targets"
                    placeholder="http://10.0.1.10:8080&#10;http://10.0.1.11:8080,2"
                    rows={4}
                    value={formBackends}
                    onChange={(e) => setFormBackends(e.target.value)}
                    helperText="One target per line (URL,weight)"
                  />
                  <Select
                    id="route-inline-strategy"
                    labelText="Balancing strategy"
                    value={formStrategy}
                    onChange={(e) => setFormStrategy(e.target.value)}
                  >
                    <SelectItem value="round_robin" text="Round robin" />
                    <SelectItem value="weighted_rr" text="Weighted round robin" />
                    <SelectItem value="least_conn" text="Least connections" />
                    <SelectItem value="ip_hash" text="IP hash" />
                  </Select>
                </div>
              )}

              {deliveryMode === 'default' && (
                <div style={{ padding: '16px', background: 'var(--cds-layer-01)', borderRadius: '4px', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                  Requests matching this route are proxied directly to the default target configured in <strong>Proxy Settings</strong>.
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Path handling & options"
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '20px' }}>
              <Select
                id="route-path-transform"
                labelText="Path handling"
                value={pathTransform}
                onChange={(e) => setPathTransform(e.target.value as PathTransform)}
              >
                <SelectItem value="keep" text="Pass through (keep path)" />
                <SelectItem value="strip" text="Strip prefix" />
                <SelectItem value="rewrite" text="Rewrite path" />
              </Select>

              {pathTransform === 'strip' && (
                <TextInput
                  id="route-strip"
                  labelText="Prefix to strip"
                  placeholder="/api/v1"
                  value={formStripPrefix}
                  onChange={(e) => setFormStripPrefix(e.target.value)}
                  helperText="Prefix removed before forwarding"
                />
              )}

              {pathTransform === 'rewrite' && (
                <TextInput
                  id="route-rewrite"
                  labelText="Replacement path"
                  placeholder="/internal/api"
                  value={formRewritePath}
                  onChange={(e) => setFormRewritePath(e.target.value)}
                  helperText="Exact path sent to origin"
                />
              )}

              <TextInput
                id="route-timeout"
                labelText="Timeout"
                placeholder="15s"
                value={formTimeout}
                onChange={(e) => setFormTimeout(e.target.value)}
                helperText="Leave blank for global timeout"
              />

              <NumberInput
                id="route-retries"
                label="Retries on 5xx"
                min={0}
                max={5}
                value={formRetries}
                onChange={(_, { value }) => setFormRetries(Number(value) || 0)}
              />
            </div>

            <div style={{ marginTop: '20px' }}>
              <StatusToggle
                id="toggle-preserve-host"
                label="Preserve host header"
                description="Forward original client Host header to upstream"
                toggled={formPreserveHost}
                onToggle={(checked) => setFormPreserveHost(checked)}
              />
            </div>
          </SectionCard>

          <Accordion>
            <AccordionItem title="Advanced matching (methods, source IPs, headers, query)">
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '12px 0' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
                  <TextInput
                    id="route-methods"
                    labelText="HTTP methods"
                    placeholder="GET, POST, PUT, DELETE"
                    value={formMethods}
                    onChange={(e) => setFormMethods(e.target.value)}
                    helperText="Leave empty for all methods"
                  />
                  <TextInput
                    id="route-source-cidrs"
                    labelText="Source IPs / CIDRs"
                    placeholder="10.0.0.0/8, 192.168.1.0/24"
                    value={formSourceCIDRs}
                    onChange={(e) => setFormSourceCIDRs(e.target.value)}
                    helperText="Client IP addresses or networks"
                  />
                  <TextArea
                    id="route-headers"
                    labelText="Header matchers (JSON)"
                    placeholder='{"X-Environment": ["production"]}'
                    rows={3}
                    value={formHeadersJSON}
                    onChange={(e) => setFormHeadersJSON(e.target.value)}
                    helperText='JSON map: { "Header-Name": ["val1", "val2"] }'
                  />
                  <TextArea
                    id="route-query"
                    labelText="Query matchers (JSON)"
                    placeholder='{"tenant": ["primary"]}'
                    rows={3}
                    value={formQueryJSON}
                    onChange={(e) => setFormQueryJSON(e.target.value)}
                    helperText='JSON map: { "param": ["val"] }'
                  />
                </div>
              </div>
            </AccordionItem>
          </Accordion>

          <SectionCard
            title="Security filters"
          >
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '20px' }}>
              <StatusToggle
                id="toggle-waf-core"
                label="Core WAF"
                description="OWASP CRS inspection"
                toggled={formWafCore}
                onToggle={(checked) => setFormWafCore(checked)}
              />
              <StatusToggle
                id="toggle-traffic-control"
                label="Traffic control"
                description="Rate limits & throttle"
                toggled={formTrafficControl}
                onToggle={(checked) => setFormTrafficControl(checked)}
              />
              <StatusToggle
                id="toggle-http-security"
                label="App defense"
                description="Security headers & sanitization"
                toggled={formHttpSecurity}
                onToggle={(checked) => setFormHttpSecurity(checked)}
              />
              <StatusToggle
                id="toggle-bot-protection"
                label="Bot defense"
                description="Automation & crawler protection"
                toggled={formBotProtection}
                onToggle={(checked) => setFormBotProtection(checked)}
              />
              <StatusToggle
                id="toggle-api-security"
                label="API security"
                description="Contract validation & discovery"
                toggled={formApiSecurity}
                onToggle={(checked) => setFormApiSecurity(checked)}
              />
              {hasAccessControl && (
                <StatusToggle
                  id="toggle-access-control"
                  label="Edge access"
                  description="Identity & zero trust policies"
                  toggled={formAccessControl}
                  onToggle={(checked) => setFormAccessControl(checked)}
                />
              )}
            </div>
          </SectionCard>

          {hasAccessControl && editingRoute && accessContext && (
            <SectionCard
              title="Edge access"
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: '16px',
                  padding: '16px',
                  background: 'var(--cds-layer-01)',
                  borderRadius: '4px',
                  border: '1px solid var(--cds-border-subtle)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <Tag type={accessContext.tone} size="md">
                    {accessContext.label}
                  </Tag>
                  <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {accessContext.description}
                  </span>
                </div>

                {onNavigate && (
                  <Button
                    kind="tertiary"
                    size="sm"
                    onClick={() => onNavigate('access-apps')}
                  >
                    {accessContext.app ? 'Open app' : 'Protect with Edge access'}
                  </Button>
                )}
              </div>
            </SectionCard>
          )}

          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-start', paddingTop: '8px', paddingBottom: '32px' }}>
            <Button kind="secondary" size="md" onClick={() => setIsEditing(false)}>
              Cancel
            </Button>
            <Button
              kind="primary"
              size="md"
              renderIcon={CheckmarkOutline}
              disabled={saving}
              onClick={handleSaveRoute}
            >
              {saving ? 'Saving...' : editingRoute ? 'Save changes' : 'Create route'}
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px 32px 80px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        title="Routing"
        icon={Globe}
        action={
          <Button kind="primary" renderIcon={Add} size="md" onClick={openAddEditor}>
            Add route
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
        <DataTableSkeleton headers={headers} rowCount={8} columnCount={headers.length} />
      ) : (
        <DataTable rows={tableRows} headers={headers}>
          {({ rows, headers, getHeaderProps, getRowProps, getTableProps }) => (
            <TableContainer title="Route rules">
              <TableToolbar>
                <TableToolbarContent>
                  <TableToolbarSearch
                    persistent
                    placeholder="Search routes by name, host, or path..."
                    value={searchQuery}
                    onChange={(e: any) => {
                      setSearchQuery(e.target.value || '');
                      setCurrentPage(1);
                    }}
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

              <Table {...getTableProps()} size="md" aria-label="Route Rules Table">
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
                          {searchQuery ? 'No routes match your search' : 'No routes configured'}
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', marginBottom: '16px' }}>
                          {searchQuery
                            ? 'Try clearing the search query or search with a different keyword.'
                            : 'Add a route to match client traffic and forward it to an origin pool.'}
                        </div>
                        {searchQuery ? (
                          <Button kind="secondary" size="sm" onClick={() => setSearchQuery('')}>
                            Clear search
                          </Button>
                        ) : (
                          <Button kind="tertiary" size="sm" renderIcon={Add} onClick={openAddEditor}>
                            Add Route
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ) : (
                    rows.map((row) => {
                      const raw = routesById.get(row.id);
                      if (!raw) return null;
                      const { key, ...rowProps } = getRowProps({ row });

                      const hosts = raw.hosts || raw.match?.hosts || ['*'];
                      const paths = raw.paths || raw.match?.paths || ['/*'];
                      const backends = raw.action?.backends || raw.backends || [];
                      const upstream = raw.action?.upstream;
                      const isEnabled = raw.enabled !== false;
                      const accessInfo = getRouteAccessInfo(raw);

                      return (
                        <TableRow key={key} {...rowProps}>
                          <TableCell>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                              <Button
                                kind="ghost"
                                size="sm"
                                style={{ padding: '0 4px', fontWeight: 600, color: 'var(--cds-link-primary)' }}
                                onClick={() => openEditEditor(raw)}
                              >
                                <Network_3 size={16} style={{ marginRight: '8px' }} />
                                {raw.name || 'Unnamed route'}
                              </Button>
                              <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', paddingLeft: '28px' }}>
                                {hosts.join(', ') || 'All hosts (*)'}
                              </div>
                            </div>
                          </TableCell>

                          <TableCell>
                            <span style={{ fontFamily: 'var(--cds-font-family-mono, monospace)', fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                              P{raw.priority ?? 100}
                            </span>
                          </TableCell>

                          <TableCell>
                            <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                              {paths.map((p, pIdx) => (
                                <code
                                  key={pIdx}
                                  style={{
                                    fontFamily: 'var(--cds-font-family-mono, monospace)',
                                    fontSize: '12px',
                                    color: 'var(--cds-text-primary)',
                                    backgroundColor: 'var(--cds-layer-02, #262626)',
                                    padding: '2px 6px',
                                    borderRadius: '3px',
                                    border: '1px solid var(--cds-border-subtle, #393939)',
                                  }}
                                >
                                  {p}
                                </code>
                              ))}
                            </div>
                          </TableCell>

                          <TableCell>
                            {upstream && upstream !== 'default' ? (
                              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                                <span>
                                  Origin: <strong style={{ color: 'var(--cds-text-primary)' }}>{upstream}</strong>
                                </span>
                                {raw.action?.strip_prefix && (
                                  <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                    (strip: <code>{raw.action.strip_prefix}</code>)
                                  </span>
                                )}
                                {raw.action?.rewrite_path && (
                                  <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                    (rewrite: <code>{raw.action.rewrite_path}</code>)
                                  </span>
                                )}
                              </div>
                            ) : backends.length > 0 ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                {backends.slice(0, 2).map((b, bIdx) => (
                                  <div key={bIdx} style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                                    <code style={{ fontFamily: 'var(--cds-font-family-mono, monospace)' }}>
                                      {b.url}
                                    </code>
                                    {b.weight && b.weight > 1 && (
                                      <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                        (w:{b.weight})
                                      </span>
                                    )}
                                  </div>
                                ))}
                                {backends.length > 2 && (
                                  <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary)' }}>
                                    +{backends.length - 2} more backends
                                  </span>
                                )}
                              </div>
                            ) : (
                              <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                                Default proxy target
                              </span>
                            )}
                          </TableCell>

                          <TableCell>
                            {(() => {
                              if (upstream && upstream !== 'default') {
                                const pool = origins.find((o) => o.name === upstream);
                                return <PolicyTag strategy={pool?.strategy || 'origin_pool'} />;
                              }
                              if (backends.length > 0) {
                                return (
                                  <PolicyTag
                                    strategy={raw.action?.strategy || raw.load_balance || 'round_robin'}
                                  />
                                );
                              }
                              return <PolicyTag strategy="default_proxy" />;
                            })()}
                          </TableCell>

                          {hasAccessControl && (
                            <TableCell>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                                <Tag
                                  type={accessInfo.tone}
                                  size="sm"
                                  title={accessInfo.description}
                                >
                                  {accessInfo.label}
                                </Tag>
                              </div>
                            </TableCell>
                          )}

                          <TableCell>
                            <StatusToggle
                              id={`toggle-${raw.id}`}
                              hideLabel
                              ariaLabel={isEnabled ? 'Disable route' : 'Enable route'}
                              toggled={isEnabled}
                              onToggle={(checked: boolean) => handleToggleRoute(raw, checked)}
                            />
                          </TableCell>

                          <TableCell>
                            <OverflowMenu flipped size="sm" ariaLabel={`Actions for ${raw.name}`}>
                              <OverflowMenuItem
                                itemText="Edit route"
                                onClick={() => openEditEditor(raw)}
                              />
                              <OverflowMenuItem
                                itemText={isEnabled ? 'Disable route' : 'Enable route'}
                                onClick={() => handleToggleRoute(raw, !isEnabled)}
                              />
                              {hasAccessControl && onNavigate && (
                                <OverflowMenuItem
                                  itemText={accessInfo.app ? 'Open App' : 'Protect with Edge Access'}
                                  onClick={() => onNavigate('access-apps')}
                                />
                              )}
                              <OverflowMenuItem
                                isDelete
                                itemText="Delete route"
                                onClick={() => confirmDelete(raw)}
                              />
                            </OverflowMenu>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              {filteredRoutes.length > 0 && (
                <Pagination
                  totalItems={filteredRoutes.length}
                  backwardText="Previous page"
                  forwardText="Next page"
                  pageSize={pageSize}
                  pageSizes={[10, 20, 50]}
                  page={currentPage}
                  onChange={({ page, pageSize: newSize }) => {
                    setCurrentPage(page);
                    setPageSize(newSize);
                  }}
                />
              )}
            </TableContainer>
          )}
        </DataTable>
      )}

      <Modal
        danger={!appBlockingDelete}
        open={deleteConfirmOpen}
        modalHeading="Delete Route Rule"
        primaryButtonText={appBlockingDelete ? 'Blocked' : 'Delete route'}
        primaryButtonDisabled={Boolean(appBlockingDelete)}
        secondaryButtonText="Cancel"
        onRequestClose={() => setDeleteConfirmOpen(false)}
        onRequestSubmit={appBlockingDelete ? () => {} : handleDelete}
      >
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '16px 0' }}>
          {appBlockingDelete ? (
            <>
              <InlineNotification
                kind="error"
                title="Route is locked by Edge Access"
                subtitle={`Route "${routeToDelete?.name}" is actively attached to Protected App "${appBlockingDelete.name}". Linked Edge Access routes cannot be deleted.`}
                lowContrast
              />
              <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
                To delete this route, you must first unlink or remove Protected App{' '}
                <strong>"{appBlockingDelete.name}"</strong> in Edge Access.
              </p>
              {onNavigate && (
                <div>
                  <Button
                    kind="tertiary"
                    size="sm"
                    onClick={() => {
                      setDeleteConfirmOpen(false);
                      onNavigate('access-apps');
                    }}
                  >
                    Manage Protected App
                  </Button>
                </div>
              )}
            </>
          ) : (
            <p style={{ margin: 0 }}>
              Are you sure you want to delete route <strong>"{routeToDelete?.name}"</strong>? Incoming client requests matching this host/path pattern will no longer be routed through this rule.
            </p>
          )}
        </div>
      </Modal>

    </div>
  );
};