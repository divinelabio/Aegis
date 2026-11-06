import type {
  OriginPool,
  UpstreamGroupRuntimeStatus,
  RouteRecord,
  RouteTestRequest,
  RouteTestResponse,
  AppV2,
  InfrastructureSettings,
  DeploymentMode,
  ProxySettingsResponse,
  ProxyGuideResponse,
  CertificateRecord,
  TLSConfigState,
  WafCoreConfig,
  CrsRuleGroup,
  WAFCustomRule,
  WAFRuleDetailResponse,
  RateLimitPolicy,
  BotDefenseConfig,
  SecurityEventItem,
  TrafficStats,
  AegisModule,
  SystemSettings,
  AuditLogsResponse,
  AuditQueryParams,
  WAFExclusion,
  TrafficEventsDashboardData,
  TrafficOperations,
  TrafficGeoConfig,
  TrafficGeoStatus,
  IPBlacklistConfig,
  BlockedIPStatus,
  TrafficTrustedException,
  LicenseSnapshot,
  StorageStatusResponse,
  PostgreSQLPreflightRequest,
  PostgreSQLControlPendingRequest,
  ClickHousePreflightRequest,
  ClickHouseAnalyticsPendingRequest,
  UpstreamSettings,
  CircuitBreakerConfig,
  StickySecretStatus,
  SystemUpdateStatus,
  WAFProfile,
  WAFManagedRuleFile,
  WAFConfigDashboardStats,
  WAFHealth,
  WAFSectionConfig,
  WAFLeakProtectionConfig,
  SecurityDashboardData,
  CaptchaModuleConfig,
  ChallengeModuleConfig,
  ErrorPagesModuleConfig,
  EdgeAccessSettings,
  ReloadStatusResponse,
  ProfileDetails,
  MFASecretData,
  UserSession,
  LoginResult,
  AppSecurityEffectiveState,
  AppSecurityConfig,
  AppSecurityStats,
  AlertsResponse,
  UserPayload,
  RolePayload,
  UsersListResponse,
  RolesListResponse,
  PermissionsListResponse,
  SetupStatusResponse,
  SetupBootstrapResponse,
  SetupFirstAdminRequest,
  SetupFirstAdminResponse,
  SetupCompleteResponse,
} from '../types';

let cachedCsrfToken: string | null = null;
let sessionCheckPromise: Promise<string | null> | null = null;
let cachedLicense: LicenseSnapshot | null = null;
let cachedLicenseTime = 0;

export async function fetchCsrfToken(): Promise<string | null> {
  if (cachedCsrfToken) return cachedCsrfToken;
  if (sessionCheckPromise) return sessionCheckPromise;
  sessionCheckPromise = (async () => {
    try {
      const res = await fetch('/api/verify_session', {
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.csrf_token) {
          cachedCsrfToken = data.csrf_token;
          return cachedCsrfToken;
        }
      }
    } catch (err) {
      console.warn('[Aegis API] Failed to fetch session/CSRF token:', err);
    } finally {
      sessionCheckPromise = null;
    }
    return cachedCsrfToken;
  })();
  return sessionCheckPromise;
}

export function clearCsrfToken(): void {
  cachedCsrfToken = null;
}

// In-memory SWR response cache & in-flight request deduplication
interface CachedHttpResponse {
  status: number;
  statusText: string;
  headers: [string, string][];
  bodyText: string;
  timestamp: number;
}

const apiResponseCache = new Map<string, CachedHttpResponse>();
const inFlightRequests = new Map<string, Promise<Response>>();
const API_CACHE_TTL_MS = 30000; // 30 seconds

export function clearApiCache(pathPrefix?: string): void {
  if (!pathPrefix) {
    apiResponseCache.clear();
    cachedLicense = null;
    cachedLicenseTime = 0;
    return;
  }
  for (const key of apiResponseCache.keys()) {
    if (key.includes(pathPrefix)) {
      apiResponseCache.delete(key);
    }
  }
}

function isStateChanging(method?: string): boolean {
  if (!method) return false;
  return ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase());
}

const OPERATIONAL_CACHE_BYPASS_ENDPOINTS = [
  '/api/verify_session',
  '/api/login',
  '/api/logout',
  '/api/upstreams/status',
  '/api/sections/traffic_control/stats',
  '/api/sections/traffic_control/operations',
  '/api/traffic-events',
  '/api/logs',
];

function shouldBypassCache(path: string, init: RequestInit): boolean {
  if (init.cache === 'no-store' || init.cache === 'reload') return true;
  return OPERATIONAL_CACHE_BYPASS_ENDPOINTS.some((endpoint) => path.includes(endpoint));
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const method = (init.method || 'GET').toUpperCase();
  const headers = new Headers(init.headers || {});
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }

  // Auto-invalidate cache on mutations
  if (isStateChanging(method)) {
    clearApiCache();
    if (!cachedCsrfToken) {
      await fetchCsrfToken();
    }
    if (cachedCsrfToken) {
      headers.set('X-CSRF-Token', cachedCsrfToken);
    }
  }

  const reqInit: RequestInit = {
    ...init,
    method,
    headers,
    credentials: 'include',
  };

  // Serve from memory cache for GET requests
  const isGet = method === 'GET';
  const bypass = !isGet || shouldBypassCache(path, init);
  const cacheKey = `${method}:${path}`;

  if (!bypass) {
    const cached = apiResponseCache.get(cacheKey);
    const now = Date.now();
    if (cached && now - cached.timestamp < API_CACHE_TTL_MS) {
      return new Response(cached.bodyText, {
        status: cached.status,
        statusText: cached.statusText,
        headers: new Headers(cached.headers),
      });
    }

    // In-flight deduplication: collapse simultaneous concurrent requests
    if (inFlightRequests.has(cacheKey)) {
      const ongoing = inFlightRequests.get(cacheKey)!;
      const res = await ongoing;
      return res.clone();
    }
  }

  const executeFetch = async (): Promise<Response> => {
    let res = await fetch(path, reqInit);

    // If unauthorized (401), check if session is genuinely invalid
    if (res.status === 401) {
      cachedCsrfToken = null;
      if (path.includes('/api/verify_session') || path.includes('/api/login')) {
        window.dispatchEvent(new CustomEvent('aegis:auth-required'));
      } else {
        void (async () => {
          try {
            const check = await fetch('/api/verify_session', { credentials: 'include', headers: { Accept: 'application/json' } });
            if (check.status === 401) {
              window.dispatchEvent(new CustomEvent('aegis:auth-required'));
            }
          } catch {
          }
        })();
      }
      return res;
    }

    // If CSRF rejected (403), re-fetch CSRF token and retry once
    if (isStateChanging(method) && res.status === 403) {
      try {
        const clone = res.clone();
        const text = await clone.text();
        if (/csrf/i.test(text)) {
          console.info('[Aegis API] CSRF expired or required, refreshing token and retrying...');
          cachedCsrfToken = null;
          const freshToken = await fetchCsrfToken();
          if (freshToken) {
            headers.set('X-CSRF-Token', freshToken);
            res = await fetch(path, { ...reqInit, headers });
          }
        }
      } catch {
      }
    }

    // Cache successful GET responses
    if (!bypass && res.ok) {
      try {
        const clone = res.clone();
        const bodyText = await clone.text();
        const headerEntries: [string, string][] = [];
        res.headers.forEach((val, key) => headerEntries.push([key, val]));
        apiResponseCache.set(cacheKey, {
          status: res.status,
          statusText: res.statusText,
          headers: headerEntries,
          bodyText,
          timestamp: Date.now(),
        });
      } catch {
      }
    }

    return res;
  };

  if (!bypass) {
    const promise = executeFetch();
    inFlightRequests.set(cacheKey, promise);
    try {
      const res = await promise;
      return res.clone();
    } finally {
      inFlightRequests.delete(cacheKey);
    }
  }

  return executeFetch();
}

export type TrafficSectionTarget =
  | 'blacklist'
  | 'geo'
  | 'ratelimit'
  | 'reputation'
  | 'application_flood'
  | 'trusted_exceptions'
  | 'full';

export function normalizeTrafficConfigForSave(
  existingConfig: Record<string, any>,
  updates: Record<string, any>,
  targetSection: TrafficSectionTarget = 'full'
): Record<string, any> {
  const isCommercial =
    existingConfig?.control?.schema_version === 2 ||
    (!('rate_limit' in existingConfig) && Object.keys(existingConfig).length > 0);

  const raw: Record<string, any> = {
    ...existingConfig,
    ...updates,
  };

  const payload: Record<string, any> = {
    enabled: raw.enabled !== false,
  };

  if (raw.control && typeof raw.control === 'object') {
    payload.control = {
      schema_version: raw.control.schema_version || 2,
      ...(raw.control.revision ? { revision: raw.control.revision } : {}),
      ...(raw.control.checksum ? { checksum: raw.control.checksum } : {}),
      ...(raw.control.updated_at ? { updated_at: raw.control.updated_at } : {}),
      ...(raw.control.updated_by ? { updated_by: raw.control.updated_by } : {}),
    };
  }

  if (raw.protection_level) {
    payload.protection_level = raw.protection_level;
  }

  if (raw.conn_stats || raw.connstats) {
    const cs = raw.conn_stats || raw.connstats || {};
    payload.conn_stats = {
      enabled: Boolean(cs.enabled),
    };
  }

  const rawBl = raw.blacklist || {};
  const blIps = Array.isArray(rawBl.ips) ? rawBl.ips.map((s: any) => String(s).trim()).filter(Boolean) : [];
  const blCidrs = Array.isArray(rawBl.cidrs) ? rawBl.cidrs.map((s: any) => String(s).trim()).filter(Boolean) : [];
  const nowMs = Date.now();
  const blEntries: Array<{ target: string; note?: string; expires_at?: string }> = [];
  if (Array.isArray(rawBl.entries)) {
    for (const entry of rawBl.entries) {
      const target = String(entry?.target || '').trim();
      if (!target) continue;
      const item: { target: string; note?: string; expires_at?: string } = {
        target,
        ...(entry?.note ? { note: String(entry.note).trim() } : {}),
      };
      if (entry?.expires_at) {
        const expMs = Date.parse(String(entry.expires_at));
        if (!Number.isNaN(expMs)) {
          if (expMs <= nowMs) {
            // Skip already-expired entry so Go validateBlacklistConfig does not reject with 400
            continue;
          }
          item.expires_at = new Date(expMs).toISOString();
        }
      }
      blEntries.push(item);
    }
  }
  const entryTargetSet = new Set(blEntries.map((e) => e.target));
  const cleanIps = blIps.filter((ip: string) => !entryTargetSet.has(ip));
  const cleanCidrs = blCidrs.filter((cidr: string) => !entryTargetSet.has(cidr));
  payload.blacklist = {
    enabled:
      rawBl.enabled !== undefined
        ? Boolean(rawBl.enabled)
        : cleanIps.length > 0 || cleanCidrs.length > 0 || blEntries.length > 0,
    ips: cleanIps,
    cidrs: cleanCidrs,
    entries: blEntries,
    ...(typeof rawBl.auto_expire === 'number' && Number.isFinite(rawBl.auto_expire)
      ? { auto_expire: rawBl.auto_expire }
      : {}),
  };

  const rawGeo = raw.geo || {};
  const normalizeCodes = (arr: any[]) =>
    Array.from(
      new Set(
        (Array.isArray(arr) ? arr : [])
          .map((c) => String(c || '').trim().toUpperCase())
          .filter((c) => /^[A-Z]{2}$/.test(c))
      )
    ).sort();
  const normalizeGroups = (arr: any[]) =>
    Array.from(
      new Set(
        (Array.isArray(arr) ? arr : [])
          .map((g) => String(g || '').trim().replace(/^@/, '').toUpperCase())
          .filter(Boolean)
      )
    ).sort();

  const geoMode: 'blocklist' | 'allowlist' = rawGeo.mode === 'allowlist' ? 'allowlist' : 'blocklist';
  const rawCountries = normalizeCodes(
    geoMode === 'allowlist'
      ? rawGeo.allow_countries?.length
        ? rawGeo.allow_countries
        : rawGeo.countries || []
      : rawGeo.block_countries?.length
      ? rawGeo.block_countries
      : rawGeo.countries || []
  );
  const geoGroups = normalizeGroups([...(rawGeo.groups || []), ...(rawGeo.regions || [])]);
  const unknownAction = ['allow', 'block', 'challenge'].includes(rawGeo.unknown_action)
    ? rawGeo.unknown_action
    : 'allow';

  payload.geo = {
    enabled:
      rawGeo.enabled !== undefined
        ? Boolean(rawGeo.enabled)
        : rawCountries.length > 0 || geoGroups.length > 0,
    mode: geoMode,
    db_path: rawGeo.db_path || './data/dbip-country.mmdb',
    auto_update: Boolean(rawGeo.auto_update),
    ...(rawGeo.update_interval ? { update_interval: String(rawGeo.update_interval) } : {}),
    ...(rawGeo.update_url ? { update_url: String(rawGeo.update_url) } : {}),
    allow_countries: geoMode === 'allowlist' ? rawCountries : [],
    block_countries: geoMode === 'blocklist' ? rawCountries : [],
    countries: rawCountries,
    groups: geoGroups,
    regions: geoGroups,
    exceptions: Array.isArray(rawGeo.exceptions)
      ? rawGeo.exceptions.map((s: any) => String(s).trim()).filter(Boolean)
      : [],
    unknown_action: unknownAction,
    cache_ttl: rawGeo.cache_ttl || '24h',
  };

  const rawRl = raw.ratelimit || raw.rate_limit || {};
  const mapKeyBy = (k: any): 'ip' | 'ip_ua' | 'cookie' | 'token' => {
    if (k === 'ip_ua' || k === 'cookie' || k === 'token') return k;
    if (k === 'header') return 'token';
    return 'ip';
  };
  const mapAlgo = (a: any): 'token_bucket' | 'fixed_window' | 'sliding_window' => {
    if (a === 'fixed_window' || a === 'sliding_window') return a;
    return 'token_bucket';
  };
  const mapMatch = (m: any): 'exact' | 'prefix' | 'glob' => {
    if (m === 'exact' || m === 'prefix' || m === 'glob') return m;
    return 'glob';
  };
  const topDryRun = rawRl.action === 'dry_run' ? true : Boolean(rawRl.dry_run);
  const topRlAction: 'block' | 'challenge' =
    rawRl.action === 'challenge' ? 'challenge' : 'block';
  const rawOverrides = Array.isArray(rawRl.path_overrides) ? rawRl.path_overrides : [];

  const pathOverrides = rawOverrides.map((o: any, idx: number) => {
    const rawPattern = String(o?.pattern || o?.path || '/').trim();
    const pattern = rawPattern.startsWith('/') ? rawPattern : '/' + rawPattern;
    const ruleDryRun = o?.action === 'dry_run' ? true : Boolean(o?.dry_run);
    const ruleAction = o?.action === 'challenge' ? 'challenge' : 'block';
    const grace = Math.min(5, Math.max(1, Number(o?.verified_grace_multiplier) || 2));
    return {
      id: String(o?.id || `rule-${idx + 1}`).trim(),
      name: String(o?.name || pattern).trim(),
      priority: Number(o?.priority ?? 100),
      hosts: Array.isArray(o?.hosts) ? o.hosts.map((h: any) => String(h).trim()).filter(Boolean) : [],
      methods: Array.isArray(o?.methods)
        ? o.methods.map((m: any) => String(m).trim().toUpperCase()).filter(Boolean)
        : [],
      pattern,
      match: mapMatch(o?.match),
      rate: Math.max(1, Number(o?.rate) || 60),
      burst: Math.max(0, Number(o?.burst ?? 10)),
      window: String(o?.window || rawRl.window || '1m').trim() || '1m',
      algorithm: mapAlgo(o?.algorithm || rawRl.algorithm),
      key_by: mapKeyBy(o?.key_by || rawRl.key_by),
      action: ruleAction,
      bypass_static: o?.bypass_static !== false,
      dry_run: ruleDryRun,
      verified_grace_multiplier: grace,
    };
  });

  payload.ratelimit = {
    enabled: rawRl.enabled !== false,
    default_rate: Math.max(1, Number(rawRl.default_rate) || 60),
    default_burst: Math.max(0, Number(rawRl.default_burst ?? 20)),
    window: String(rawRl.window || '1m').trim() || '1m',
    algorithm: mapAlgo(rawRl.algorithm),
    key_by: mapKeyBy(rawRl.key_by),
    action: topRlAction,
    bypass_static: rawRl.bypass_static !== false,
    bypass_known_bots: Boolean(rawRl.bypass_known_bots),
    verified_grace_multiplier: Math.min(5, Math.max(1, Number(rawRl.verified_grace_multiplier) || 2)),
    dry_run: topDryRun,
    max_states: Math.min(250000, Math.max(1, Number(rawRl.max_states) || 100000)),
    state_idle_ttl: String(rawRl.state_idle_ttl || '5m').trim() || '5m',
    ...(rawRl.cookie_name ? { cookie_name: String(rawRl.cookie_name) } : {}),
    ...(rawRl.header_name ? { header_name: String(rawRl.header_name) } : {}),
    ...(Array.isArray(rawRl.static_extensions) ? { static_extensions: rawRl.static_extensions } : {}),
    path_overrides: pathOverrides,
  };

  const rawRep = raw.reputation || {};
  const repAction = ['block', 'challenge', 'captcha', 'js'].includes(rawRep.action)
    ? rawRep.action
    : 'block';
  const rawCti = rawRep.cti || {};
  const allowedIps = Array.isArray(rawRep.allowed_ips) ? rawRep.allowed_ips.map((s: any) => String(s).trim()).filter(Boolean) : [];
  const blockedIps = Array.isArray(rawRep.blocked_ips) ? rawRep.blocked_ips.map((s: any) => String(s).trim()).filter(Boolean) : [];
  if (Array.isArray(rawRep.rules)) {
    for (const r of rawRep.rules) {
      const target = String(r?.target || r?.ip_or_cidr || r?.ip || '').trim();
      if (!target) continue;
      if (r.action === 'allow' && !allowedIps.includes(target)) allowedIps.push(target);
      if (r.action === 'block' && !blockedIps.includes(target)) blockedIps.push(target);
    }
  }

  payload.reputation = {
    enabled: Boolean(rawRep.enabled),
    block_tor: Boolean(rawRep.block_tor),
    block_datacenter: Boolean(rawRep.block_datacenter),
    cache_ttl: String(rawRep.cache_ttl || '1h').trim() || '1h',
    sensitivity: Math.min(100, Math.max(0, Math.round(Number(rawRep.sensitivity ?? 75)))),
    action: repAction,
    allowed_ips: allowedIps,
    blocked_ips: blockedIps,
    cti: {
      enabled: Boolean(rawCti.enabled),
      url: String(rawCti.url || 'http://localhost:8090').trim(),
      min_score: Math.min(100, Math.max(0, Math.round(Number(rawCti.min_score ?? 60)))),
      ...(rawCti.api_key ? { api_key: String(rawCti.api_key) } : {}),
      ...(rawCti.clear_api_key ? { clear_api_key: Boolean(rawCti.clear_api_key) } : {}),
    },
  };

  const rawFlood = raw.application_flood || raw.ddos || {};
  const rawChallenge = {
    ...(raw.challenge || {}),
    ...(rawFlood.challenge && typeof rawFlood.challenge === 'object' ? rawFlood.challenge : {}),
  };
  const floodAction = ['block', 'challenge', 'http_reject'].includes(rawFlood.action)
    ? rawFlood.action
    : 'challenge';
  const floodAutoBan = Boolean(rawFlood.auto_ban);
  const floodObjects = (Array.isArray(rawFlood.objects) ? rawFlood.objects : []).map(
    (obj: any, idx: number) => {
      let rawId = String(obj?.id || obj?.name || `obj-${idx + 1}`)
        .trim()
        .replace(/\s+/g, '-')
        .toLowerCase();
      if (!rawId || rawId === 'default') rawId = `obj-${idx + 1}`;
      const rawPath = String(obj?.path || '/').trim();
      const path = rawPath.startsWith('/') ? rawPath : '/' + rawPath;
      const objAction = ['block', 'challenge', 'http_reject'].includes(obj?.action)
        ? obj.action
        : 'challenge';
      const objAutoBan = Boolean(obj?.auto_ban);
      return {
        id: rawId,
        ...(obj?.priority !== undefined ? { priority: Number(obj.priority) } : {}),
        hosts: Array.isArray(obj?.hosts) ? obj.hosts.map((h: any) => String(h).trim()).filter(Boolean) : [],
        methods: Array.isArray(obj?.methods)
          ? obj.methods.map((m: any) => String(m).trim().toUpperCase()).filter(Boolean)
          : [],
        path,
        path_match: mapMatch(obj?.path_match),
        max_rps: Math.max(1, Number(obj?.max_rps) || 50),
        max_concurrency: Math.max(1, Number(obj?.max_concurrency) || 25),
        burst_multiplier: Math.max(1, Number(obj?.burst_multiplier) || 2),
        action: objAction,
        auto_ban: objAutoBan,
        ban_duration: objAutoBan ? Math.max(1, Number(obj?.ban_duration) || 300) : Number(obj?.ban_duration || 0),
        verified_grace_multiplier: Math.min(5, Math.max(1, Number(obj?.verified_grace_multiplier) || 2)),
      };
    }
  );

  payload.application_flood = {
    enabled: Boolean(rawFlood.enabled),
    max_rps: Number.isFinite(Number(rawFlood.max_rps)) && Number(rawFlood.max_rps) >= 1 ? Number(rawFlood.max_rps) : 100,
    max_connections: Number.isFinite(Number(rawFlood.max_connections)) && Number(rawFlood.max_connections) >= 1 ? Number(rawFlood.max_connections) : 50,
    burst_multiplier: Number.isFinite(Number(rawFlood.burst_multiplier)) && Number(rawFlood.burst_multiplier) >= 1 ? Number(rawFlood.burst_multiplier) : 2,
    action: floodAction,
    auto_ban: floodAutoBan,
    ban_duration: floodAutoBan
      ? Math.max(1, Number(rawFlood.ban_duration) || 300)
      : Number(rawFlood.ban_duration || 60),
    objects: floodObjects,
  };

  const challengeNeededByFlood =
    Boolean(rawFlood.enabled) && (floodAction === 'challenge' || floodObjects.some((o: any) => o.action === 'challenge'));
  const challengeMode = ['js', 'captcha', 'managed', 'hybrid', 'interactive'].includes(rawChallenge.mode)
    ? rawChallenge.mode
    : 'managed';
  payload.challenge = {
    enabled: challengeNeededByFlood ? true : Boolean(rawChallenge.enabled),
    mode: challengeMode,
    threshold: Math.max(1, Number(rawChallenge.threshold) || 5),
  };

  const rawExceptions = Array.isArray(raw.trusted_exceptions) ? raw.trusted_exceptions : [];
  const mapControlName = (c: string): 'flood' | 'rate' | 'geo' | 'reputation' | null => {
    const clean = String(c || '').trim().toLowerCase();
    if (clean === 'flood' || clean === 'application_flood' || clean === 'ddos') return 'flood';
    if (clean === 'rate' || clean === 'rate_limit' || clean === 'ratelimit') return 'rate';
    if (clean === 'geo' || clean === 'geoblock') return 'geo';
    if (clean === 'reputation') return 'reputation';
    return null;
  };

  payload.trusted_exceptions = rawExceptions
    .map((exc: any, idx: number) => {
      const id = String(exc?.id || exc?.name || `exc-${idx + 1}`).trim();
      const targets = Array.isArray(exc?.targets)
        ? exc.targets.map((t: any) => String(t).trim()).filter(Boolean)
        : [];
      if (!id || targets.length === 0) return null;

      const mappedControls = Array.from(
        new Set(
          (Array.isArray(exc?.controls) ? exc.controls : [])
            .map(mapControlName)
            .filter(Boolean) as Array<'flood' | 'rate' | 'geo' | 'reputation'>
        )
      );
      const controls: Array<'flood' | 'rate' | 'geo' | 'reputation'> =
        mappedControls.length > 0 ? mappedControls : ['flood', 'rate', 'geo', 'reputation'];

      let rawPath = '';
      if (typeof exc?.path === 'string' && exc.path.trim()) {
        rawPath = exc.path.trim();
      } else if (Array.isArray(exc?.paths) && exc.paths.length > 0 && String(exc.paths[0]).trim()) {
        rawPath = String(exc.paths[0]).trim();
      }
      const path = rawPath ? (rawPath.startsWith('/') ? rawPath : '/' + rawPath) : undefined;

      let validExpiresAt: string | undefined;
      if (exc?.expires_at) {
        const expMs = Date.parse(String(exc.expires_at));
        if (!Number.isNaN(expMs)) {
          if (expMs <= nowMs) {
            return null;
          }
          validExpiresAt = new Date(expMs).toISOString();
        }
      }

      const item: Record<string, any> = {
        id,
        targets,
        controls,
      };
      if (Array.isArray(exc?.hosts) && exc.hosts.length > 0) {
        item.hosts = exc.hosts.map((h: any) => String(h).trim()).filter(Boolean);
      }
      if (Array.isArray(exc?.methods) && exc.methods.length > 0) {
        item.methods = exc.methods.map((m: any) => String(m).trim().toUpperCase()).filter(Boolean);
      }
      if (path) {
        item.path = path;
        item.path_match = mapMatch(exc?.path_match || 'prefix');
      }
      if (validExpiresAt) {
        item.expires_at = validExpiresAt;
      }
      if (exc?.note) {
        item.note = String(exc.note).trim();
      }
      return item;
    })
    .filter(Boolean);

  // Community edition compatibility: when saving a Community-allowed section on Community backend,
  // ensure paid sections are not inadvertently flagged as enabled by leftover defaults.
  if (
    !isCommercial &&
    (targetSection === 'blacklist' ||
      targetSection === 'geo' ||
      targetSection === 'ratelimit' ||
      targetSection === 'full')
  ) {
    payload.reputation = { enabled: false };
    payload.application_flood = { enabled: false };
    payload.challenge = { enabled: false };
    payload.trusted_exceptions = [];
  }

  return payload;
}

export function normalizeApiSecurityConfigForSave(input: any): { enabled: boolean; settings: Record<string, any> } {
  const root = input && typeof input === 'object' ? input : {};
  const enabled = root.enabled !== false;
  const rawSettings = root.settings && typeof root.settings === 'object' ? root.settings : root;

  const settings: Record<string, any> = {};

  // Helper to ensure 'detect' | 'block'
  const normMode = (val: any, fallback: 'detect' | 'block' = 'detect'): 'detect' | 'block' => {
    const s = String(val || '').trim().toLowerCase();
    if (s === 'block') return 'block';
    if (s === 'detect') return 'detect';
    return fallback;
  };

  if (rawSettings.discovery && typeof rawSettings.discovery === 'object') {
    const d = rawSettings.discovery;
    const intervalStr = typeof d.interval === 'string' ? d.interval.trim() : '';
    const validInterval = /^\d+(?:ns|us|µs|ms|s|m|h)+$/.test(intervalStr) ? intervalStr : '5m';
    const rawZombie = typeof d.zombie_inactivity_days === 'number' && !isNaN(d.zombie_inactivity_days) ? Math.floor(d.zombie_inactivity_days) : 30;
    const zombieDays = Math.min(Math.max(1, rawZombie), 3650);

    settings.discovery = {
      enabled: d.enabled !== false,
      paths: Array.isArray(d.paths) ? d.paths : ['/api/*', '/v1/*', '/v2/*', '/graphql'],
      interval: validInterval,
      index_headers: Array.isArray(d.index_headers) ? d.index_headers : ['Content-Type', 'X-API-Version'],
      detect_shadow_apis: d.detect_shadow_apis !== false,
      detect_zombie_apis: d.detect_zombie_apis !== false,
      zombie_inactivity_days: zombieDays,
      auto_classify: d.auto_classify !== false,
    };
  }

  if (rawSettings.validation && typeof rawSettings.validation === 'object') {
    const v = rawSettings.validation;
    const allowedFormats = ['openapi', 'graphql', 'json-schema'];
    const filteredFormats = Array.isArray(v.schema_formats)
      ? v.schema_formats
          .map((s: any) => String(s || '').trim().toLowerCase())
          .filter((s: string) => allowedFormats.includes(s))
          .slice(0, 8)
      : [];

    settings.validation = {
      enabled: v.enabled !== false,
      mode: normMode(v.mode, 'detect'),
      block_unknown_endpoints: Boolean(v.block_unknown_endpoints),
      block_invalid_methods: v.block_invalid_methods !== false,
      block_invalid_content_types: v.block_invalid_content_types !== false,
      strict_mode: Boolean(v.strict_mode),
      allow_unknown_fields: v.allow_unknown_fields !== false,
      schema_formats: filteredFormats.length > 0 ? filteredFormats : ['openapi', 'graphql', 'json-schema'],
      validate_responses: Boolean(v.validate_responses),
    };
  }

  if (rawSettings.injection && typeof rawSettings.injection === 'object') {
    const i = rawSettings.injection;
    const sens = String(i.sensitivity || '').toLowerCase();
    settings.injection = {
      enabled: i.enabled !== false,
      mode: normMode(i.mode, 'detect'),
      sqli: i.sqli !== false,
      nosqli: i.nosqli !== false,
      cmdi: i.cmdi !== false,
      xss: i.xss !== false,
      sensitivity: sens === 'low' || sens === 'high' ? sens : 'medium',
      custom_patterns: Array.isArray(i.custom_patterns) ? i.custom_patterns : [],
    };
  }

  if (rawSettings.ssrf && typeof rawSettings.ssrf === 'object') {
    const s = rawSettings.ssrf;
    settings.ssrf = {
      enabled: s.enabled !== false,
      mode: normMode(s.mode, 'detect'),
      block_private_networks: s.block_private_networks !== false,
      block_cloud_metadata: s.block_cloud_metadata !== false,
    };
  }

  if (rawSettings.payload_abuse && typeof rawSettings.payload_abuse === 'object') {
    const p = rawSettings.payload_abuse;
    const sens = String(p.sensitivity || '').toLowerCase() === 'strict' ? 'strict' : 'balanced';
    settings.payload_abuse = {
      enabled: p.enabled !== false,
      mode: normMode(p.mode, 'detect'),
      sensitivity: sens,
    };
  }

  if (rawSettings.graphql && typeof rawSettings.graphql === 'object') {
    const g = rawSettings.graphql;
    const clampLimit = (val: any, fallback: number) => {
      if (typeof val === 'number' && !isNaN(val)) {
        return Math.min(Math.max(1, Math.floor(val)), 1000000);
      }
      return fallback;
    };

    settings.graphql = {
      enabled: g.enabled !== false,
      mode: normMode(g.mode, 'detect'),
      paths: Array.isArray(g.paths) && g.paths.length > 0 ? g.paths : ['/graphql', '/api/graphql'],
      max_depth: clampLimit(g.max_depth, 15),
      max_aliases: clampLimit(g.max_aliases, 25),
      max_batch_size: clampLimit(g.max_batch_size, 5),
      max_complexity: clampLimit(g.max_complexity, 500),
      block_introspection: g.block_introspection !== false,
    };
  }

  if (rawSettings.auth_tokens && typeof rawSettings.auth_tokens === 'object') {
    const a = rawSettings.auth_tokens;
    const rawIssuers = Array.isArray(a.issuers) ? a.issuers : [];
    const sanitizedIssuers = rawIssuers
      .filter((iss: any) => iss && typeof iss === 'object' && iss.name && iss.issuer)
      .map((iss: any) => ({
        name: String(iss.name).trim(),
        issuer: String(iss.issuer).trim(),
        audiences: Array.isArray(iss.audiences) ? iss.audiences.map(String).map((s: string) => s.trim()).filter(Boolean) : [],
        allowed_algorithms: Array.isArray(iss.allowed_algorithms) && iss.allowed_algorithms.length > 0
          ? iss.allowed_algorithms.map(String).map((s: string) => s.trim().toUpperCase()).filter(Boolean)
          : ['RS256'],
        jwks_url: String(iss.jwks_url || '').trim(),
      }));

    const hasValidIssuer = sanitizedIssuers.some(
      (iss: any) => iss.issuer && iss.jwks_url && Array.isArray(iss.audiences) && iss.audiences.length > 0
    );
    const resolvedAuthMode = a.mode === 'block' && !hasValidIssuer ? 'detect' : normMode(a.mode, 'detect');

    settings.auth_tokens = {
      enabled: a.enabled !== false,
      mode: resolvedAuthMode,
      protected_paths: Array.isArray(a.protected_paths) ? a.protected_paths : [],
      excluded_paths: Array.isArray(a.excluded_paths) ? a.excluded_paths : [],
      required_claims: Array.isArray(a.required_claims) && a.required_claims.length > 0 ? a.required_claims : ['sub'],
      require_signature: a.require_signature === true || (hasValidIssuer && resolvedAuthMode === 'block'),
      issuers: sanitizedIssuers,
    };
  }

  if (rawSettings.automation_abuse && typeof rawSettings.automation_abuse === 'object') {
    const auto = rawSettings.automation_abuse;
    const sens = String(auto.sensitivity || '').toLowerCase() === 'strict' ? 'strict' : 'balanced';
    settings.automation_abuse = {
      enabled: auto.enabled !== false,
      mode: normMode(auto.mode, 'detect'),
      sensitivity: sens,
      enable_credential_stuffing: auto.enable_credential_stuffing !== false,
      enable_otp_bruteforce: auto.enable_otp_bruteforce !== false,
      enable_forced_browsing: auto.enable_forced_browsing !== false,
      enable_user_enumeration: auto.enable_user_enumeration !== false,
      enable_object_enumeration: auto.enable_object_enumeration !== false,
      enable_scraping: auto.enable_scraping !== false,
      login_paths: Array.isArray(auto.login_paths) ? auto.login_paths : ['/api/v1/auth/login', '/login'],
      otp_paths: Array.isArray(auto.otp_paths) ? auto.otp_paths : ['/api/v1/auth/verify-otp', '/verify'],
      monitored_paths: Array.isArray(auto.monitored_paths) ? auto.monitored_paths : ['/api/*'],
      identifier_fields: Array.isArray(auto.identifier_fields) ? auto.identifier_fields : ['username', 'email', 'user_id'],
    };
  }

  if (rawSettings.bfla && typeof rawSettings.bfla === 'object') {
    const bf = rawSettings.bfla;
    const rawRules = Array.isArray(bf.rules) ? bf.rules : [];
    const validRules = rawRules
      .filter((r: any) => r && typeof r === 'object' && r.name && r.path_pattern)
      .map((r: any) => {
        const allowedRoles = Array.isArray(r.allowed_roles) ? r.allowed_roles.map(String).map((s: string) => s.trim()).filter(Boolean) : [];
        const requiredClaimKey = r.required_claim_key ? String(r.required_claim_key).trim() : '';
        const requiredClaimValues = Array.isArray(r.required_claim_values) && r.required_claim_values.length > 0
          ? r.required_claim_values.map(String).map((s: string) => s.trim()).filter(Boolean)
          : [];
        const effectiveRoles = allowedRoles.length === 0 && !requiredClaimKey ? ['admin'] : allowedRoles;
        return {
          name: String(r.name).trim(),
          methods: Array.isArray(r.methods) ? r.methods.map(String).map((m: string) => m.trim().toUpperCase()).filter(Boolean) : [],
          path_pattern: String(r.path_pattern).trim(),
          allowed_roles: effectiveRoles,
          ...(requiredClaimKey ? { required_claim_key: requiredClaimKey } : {}),
          ...(requiredClaimKey && requiredClaimValues.length > 0 ? { required_claim_values: requiredClaimValues } : {}),
        };
      });

    settings.bfla = {
      enabled: bf.enabled !== false,
      mode: normMode(bf.mode, 'detect'),
      rules: validRules,
    };
  }

  if (rawSettings.mass_assignment && typeof rawSettings.mass_assignment === 'object') {
    const ma = rawSettings.mass_assignment;
    const rawPathRules = Array.isArray(ma.path_rules) ? ma.path_rules : [];
    const validPathRules = rawPathRules
      .filter((pr: any) => pr && typeof pr === 'object' && pr.path_pattern && Array.isArray(pr.fields) && pr.fields.length > 0)
      .map((pr: any) => ({
        path_pattern: String(pr.path_pattern).trim(),
        fields: pr.fields.map(String).map((s: string) => s.trim()).filter(Boolean),
      }));

    settings.mass_assignment = {
      enabled: ma.enabled !== false,
      mode: normMode(ma.mode, 'detect'),
      protected_fields: Array.isArray(ma.protected_fields) && ma.protected_fields.length > 0
        ? ma.protected_fields.map(String).map((s: string) => s.trim()).filter(Boolean)
        : ['roles', 'admin', 'tenant_id', 'owner_id', 'status', 'scopes', 'role', 'is_admin', 'permissions', 'balance'],
      path_rules: validPathRules,
    };
  }

  if (rawSettings.data_exposure && typeof rawSettings.data_exposure === 'object') {
    const de = rawSettings.data_exposure;
    const handling = String(de.response_handling || '').toLowerCase() === 'redact' ? 'redact' : 'block';
    const sens = String(de.sensitivity || '').toLowerCase() === 'strict' ? 'strict' : 'balanced';
    settings.data_exposure = {
      enabled: de.enabled !== false,
      mode: normMode(de.mode, 'detect'),
      sensitivity: sens,
      inspect_requests: de.inspect_requests !== false,
      inspect_responses: de.response_handling !== 'disable' && de.inspect_responses !== false,
      response_handling: handling,
      detect_secrets: de.detect_secrets !== false,
      detect_tokens: de.detect_tokens !== false,
      detect_payment_data: de.detect_payment_data !== false,
      detect_pii: de.detect_pii !== false,
      detect_debug_data: de.detect_debug_data !== false,
      detect_internal_data: de.detect_internal_data !== false,
      excluded_paths: Array.isArray(de.excluded_paths) ? de.excluded_paths : [],
    };
  }

  if (rawSettings.bola && typeof rawSettings.bola === 'object') {
    const bo = rawSettings.bola;
    const rawOwnershipRules = Array.isArray(bo.ownership_rules) ? bo.ownership_rules : [];
    const validOwnershipRules = rawOwnershipRules
      .filter((or: any) => or && typeof or === 'object' && or.name && or.resource_pattern && or.owner_id_param)
      .map((or: any) => ({
        name: String(or.name).trim(),
        resource_pattern: String(or.resource_pattern).trim(),
        owner_id_param: String(or.owner_id_param).trim(),
        ...(or.owner_id_claim ? { owner_id_claim: String(or.owner_id_claim).trim() } : {}),
        allowed_roles: Array.isArray(or.allowed_roles) ? or.allowed_roles.map(String).map((s: string) => s.trim()).filter(Boolean) : [],
      }));

    const enableOwnership = bo.enable_ownership !== undefined
      ? Boolean(bo.enable_ownership)
      : validOwnershipRules.length > 0;
    const enableTenant = bo.enable_tenant !== undefined
      ? Boolean(bo.enable_tenant)
      : (Array.isArray(bo.isolated_paths) && bo.isolated_paths.length > 0);

    settings.bola = {
      enabled: bo.enabled !== false,
      mode: normMode(bo.mode, 'detect'),
      enable_ownership: enableOwnership,
      enable_tenant: enableTenant,
      enable_idor: bo.enable_idor !== false,
      strict_mode: Boolean(bo.strict_mode),
      isolated_paths: Array.isArray(bo.isolated_paths) ? bo.isolated_paths : [],
      ownership_rules: validOwnershipRules,
    };
  }

  // Workflow / metadata pass-through (if present and supported)
  if (rawSettings.inventory_metadata && typeof rawSettings.inventory_metadata === 'object') {
    settings.inventory_metadata = rawSettings.inventory_metadata;
  }
  if (Array.isArray(rawSettings.dashboard_views)) {
    settings.dashboard_views = rawSettings.dashboard_views;
  }
  if (Array.isArray(rawSettings.alert_rules)) {
    settings.alert_rules = rawSettings.alert_rules;
  }
  if (rawSettings.setup_workflow && typeof rawSettings.setup_workflow === 'object') {
    settings.setup_workflow = rawSettings.setup_workflow;
  }
  if (Array.isArray(rawSettings.exceptions)) {
    settings.exceptions = rawSettings.exceptions;
  }

  return {
    enabled,
    settings,
  };
}

export function normalizeBotConfigForSave(input: any): Record<string, any> {
  const root = input && typeof input === 'object' ? input : {};

  // Strip read-only, retired, or informational properties
  const {
    hmac_secret_configured: _hmacSecretConfigured,
    revision: _revision,
    sdk_version: _sdkVersion,
    sdk_obfuscate: _sdkObfuscate,
    network: _network,
    fingerprint: _fingerprint,
    ...rest
  } = root;

  const payload: Record<string, any> = { ...rest };

  payload.schema_version = 4;

  payload.enabled = payload.enabled !== false;

  const allowedModes = ['permissive', 'balanced', 'strict'];
  const allowedStrictness = ['low', 'balanced', 'high', 'under_attack'];
  const allowedResponseModes = ['log', 'challenge', 'block'];

  let strictness = String(payload.strictness || '').toLowerCase().trim();
  if (!allowedStrictness.includes(strictness)) {
    strictness = 'balanced';
  }
  payload.strictness = strictness;

  let mode = String(payload.mode || '').toLowerCase().trim();
  if (!allowedModes.includes(mode)) {
    // derive from strictness if invalid
    mode = strictness === 'low' ? 'permissive' : (strictness === 'high' || strictness === 'under_attack' ? 'strict' : 'balanced');
  }
  payload.mode = mode;

  let responseMode = String(payload.response_mode || '').toLowerCase().trim();
  if (!allowedResponseModes.includes(responseMode)) {
    responseMode = 'challenge';
  }
  payload.response_mode = responseMode;

  if (typeof payload.protection_level === 'number') {
    payload.protection_level = Math.max(0, Math.min(5, Math.floor(payload.protection_level)));
  }

  if (payload.managed_thresholds && typeof payload.managed_thresholds === 'object') {
    const mt = payload.managed_thresholds;
    const observe = typeof mt.observe === 'number' ? Math.max(0, Math.min(100, Math.floor(mt.observe))) : 30;
    const challenge = typeof mt.challenge === 'number' ? Math.max(observe, Math.min(100, Math.floor(mt.challenge))) : Math.max(observe, 60);
    const block = typeof mt.block === 'number' ? Math.max(challenge, Math.min(100, Math.floor(mt.block))) : Math.max(challenge, 85);
    const repeat = typeof mt.repeat_offender === 'number' ? Math.max(1, Math.min(1000, Math.floor(mt.repeat_offender))) : 3;
    payload.managed_thresholds = {
      observe,
      challenge,
      block,
      repeat_offender: repeat,
    };
  }

  if (payload.detection && typeof payload.detection === 'object') {
    const dt = payload.detection;
    const challengeThreshold = typeof dt.challenge_threshold === 'number' ? Math.max(0, Math.min(100, Math.floor(dt.challenge_threshold))) : 60;
    const blockThreshold = typeof dt.block_threshold === 'number' ? Math.max(challengeThreshold, Math.min(100, Math.floor(dt.block_threshold))) : Math.max(challengeThreshold, 85);
    payload.detection = {
      ...dt,
      enabled: dt.enabled !== false,
      challenge_threshold: challengeThreshold,
      block_threshold: blockThreshold,
      block_datacenters: Boolean(dt.block_datacenters),
    };
  }

  if (payload.classification && typeof payload.classification === 'object') {
    const cl = payload.classification;
    const sanitizedGoodRules: Record<string, { action: string; verify_dns: boolean }> = {};
    if (cl.good_bot_rules && typeof cl.good_bot_rules === 'object') {
      const allowedActions = ['allow', 'block', 'challenge', 'observe', 'log', 'disabled'];
      for (const [botName, r] of Object.entries(cl.good_bot_rules)) {
        if (!botName.trim() || botName.length > 128) continue;
        const ruleObj = (r && typeof r === 'object') ? (r as any) : {};
        const act = String(ruleObj.action || 'allow').toLowerCase().trim();
        sanitizedGoodRules[botName.trim()] = {
          action: allowedActions.includes(act) ? act : 'allow',
          verify_dns: ruleObj.verify_dns !== false,
        };
      }
    }
    payload.classification = {
      ...cl,
      allow_good_bots: cl.allow_good_bots !== false,
      block_bad_bots: cl.block_bad_bots !== false,
      verify_search_engines: cl.verify_search_engines !== false,
      treat_unknown_as_bot: Boolean(cl.treat_unknown_as_bot),
      good_bot_rules: sanitizedGoodRules,
    };
  }

  if (payload.ai_crawlers && typeof payload.ai_crawlers === 'object') {
    const ai = payload.ai_crawlers;
    const sanitizedAiRules: Record<string, { action: string; verify_dns: boolean }> = {};
    if (ai.rules && typeof ai.rules === 'object') {
      const allowedActions = ['allow', 'block', 'challenge', 'observe', 'log', 'disabled'];
      for (const [crawlerName, r] of Object.entries(ai.rules)) {
        if (!crawlerName.trim() || crawlerName.length > 128) continue;
        const ruleObj = (r && typeof r === 'object') ? (r as any) : {};
        const act = String(ruleObj.action || 'challenge').toLowerCase().trim();
        sanitizedAiRules[crawlerName.trim()] = {
          action: allowedActions.includes(act) ? act : 'challenge',
          verify_dns: ruleObj.verify_dns !== false,
        };
      }
    }
    payload.ai_crawlers = {
      ...ai,
      enabled: ai.enabled !== false,
      rules: sanitizedAiRules,
    };
  }

  if (payload.whitelist && typeof payload.whitelist === 'object') {
    const wl = payload.whitelist;
    const cleanList = (arr: any) => (Array.isArray(arr) ? arr.map(String).map((s: string) => s.trim()).filter(Boolean) : []);
    payload.whitelist = {
      ...wl,
      ips: cleanList(wl.ips),
      user_agents: cleanList(wl.user_agents),
      paths: cleanList(wl.paths),
      methods: cleanList(wl.methods).map((m: string) => m.toUpperCase()),
      headers: cleanList(wl.headers),
    };
  }

  return payload;
}

export const apiService = {
  clearCache(pathPrefix?: string): void {
    clearApiCache(pathPrefix);
  },

  async checkSession(): Promise<{ status: string; csrf_token?: string; username?: string; role_id?: number } | null> {
    try {
      const res = await apiFetch('/api/verify_session');
      if (res.ok) {
        const data = await res.json();
        if (data && data.csrf_token) {
          cachedCsrfToken = data.csrf_token;
        }
        return data;
      }
      return null;
    } catch {
      return null;
    }
  },

  getCsrfToken(): string | null {
    return cachedCsrfToken;
  },

  async getOrigins(): Promise<OriginPool[]> {
    try {
      const res = await apiFetch('/api/upstreams');
      if (res.status === 404) return [];
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      return Array.isArray(data)
        ? data.map((item: any, idx: number) => ({
            id: item.name || `pool-${idx}`,
            name: item.name || 'default',
            strategy: item.strategy || 'round_robin',
            targets: Array.isArray(item.targets)
              ? item.targets.map((t: any) => ({
                  url: t.url || '',
                  weight: typeof t.weight === 'number' ? t.weight : 1,
                }))
              : [],
            health_check: item.health_check || { enabled: false },
            sticky: item.sticky || { enabled: false },
          }))
        : [];
    } catch (err) {
      console.error('[Aegis API] getOrigins error:', err);
      throw err;
    }
  },

  async getUpstreamStatus(): Promise<{ data: UpstreamGroupRuntimeStatus[]; available: boolean }> {
    try {
      const res = await apiFetch('/api/upstreams/status');
      if (res.status === 404 || !res.ok) return { data: [], available: false };
      const data = await res.json();
      return { data: Array.isArray(data) ? data : [], available: true };
    } catch {
      return { data: [], available: false };
    }
  },

  async saveOrigin(pool: OriginPool): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const validTargets = (pool.targets || [])
        .filter((t) => t && typeof t.url === 'string' && t.url.trim() !== '')
        .map((t) => ({
          url: t.url.trim(),
          weight: Math.max(1, Math.min(1000, Number(t.weight) || 1)),
        }));

      const payload: Record<string, any> = {
        name: pool.name.trim(),
        strategy: pool.strategy || 'round_robin',
        targets: validTargets,
      };

      if (pool.health_check) {
        const hc = pool.health_check;
        payload.health_check = {
          enabled: Boolean(hc.enabled),
          interval: typeof hc.interval === 'number' ? `${hc.interval}s` : (hc.interval?.trim() || '10s'),
          timeout: typeof hc.timeout === 'number' ? `${hc.timeout}s` : (hc.timeout?.trim() || '3s'),
          path: hc.path?.trim() || '/',
          method: (hc.method || 'GET').toUpperCase(),
          expected_statuses: Array.isArray(hc.expected_statuses) && hc.expected_statuses.length > 0
            ? hc.expected_statuses.map(Number).filter((s) => s >= 100 && s <= 599)
            : [200],
          healthy_threshold: Math.max(1, Math.min(20, Number(hc.healthy_threshold) || 2)),
          unhealthy_threshold: Math.max(1, Math.min(20, Number(hc.unhealthy_threshold) || 3)),
        };
      }

      if (pool.sticky) {
        const st = pool.sticky;
        payload.sticky = {
          enabled: Boolean(st.enabled),
          cookie: st.cookie !== undefined ? st.cookie.trim() : '',
          ttl: st.ttl?.trim() || '24h',
        };
      }

      const res = await apiFetch('/api/upstreams', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const errMsg = errData?.error || `HTTP ${res.status}`;
        console.error(`[Aegis API] saveOrigin failed HTTP ${res.status}:`, errMsg);
        return { success: false, error: errMsg };
      }

      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] saveOrigin error:', err);
      return { success: false, error: err?.message || 'Network error saving origin pool' };
    }
  },

  async deleteOrigin(name: string): Promise<{ success: boolean; error?: string }> {
    try {
      const trimmed = name.trim();
      const res = await apiFetch(`/api/upstreams?name=${encodeURIComponent(trimmed)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: trimmed }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const errMsg = errData?.error || `HTTP ${res.status}`;
        console.error(`[Aegis API] deleteOrigin failed HTTP ${res.status}:`, errMsg);
        return { success: false, error: errMsg };
      }

      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] deleteOrigin error:', err);
      return { success: false, error: err?.message || 'Network error deleting origin pool' };
    }
  },

  async getCircuitBreakerSettings(): Promise<CircuitBreakerConfig> {
    const res = await apiFetch('/api/upstreams/circuit-breaker');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async saveCircuitBreakerSettings(config: CircuitBreakerConfig): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/upstreams/circuit-breaker', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        return { success: false, error: errData?.error || `HTTP ${res.status}` };
      }
      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Failed to save circuit breaker settings' };
    }
  },

  async getStickySecretStatus(): Promise<StickySecretStatus> {
    const res = await apiFetch('/api/upstreams/sticky-secret');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async saveStickySecret(secret: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/upstreams/sticky-secret', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret_ref: secret }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        return { success: false, error: errData?.error || `HTTP ${res.status}` };
      }
      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Failed to save sticky secret' };
    }
  },

  async getRoutes(): Promise<RouteRecord[]> {
    try {
      const res = await apiFetch('/api/routes');
      if (res.status === 404) return [];
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      const list = Array.isArray(data) ? data : data?.routes || [];
      return list.map((r: any, idx: number) => {
        const hosts = r.match?.hosts?.length ? r.match.hosts : (r.hosts || ['*']);
        const paths = r.match?.paths?.length ? r.match.paths : (r.paths || ['/']);
        const backends = r.action?.backends?.length ? r.action.backends : (r.backends || []);
        return {
          id: r.id || `route-${idx}`,
          name: r.name || `Route ${idx + 1}`,
          priority: r.priority !== undefined ? r.priority : 100,
          hosts,
          paths,
          match: {
            hosts,
            paths,
            methods: Array.isArray(r.match?.methods) ? r.match.methods : [],
            source_cidrs: Array.isArray(r.match?.source_cidrs) ? r.match.source_cidrs : [],
            headers: r.match?.headers && typeof r.match.headers === 'object' ? r.match.headers : {},
            query: r.match?.query && typeof r.match.query === 'object' ? r.match.query : {},
          },
          action: {
            upstream: r.action?.upstream || '',
            backends: Array.isArray(backends)
              ? backends.map((b: any) => ({
                  url: b.url || '',
                  weight: typeof b.weight === 'number' ? b.weight : 1,
                }))
              : [],
            strategy: r.action?.strategy || r.load_balance || 'round_robin',
            strip_prefix: r.action?.strip_prefix || r.strip_prefix || '',
            rewrite_path: r.action?.rewrite_path || '',
            preserve_host: r.action?.preserve_host ?? true,
            timeout: r.action?.timeout || '',
            retries: r.action?.retries ?? 0,
          },
          backends: Array.isArray(backends)
            ? backends.map((b: any) => ({
                url: b.url || '',
                weight: typeof b.weight === 'number' ? b.weight : 1,
              }))
            : [],
          load_balance: r.load_balance || r.action?.strategy,
          strip_prefix: r.strip_prefix || r.action?.strip_prefix,
          enabled: r.enabled !== false,
          security: {
            waf_core: r.security?.waf_core !== false,
            traffic_control: r.security?.traffic_control !== false,
            http_security: r.security?.http_security !== false,
            bot_protection: r.security?.bot_protection !== false,
            api_security: r.security?.api_security !== false,
            access_control: Boolean(r.security?.access_control),
            country: r.security?.country,
          },
        };
      });
    } catch (err) {
      console.error('[Aegis API] getRoutes error:', err);
      throw err;
    }
  },

  async saveRoute(route: RouteRecord): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const isEdit = Boolean(route.id?.trim());
      const hosts = Array.isArray(route.hosts) && route.hosts.length
        ? route.hosts.map((h) => h.trim()).filter(Boolean)
        : ['*'];
      const paths = Array.isArray(route.paths) && route.paths.length
        ? route.paths.map((p) => p.trim()).filter(Boolean)
        : ['/'];
      const actionUpstream = (route.action?.upstream || '').trim();

      const rawBackends = Array.isArray(route.action?.backends) && route.action!.backends.length > 0
        ? route.action!.backends
        : (Array.isArray(route.backends) ? route.backends : []);

      const validBackends = rawBackends
        .filter((b) => b && typeof b.url === 'string' && b.url.trim() !== '')
        .map((b) => ({
          url: b.url.trim(),
          weight: Math.max(1, Math.min(1000, Number(b.weight) || 1)),
        }));

      const cleanMethods = Array.isArray(route.match?.methods)
        ? route.match!.methods.map((m) => m.trim().toUpperCase()).filter(Boolean)
        : [];

      const cleanCIDRs = Array.isArray(route.match?.source_cidrs)
        ? route.match!.source_cidrs.map((c) => c.trim()).filter(Boolean)
        : [];

      const payload: Record<string, any> = {
        ...(route.id?.trim() ? { id: route.id.trim() } : {}),
        name: route.name?.trim() || 'Route',
        priority: Math.max(1, Math.min(10000, Number(route.priority) || 100)),
        hosts,
        paths,
        match: {
          hosts,
          paths,
          methods: cleanMethods,
          source_cidrs: cleanCIDRs,
          headers: route.match?.headers && typeof route.match.headers === 'object' && !Array.isArray(route.match.headers)
            ? route.match.headers
            : {},
          query: route.match?.query && typeof route.match.query === 'object' && !Array.isArray(route.match.query)
            ? route.match.query
            : {},
        },
        action: {
          upstream: actionUpstream,
          backends: validBackends,
          strategy: route.action?.strategy || 'round_robin',
          strip_prefix: route.action?.strip_prefix?.trim() || '',
          rewrite_path: route.action?.rewrite_path?.trim() || '',
          preserve_host: route.action?.preserve_host ?? true,
          timeout: route.action?.timeout?.trim() || '',
          retries: Math.max(0, Math.min(5, Number(route.action?.retries) || 0)),
        },
        backends: validBackends,
        enabled: route.enabled !== false,
        security: {
          waf_core: route.security?.waf_core !== false,
          traffic_control: route.security?.traffic_control !== false,
          http_security: route.security?.http_security !== false,
          bot_protection: route.security?.bot_protection !== false,
          api_security: route.security?.api_security !== false,
          access_control: Boolean(route.security?.access_control),
        },
      };

      if (route.security?.country) {
        payload.security.country = route.security.country;
      }

      let res: Response;
      if (isEdit) {
        res = await apiFetch('/api/routes', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
        if (res.status === 404) {
          res = await apiFetch('/api/routes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
        }
      } else {
        res = await apiFetch('/api/routes', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const errMsg = errData?.error || `HTTP ${res.status}`;
        console.error(`[Aegis API] saveRoute failed HTTP ${res.status}:`, errMsg);
        return { success: false, error: errMsg };
      }

      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] saveRoute error:', err);
      return { success: false, error: err?.message || 'Network error saving route' };
    }
  },

  async deleteRoute(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const trimmedId = id.trim();
      const res = await apiFetch(`/api/routes?id=${encodeURIComponent(trimmedId)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: trimmedId }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        const errMsg = errData?.error || `HTTP ${res.status}`;
        console.error(`[Aegis API] deleteRoute failed HTTP ${res.status}:`, errMsg);
        return { success: false, error: errMsg };
      }

      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] deleteRoute error:', err);
      return { success: false, error: err?.message || 'Network error deleting route' };
    }
  },

  async testRoute(req: RouteTestRequest): Promise<RouteTestResponse> {
    try {
      let res = await apiFetch('/api/infrastructure/routes/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (res.status === 404) {
        res = await apiFetch('/api/edge/routes/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(req),
        });
      }
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.error || `HTTP ${res.status}`);
      }
      return res.json();
    } catch (err: any) {
      console.error('[Aegis API] testRoute error:', err);
      throw err;
    }
  },

  async getProtectedApps(): Promise<{ apps: AppV2[]; available: boolean }> {
    try {
      const res = await apiFetch('/api/sections/access_control/protected-apps/catalog');
      if (!res.ok) {
        return { apps: [], available: false };
      }
      const data = await res.json();
      const list: AppV2[] = Array.isArray(data)
        ? data
        : Array.isArray(data?.apps)
        ? data.apps.map((item: any) => item.protected_app || item)
        : [];
      return { apps: list, available: true };
    } catch {
      return { apps: [], available: false };
    }
  },

  async getProxySettings(): Promise<ProxySettingsResponse> {
    const res = await apiFetch('/api/infrastructure/proxy-settings');
    if (res.status === 404) {
      const legacyRes = await apiFetch('/api/config');
      if (legacyRes.ok) {
        const legacy = await legacyRes.json();
        const infra = legacy.infrastructure || {};
        const trusted = infra.trusted_proxies || {};
        const mode = infra.mode || 'standalone';
        return {
          settings: {
            mode,
            proxy_provider: infra.proxy_provider || 'nginx',
            public_base_url: infra.public_base_url || 'https://example.com',
            aegis_address: infra.aegis_address || `http://127.0.0.1:${legacy.server?.port || 8080}`,
            trusted_proxies: {
              enabled: mode !== 'standalone',
              cidrs: trusted.cidrs || ['127.0.0.1/32', '::1/128'],
              real_ip_headers: trusted.real_ip_headers || ['X-Forwarded-For', 'X-Real-IP'],
              proto_header: trusted.proto_header || 'X-Forwarded-Proto',
              host_header: trusted.host_header || 'X-Forwarded-Host',
              forwarded_header: trusted.forwarded_header === true,
              recursive: trusted.recursive !== false,
              source_urls: trusted.source_urls || [],
              source_files: trusted.source_files || [],
              source_root: trusted.source_root || './data/trusted-proxies/sources',
              combined_list: trusted.combined_list || './data/trusted-proxies/combined.list',
            },
          },
          runtime: { applied: false, restart_required: true, revision: 'legacy' },
          trusted_list: {
            path: './data/trusted-proxies/combined.list',
            exists: false,
            entries: 0,
            configured_sources: 0,
          },
        };
      }
    }
    if (!res.ok) {
      let errMsg = `Request failed: ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson && errJson.error) errMsg = errJson.error;
      } catch {}
      throw new Error(errMsg);
    }
    const data = await res.json();
    const rawSettings = data.settings || {};
    const mode = (rawSettings.mode && String(rawSettings.mode).trim() as DeploymentMode) || 'standalone';
    return {
      settings: {
        mode,
        proxy_provider: rawSettings.proxy_provider || 'nginx',
        public_base_url: rawSettings.public_base_url || 'https://example.com',
        aegis_address: rawSettings.aegis_address || 'http://127.0.0.1:8080',
        trusted_proxies: rawSettings.trusted_proxies || {
          enabled: mode !== 'standalone',
          cidrs: ['127.0.0.1/32', '::1/128'],
          real_ip_headers: ['X-Forwarded-For', 'X-Real-IP'],
          proto_header: 'X-Forwarded-Proto',
          host_header: 'X-Forwarded-Host',
          forwarded_header: false,
          recursive: true,
          source_urls: [],
          source_files: [],
          source_root: './data/trusted-proxies/sources',
          combined_list: './data/trusted-proxies/combined.list',
        },
      },
      runtime: data.runtime || { applied: true, restart_required: false, revision: '1' },
      trusted_list: data.trusted_list || {
        path: './data/trusted-proxies/combined.list',
        exists: false,
        entries: 0,
        configured_sources: 0,
      },
    };
  },

  async saveProxySettings(settings: InfrastructureSettings): Promise<{
    ok: boolean;
    restartRequired?: boolean;
    data?: ProxySettingsResponse;
    error?: string;
  }> {
    try {
      const mode = settings.mode || 'standalone';
      const isStandalone = mode === 'standalone';
      const payload: InfrastructureSettings = {
        mode,
        proxy_provider: settings.proxy_provider || 'nginx',
        public_base_url: settings.public_base_url || 'https://example.com',
        aegis_address: settings.aegis_address || 'http://127.0.0.1:8080',
        trusted_proxies: {
          enabled: !isStandalone,
          cidrs: settings.trusted_proxies?.cidrs || [],
          real_ip_headers: settings.trusted_proxies?.real_ip_headers?.length
            ? settings.trusted_proxies.real_ip_headers
            : ['X-Forwarded-For', 'X-Real-IP'],
          proto_header: settings.trusted_proxies?.proto_header || 'X-Forwarded-Proto',
          host_header: settings.trusted_proxies?.host_header || 'X-Forwarded-Host',
          forwarded_header: !isStandalone && (settings.trusted_proxies?.forwarded_header === true),
          recursive: settings.trusted_proxies?.recursive !== false,
          source_urls: settings.trusted_proxies?.source_urls || [],
          source_files: settings.trusted_proxies?.source_files || [],
          source_root: settings.trusted_proxies?.source_root || './data/trusted-proxies/sources',
          combined_list: settings.trusted_proxies?.combined_list || './data/trusted-proxies/combined.list',
        },
      };

      const res = await apiFetch('/api/infrastructure/proxy-settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        let errMsg = `Request failed: ${res.status}`;
        try {
          const errData = await res.json();
          if (errData && errData.error) errMsg = errData.error;
        } catch {}
        return { ok: false, error: errMsg };
      }

      const responseData: ProxySettingsResponse = await res.json();
      return {
        ok: true,
        restartRequired: responseData.runtime?.restart_required ?? false,
        data: responseData,
      };
    } catch (err: any) {
      console.error('[Aegis API] saveProxySettings error:', err);
      return { ok: false, error: err?.message || 'Failed to update proxy settings' };
    }
  },

  async getProxyTemplate(
    provider: string,
    publicBaseUrl: string,
    aegisAddress: string,
    signal?: AbortSignal
  ): Promise<ProxyGuideResponse> {
    const query = new URLSearchParams({
      public_base_url: publicBaseUrl,
      aegis_address: aegisAddress,
    });
    const res = await apiFetch(`/api/infrastructure/templates/${encodeURIComponent(provider)}?${query}`, {
      headers: { Accept: 'application/json' },
      signal,
    });
    if (!res.ok) {
      let errMsg = `Guide request failed: ${res.status}`;
      try {
        const errJson = await res.json();
        if (errJson && errJson.error) errMsg = errJson.error;
      } catch {}
      throw new Error(errMsg);
    }
    return await res.json();
  },

  async getCertificates(): Promise<CertificateRecord[]> {
    try {
      const res = await apiFetch('/api/certificates');
      if (!res.ok) {
        if (res.status === 404) return [];
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      return Array.isArray(data) ? data : [];
    } catch (err) {
      console.error('[Aegis API] getCertificates error:', err);
      throw err;
    }
  },

  async getTLSConfig(): Promise<TLSConfigState> {
    try {
      const res = await apiFetch('/api/certificates/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[Aegis API] getTLSConfig error:', err);
      throw err;
    }
  },

  async saveTLSConfig(config: TLSConfigState): Promise<{ success: boolean; restart_required?: boolean; error?: string }> {
    try {
      const payload = {
        enabled: Boolean(config.enabled),
        auto: Boolean(config.auto),
        domains: Array.isArray(config.domains) ? config.domains : [],
        email: config.email ? config.email.trim() : '',
      };
      const res = await apiFetch('/api/certificates/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        const errorMsg = errData?.error || `HTTP ${res.status}: Failed to save TLS settings`;
        console.error(`[Aegis API] saveTLSConfig failed HTTP ${res.status}:`, errorMsg);
        return { success: false, error: errorMsg };
      }
      const data = await res.json().catch(() => ({}));
      return { success: true, restart_required: Boolean(data?.restart_required) };
    } catch (err: any) {
      console.error('[Aegis API] saveTLSConfig error:', err);
      return { success: false, error: err?.message || 'Network error saving TLS settings' };
    }
  },

  async deleteCertificate(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/certificates', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        const errorMsg = errData?.error || `HTTP ${res.status}: Failed to delete certificate`;
        console.error(`[Aegis API] deleteCertificate failed HTTP ${res.status}:`, errorMsg);
        return { success: false, error: errorMsg };
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] deleteCertificate error:', err);
      return { success: false, error: err?.message || 'Network error deleting certificate' };
    }
  },

  async uploadCertificate(certData: {
    domain?: string;
    certPem?: string;
    keyPem?: string;
    certFile?: File;
    keyFile?: File;
  }): Promise<{ success: boolean; restart_required?: boolean; warnings?: string[]; error?: string }> {
    try {
      const formData = new FormData();
      formData.append('domain', certData.domain || '');
      if (certData.certFile) {
        formData.append('certificate', certData.certFile);
      } else if (certData.certPem) {
        formData.append('certificate', new Blob([certData.certPem], { type: 'application/x-pem-file' }), 'cert.pem');
      }
      if (certData.keyFile) {
        formData.append('key', certData.keyFile);
      } else if (certData.keyPem) {
        formData.append('key', new Blob([certData.keyPem], { type: 'application/x-pem-file' }), 'key.pem');
      }

      const res = await apiFetch('/api/certificates', {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        const errorMsg = errData?.error || `HTTP ${res.status}: Failed to upload certificate`;
        console.error(`[Aegis API] uploadCertificate failed HTTP ${res.status}:`, errorMsg);
        return { success: false, error: errorMsg };
      }
      const data = await res.json().catch(() => ({}));
      return {
        success: true,
        restart_required: Boolean(data?.restart_required),
        warnings: Array.isArray(data?.warnings) ? data.warnings : [],
      };
    } catch (err: any) {
      console.error('[Aegis API] uploadCertificate error:', err);
      return { success: false, error: err?.message || 'Network error uploading certificate' };
    }
  },

  async getWafFullConfig(): Promise<{ config: WAFSectionConfig; health: WAFHealth }> {
    try {
      const res = await apiFetch('/api/sections/waf_core/config');
      if (res.ok) {
        const data = await res.json();
        return {
          config: data.config || {},
          health: data.health || {},
        };
      }
      console.error(`[Aegis API] getWafFullConfig HTTP ${res.status}`);
    } catch (err) {
      console.error('[Aegis API] getWafFullConfig error:', err);
    }
    return {
      config: {},
      health: {},
    };
  },

  async saveWafFullConfig(
    config: Partial<WAFSectionConfig>,
    baseServerConfig?: WAFSectionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const source = { ...(baseServerConfig || {}), ...config };
      const isCommunityBackend =
        source.protection_level !== undefined &&
        source.crs_paranoia_level === undefined &&
        source.active_policy_id === undefined &&
        source.failure_mode === undefined;

      let payload: Record<string, any>;

      if (isCommunityBackend) {
        const strictness = Number(
          config.rule_strictness ??
            config.crs_paranoia_level ??
            source.engine?.paranoia_level ??
            source.rule_strictness ??
            1,
        );
        const threshold = Number(
          config.anomaly_threshold ??
            source.engine?.anomaly_threshold ??
            source.anomaly_threshold ??
            5,
        );
        const maxReqBody = Number(
          config.max_request_body_size ??
            source.validation?.max_body_size ??
            source.max_request_body_size ??
            10 * 1024 * 1024,
        );
        const maxRespBody = Number(
          config.max_response_body_size ??
            source.max_response_body_size ??
            10 * 1024 * 1024,
        );
        const crsEnabled =
          config.crs_enabled !== undefined
            ? Boolean(config.crs_enabled)
            : source.engine?.enable_crs !== false && source.crs_enabled !== false;

        payload = {
          enabled: source.enabled !== false && source.mode !== 'off',
          mode: source.mode || 'blocking',
          protection_level: Number(source.protection_level) || strictness || 3,
          engine: {
            ...(source.engine || {}),
            paranoia_level: strictness,
            anomaly_threshold: threshold,
            enable_crs: crsEnabled,
          },
          validation: {
            ...(source.validation || {}),
            max_body_size: maxReqBody,
          },
          response_inspection: source.response_inspection !== false,
          max_response_body_size: maxRespBody,
        };
        if (Array.isArray(source.excluded_paths)) {
          payload.excluded_paths = source.excluded_paths;
        }
        if (source.active_profile_id !== undefined) {
          payload.active_profile_id = source.active_profile_id;
        }
      } else {
        // Commercial backend strictly validates known WAFConfig HTTP fields and rejects
        // server-managed or unknown fields (security_hardening.go).
        const allowedTopLevelKeys = [
          'enabled',
          'mode',
          'failure_mode',
          'rule_strictness',
          'crs_enabled',
          'crs_paranoia_level',
          'custom_rules_enabled',
          'excluded_paths',
          'active_policy_id',
          'active_profile_id',
          'anomaly_threshold',
          'outbound_anomaly_threshold',
          'max_request_body_size',
          'rule_groups',
          'response_inspection',
          'max_response_body_size',
          'leak_protection',
          'upload_protection',
          'request_body_guard',
        ] as const;

        payload = {};
        for (const key of allowedTopLevelKeys) {
          if (source[key] !== undefined) {
            payload[key] = source[key];
          }
        }

        // Keep active_profile_id and active_policy_id strictly synchronized
        if (config.active_profile_id !== undefined) {
          payload.active_profile_id = config.active_profile_id;
          payload.active_policy_id = config.active_profile_id;
        } else if (config.active_policy_id !== undefined) {
          payload.active_policy_id = config.active_policy_id;
          payload.active_profile_id = config.active_policy_id;
        }

        if (payload.leak_protection && typeof payload.leak_protection === 'object') {
          const lp = payload.leak_protection as WAFLeakProtectionConfig;
          const sanitizedLp: Record<string, any> = {
            enabled: Boolean(lp.enabled),
            mode: lp.mode || lp.default_action || 'detect',
            default_action: lp.default_action || lp.mode || 'detect',
            max_body_size: Number(lp.max_body_size) || 1048576,
            inspect_content_types: Array.isArray(lp.inspect_content_types)
              ? lp.inspect_content_types
              : ['text/html', 'text/plain', 'application/json', 'application/javascript', 'text/xml', 'application/xml'],
            skip_content_types: Array.isArray(lp.skip_content_types)
              ? lp.skip_content_types
              : ['image/*', 'video/*', 'audio/*', 'font/*', 'application/octet-stream', 'application/pdf'],
            redaction_enabled: lp.redaction_enabled !== false,
            block_status_code: Number(lp.block_status_code) || 403,
            replacement_body: lp.replacement_body ?? 'Response blocked by Aegis Leak Protection',
            rules: lp.rules || lp.categories || {},
            custom_patterns: Array.isArray(lp.custom_patterns)
              ? lp.custom_patterns.map((p) => ({
                  id: p.id,
                  name: p.name,
                  pattern: p.pattern || '',
                  category: p.category || 'custom',
                  severity: p.severity || 'medium',
                  action: p.action || '',
                  enabled: p.enabled !== false,
                  confidence: Number(p.confidence) || 75,
                }))
              : [],
            allowlist: Array.isArray(lp.allowlist)
              ? lp.allowlist.map((entry) => ({
                  id: entry.id,
                  enabled: entry.enabled !== false,
                  category: entry.category || '',
                  host: entry.host || '',
                  path: entry.path || '',
                  content_type: entry.content_type || '',
                  expires_at: entry.expires_at || '',
                  reason: entry.reason || '',
                }))
              : [],
          };
          payload.leak_protection = sanitizedLp;
        }
      }

      const res = await apiFetch('/api/sections/waf_core/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (res.ok) {
        return { success: true };
      }
      let errorMsg = `Server error (${res.status})`;
      try {
        const data = await res.json();
        if (data && (data.error || data.message)) {
          errorMsg = data.error || data.message;
        }
      } catch {
        const text = await res.text().catch(() => '');
        if (text) errorMsg = text.trim();
      }
      return { success: false, error: errorMsg };
    } catch (err: any) {
      console.error('[Aegis API] saveWafFullConfig error:', err);
      return { success: false, error: err?.message || 'Connection error. Please try again.' };
    }
  },

  async getWafStats(): Promise<WAFConfigDashboardStats | null> {
    try {
      const res = await apiFetch('/api/sections/waf_core/dashboard?window=24h');
      if (res.ok) {
        const data = await res.json();
        if (data?.dashboard) {
          return data.dashboard;
        }
        if (data?.total_requests !== undefined || data?.TotalRequests !== undefined) {
          return {
            total_requests: data.total_requests ?? data.TotalRequests ?? 0,
            blocked_requests: data.blocked_requests ?? data.BlockedRequests ?? 0,
            allowed_requests: data.allowed_requests ?? data.AllowedRequests ?? 0,
          };
        }
      }
      const statsRes = await apiFetch('/api/sections/waf_core/stats');
      if (statsRes.ok) {
        const data = await statsRes.json();
        return {
          total_requests: data.total_requests ?? data.TotalRequests ?? 0,
          blocked_requests: data.blocked_requests ?? data.BlockedRequests ?? 0,
          allowed_requests: data.allowed_requests ?? data.AllowedRequests ?? 0,
          engine: data.engine,
        };
      }
    } catch (err) {
      console.warn('[Aegis API] getWafStats error:', err);
    }
    return null;
  },

  async getWafProfiles(): Promise<WAFProfile[]> {
    try {
      const res = await apiFetch('/api/sections/waf_core/profiles');
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data.profiles) ? data.profiles : (Array.isArray(data.policies) ? data.policies : []);
      }
    } catch (err) {
      console.warn('[Aegis API] getWafProfiles error:', err);
    }
    return [];
  },

  async getWafCrsFiles(): Promise<WAFManagedRuleFile[]> {
    try {
      const res = await apiFetch('/api/sections/waf_core/rules/crs');
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data.files) ? data.files : [];
      }
    } catch (err) {
      console.warn('[Aegis API] getWafCrsFiles error:', err);
    }
    return [];
  },

  async toggleWafCrsFile(fileName: string, action: 'enable' | 'disable'): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/rules/crs?file=${encodeURIComponent(fileName)}&action=${action}`, {
        method: 'POST',
      });
      if (res.ok) {
        return { success: true };
      }
      let errorMsg = `Server error (${res.status})`;
      try {
        const text = await res.text();
        if (text) {
          try {
            const data = JSON.parse(text);
            errorMsg = data.error || data.message || text;
          } catch {
            errorMsg = text;
          }
        }
      } catch {
      }
      return { success: false, error: errorMsg };
    } catch (err: any) {
      console.error('[Aegis API] toggleWafCrsFile error:', err);
      return { success: false, error: err?.message || 'Network error toggling ruleset' };
    }
  },

  async bulkToggleWafCrsFiles(files: string[], action: 'enable' | 'disable'): Promise<{
    success: boolean;
    changed?: string[];
    skipped?: string[];
    error?: string;
  }> {
    try {
      const res = await apiFetch('/api/sections/waf_core/rules/crs/bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action, files }),
      });
      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        return {
          success: true,
          changed: Array.isArray(data?.changed) ? data.changed : [],
          skipped: Array.isArray(data?.skipped) ? data.skipped : [],
        };
      }
      let errorMsg = `Server error (${res.status})`;
      try {
        const text = await res.text();
        if (text) {
          try {
            const data = JSON.parse(text);
            errorMsg = data.error || data.message || text;
          } catch {
            errorMsg = text;
          }
        }
      } catch {
      }
      return { success: false, error: errorMsg };
    } catch (err: any) {
      console.error('[Aegis API] bulkToggleWafCrsFiles error:', err);
      return { success: false, error: err?.message || 'Network error updating rulesets' };
    }
  },

  async getWafCrsFileContent(fileName: string): Promise<{ success: boolean; content?: string; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/rules/crs?file=${encodeURIComponent(fileName)}&content=true`);
      if (res.ok) {
        const content = await res.text();
        return { success: true, content };
      }
      let errorMsg = `HTTP ${res.status}`;
      try {
        const text = await res.text();
        if (text) errorMsg = text;
      } catch {
      }
      return { success: false, error: errorMsg };
    } catch (err: any) {
      console.warn('[Aegis API] getWafCrsFileContent error:', err);
      return { success: false, error: err?.message || 'Failed to fetch ruleset content' };
    }
  },

  async getWafConfig(): Promise<WafCoreConfig> {
    const { config: cfg, health } = await this.getWafFullConfig();
    const rawMode = String(cfg.mode || 'blocking').toLowerCase();
    const mode = rawMode === 'detection' ? 'detection' : 'prevention';
    const paranoia = Number(cfg.rule_strictness ?? cfg.crs_paranoia_level ?? cfg.engine?.paranoia_level ?? 1);
    const threshold = Number(cfg.anomaly_threshold ?? cfg.engine?.anomaly_threshold ?? 5);
    return {
      enabled: cfg.enabled !== false && rawMode !== 'off',
      mode,
      paranoia_level: paranoia,
      inbound_anomaly_threshold: threshold,
      outbound_anomaly_threshold: Number(cfg.outbound_anomaly_threshold || (threshold > 1 ? threshold - 1 : 4)),
      response_inspection: cfg.response_inspection !== false,
      health: health as any,
    };
  },

  async saveWafConfig(config: WafCoreConfig): Promise<{ success: boolean; error?: string }> {
    const { config: currentServerConfig } = await this.getWafFullConfig();
    const backendMode = config.enabled === false ? 'off' : (config.mode === 'detection' ? 'detection' : 'blocking');
    const strictness = Number(config.paranoia_level) || 1;
    const threshold = Number(config.inbound_anomaly_threshold) || 5;
    return this.saveWafFullConfig(
      {
        enabled: config.enabled !== false,
        mode: backendMode,
        rule_strictness: strictness,
        crs_paranoia_level: strictness,
        anomaly_threshold: threshold,
        outbound_anomaly_threshold: Number(config.outbound_anomaly_threshold) || 4,
        response_inspection: config.response_inspection !== false,
      },
      currentServerConfig,
    );
  },

  async getCrsRules(): Promise<CrsRuleGroup[]> {
    try {
      const res = await apiFetch('/api/sections/waf_core/rules/crs');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (Array.isArray(data?.files)) {
        return data.files.map((f: any, idx: number) => {
          const name = f.name || `crs-${idx}`;
          const cleanName = name
            .replace(/^REQUEST-/, '')
            .replace(/\.conf$/, '')
            .replace(/-/g, ' ');
          return {
            id: name,
            file_name: name,
            name: cleanName,
            description: f.description || `OWASP CRS Rule Group: ${cleanName}`,
            category: (f.category as any) || 'attack',
            rule_count: f.rule_count || 0,
            paranoia_level: f.paranoia_level || 1,
            enabled: f.enabled !== false,
          };
        });
      }
    } catch (err) {
      console.error('[Aegis API] getCrsRules error:', err);
    }
    return [];
  },

  async toggleCrsRule(id: string, enabled: boolean): Promise<boolean> {
    try {
      const action = enabled ? 'enable' : 'disable';
      const res = await apiFetch(`/api/sections/waf_core/rules/crs?file=${encodeURIComponent(id)}&action=${action}`, {
        method: 'POST',
      });
      return res.ok;
    } catch (err) {
      console.error('[Aegis API] toggleCrsRule error:', err);
      return false;
    }
  },

  async getCustomRules(): Promise<WAFCustomRule[]> {
    try {
      const res = await apiFetch('/api/sections/waf_core/rules/custom');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (Array.isArray(data?.rules)) {
        return data.rules;
      }
    } catch (err) {
      console.error('[Aegis API] getCustomRules error:', err);
    }
    return [];
  },

  async getCustomRule(id: string): Promise<WAFRuleDetailResponse | null> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/rules/custom/${encodeURIComponent(id)}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return data;
    } catch (err) {
      console.warn('[Aegis API] getCustomRule error:', err);
      const all = await this.getCustomRules();
      const r = all.find((x) => x.id === id);
      if (r) {
        return { rule: r, valid: r.valid !== false, validation_errors: r.validation_errors };
      }
      return null;
    }
  },

  async saveCustomRule(rule: WAFCustomRule, isEdit?: boolean): Promise<{ success: boolean; error?: string }> {
    try {
      const payload = {
        schema_version: rule.schema_version || 1,
        id: rule.id,
        name: rule.name,
        message: rule.message || rule.name,
        severity: rule.severity || 'medium',
        score: Number(rule.score) || 25,
        enabled: rule.enabled !== false,
        tags: rule.tags && rule.tags.length > 0 ? rule.tags : ['custom', 'local'],
        targets: rule.targets || [],
      };

      const res =
        isEdit && rule.id
          ? await apiFetch(`/api/sections/waf_core/rules/custom/${encodeURIComponent(rule.id)}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            })
          : await apiFetch('/api/sections/waf_core/rules/custom', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
            });

      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const text = await res.text();
          if (text) {
            try {
              const json = JSON.parse(text);
              errMsg = json.error || json.message || text.trim();
            } catch {
              errMsg = text.trim();
            }
          }
        } catch {
        }
        return { success: false, error: errMsg };
      }

      // Ensure custom_rules_enabled is active on the WAF engine when a rule is created and enabled
      if (payload.enabled) {
        const { config: currentCfg } = await this.getWafFullConfig();
        if (currentCfg && currentCfg.custom_rules_enabled === false) {
          await this.saveWafFullConfig({ custom_rules_enabled: true }, currentCfg);
        }
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] saveCustomRule error:', err);
      return { success: false, error: err?.message || 'Failed to save custom rule' };
    }
  },

  async toggleCustomRule(id: string, enabled: boolean): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/rules/custom/${encodeURIComponent(id)}/enabled`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const text = await res.text();
          if (text) {
            try {
              const json = JSON.parse(text);
              errMsg = json.error || json.message || text.trim();
            } catch {
              errMsg = text.trim();
            }
          }
        } catch {
        }
        return { success: false, error: errMsg };
      }
      if (enabled) {
        const { config: currentCfg } = await this.getWafFullConfig();
        if (currentCfg && currentCfg.custom_rules_enabled === false) {
          await this.saveWafFullConfig({ custom_rules_enabled: true }, currentCfg);
        }
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] toggleCustomRule error:', err);
      return { success: false, error: err?.message || 'Failed to toggle custom rule' };
    }
  },

  async deleteCustomRule(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/rules/custom/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const text = await res.text();
          if (text) {
            try {
              const json = JSON.parse(text);
              errMsg = json.error || json.message || text.trim();
            } catch {
              errMsg = text.trim();
            }
          }
        } catch {
        }
        return { success: false, error: errMsg };
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] deleteCustomRule error:', err);
      return { success: false, error: err?.message || 'Failed to delete custom rule' };
    }
  },

  async testCustomRule(
    rule: WAFCustomRule,
    request?: { method?: string; uri?: string; headers?: Record<string, string>; body?: string },
  ): Promise<{ success: boolean; valid?: boolean; matched?: boolean; matches?: any[]; error?: string }> {
    try {
      const payload = {
        rule: {
          schema_version: rule.schema_version || 1,
          id: rule.id || 'draft-rule',
          name: rule.name || 'Draft Rule',
          message: rule.message || rule.name,
          severity: rule.severity || 'medium',
          score: Number(rule.score) || 25,
          enabled: true,
          tags: rule.tags && rule.tags.length > 0 ? rule.tags : ['custom'],
          targets: rule.targets || [],
        },
        request: {
          method: request?.method || 'GET',
          uri: request?.uri || '/test',
          headers: request?.headers || {},
          body: request?.body || '',
        },
      };
      const res = await apiFetch('/api/sections/waf_core/rules/custom/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        const matches = data?.matched_rules || data?.matches || [];
        return {
          success: true,
          valid: data?.valid !== false,
          matched: Boolean(data?.matched ?? (matches.length > 0)),
          matches,
        };
      }
      return { success: false, valid: false, matched: false, error: data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] testCustomRule error:', err);
      return { success: false, error: err?.message || 'Failed to test custom rule' };
    }
  },

  async testWafConfig(config: Partial<WAFSectionConfig>): Promise<{ success: boolean; valid?: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/waf_core/config/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        return { success: true, valid: data?.valid !== false };
      }
      return { success: false, valid: false, error: data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] testWafConfig error:', err);
      return { success: false, error: err?.message || 'Failed to test WAF configuration' };
    }
  },

  async testLeakProtection(params: {
    body: string;
    path?: string;
    host?: string;
    headers?: Record<string, string>;
    status_code?: number;
  }): Promise<{ success: boolean; result?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/waf_core/leak-protection/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          body: params.body,
          path: params.path || '/test',
          host: params.host || 'localhost',
          headers: params.headers || { 'Content-Type': 'text/plain' },
          status_code: params.status_code || 200,
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        return { success: true, result: data?.result };
      }
      return { success: false, error: data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] testLeakProtection error:', err);
      return { success: false, error: err?.message || 'Failed to test leak protection' };
    }
  },

  async getExclusions(): Promise<WAFExclusion[]> {
    try {
      const res = await apiFetch('/api/sections/waf_core/exclusions');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (Array.isArray(data?.exclusions)) {
        return data.exclusions.map((e: any, idx: number) => {
          const paths = Array.isArray(e.paths)
            ? e.paths
            : e.path_pattern
              ? [e.path_pattern]
              : [];
          const params = Array.isArray(e.params) ? e.params : [];
          const ips = Array.isArray(e.ips) ? e.ips : [];
          const reason = e.reason || e.description || e.comment || '';
          return {
            id: e.id || `excl-${idx}`,
            rule_id: e.rule_id || '',
            paths,
            params,
            ips,
            reason,
            description: e.description || reason,
            path_pattern: paths.join(', '),
            comment: reason,
            enabled: e.enabled !== false,
            created_at: e.created_at || new Date().toISOString(),
            expires_at: e.expires_at || undefined,
          };
        });
      }
    } catch (err) {
      console.error('[Aegis API] getExclusions error:', err);
    }
    return [];
  },

  async saveExclusion(
    exclusion: WAFExclusion,
    isEdit?: boolean,
  ): Promise<{ success: boolean; exclusion?: WAFExclusion; error?: string }> {
    try {
      const rawPaths =
        Array.isArray(exclusion.paths) && exclusion.paths.length > 0
          ? exclusion.paths
          : exclusion.path_pattern
            ? exclusion.path_pattern
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean)
            : [];
      const paths = rawPaths.map((p: string) => {
        let s = p.trim();
        if (!s.startsWith('/')) s = '/' + s;
        if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
        return s;
      });
      const params = Array.isArray(exclusion.params) ? exclusion.params.filter(Boolean) : [];
      const ips = Array.isArray(exclusion.ips) ? exclusion.ips.filter(Boolean) : [];
      const reason = (exclusion.reason ?? exclusion.comment ?? exclusion.description ?? '').trim();

      const body: Record<string, any> = {
        reason,
        enabled: exclusion.enabled !== false,
      };
      if (exclusion.id) body.id = exclusion.id;
      if (exclusion.rule_id && exclusion.rule_id.trim()) body.rule_id = exclusion.rule_id.trim();
      if (paths.length > 0) body.paths = paths;
      if (params.length > 0) body.params = params;
      if (ips.length > 0) body.ips = ips;
      if (exclusion.expires_at && exclusion.expires_at.trim()) {
        body.expires_at = exclusion.expires_at.trim();
      }

      const res =
        isEdit && exclusion.id
          ? await apiFetch(`/api/sections/waf_core/exclusions/${encodeURIComponent(exclusion.id)}`, {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body),
            })
          : await apiFetch('/api/sections/waf_core/exclusions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body),
            });

      if (res.ok) {
        const data = await res.json().catch(() => ({}));
        return { success: true, exclusion: data?.exclusion };
      }

      let errMsg = `HTTP ${res.status}`;
      try {
        const text = await res.text();
        if (text) {
          try {
            const json = JSON.parse(text);
            errMsg = json.error || json.message || text.trim();
          } catch {
            errMsg = text.trim();
          }
        }
      } catch {
      }
      return { success: false, error: errMsg };
    } catch (err: any) {
      console.error('[Aegis API] saveExclusion error:', err);
      return { success: false, error: err?.message || 'Failed to save exclusion' };
    }
  },

  async deleteExclusion(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/waf_core/exclusions/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        return { success: true };
      }
      let errMsg = `HTTP ${res.status}`;
      try {
        const text = await res.text();
        if (text) {
          try {
            const json = JSON.parse(text);
            errMsg = json.error || json.message || text.trim();
          } catch {
            errMsg = text.trim();
          }
        }
      } catch {
      }
      return { success: false, error: errMsg };
    } catch (err: any) {
      console.error('[Aegis API] deleteExclusion error:', err);
      return { success: false, error: err?.message || 'Failed to delete exclusion' };
    }
  },

  async toggleExclusion(id: string, enabled: boolean, currentExclusion?: WAFExclusion): Promise<{ success: boolean; error?: string }> {
    try {
      let current = currentExclusion;
      if (!current) {
        const all = await this.getExclusions();
        current = all.find((e) => e.id === id);
      }
      const rawPaths = current?.paths || (current?.path_pattern ? current.path_pattern.split(',').map((s) => s.trim()).filter(Boolean) : []);
      const paths = rawPaths.map((p: string) => {
        let s = p.trim();
        if (!s.startsWith('/')) s = '/' + s;
        if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
        return s;
      });
      const payload: Record<string, any> = {
        id,
        rule_id: current?.rule_id || '',
        paths,
        params: current?.params || [],
        ips: current?.ips || [],
        reason: current?.reason || current?.comment || current?.description || '',
        enabled,
      };
      if (current?.expires_at && current.expires_at.trim()) {
        payload.expires_at = current.expires_at.trim();
      }
      if (current?.created_at && current.created_at.trim()) {
        payload.created_at = current.created_at.trim();
      }

      const putRes = await apiFetch(`/api/sections/waf_core/exclusions/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (putRes.ok) {
        return { success: true };
      }
      let errMsg = `HTTP ${putRes.status}`;
      try {
        const text = await putRes.text();
        if (text) {
          try {
            const json = JSON.parse(text);
            errMsg = json.error || json.message || text.trim();
          } catch {
            errMsg = text.trim();
          }
        }
      } catch {
      }
      return { success: false, error: errMsg };
    } catch (err: any) {
      console.error('[Aegis API] toggleExclusion error:', err);
      return { success: false, error: err?.message || 'Failed to toggle exclusion' };
    }
  },

  async suggestWafExclusion(
    eventId: string,
    details?: { rule_id?: string; path?: string; param?: string; ip?: string; reason?: string }
  ): Promise<{ success: boolean; exclusion?: WAFExclusion; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/waf_core/exclusions/suggest', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          rule_id: details?.rule_id || '',
          path: details?.path || '',
          param: details?.param || '',
          ip: details?.ip || '',
          reason: details?.reason || 'False-positive tuning from security event',
        }),
      });
      const data = await res.json().catch(() => ({}));
      if (res.ok && (data?.exclusion || data?.id)) {
        return { success: true, exclusion: data.exclusion || data };
      }
      return { success: false, error: data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] suggestWafExclusion error:', err);
      return { success: false, error: err?.message || 'Failed to suggest WAF exclusion' };
    }
  },

  async getRateLimitPolicies(): Promise<RateLimitPolicy[]> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const rl = data?.ratelimit || data?.rate_limit;
      if (Array.isArray(rl?.path_overrides) && rl.path_overrides.length > 0) {
        return rl.path_overrides.map((o: any, idx: number) => ({
          id: o.id || `rl-rule-${idx + 1}`,
          name: o.name || o.pattern || `Rule ${idx + 1}`,
          description: `Path ${o.match || 'prefix'} ${o.pattern || '/'}`,
          key_by: (o.key_by === 'ip' ? 'client_ip' : o.key_by) || 'client_ip',
          rate: Number(o.rate) || 60,
          burst: Number(o.burst ?? 20),
          action: (o.dry_run ? 'dry_run' : o.action) || 'block',
          enabled: rl.enabled !== false,
        }));
      }
      if (rl) {
        return [
          {
            id: 'rl-global-ip',
            name: 'Global IP Rate Limit',
            description: 'Limits individual IP addresses to token bucket threshold.',
            key_by: (rl.key_by === 'ip' ? 'client_ip' : rl.key_by) || 'client_ip',
            rate: Number(rl.default_rate) || 60,
            burst: Number(rl.default_burst ?? 20),
            action: (rl.action as any) || 'block',
            enabled: rl.enabled !== false,
          },
        ];
      }
    } catch (err) {
      console.warn('API getRateLimitPolicies error:', err);
    }
    return [];
  },

  async saveRateLimitPolicy(policy: RateLimitPolicy): Promise<boolean> {
    try {
      const current = await this.getRateLimitConfig();
      const overrides = Array.isArray(current.path_overrides) ? [...current.path_overrides] : [];
      if (policy.id === 'rl-global-ip') {
        return await this.saveRateLimitConfig({
          ...current,
          enabled: policy.enabled !== false,
          default_rate: policy.rate,
          default_burst: policy.burst,
          action: policy.action === 'rate_limit_429' ? 'block' : policy.action,
          key_by: policy.key_by === 'client_ip' ? 'ip' : policy.key_by,
        });
      }
      const idx = overrides.findIndex((p: any) => p.id === policy.id);
      const nextRule = {
        id: policy.id,
        name: policy.name,
        pattern: (policy as any).path || (policy as any).pattern || '/',
        match: (policy as any).match || 'prefix',
        rate: policy.rate,
        burst: policy.burst,
        window: '1m',
        action: policy.action === 'rate_limit_429' ? 'block' : policy.action,
        key_by: policy.key_by === 'client_ip' ? 'ip' : policy.key_by,
      };
      if (idx >= 0) {
        overrides[idx] = { ...overrides[idx], ...nextRule };
      } else {
        overrides.push(nextRule);
      }
      return await this.saveRateLimitConfig({
        ...current,
        path_overrides: overrides,
      });
    } catch (err) {
      console.error('[Aegis API] saveRateLimitPolicy error:', err);
      return false;
    }
  },

  async deleteRateLimitPolicy(id: string): Promise<boolean> {
    try {
      const current = await this.getRateLimitConfig();
      const overrides = Array.isArray(current.path_overrides)
        ? current.path_overrides.filter((p: any) => p.id !== id)
        : [];
      return await this.saveRateLimitConfig({
        ...current,
        path_overrides: overrides,
      });
    } catch (err) {
      console.error('[Aegis API] deleteRateLimitPolicy error:', err);
      return false;
    }
  },

  async getBotDefenseConfig(): Promise<BotDefenseConfig> {
    try {
      const res = await apiFetch('/api/modules/captcha/config');
      if (res.ok) {
        const data = await res.json();
        return {
          mode: data.enabled ? 'balanced' : 'off',
          allow_good_bots: true,
          challenge_unknown: true,
          block_bad_bots: true,
          captcha_provider: (data.provider_name as any) || 'turnstile',
          site_key: data.site_key || '',
          secret_key: data.secret_key_ref || '',
          score_threshold: data.score_threshold ?? 0.5,
        };
      }
    } catch (err) {
      console.warn('API getBotDefenseConfig error:', err);
    }
    return {
      mode: 'off',
      allow_good_bots: true,
      challenge_unknown: true,
      block_bad_bots: true,
      captcha_provider: 'turnstile',
      site_key: '',
      secret_key: '',
      score_threshold: 0.5,
    };
  },

  async saveBotDefenseConfig(config: BotDefenseConfig): Promise<boolean> {
    try {
      const secretRef = config.secret_key.trim().startsWith('env:')
        ? config.secret_key.trim()
        : (config.secret_key.trim() ? `env:${config.secret_key.trim().toUpperCase()}` : 'env:AEGIS_CAPTCHA_SECRET');

      const payload = {
        enabled: config.mode !== 'off',
        provider_name: config.captcha_provider,
        site_key: config.site_key.trim(),
        secret_key_ref: secretRef,
        score_threshold: Number(config.score_threshold) || 0.5,
      };

      const res = await apiFetch('/api/modules/captcha/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return res.ok;
    } catch (err) {
      console.error('[Aegis API] saveBotDefenseConfig error:', err);
      return false;
    }
  },

    async getTrafficEventsDashboard(queryParams?: Record<string, string | number | undefined>): Promise<TrafficEventsDashboardData> {
    const params = new URLSearchParams();
    if (queryParams) {
      Object.entries(queryParams).forEach(([k, v]) => {
        if (v !== undefined && v !== '') {
          const paramKey = k === 'statusClass' ? 'status_class' : k;
          params.append(paramKey, String(v));
        }
      });
    }
    if (!params.has('window')) params.append('window', '24h');

    const res = await apiFetch(`/api/traffic-events/dashboard?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const dashboard: TrafficEventsDashboardData = data.dashboard || data;

    // Attach live operations if available
    try {
      const ops = await this.getTrafficControlOperations();
      if (ops) dashboard.operations = ops;
    } catch {
    }

    // Ensure authentic structure defaults if missing from payload
    dashboard.summary = dashboard.summary || {
      total_requests: 0,
      status_2xx: 0,
      status_3xx: 0,
      status_4xx: 0,
      status_5xx: 0,
      avg_latency_ms: 0,
      p95_latency_ms: 0,
      unique_source_ips: 0,
      unique_countries: 0,
      total_bytes_sent: 0,
      current_rps: 0,
      window: params.get('window') || '24h',
    };
    dashboard.timeseries = Array.isArray(dashboard.timeseries) ? dashboard.timeseries : [];
    dashboard.breakdowns = dashboard.breakdowns || {};
    dashboard.events = dashboard.events || { events: [], count: 0 };

    return dashboard;
  },

  async getTrafficControlOperations(): Promise<TrafficOperations | null> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/operations');
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('API getTrafficControlOperations error:', err);
    }
    return null;
  },

    async getSecurityEvents(filters?: { action?: string; severity?: string; query?: string }): Promise<SecurityEventItem[]> {
    try {
      const params = new URLSearchParams();
      if (filters?.action) params.append('action', filters.action);
      if (filters?.severity) params.append('severity', filters.severity);
      if (filters?.query) params.append('q', filters.query);

      const res = await apiFetch(`/api/traffic-events/events?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return Array.isArray(data?.events) ? data.events : Array.isArray(data) ? data : [];
    } catch (err) {
      console.warn('API getSecurityEvents error:', err);
      return [];
    }
  },

  async getSecurityEvent(id: string): Promise<SecurityEventItem | null> {
    try {
      const res = await apiFetch(`/api/security/dashboard/events/${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        if (data && data.event) return data.event;
      }
    } catch (err) {
      console.warn('API getSecurityEvent error:', err);
    }
    return null;
  },

    async getSecurityDashboard(queryParams?: Record<string, any>): Promise<SecurityDashboardData> {
    const params = new URLSearchParams();
    if (queryParams) {
      Object.entries(queryParams).forEach(([k, v]) => {
        if (v !== undefined && v !== '') params.append(k, String(v));
      });
    }
    if (!params.has('window')) params.append('window', '24h');

    const res = await apiFetch(`/api/security/dashboard?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    const d: SecurityDashboardData = data.dashboard || data;

    d.summary = d.summary || {
      total_requests: 0,
      blocked_requests: 0,
      detected_requests: 0,
      allowed_requests: 0,
      error_requests: 0,
      block_rate: 0,
      detection_rate: 0,
      avg_latency_ms: 0,
      p95_latency_ms: 0,
      avg_anomaly_score: 0,
      max_anomaly_score: 0,
      unique_source_ips: 0,
      unique_countries: 0,
      top_attack_category: '',
      dropped_events: 0,
      window: params.get('window') || '24h',
    };
    d.timeseries = Array.isArray(d.timeseries) ? d.timeseries : [];
    d.breakdowns = d.breakdowns || {};
    d.events = d.events || { events: [], count: 0 };
    d.section_analytics = Array.isArray(d.section_analytics) ? d.section_analytics : [];

    return d;
  },

  async getSecurityEventDetails(id: string): Promise<any> {
    try {
      const res = await apiFetch(`/api/security/dashboard/events/${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        return data.event || data;
      }
    } catch (err) {
      console.warn('API getSecurityEventDetails live error:', err);
    }
    return null;
  },

    async getTrafficStats(): Promise<TrafficStats> {
    try {
      const res = await apiFetch('/api/traffic-events/dashboard');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const s = data?.dashboard?.summary || data?.summary || data || {};
      return {
        total_requests: Number(s.total_requests || 0),
        blocked_requests: Number(s.blocked_requests || 0),
        challenges_issued: Number(s.challenged_requests || s.challenges_issued || 0),
        p95_latency_ms: Number(s.p95_latency_ms || 0),
        status_2xx: Number(s.status_2xx || 0),
        status_3xx: Number(s.status_3xx || 0),
        status_4xx: Number(s.status_4xx || 0),
        status_5xx: Number(s.status_5xx || 0),
      };
    } catch (err) {
      console.warn('API getTrafficStats error:', err);
      return {
        total_requests: 0,
        blocked_requests: 0,
        challenges_issued: 0,
        p95_latency_ms: 0,
        status_2xx: 0,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
      };
    }
  },

    async getThreatLogs(queryParams?: Record<string, string | number | undefined>): Promise<SecurityEventItem[]> {
    const params = new URLSearchParams();
    if (queryParams) {
      Object.entries(queryParams).forEach(([k, v]) => {
        if (v !== undefined && v !== '') params.append(k, String(v));
      });
    }
    if (!params.has('limit')) params.append('limit', '250');
    const res = await apiFetch(`/api/logs?${params.toString()}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    if (Array.isArray(data?.logs)) {
      return data.logs.map((item: any, idx: number) => ({
        ...item,
        id: String(item.id || item.request_id || `threat-${idx}`),
        timestamp: item.timestamp || item.ts || new Date().toISOString(),
        client_ip: item.client_ip || item.ip || '127.0.0.1',
        method: (item.method || 'GET').toUpperCase(),
        path: item.path || '/',
        host: item.host || '',
        status_code: Number(item.status_code || item.statusCode || 403),
        action: (item.action || (item.blocked ? 'BLOCK' : 'ALLOW')).toUpperCase(),
        blocked: Boolean(item.blocked ?? (String(item.action).toUpperCase() === 'BLOCK')),
        rule_name: item.rule_name || item.rule || 'Security Alert',
        rule_id: item.rule_id || item.ruleId || '',
        severity: item.severity || (Number(item.score || 0) >= 10 ? 'critical' : 'high'),
        score: Number(item.score || 0),
        category: item.category || 'Threat',
        matched_fields: item.matched_fields || item.matchedFields || [],
        rule_messages: item.rule_messages || item.ruleMessages || [item.rule_name || 'Rule Triggered'],
        user_agent: item.user_agent || item.userAgent || '',
        user_agent_family: item.user_agent_family || item.userAgentFamily || '',
        latency_ms: Number(item.latency_ms || item.latencyMs || 0),
        request_id: item.request_id || item.requestId || `req_${idx}`,
      }));
    }
    return [];
  },

  async getCaptchaConfig(): Promise<CaptchaModuleConfig> {
    const res = await apiFetch('/api/modules/captcha/config');
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async saveCaptchaConfig(config: CaptchaModuleConfig): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload: CaptchaModuleConfig = {
        enabled: Boolean(config.enabled),
        provider_name: config.provider_name || 'recaptcha_v2',
        site_key: (config.site_key || '').trim(),
        secret_key_ref: (config.secret_key_ref || '').trim(),
        score_threshold: Number(config.score_threshold ?? 0),
      };
      const res = await apiFetch('/api/modules/captcha/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        return { success: false, error: errData?.error || `HTTP ${res.status}` };
      }
      const data = await res.json().catch(() => null);
      return { success: true, data };
    } catch (err: any) {
      console.error('API saveCaptchaConfig error:', err);
      return { success: false, error: err?.message || 'Network error saving CAPTCHA configuration' };
    }
  },

  async getChallengeConfig(): Promise<ChallengeModuleConfig> {
    const res = await apiFetch('/api/modules/challenge/config');
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async saveChallengeConfig(config: ChallengeModuleConfig): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const mode = config.mode || 'managed';
      const isInvisible = mode === 'invisible';
      const isInteractive = mode === 'interactive';
      const isManaged = mode === 'managed' || mode === 'captcha';
      const isCaptcha = mode === 'captcha';

      const payload: ChallengeModuleConfig = {
        enabled: config.enabled !== false,
        mode,
        preset: config.preset || 'balanced',
        invisible_enabled: isInvisible,
        managed_enabled: isManaged,
        interactive_enabled: isInteractive,
        interactive_style: config.interactive_style || 'hold',
        captcha_enabled: isCaptcha,
        escalation_policy: config.escalation_policy || 'progressive',
        cooldown_seconds: Number(config.cooldown_seconds || 1800),
        max_failures: Number(config.max_failures || 3),
        failure_action: config.failure_action || 'block',
        theme: config.theme || 'dark',
        custom_title: config.custom_title || 'Checking your browser...',
        custom_message: config.custom_message || 'Please wait a moment while we verify your request.',
        cookie_ttl: Number(config.cookie_ttl || 3600),
        pow_difficulty: Number(config.pow_difficulty || 0),
      };

      const res = await apiFetch('/api/modules/challenge/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        return { success: false, error: errData?.error || `HTTP ${res.status}` };
      }
      const data = await res.json().catch(() => null);
      return { success: true, data };
    } catch (err: any) {
      console.error('API saveChallengeConfig error:', err);
      return { success: false, error: err?.message || 'Network error saving Smart Challenge configuration' };
    }
  },

  async getErrorPagesConfig(): Promise<ErrorPagesModuleConfig> {
    const res = await apiFetch('/api/config');
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    const data = await res.json();
    const ep = data?.modules?.errorpages || {};
    const rawId = ep.active_template_id || 'aegis';
    const uiId = rawId === 'aegis' ? 'carbon' : rawId;
    return {
      enabled: ep.enabled ?? true,
      theme: ep.theme || 'dark',
      active_template_id: uiId,
      templates: Array.isArray(ep.templates) ? ep.templates : [],
      page_403: ep.page_403 || '',
      page_404: ep.page_404 || '',
      page_503: ep.page_503 || '',
    };
  },

  async saveErrorPagesConfig(config: ErrorPagesModuleConfig): Promise<{ success: boolean; error?: string }> {
    try {
      const backendId = (config.active_template_id === 'carbon' || !config.active_template_id)
        ? 'aegis'
        : config.active_template_id;

      const cleanedTemplates = (config.templates || []).map((t) => ({
        id: t.id,
        name: t.name,
        html: t.html,
      }));

      const res = await apiFetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          'modules.errorpages.enabled': Boolean(config.enabled),
          'modules.errorpages.theme': config.theme || 'dark',
          'modules.errorpages.active_template_id': backendId,
          'modules.errorpages.templates': cleanedTemplates,
          'modules.errorpages.page_403': config.page_403 || '',
          'modules.errorpages.page_404': config.page_404 || '',
          'modules.errorpages.page_503': config.page_503 || '',
        }),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        return { success: false, error: errData?.error || `HTTP ${res.status}` };
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] saveErrorPagesConfig error:', err);
      return { success: false, error: err?.message || 'Network error saving error pages configuration' };
    }
  },

  async getModules(): Promise<AegisModule[]> {
    const baseModules: AegisModule[] = [
      {
        id: 'mod-routing',
        name: 'Traffic Routing & Load Balancing',
        description: 'Host and path-based dynamic proxy routing to backend origin server pools.',
        category: 'delivery',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-waf',
        name: 'OWASP Core Application Firewall (CRS)',
        description: 'Deep packet inspection preventing SQLi, XSS, RFI/LFI, and protocol attacks.',
        category: 'security',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-ratelimit',
        name: 'Adaptive Rate Limiting & DoS Shield',
        description: 'Token bucket rate limiting by client IP, session cookie, or API key header.',
        category: 'traffic',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-botdefense',
        name: 'Bot Protection & Challenge Engine',
        description: 'Client behavior classification, search engine validation, and CAPTCHA challenge.',
        category: 'security',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-tls',
        name: 'Automated TLS / ACME Certificates',
        description: "Let's Encrypt automated HTTP-01/DNS-01 TLS certificate provisioning and renewal.",
        category: 'delivery',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-observability',
        name: 'Telemetry & Prometheus Metrics',
        description: 'Real-time security analytics, HTTP status metrics, and Prometheus exporter.',
        category: 'observability',
        enabled: true,
        edition: 'community',
        status: 'active',
      },
      {
        id: 'mod-bodyguard',
        name: 'Advanced Leak Protection & PII Body Guard',
        description: 'Deep content filtering preventing data exfiltration of credit cards, SSNs, and API keys.',
        category: 'security',
        enabled: false,
        edition: 'enterprise',
        status: 'locked',
      },
      {
        id: 'mod-geo',
        name: 'GeoIP Country Restriction & IP Intelligence',
        description: 'Autonomous country filtering using MaxMind database and threat feed intelligence.',
        category: 'traffic',
        enabled: false,
        edition: 'community',
        status: 'active',
      },
    ];

    try {
      const [wafRes, trafficRes, botRes, tlsRes, sysRes] = await Promise.allSettled([
        apiFetch('/api/sections/waf_core/config'),
        apiFetch('/api/sections/traffic_control/config'),
        apiFetch('/api/sections/bot_protection/config'),
        apiFetch('/api/certificates/config'),
        apiFetch('/api/config'),
      ]);

      if (wafRes.status === 'fulfilled' && wafRes.value.ok) {
        const d = await wafRes.value.json();
        const m = baseModules.find((x) => x.id === 'mod-waf');
        if (m) {
          m.enabled = d?.enabled !== false && d?.mode !== 'off';
          m.status = m.enabled ? 'active' : 'disabled';
        }
      }

      if (trafficRes.status === 'fulfilled' && trafficRes.value.ok) {
        const d = await trafficRes.value.json();
        const rl = baseModules.find((x) => x.id === 'mod-ratelimit');
        if (rl) {
          rl.enabled = d?.ratelimit?.enabled !== false;
          rl.status = rl.enabled ? 'active' : 'disabled';
        }
        const geo = baseModules.find((x) => x.id === 'mod-geo');
        if (geo) {
          geo.enabled = Boolean(d?.geo?.enabled);
          geo.status = geo.enabled ? 'active' : 'disabled';
        }
      }

      if (botRes.status === 'fulfilled' && botRes.value.ok) {
        const d = await botRes.value.json();
        const b = baseModules.find((x) => x.id === 'mod-botdefense');
        if (b) {
          b.enabled = d?.enabled !== false && d?.mode !== 'off';
          b.status = b.enabled ? 'active' : 'disabled';
        }
      }

      if (tlsRes.status === 'fulfilled' && tlsRes.value.ok) {
        const d = await tlsRes.value.json();
        const t = baseModules.find((x) => x.id === 'mod-tls');
        if (t) {
          t.enabled = Boolean(d?.enabled);
          t.status = t.enabled ? 'active' : 'disabled';
        }
      }

      if (sysRes.status === 'fulfilled' && sysRes.value.ok) {
        const d = await sysRes.value.json();
        const obs = baseModules.find((x) => x.id === 'mod-observability');
        if (obs) {
          obs.enabled = Boolean(d?.telemetry?.prometheus_enabled ?? true);
          obs.status = obs.enabled ? 'active' : 'disabled';
        }
      }
    } catch (err) {
      console.warn('API getModules enrichment error:', err);
    }

    return baseModules;
  },

  async toggleModule(id: string, enabled: boolean): Promise<boolean> {
    try {
      if (id === 'mod-waf') {
        const cur = await this.getWafConfig();
        const res = await this.saveWafConfig({
          ...cur,
          enabled,
        });
        return res.success;
      }

      if (id === 'mod-ratelimit') {
        const curRl = await this.getRateLimitConfig();
        return await this.saveRateLimitConfig({
          ...curRl,
          enabled,
        });
      }

      if (id === 'mod-geo') {
        const curGeo = await this.getTrafficGeoConfig();
        return await this.saveTrafficGeoConfig({
          ...curGeo,
          enabled,
        });
      }

      if (id === 'mod-botdefense') {
        const curBot = await this.getBotProtectionConfig();
        const res = await this.saveBotProtectionConfig({
          ...(curBot || {}),
          enabled,
          mode: enabled ? (curBot?.mode === 'off' ? 'balanced' : curBot?.mode || 'balanced') : (curBot?.mode || 'balanced'),
        });
        return res.success;
      }

      if (id === 'mod-tls') {
        const curTls = await this.getTLSConfig();
        const res = await this.saveTLSConfig({
          ...curTls,
          enabled,
        });
        return res.success;
      }

      if (id === 'mod-observability') {
        const res = await apiFetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            'telemetry.prometheus_enabled': enabled,
          }),
        });
        return res.ok;
      }

      if (id === 'mod-ipblacklist') {
        return await this.toggleIPBlacklist(enabled);
      }

      if (id === 'mod-routing') {
        return true;
      }

      return false;
    } catch (err) {
      console.error('[Aegis API] toggleModule error:', err);
      return false;
    }
  },

  async getSystemSettings(): Promise<SystemSettings> {
    const res = await apiFetch('/api/config');
    if (!res.ok) throw new Error(`Failed to load system settings (HTTP ${res.status})`);
    const data = await res.json();

    return {
      http_port: data?.server?.port ?? 8080,
      admin_port: data?.server?.admin?.port ?? 8081,
      admin_host: data?.server?.admin?.host ?? '127.0.0.1',
      prometheus_enabled: data?.telemetry?.prometheus_enabled ?? true,
      prometheus_path: data?.telemetry?.prometheus_path || '/metrics',
      prometheus_token: data?.telemetry?.prometheus_token || '',
      request_logging: data?.telemetry?.request_logging ?? false,
    };
  },

  async saveSystemSettings(settings: SystemSettings): Promise<boolean> {
    try {
      const updates: Record<string, any> = {
        'server.port': Number(settings.http_port) || 8080,
        'server.admin.port': Number(settings.admin_port) || 8081,
        'server.admin.host': settings.admin_host || '127.0.0.1',
        'telemetry.prometheus_enabled': Boolean(settings.prometheus_enabled),
        'telemetry.prometheus_path': settings.prometheus_path || '/metrics',
        'telemetry.request_logging': Boolean(settings.request_logging),
      };
      if (settings.prometheus_token !== undefined) {
        updates['telemetry.prometheus_token'] = settings.prometheus_token;
      }
      const res = await apiFetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      return res.ok;
    } catch (err) {
      console.error('[Aegis API] saveSystemSettings error:', err);
      return false;
    }
  },

  async getFullConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/config');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getFullConfig error:', err);
    }
    return null;
  },

  async saveConfigUpdates(updates: Record<string, unknown>): Promise<boolean> {
    try {
      if (Object.keys(updates).length === 0) return true;

      const res = await apiFetch('/api/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      });
      return res.ok;
    } catch (err) {
      console.error('[Aegis API] saveConfigUpdates error:', err);
      return false;
    }
  },

  async downloadConfigBackup(): Promise<{ ok: boolean; error?: string; blob?: Blob; filename?: string }> {
    try {
      const res = await apiFetch('/api/config/backup');
      if (res.status === 409) {
        const text = await res.text().catch(() => '');
        return {
          ok: false,
          error: text || 'Backup archive cannot be created while PostgreSQL has active control-plane documents.',
        };
      }
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        return { ok: false, error: text || `Failed to download backup (HTTP ${res.status})` };
      }
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/);
      const filename = match ? match[1] : `aegis-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.tar.gz`;
      return { ok: true, blob, filename };
    } catch (err: any) {
      return { ok: false, error: err?.message || 'Network error downloading backup archive' };
    }
  },

  async downloadConfigExport(): Promise<{ ok: boolean; error?: string; blob?: Blob; filename?: string }> {
    try {
      const res = await apiFetch('/api/config/export');
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        return { ok: false, error: text || `Failed to export config (HTTP ${res.status})` };
      }
      const blob = await res.blob();
      const disposition = res.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^";]+)"?/);
      const filename = match ? match[1] : 'aegis-config.yaml';
      return { ok: true, blob, filename };
    } catch (err: any) {
      return { ok: false, error: err?.message || 'Network error exporting configuration' };
    }
  },

  async getStorageStatus(): Promise<StorageStatusResponse | null> {
    try {
      const res = await apiFetch('/api/storage/status');
      if (!res.ok) return null;
      const data = await res.json();
      if (!data?.control || !data?.analytics) return null;
      return data;
    } catch (err) {
      console.warn('[Aegis API] getStorageStatus error:', err);
      return null;
    }
  },

  async testPostgreSQLControl(req: PostgreSQLPreflightRequest): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/storage/control/postgresql/preflight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || data?.status !== 'ok' || !data?.connection) {
        return { success: false, error: data?.error?.message || data?.error || 'PostgreSQL connection could not be established. Confirm the details and try again.' };
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'PostgreSQL connection test failed.' };
    }
  },

  async savePostgreSQLControlPending(req: PostgreSQLControlPendingRequest): Promise<{ success: boolean; restart_required?: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/storage/control/postgresql/pending', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || data?.status !== 'pending') {
        return { success: false, error: data?.error?.message || data?.error || 'PostgreSQL configuration could not be saved.' };
      }
      return { success: true, restart_required: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'PostgreSQL configuration save failed.' };
    }
  },

  async testClickHouseAnalytics(req: ClickHousePreflightRequest): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/storage/analytics/clickhouse/preflight', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || data?.status !== 'ok' || !data?.connection) {
        return { success: false, error: data?.error?.message || data?.error || 'ClickHouse connection could not be established. Confirm the details and try again.' };
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'ClickHouse connection test failed.' };
    }
  },

  async saveClickHouseAnalyticsPending(req: ClickHouseAnalyticsPendingRequest): Promise<{ success: boolean; restart_required?: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/storage/analytics/clickhouse/pending', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok || (data?.status !== 'pending' && data?.status !== 'active')) {
        return { success: false, error: data?.error?.message || data?.error || 'ClickHouse configuration could not be saved.' };
      }
      return { success: true, restart_required: data?.restart_required !== undefined ? Boolean(data.restart_required) : data?.status === 'pending' };
    } catch (err: any) {
      return { success: false, error: err.message || 'ClickHouse configuration save failed.' };
    }
  },

  async getUpstreamSettings(): Promise<{ data: UpstreamSettings | null; availability: 'available' | 'unsupported' | 'forbidden' | 'unavailable' }> {
    try {
      const res = await apiFetch('/api/upstreams/settings');
      if (res.status === 404) return { data: null, availability: 'unsupported' };
      if (res.status === 401 || res.status === 403) return { data: null, availability: 'forbidden' };
      if (!res.ok) return { data: null, availability: 'unavailable' };
      const data = await res.json();
      return { data, availability: 'available' };
    } catch (err) {
      console.warn('[Aegis API] getUpstreamSettings error:', err);
      return { data: null, availability: 'unavailable' };
    }
  },

  async saveUpstreamSettings(settings: UpstreamSettings): Promise<{ success: boolean; data?: UpstreamSettings; error?: string }> {
    try {
      const res = await apiFetch('/api/upstreams/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        return { success: false, error: data?.error?.message || data?.error || `Failed to save Origin settings (HTTP ${res.status})` };
      }
      const data = await res.json();
      return { success: true, data };
    } catch (err: any) {
      return { success: false, error: err.message || 'Failed to save Origin settings' };
    }
  },

  async importConfigFile(file: File): Promise<{ success: boolean; error?: string }> {
    try {
      const formData = new FormData();
      formData.append('config', file);
      const res = await apiFetch('/api/config/import', {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        return { success: false, error: text || `Import failed (HTTP ${res.status})` };
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Error importing config' };
    }
  },

  async factoryReset(): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/config/reset', {
        method: 'POST',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => null);
        return { success: false, error: data?.error?.message || data?.error || `Reset failed (HTTP ${res.status})` };
      }
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message || 'Error resetting configuration' };
    }
  },

  async getAuditLogs(params?: AuditQueryParams): Promise<AuditLogsResponse> {
    const query = new URLSearchParams();
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.cursor) query.set('cursor', params.cursor);
    if (params?.action) query.set('action', params.action);
    if (params?.actor) query.set('actor', params.actor);
    if (params?.from) query.set('from', params.from);
    if (params?.to) query.set('to', params.to);

    const queryString = query.toString();
    const url = `/api/audit-logs${queryString ? `?${queryString}` : ''}`;
    const res = await apiFetch(url);
    if (!res.ok) {
      throw new Error(`Audit log request failed with status ${res.status}`);
    }
    const data = await res.json();
    return {
      data: Array.isArray(data?.data) ? data.data : [],
      meta: data?.meta,
    };
  },

  async exportAuditLogs(params?: Omit<AuditQueryParams, 'limit' | 'cursor'>): Promise<{ blob: Blob; truncated: boolean }> {
    const query = new URLSearchParams();
    query.set('limit', '5000');
    if (params?.action) query.set('action', params.action);
    if (params?.actor) query.set('actor', params.actor);
    if (params?.from) query.set('from', params.from);
    if (params?.to) query.set('to', params.to);

    const queryString = query.toString();
    const url = `/api/audit-logs/export${queryString ? `?${queryString}` : ''}`;
    const res = await apiFetch(url, {
      headers: { Accept: 'text/csv' },
    });
    if (!res.ok) {
      throw new Error(`Audit export failed with status ${res.status}`);
    }
    const blob = await res.blob();
    const truncated = res.headers.get('X-Aegis-Export-Truncated') === 'true';
    return { blob, truncated };
  },

  async getTrafficControlFullConfig(): Promise<Record<string, any> | null> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getTrafficControlFullConfig error:', err);
      return null;
    }
  },

  async saveTrafficControlFullConfig(
    updates: Record<string, any>,
    targetSection: TrafficSectionTarget = 'full'
  ): Promise<boolean> {
    try {
      let existingConfig: Record<string, any> = {};
      try {
        const getRes = await apiFetch('/api/sections/traffic_control/config');
        if (getRes.ok) existingConfig = await getRes.json();
      } catch {
      }

      const payload = normalizeTrafficConfigForSave(existingConfig, updates, targetSection);
      const res = await apiFetch('/api/sections/traffic_control/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => '');
        console.error(`[Aegis API] saveTrafficControlFullConfig failed HTTP ${res.status}:`, text);
        return false;
      }
      return true;
    } catch (err) {
      console.error('[Aegis API] saveTrafficControlFullConfig error:', err);
      return false;
    }
  },

  async getTrafficControlStats(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/stats');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getTrafficControlStats error:', err);
      return {
        total_requests: 0,
        blocked_requests: 0,
        active_connections: 0,
        in_flight_requests: 0,
        custom: {},
      };
    }
  },

  async getTrafficControlCapabilities(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/capabilities');
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getTrafficControlCapabilities error:', err);
      return null;
    }
  },

  async getTrafficGeoConfig(): Promise<TrafficGeoConfig> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data?.geo) {
        const mode: 'blocklist' | 'allowlist' = data.geo.mode === 'allowlist' ? 'allowlist' : 'blocklist';
        const allow_countries = Array.isArray(data.geo.allow_countries) ? data.geo.allow_countries : [];
        const block_countries = Array.isArray(data.geo.block_countries)
          ? data.geo.block_countries
          : Array.isArray(data.geo.countries) && mode === 'blocklist'
          ? data.geo.countries
          : [];
        const countries =
          mode === 'allowlist'
            ? allow_countries.length > 0
              ? allow_countries
              : data.geo.countries || []
            : block_countries.length > 0
            ? block_countries
            : data.geo.countries || [];
        const groups = Array.isArray(data.geo.groups)
          ? data.geo.groups
          : Array.isArray(data.geo.regions)
          ? data.geo.regions
          : [];
        return {
          ...data.geo,
          enabled: Boolean(data.geo.enabled),
          mode,
          countries,
          block_countries: mode === 'blocklist' ? countries : [],
          allow_countries: mode === 'allowlist' ? countries : [],
          regions: groups,
          groups,
          exceptions: Array.isArray(data.geo.exceptions) ? data.geo.exceptions : [],
          unknown_action: data.geo.unknown_action || 'allow',
          cache_ttl: data.geo.cache_ttl || '24h',
          db_path: data.geo.db_path || './data/dbip-country.mmdb',
          auto_update: Boolean(data.geo.auto_update),
        };
      }
    } catch (err) {
      console.warn('API /api/sections/traffic_control/config geo error:', err);
    }
    return {
      enabled: false,
      mode: 'blocklist',
      db_path: './data/dbip-country.mmdb',
      countries: [],
      block_countries: [],
      allow_countries: [],
      regions: [],
      groups: [],
      exceptions: [],
      unknown_action: 'allow',
      auto_update: false,
      cache_ttl: '24h',
    };
  },

  async getTrafficGeoStatus(): Promise<TrafficGeoStatus | null> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/geo/status');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('API /api/sections/traffic_control/geo/status error:', err);
      return null;
    }
  },

  async saveTrafficGeoConfig(geoConfig: TrafficGeoConfig): Promise<boolean> {
    return await this.saveTrafficControlFullConfig({ geo: geoConfig }, 'geo');
  },

  async getIPBlacklistConfig(): Promise<IPBlacklistConfig> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const bl = data?.blacklist || {};
      const ips = Array.isArray(bl.ips) ? bl.ips : [];
      const cidrs = Array.isArray(bl.cidrs) ? bl.cidrs : [];
      const rawEntries = Array.isArray(bl.entries) ? bl.entries : [];

      const totalCount = ips.length + cidrs.length + rawEntries.length;
      return {
        enabled: Boolean(bl.enabled),
        ips,
        cidrs,
        entries: rawEntries,
        total_count: totalCount,
      };
    } catch (err) {
      console.warn('API getIPBlacklistConfig error:', err);
      return {
        enabled: false,
        ips: [],
        cidrs: [],
        entries: [],
        total_count: 0,
      };
    }
  },

  async getBlockedIPs(): Promise<BlockedIPStatus> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/blocked');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return {
        blocked: Array.isArray(data?.blocked) ? data.blocked : [],
        cidrs: Array.isArray(data?.cidrs) ? data.cidrs : [],
        count: Number(data?.count) || 0,
      };
    } catch (err) {
      console.warn('API getBlockedIPs error:', err);
      return {
        blocked: [],
        cidrs: [],
        count: 0,
      };
    }
  },

  async saveIPBlacklistConfig(blacklistConfig: IPBlacklistConfig): Promise<boolean> {
    return await this.saveTrafficControlFullConfig({ blacklist: blacklistConfig }, 'blacklist');
  },

  async addIPBlockEntry(entry: { target: string; note?: string; expires_in?: string }): Promise<boolean> {
    try {
      const target = entry.target.trim();
      if (!target) return false;

      let expiresAt: string | undefined = undefined;
      if (entry.expires_in && entry.expires_in !== 'permanent') {
        const map: Record<string, number> = {
          '1h': 3600 * 1000,
          '24h': 86400 * 1000,
          '7d': 7 * 86400 * 1000,
          '30d': 30 * 86400 * 1000,
        };
        if (map[entry.expires_in]) {
          expiresAt = new Date(Date.now() + map[entry.expires_in]).toISOString();
        } else if (!isNaN(Date.parse(entry.expires_in))) {
          expiresAt = new Date(entry.expires_in).toISOString();
        } else {
          expiresAt = new Date(Date.now() + 86400 * 1000).toISOString();
        }
      }

      const current = await this.getIPBlacklistConfig();
      const nextIps = current.ips.filter((ip) => ip !== target);
      const nextCidrs = current.cidrs.filter((cidr) => cidr !== target);

      const newEntry = {
        target,
        note: entry.note?.trim() || 'Manual edge block',
        ...(expiresAt ? { expires_at: expiresAt } : {}),
      };

      const filteredEntries = current.entries.filter((e) => e.target !== target);
      filteredEntries.push(newEntry);

      return await this.saveIPBlacklistConfig({
        enabled: true,
        ips: nextIps,
        cidrs: nextCidrs,
        entries: filteredEntries,
      });
    } catch (err) {
      console.error('[Aegis API] addIPBlockEntry error:', err);
      return false;
    }
  },

  async removeIPBlockEntry(target: string): Promise<boolean> {
    try {
      const cleanTarget = target.trim();
      const current = await this.getIPBlacklistConfig();
      const nextIps = current.ips.filter((ip) => ip !== cleanTarget);
      const nextCidrs = current.cidrs.filter((cidr) => cidr !== cleanTarget);
      const nextEntries = current.entries.filter((e) => e.target !== cleanTarget);

      return await this.saveIPBlacklistConfig({
        enabled: current.enabled,
        ips: nextIps,
        cidrs: nextCidrs,
        entries: nextEntries,
      });
    } catch (err) {
      console.error('[Aegis API] removeIPBlockEntry error:', err);
      return false;
    }
  },

  async toggleIPBlacklist(enabled: boolean): Promise<boolean> {
    try {
      const current = await this.getIPBlacklistConfig();
      return await this.saveIPBlacklistConfig({
        ...current,
        enabled,
      });
    } catch (err) {
      console.error('[Aegis API] toggleIPBlacklist error:', err);
      return false;
    }
  },

  async getRateLimitConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const rl = data?.ratelimit || data?.rate_limit || {};
      const overrides = Array.isArray(rl.path_overrides)
        ? rl.path_overrides
        : Array.isArray(rl.policies)
        ? rl.policies.map((p: any, idx: number) => ({
            id: p.id || `rule-${idx + 1}`,
            name: p.name || p.path || p.pattern || '/',
            pattern: p.path || p.pattern || '/',
            match: p.match || 'glob',
            priority: p.priority ?? 100,
            methods: p.methods || [],
            hosts: p.hosts || [],
            rate: p.rate || 60,
            burst: p.burst ?? 10,
            window: p.window || '1m',
            action: p.action || 'block',
            algorithm: p.algorithm || 'token_bucket',
            key_by: p.key_by || 'ip',
            bypass_static: p.bypass_static !== false,
            dry_run: Boolean(p.dry_run),
            verified_grace_multiplier: p.verified_grace_multiplier || 2,
          }))
        : [];
      return {
        ...rl,
        enabled: rl.enabled !== false,
        default_rate: Number(rl.default_rate) || 60,
        default_burst: Number(rl.default_burst ?? 20),
        window: rl.window || '1m',
        algorithm: rl.algorithm || 'token_bucket',
        action: rl.dry_run ? 'dry_run' : rl.action || 'block',
        key_by: rl.key_by || 'ip',
        bypass_static: rl.bypass_static !== false,
        bypass_known_bots: Boolean(rl.bypass_known_bots),
        verified_grace_multiplier: Number(rl.verified_grace_multiplier) || 2,
        dry_run: Boolean(rl.dry_run),
        max_states: Number(rl.max_states) || 100000,
        state_idle_ttl: rl.state_idle_ttl || '5m',
        path_overrides: overrides,
      };
    } catch (err) {
      console.warn('getRateLimitConfig error:', err);
      return {
        enabled: false,
        default_rate: 60,
        default_burst: 20,
        window: '1m',
        algorithm: 'token_bucket',
        action: 'block',
        key_by: 'ip',
        bypass_static: true,
        bypass_known_bots: false,
        verified_grace_multiplier: 2,
        dry_run: false,
        max_states: 100000,
        state_idle_ttl: '5m',
        path_overrides: [],
      };
    }
  },

  async saveRateLimitConfig(rlConfig: any): Promise<boolean> {
    return await this.saveTrafficControlFullConfig({ ratelimit: rlConfig }, 'ratelimit');
  },

  async getReputationConfig(): Promise<any> {
    const res = await apiFetch('/api/sections/traffic_control/config');
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.error || `HTTP ${res.status}`);
    }
    const data = await res.json();
    const rep = data?.reputation || {};
    const allowedIps = Array.isArray(rep.allowed_ips) ? rep.allowed_ips : [];
    const blockedIps = Array.isArray(rep.blocked_ips) ? rep.blocked_ips : [];
    const derivedRules = [
      ...allowedIps.map((ip: string, idx: number) => ({
        id: `allow-${idx}-${ip}`,
        target: ip,
        action: 'allow' as const,
        note: 'Allowlist IP override',
      })),
      ...blockedIps.map((ip: string, idx: number) => ({
        id: `block-${idx}-${ip}`,
        target: ip,
        action: 'block' as const,
        note: 'Blocklist IP override',
      })),
    ];
    return {
      enabled: Boolean(rep.enabled),
      action: rep.action || 'block',
      sensitivity: Number(rep.sensitivity ?? 75),
      cache_ttl: rep.cache_ttl || '1h',
      block_tor: Boolean(rep.block_tor),
      block_datacenter: Boolean(rep.block_datacenter),
      cti: {
        enabled: Boolean(rep.cti?.enabled),
        url: rep.cti?.url || 'http://localhost:8090',
        min_score: Number(rep.cti?.min_score ?? 60),
        api_key_configured: Boolean(rep.cti?.api_key_configured),
      },
      rules: Array.isArray(rep.rules) && rep.rules.length > 0 ? rep.rules : derivedRules,
      allowed_ips: allowedIps,
      blocked_ips: blockedIps,
    };
  },

  async saveReputationConfig(repConfig: any): Promise<boolean> {
    return await this.saveTrafficControlFullConfig({ reputation: repConfig }, 'reputation');
  },

  async getThreatFeed(): Promise<any> {
    const res = await apiFetch('/api/sections/traffic_control/reputation/feed');
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async refreshThreatFeed(): Promise<any> {
    const res = await apiFetch('/api/sections/traffic_control/reputation/feed/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => null);
      throw new Error(err?.error || `HTTP ${res.status}`);
    }
    return await res.json();
  },

  async getApplicationFloodConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      const ddos = data?.application_flood || data?.ddos || {};
      const challenge = data?.challenge || ddos?.challenge || {};
      return {
        enabled: Boolean(ddos.enabled),
        action: ddos.action || 'challenge',
        max_rps: Number(ddos.max_rps ?? ddos.maxrps ?? 100),
        max_connections: Number(ddos.max_connections ?? ddos.maxconnections ?? 50),
        burst_multiplier: Number(ddos.burst_multiplier ?? ddos.burstmultiplier ?? 2.0),
        auto_ban: Boolean(ddos.auto_ban ?? ddos.autoban ?? false),
        ban_duration: Number(ddos.ban_duration ?? ddos.banduration ?? 300),
        challenge: {
          enabled: Boolean(challenge.enabled ?? true),
          mode: challenge.mode || 'managed',
          threshold: Number(challenge.threshold ?? 5),
        },
        objects: Array.isArray(ddos.objects) ? ddos.objects : [],
      };
    } catch (err) {
      console.warn('getApplicationFloodConfig error:', err);
      return {
        enabled: false,
        action: 'challenge',
        max_rps: 100,
        max_connections: 50,
        burst_multiplier: 2.0,
        auto_ban: false,
        ban_duration: 300,
        challenge: { enabled: true, mode: 'managed', threshold: 5 },
        objects: [],
      };
    }
  },

  async saveApplicationFloodConfig(floodConfig: any): Promise<boolean> {
    const updates: Record<string, any> = {
      application_flood: floodConfig,
    };
    if (floodConfig?.challenge && typeof floodConfig.challenge === 'object') {
      updates.challenge = floodConfig.challenge;
    }
    return await this.saveTrafficControlFullConfig(updates, 'application_flood');
  },

  async getTrafficExceptions(): Promise<TrafficTrustedException[]> {
    try {
      const res = await apiFetch('/api/sections/traffic_control/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      return Array.isArray(data?.trusted_exceptions) ? data.trusted_exceptions : [];
    } catch (err) {
      console.warn('getTrafficExceptions error:', err);
      return [];
    }
  },

  async saveTrafficExceptions(exceptions: TrafficTrustedException[]): Promise<boolean> {
    return await this.saveTrafficControlFullConfig(
      { trusted_exceptions: exceptions },
      'trusted_exceptions'
    );
  },

  async getLicense(forceRefresh = false): Promise<LicenseSnapshot | null> {
    const now = Date.now();
    if (!forceRefresh && cachedLicense && now - cachedLicenseTime < 10000) {
      return cachedLicense;
    }
    try {
      const res = await apiFetch('/api/license');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      cachedLicense = await res.json();
      cachedLicenseTime = Date.now();
      return cachedLicense;
    } catch (err) {
      console.warn('getLicense error:', err);
      return cachedLicense;
    }
  },

  async activateLicense(key: string): Promise<{ success: boolean; error?: string; license?: LicenseSnapshot }> {
    try {
      const res = await apiFetch('/api/license/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key }),
      });
      const data = await res.json();
      if (!res.ok || data.status === 'error' || data.error) {
        return { success: false, error: data.error?.message || data.error || 'Activation failed' };
      }
      cachedLicense = null;
      return { success: true, license: data.license || data };
    } catch (err: any) {
      return { success: false, error: err.message || 'Activation failed' };
    }
  },

  async refreshLicense(): Promise<LicenseSnapshot | null> {
    try {
      const res = await apiFetch('/api/license/refresh', { method: 'POST' });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] refreshLicense error:', err);
      return null;
    }
  },

  async deactivateLicense(): Promise<LicenseSnapshot | null> {
    try {
      const res = await apiFetch('/api/license/deactivate', { method: 'POST' });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] deactivateLicense error:', err);
      return null;
    }
  },

  async checkSystemUpdates(force = true): Promise<SystemUpdateStatus | null> {
    try {
      const url = force ? '/api/system/update/check?force=true' : '/api/system/update/check';
      const res = await apiFetch(url);
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.debug('[Aegis API] checkSystemUpdates error:', err);
      return null;
    }
  },

  async applySystemUpdate(version?: string): Promise<{ ok: boolean; status?: string; error?: string }> {
    try {
      const res = await apiFetch('/api/system/update/apply', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version: version || '' }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        return { ok: false, error: data?.error?.message || data?.error || `Update failed (HTTP ${res.status})` };
      }
      return { ok: true, status: data?.status || 'started' };
    } catch (err: any) {
      return { ok: false, error: err?.message || 'Network error applying system update' };
    }
  },

  async applyLicenseUpgrade(): Promise<{ ok: boolean; message?: string; status?: string; error?: string }> {
    try {
      const res = await apiFetch('/api/license/upgrade', {
        method: 'POST',
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        return { ok: false, error: data?.error?.message || data?.error || `Upgrade failed (HTTP ${res.status})` };
      }
      return { ok: true, message: data?.message, status: data?.status };
    } catch (err: any) {
      return { ok: false, error: err?.message || 'Network error dispatching license upgrade' };
    }
  },

  async getUpdaterStatus(): Promise<{ available: boolean; status?: string; reason?: string; error?: string }> {
    try {
      const res = await apiFetch('/api/license/updater-status');
      if (!res.ok) return { available: false, reason: `HTTP ${res.status}` };
      return await res.json();
    } catch (err: any) {
      return { available: false, error: err?.message || 'Network error fetching updater status' };
    }
  },

  async getApiSecurityConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/api_security/config');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('getApiSecurityConfig error:', err);
      return null;
    }
  },

  async saveApiSecurityConfig(cfg: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload = normalizeApiSecurityConfigForSave(cfg);
      const res = await apiFetch('/api/sections/api_security/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const errData = await res.json();
          const details = (errData?.error && Array.isArray(errData.error.details))
            ? errData.error.details
            : (Array.isArray(errData?.details) ? errData.details : null);
          if (details && details.length > 0) {
            errMsg = details.map((d: any) => `${d.path ? d.path + ': ' : ''}${d.message}`).join(', ');
          } else if (errData?.error && typeof errData.error === 'object' && errData.error.message) {
            errMsg = errData.error.message;
          } else if (typeof errData?.error === 'string') {
            errMsg = errData.error;
          } else if (errData?.message) {
            errMsg = errData.message;
          }
        } catch {
        }
        return { success: false, error: errMsg };
      }
      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] saveApiSecurityConfig error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getApiSecurityStats(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/api_security/stats');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('getApiSecurityStats error:', err);
      return null;
    }
  },

  async getApiSecurityInventory(params?: Record<string, string | number>): Promise<any> {
    try {
      const qs = params ? '?' + new URLSearchParams(params as any).toString() : '';
      const res = await apiFetch(`/api/sections/api_security/inventory${qs}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('getApiSecurityInventory error:', err);
      return null;
    }
  },

  async uploadApiSecuritySchema(payload: {
    host: string;
    path: string;
    method?: string;
    type: string;
    content: string;
  }): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const method = (payload.method || 'GET').trim().toUpperCase();
      let path = (payload.path || '').trim();
      if (!path.startsWith('/')) path = '/' + path;
      const host = (payload.host || '').trim().toLowerCase();
      const type = (payload.type || 'openapi').trim().toLowerCase();
      const content = (payload.content || '').trim();

      const res = await apiFetch('/api/sections/api_security/schemas', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ host, path, method, type, content }),
      });
      if (!res.ok) {
        let errMsg = `HTTP ${res.status}`;
        try {
          const errText = await res.text();
          if (errText) {
            try {
              const errJson = JSON.parse(errText);
              const details = (errJson?.error && Array.isArray(errJson.error.details))
                ? errJson.error.details
                : (Array.isArray(errJson?.details) ? errJson.details : null);
              if (details && details.length > 0) {
                errMsg = details.map((d: any) => `${d.path ? d.path + ': ' : ''}${d.message}`).join(', ');
              } else if (errJson?.error && typeof errJson.error === 'object' && errJson.error.message) {
                errMsg = errJson.error.message;
              } else if (typeof errJson?.error === 'string') {
                errMsg = errJson.error;
              } else if (errJson?.message) {
                errMsg = errJson.message;
              } else {
                errMsg = errText.trim();
              }
            } catch {
              errMsg = errText.trim();
            }
          }
        } catch {
        }
        return { success: false, error: errMsg };
      }
      const data = await res.json().catch(() => ({}));
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] uploadApiSecuritySchema error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getApiSecuritySchemaHistory(host: string, path: string, method: string = 'GET'): Promise<any[]> {
    try {
      const q = new URLSearchParams({ host: host.trim().toLowerCase(), path: path.trim(), method: method.trim().toUpperCase() });
      const res = await apiFetch(`/api/sections/api_security/schemas/history?${q.toString()}`);
      if (!res.ok) return [];
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getApiSecuritySchemaHistory error:', err);
      return [];
    }
  },

  async getApiSecuritySchemaDiff(fromId: string, toId: string): Promise<any> {
    try {
      const q = new URLSearchParams({ from: fromId.trim(), to: toId.trim() });
      const res = await apiFetch(`/api/sections/api_security/schemas/diff?${q.toString()}`);
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getApiSecuritySchemaDiff error:', err);
      return null;
    }
  },

  async simulateApiSecurity(payload: any): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/api_security/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch (err) {
      console.warn('[Aegis API] simulateApiSecurity error:', err);
      return null;
    }
  },

  async getApiSecurityAnalytics(window: string = '24h'): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/api_security/analytics/dashboard?window=${window}&limit=5`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('getApiSecurityAnalytics error:', err);
      return null;
    }
  },

  async getEdgeAccessConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/config');
      if (res.ok) return await res.json();
      const resSettings = await apiFetch('/api/sections/access_control/settings');
      if (resSettings.ok) {
        const data = await resSettings.json();
        return data?.settings || null;
      }
    } catch (err) {
      console.warn('getEdgeAccessConfig error:', err);
    }
    return null;
  },

  async saveEdgeAccessConfig(cfg: any): Promise<boolean> {
    try {
      const res = await apiFetch('/api/sections/access_control/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      if (res.ok) return true;
      const resSettings = await apiFetch('/api/sections/access_control/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      });
      return resSettings.ok;
    } catch (err) {
      console.error('[Aegis API] saveEdgeAccessConfig error:', err);
      return false;
    }
  },

  async getEdgeAccessApps(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/protected-apps/catalog');
      if (res.ok) {
        const data = await res.json();
        return { success: true, apps: data.apps || data.protected_apps || [] };
      }
      const resFallback = await apiFetch('/api/sections/access_control/protected-apps');
      if (resFallback.ok) {
        const dataFallback = await resFallback.json();
        const apps = (dataFallback.protected_apps || []).map((app: any) => ({
          protected_app: app,
          public_addresses: (app.route?.hosts || []).map((h: string) => `${h}${(app.route?.paths && app.route.paths[0]) || '/*'}`),
          access_summary: {
            candidate_policy_count: 0,
            active_policy_count: 0,
            active_allow_count: 0,
          },
        }));
        return { success: true, apps };
      }
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessApps error:', err);
    }
    return null;
  },

  async getEdgeAccessApp(id: string): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}`);
      if (res.ok) {
        const data = await res.json();
        const inner = data.app?.protected_app || data.app || data.protected_app || data;
        return {
          ...data,
          ...inner,
          app: inner,
          raw_app: data.app,
          protected_app: inner,
        };
      }
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessApp error:', err);
    }
    return null;
  },

  async createEdgeAccessApp(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/protected-apps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.protected_app || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessApp error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async createEdgeAccessAppWithRoute(route: any, protectedApp: any): Promise<{ success: boolean; data?: any; route_id?: string; error?: string }> {
    try {
      const routePayload = {
        priority: 100,
        enabled: true,
        ...route,
      };
      const res = await apiFetch('/api/sections/access_control/protected-apps/create-with-route', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ route: routePayload, protected_app: protectedApp }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.protected_app || data, route_id: data.route_id };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessAppWithRoute error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessApp(id: string, input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload: any = { ...input };
      if (!payload.route_id || !payload.name || payload.revision === undefined) {
        const appRes = await this.getEdgeAccessApp(id);
        const existing = appRes?.app?.protected_app || appRes?.app || appRes?.protected_app || appRes;
        if (existing) {
          payload.route_id = payload.route_id ?? existing.route_id ?? existing.route?.id;
          payload.name = payload.name ?? existing.name;
          payload.revision = payload.revision ?? existing.revision;
          payload.auth_method = payload.auth_method ?? existing.auth_method;
          payload.authorization_mode = payload.authorization_mode ?? existing.authorization_mode;
          payload.deployment_state = payload.deployment_state ?? existing.deployment_state;
        }
      }
      if (payload.revision === undefined) payload.revision = 1;

      // Filter only allowed ProtectedAppInput fields for strict Go decoder compatibility
      const allowedAppFields = new Set([
        'id', 'revision', 'name', 'route_id', 'auth_method',
        'allowed_roles', 'allowed_groups', 'required_claims',
        'policy_id', 'default_action', 'identity_headers',
        'authorization_mode', 'deployment_state',
        'accepted_trust_sources', 'enabled'
      ]);
      const cleanPayload: any = {};
      for (const [key, val] of Object.entries(payload)) {
        if (allowedAppFields.has(key) && val !== undefined) {
          cleanPayload[key] = val;
        }
      }

      let res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cleanPayload),
      });
      let data = await res.json().catch(() => null);
      if (!res.ok && (res.status === 409 || data?.code === 'edge_access_stale_revision' || data?.error === 'stale_revision')) {
        const freshAppRes = await this.getEdgeAccessApp(id);
        const freshApp = freshAppRes?.app || freshAppRes?.protected_app || freshAppRes;
        if (freshApp && freshApp.revision !== undefined) {
          cleanPayload.revision = freshApp.revision;
          cleanPayload.route_id = cleanPayload.route_id || freshApp.route_id;
          res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(cleanPayload),
          });
          data = await res.json().catch(() => null);
        }
      }
      if (res.ok && data) {
        return { success: true, data: data.protected_app || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessApp error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async deleteEdgeAccessApp(id: string, revision?: number): Promise<{ success: boolean; error?: string }> {
    try {
      let rev = revision;
      const appRes = await this.getEdgeAccessApp(id);
      const existing = appRes?.app?.protected_app || appRes?.app || appRes?.protected_app || appRes;
      if (existing) {
        rev = existing.revision || rev || 1;
        if (existing.deployment_state !== 'disabled') {
          const disableRes = await this.updateEdgeAccessApp(id, {
            id: existing.id || id,
            revision: existing.revision,
            name: existing.name,
            route_id: existing.route_id || existing.route?.id,
            auth_method: existing.auth_method,
            authorization_mode: existing.authorization_mode,
            deployment_state: 'disabled',
            enabled: false,
          });
          if (disableRes.success && disableRes.data?.revision) {
            rev = disableRes.data.revision;
          }
        }
      }
      if (!rev) rev = 1;
      let res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision: rev, cascade_confirmed: true }),
      });
      let data = await res.json().catch(() => null);
      if (!res.ok && (res.status === 409 || data?.code === 'edge_access_stale_revision' || data?.error === 'stale_revision')) {
        const freshAppRes = await this.getEdgeAccessApp(id);
        const freshApp = freshAppRes?.app?.protected_app || freshAppRes?.app || freshAppRes?.protected_app || freshAppRes;
        if (freshApp) {
          if (freshApp.deployment_state !== 'disabled') {
            const disableRes = await this.updateEdgeAccessApp(id, {
              id: freshApp.id || id,
              revision: freshApp.revision,
              name: freshApp.name,
              route_id: freshApp.route_id || freshApp.route?.id,
              auth_method: freshApp.auth_method,
              authorization_mode: freshApp.authorization_mode,
              deployment_state: 'disabled',
              enabled: false,
            });
            if (disableRes.success && disableRes.data?.revision) {
              rev = disableRes.data.revision;
            }
          } else if (freshApp.revision) {
            rev = freshApp.revision;
          }
          res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ revision: rev, cascade_confirmed: true }),
          });
          data = await res.json().catch(() => null);
        }
      }
      if (res.ok) return { success: true };
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] deleteEdgeAccessApp error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async deployEdgeAccessApp(id: string, candidateFingerprint?: string, confirmationToken?: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      let fp = candidateFingerprint;
      if (!fp || fp === 'active-fp' || fp === 'reviewed-fp-active') {
        const impact = await this.getEdgeAccessPolicyImpact(id);
        fp = impact?.data?.candidate_fingerprint || (impact as any)?.candidate_fingerprint || fp;
      }
      const body: any = {
        candidate_fingerprint: fp,
        acknowledge_review: true,
      };
      if (confirmationToken) {
        body.impact_confirmation_token = confirmationToken;
      }
      let res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}/policy-deployments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      let data = await res.json().catch(() => null);
      if (!res.ok && (data?.message?.includes('enable the canonical Route') || data?.error?.includes('enable the canonical Route'))) {
        const appRes = await this.getEdgeAccessApp(id);
        const app = appRes?.app?.protected_app || appRes?.app || appRes?.protected_app || appRes;
        const routeId = app?.route_id || app?.route?.id;
        if (routeId) {
          const routes = await this.getRoutes().catch(() => []);
          const targetRoute = routes.find((r: any) => r.id === routeId);
          if (targetRoute) {
            await this.saveRoute({ ...targetRoute, enabled: true }).catch(() => null);
            res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}/policy-deployments`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(body),
            });
            data = await res.json().catch(() => null);
          }
        }
      }
      if (res.ok && data) {
        return { success: true, data: data.protected_app || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] deployEdgeAccessApp error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async rollbackEdgeAccessApp(id: string, deploymentId: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/protected-apps/${encodeURIComponent(id)}/policy-deployments/${encodeURIComponent(deploymentId)}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.protected_app || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] rollbackEdgeAccessApp error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessAppDecisions(appId: string, limit = 5): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/activity/decisions?protected_app_id=${encodeURIComponent(appId)}&limit=${limit}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessAppDecisions error:', err);
    }
    return null;
  },

  async getEdgeAccessPolicyAttachments(filter?: { protected_app_id?: string; policy_id?: string; status?: string }): Promise<any> {
    try {
      const params = new URLSearchParams();
      if (filter?.protected_app_id) params.set('protected_app_id', filter.protected_app_id);
      if (filter?.policy_id) params.set('policy_id', filter.policy_id);
      if (filter?.status) params.set('status', filter.status);
      const qs = params.toString() ? `?${params.toString()}` : '';
      const res = await apiFetch(`/api/sections/access_control/policy-attachments${qs}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessPolicyAttachments error:', err);
    }
    return null;
  },

  async getEdgeAccessAppAttachedPolicies(appId: string): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/policy-attachments?protected_app_id=${encodeURIComponent(appId)}`);
      if (res.ok) return await res.json();
      const resWorkspace = await apiFetch(`/api/sections/access_control/policy-workspace/apps/${encodeURIComponent(appId)}`);
      if (resWorkspace.ok) return await resWorkspace.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessAppAttachedPolicies error:', err);
    }
    return null;
  },

  async getEdgeAccessPolicies(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/access-policies');
      if (res.ok) return await res.json();
      const resLib = await apiFetch('/api/sections/access_control/policy-workspace/library');
      if (resLib.ok) return await resLib.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessPolicies error:', err);
    }
    return null;
  },

  async getEdgeAccessPolicyVersions(policyId: string): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/access-policies/${encodeURIComponent(policyId)}/versions`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessPolicyVersions error:', err);
    }
    return null;
  },

  async createEdgeAccessPolicy(input: { name: string; description?: string }): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/access-policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.policy || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessPolicy error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessPolicy(id: string, input: { name?: string; description?: string; archived?: boolean; revision?: number }): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload: any = { ...input };
      if (!payload.name || payload.revision === undefined) {
        const polRes = await apiFetch(`/api/sections/access_control/access-policies/${encodeURIComponent(id)}`);
        if (polRes.ok) {
          const polData = await polRes.json();
          const pol = polData.policy || polData;
          if (pol) {
            payload.name = payload.name ?? pol.name;
            payload.description = payload.description ?? pol.description;
            payload.revision = payload.revision ?? pol.revision;
          }
        }
      }
      if (payload.revision === undefined) {
        payload.revision = 1;
      }
      const res = await apiFetch(`/api/sections/access_control/access-policies/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.policy || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessPolicy error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async createEdgeAccessPolicyDraft(policyId: string, input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload = { ...input };
      delete payload.version; // Go server requires version to be omitted
      const res = await apiFetch(`/api/sections/access_control/access-policies/${encodeURIComponent(policyId)}/versions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.policy_version || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessPolicyDraft error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async publishEdgeAccessPolicyVersion(policyId: string, version: number, revision = 1): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/access-policies/${encodeURIComponent(policyId)}/versions/${version}/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.policy_version || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] publishEdgeAccessPolicyVersion error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async archiveEdgeAccessPolicy(id: string, revision?: number, name?: string): Promise<any> {
    const payload: any = { archived: true };
    if (revision !== undefined) payload.revision = revision;
    if (name !== undefined) payload.name = name;
    return this.updateEdgeAccessPolicy(id, payload);
  },

  async attachEdgeAccessPolicy(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/policy-attachments', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.attachment || data };
      }
      return { success: false, error: data?.message || data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] attachEdgeAccessPolicy error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessPolicyAttachment(attachmentId: string, input: { revision?: number; path: string; methods: string[]; auth_channels?: string[]; deployment_state?: string }): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload = {
        revision: input.revision ?? 1,
        path: input.path,
        methods: input.methods,
        auth_channels: input.auth_channels !== undefined ? input.auth_channels : ['oidc', 'jwt'],
        deployment_state: input.deployment_state || 'active',
      };
      const res = await apiFetch(`/api/sections/access_control/policy-attachments/${encodeURIComponent(attachmentId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.attachment || data };
      }
      return { success: false, error: data?.message || data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessPolicyAttachment error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async detachEdgeAccessPolicy(attachmentId: string, revision = 1): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/policy-attachments/${encodeURIComponent(attachmentId)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok) return { success: true };
      return { success: false, error: data?.message || data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] detachEdgeAccessPolicy error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async upgradeEdgeAccessPolicyAttachment(attachmentId: string, revision: number, policyVersion: number): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/policy-attachments/${encodeURIComponent(attachmentId)}/upgrade`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ revision, policy_version: policyVersion }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.attachment || data };
      }
      return { success: false, error: data?.message || data?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] upgradeEdgeAccessPolicyAttachment error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessIdentityProviders(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/identity/providers');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessIdentityProviders error:', err);
    }
    return null;
  },

  async createEdgeAccessIdentityProvider(input: any): Promise<{ success: boolean; data?: any; identity_revision?: number; error?: string }> {
    try {
      const payload = { ...input };
      if (payload.identity_revision === undefined) {
        const idpRes = await this.getEdgeAccessIdentityProviders();
        payload.identity_revision = typeof idpRes?.identity_revision === 'number' ? idpRes.identity_revision : 0;
      }
      const res = await apiFetch('/api/sections/access_control/identity/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.provider || data, identity_revision: data.identity_revision };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessIdentityProvider error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessIdentityProvider(id: string, input: any): Promise<{ success: boolean; data?: any; identity_revision?: number; error?: string }> {
    try {
      const payload = { ...input };
      if (payload.identity_revision === undefined) {
        const idpRes = await this.getEdgeAccessIdentityProviders();
        payload.identity_revision = typeof idpRes?.identity_revision === 'number' ? idpRes.identity_revision : 0;
      }
      const res = await apiFetch(`/api/sections/access_control/identity/providers/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.provider || data, identity_revision: data.identity_revision };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessIdentityProvider error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async deleteEdgeAccessIdentityProvider(id: string, revision?: number): Promise<{ success: boolean; identity_revision?: number; error?: string }> {
    try {
      let rev = revision;
      if (rev === undefined) {
        const idpRes = await this.getEdgeAccessIdentityProviders();
        rev = typeof idpRes?.identity_revision === 'number' ? idpRes.identity_revision : 0;
      }
      const res = await apiFetch(`/api/sections/access_control/identity/providers/${encodeURIComponent(id)}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_revision: rev }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok) {
        return { success: true, identity_revision: data?.identity_revision };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] deleteEdgeAccessIdentityProvider error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async validateEdgeAccessIdentityProvider(id: string, revision?: number): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      let rev = revision;
      if (rev === undefined) {
        const idpRes = await this.getEdgeAccessIdentityProviders();
        rev = typeof idpRes?.identity_revision === 'number' ? idpRes.identity_revision : 0;
      }
      const res = await apiFetch(`/api/sections/access_control/identity/providers/${encodeURIComponent(id)}/validate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_revision: rev }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.provider || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] validateEdgeAccessIdentityProvider error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async testEdgeAccessJwtIssuer(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/identity-trust/jwt/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] testEdgeAccessJwtIssuer error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async testEdgeAccessOidcProvider(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/identity-trust/oidc/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] testEdgeAccessOidcProvider error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async previewEdgeAccessClaimMapping(providerId: string, claims: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/identity/mappings/${encodeURIComponent(providerId)}/preview`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ claims }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] previewEdgeAccessClaimMapping error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async saveEdgeAccessClaimMapping(providerId: string, revision?: number, mapping?: any): Promise<{ success: boolean; data?: any; identity_revision?: number; error?: string }> {
    try {
      let rev = revision;
      let map = mapping;
      if (typeof revision === 'object' && mapping === undefined) {
        map = revision;
        rev = undefined;
      }
      if (rev === undefined) {
        const idpRes = await this.getEdgeAccessIdentityProviders();
        rev = typeof idpRes?.identity_revision === 'number' ? idpRes.identity_revision : 0;
      }
      const normalizedMapping = {
        subject: map?.subject || map?.subject_claim || 'sub',
        email: map?.email || map?.email_claim || 'email',
        roles: map?.roles || map?.roles_claim || 'roles',
        groups: map?.groups || map?.groups_claim || 'groups',
      };
      let res = await apiFetch(`/api/sections/access_control/identity/mappings/${encodeURIComponent(providerId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_revision: rev, mapping: normalizedMapping }),
      });
      let data = await res.json().catch(() => null);
      if (!res.ok && (res.status === 409 || data?.code === 'stale_revision' || data?.error === 'stale_revision')) {
        const freshIdp = await this.getEdgeAccessIdentityProviders();
        const freshRev = typeof freshIdp?.identity_revision === 'number' ? freshIdp.identity_revision : 0;
        res = await apiFetch(`/api/sections/access_control/identity/mappings/${encodeURIComponent(providerId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ identity_revision: freshRev, mapping: normalizedMapping }),
        });
        data = await res.json().catch(() => null);
      }
      if (res.ok && data) {
        return { success: true, data: data.mapping || data, identity_revision: data.identity_revision || data.IdentityRevision };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] saveEdgeAccessClaimMapping error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessServiceIdentities(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/service-credentials');
      if (res.ok) {
        const data = await res.json();
        return { success: true, identities: data.credentials || data.identities || [] };
      }
      const resSec = await apiFetch('/api/sections/access_control/identity/service-identities');
      if (resSec.ok) return await resSec.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessServiceIdentities error:', err);
    }
    return null;
  },

  async createEdgeAccessApiKeyCredential(input: any): Promise<{ success: boolean; data?: any; secret?: string; warning?: string; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/service-credentials/api-key', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return {
          success: true,
          data: data.credential || data.key || data,
          secret: data.secret,
          warning: data.warning,
        };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessApiKeyCredential error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async createEdgeAccessMtlsCredential(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/service-credentials/mtls', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.credential || data.key || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessMtlsCredential error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessServiceCredential(id: string, input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/service-credentials/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.credential || data.key || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessServiceCredential error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async rotateEdgeAccessServiceCredential(id: string, input: any = {}): Promise<{ success: boolean; data?: any; secret?: string; warning?: string; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/service-credentials/${encodeURIComponent(id)}/rotate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(input),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return {
          success: true,
          data: data.credential || data.key || data,
          secret: data.secret,
          warning: data.warning,
        };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] rotateEdgeAccessServiceCredential error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async revokeEdgeAccessServiceCredential(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/service-credentials/${encodeURIComponent(id)}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json().catch(() => null);
      if (res.ok) return { success: true };
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] revokeEdgeAccessServiceCredential error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessRoles(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/roles');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessRoles error:', err);
    }
    return null;
  },

  async createEdgeAccessRole(role: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/roles', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(role),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data: data.role || data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] createEdgeAccessRole error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async updateEdgeAccessRole(id: string, role: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/roles/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(role),
      });
      const data = await res.json().catch(() => null);
      if (res.ok) return { success: true, data: data?.role || role };
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] updateEdgeAccessRole error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async deleteEdgeAccessRole(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/sections/access_control/roles/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      const data = await res.json().catch(() => null);
      if (res.ok) return { success: true };
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] deleteEdgeAccessRole error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessDecisions(limit = 50): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/activity/decisions?limit=${limit}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessDecisions error:', err);
    }
    return null;
  },

  async getEdgeAccessDecisionDetail(id: string): Promise<any> {
    try {
      const res = await apiFetch(`/api/sections/access_control/decision-explorer/${encodeURIComponent(id)}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessDecisionDetail error:', err);
    }
    return null;
  },

  async getEdgeAccessPolicyCapabilities(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/access_control/policy-capabilities');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessPolicyCapabilities error:', err);
    }
    return null;
  },

  async getEdgeAccessPolicyImpact(protectedAppId: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/access_control/policy-impact', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ protected_app_id: protectedAppId }),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] getEdgeAccessPolicyImpact error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async simulateEdgeAccessPolicy(input: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload: any = {
        protected_app_id: input.protected_app_id,
        path: input.path || '/',
        method: input.method ? input.method.toUpperCase() : 'GET',
      };
      if (input.source) payload.source = input.source;
      if (input.auth_channel) payload.auth_channel = input.auth_channel;
      if (input.source_ip) payload.source_ip = input.source_ip;
      if (input.evaluated_at) payload.evaluated_at = input.evaluated_at;

      const idRoles = input.identity?.roles || input.roles;
      const idGroups = input.identity?.groups || input.groups;
      const idClaims = input.identity?.claims || input.claims;
      const idUser = input.identity?.id || input.identity_id || input.user_id;

      if (idRoles || idGroups || idClaims || idUser || input.identity) {
        payload.identity = {};
        if (idUser) payload.identity.id = idUser;
        if (input.identity?.type) payload.identity.type = input.identity.type;
        if (Array.isArray(idRoles)) payload.identity.roles = idRoles;
        if (Array.isArray(idGroups)) payload.identity.groups = idGroups;
        if (idClaims) payload.identity.claims = idClaims;
        if (input.identity?.service_credential_id) payload.identity.service_credential_id = input.identity.service_credential_id;
        if (typeof input.identity?.mfa_verified === 'boolean') payload.identity.mfa_verified = input.identity.mfa_verified;
      }
      const res = await apiFetch('/api/sections/access_control/policy-simulations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => null);
      if (res.ok && data) {
        return { success: true, data };
      }
      return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      console.error('[Aegis API] simulateEdgeAccessPolicy error:', err);
      return { success: false, error: err?.message || 'Network error' };
    }
  },

  async getEdgeAccessSettings(): Promise<EdgeAccessSettings | null> {
    try {
      const res = await apiFetch('/api/sections/access_control/settings');
      if (res.ok) {
        const data = await res.json();
        return data?.settings || null;
      }
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessSettings error:', err);
    }
    return null;
  },

  async updateEdgeAccessSettings(settings: EdgeAccessSettings): Promise<EdgeAccessSettings | null> {
    try {
      const res = await apiFetch('/api/sections/access_control/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      });
      if (res.ok) {
        const data = await res.json();
        return data?.settings || null;
      }
    } catch (err) {
      console.error('[Aegis API] updateEdgeAccessSettings error:', err);
    }
    return null;
  },

  async getEdgeAccessReloadStatus(): Promise<ReloadStatusResponse | null> {
    try {
      const res = await apiFetch('/api/sections/access_control/reload/status');
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[Aegis API] getEdgeAccessReloadStatus error:', err);
    }
    return null;
  },

  async reloadEdgeAccess(): Promise<ReloadStatusResponse | null> {
    try {
      const res = await apiFetch('/api/sections/access_control/reload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.error('[Aegis API] reloadEdgeAccess error:', err);
    }
    return null;
  },

  async getBotProtectionConfig(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/bot_protection/config');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getBotProtectionConfig error:', err);
    }
    return null;
  },

  async saveBotProtectionConfig(cfg: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const payload = normalizeBotConfigForSave(cfg);
      const res = await apiFetch('/api/sections/bot_protection/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const errMsg = data?.error?.message || data?.error || data?.message || `HTTP ${res.status}`;
        return { success: false, error: errMsg };
      }
      return { success: true, data: data?.data || data };
    } catch (err: any) {
      console.error('[Aegis API] saveBotProtectionConfig error:', err);
      return { success: false, error: err?.message || 'Failed to save bot protection configuration' };
    }
  },

  async getBotProtectionStats(): Promise<any> {
    try {
      const res = await apiFetch('/api/sections/bot_protection/stats');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getBotProtectionStats error:', err);
    }
    return null;
  },

  async getBotProtectionRules(): Promise<any[]> {
    try {
      const res = await apiFetch('/api/v2/security/bot/rules?section=bot');
      if (res.ok) {
        const data = await res.json();
        return Array.isArray(data?.rules) ? data.rules : [];
      }
    } catch (err) {
      console.warn('[Aegis API] getBotProtectionRules error:', err);
    }
    return [];
  },

  async saveBotRule(rule: any): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const isNew = !rule.id || String(rule.id).startsWith('bot_rule_') || String(rule.id).startsWith('tmp_') || String(rule.id).startsWith('new_');
      
      const payload: Record<string, any> = {
        name: String(rule.name || '').trim(),
        description: String(rule.description || '').trim(),
        enabled: rule.enabled !== false,
        priority: typeof rule.priority === 'number' ? Math.max(1, Math.floor(rule.priority)) : 100,
        type: 'bot',
        section: 'bot',
        phase: 'bot',
        mode: String(rule.mode || '').trim(),
        expression: String(rule.expression || '').trim(),
        action: String(rule.action || 'block').toLowerCase().trim(),
      };

      if (!isNew && rule.id) {
        payload.id = String(rule.id).trim();
      }
      if (rule.action_params && typeof rule.action_params === 'object') {
        payload.action_params = rule.action_params;
      }
      if (Array.isArray(rule.tags)) {
        payload.tags = rule.tags.map(String).map((t: string) => t.trim()).filter(Boolean);
      }

      const url = !isNew && rule.id ? `/api/v2/security/bot/rules/${encodeURIComponent(rule.id)}` : '/api/v2/security/bot/rules';
      const method = !isNew && rule.id ? 'PUT' : 'POST';
      const res = await apiFetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const errMsg = data?.error?.message || data?.error || data?.message || `HTTP ${res.status}`;
        return { success: false, error: errMsg };
      }
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] saveBotRule error:', err);
      return { success: false, error: err?.message || 'Failed to save bot rule' };
    }
  },

  async deleteBotRule(id: string): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch(`/api/v2/security/bot/rules/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        const errMsg = data?.error?.message || data?.error || data?.message || `HTTP ${res.status}`;
        return { success: false, error: errMsg };
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] deleteBotRule error:', err);
      return { success: false, error: err?.message || 'Failed to delete bot rule' };
    }
  },

  async reorderBotRules(ids: string[]): Promise<{ success: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/v2/security/bot/rules/reorder', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        const errMsg = data?.error?.message || data?.error || data?.message || `HTTP ${res.status}`;
        return { success: false, error: errMsg };
      }
      return { success: true };
    } catch (err: any) {
      console.error('[Aegis API] reorderBotRules error:', err);
      return { success: false, error: err?.message || 'Failed to reorder bot rules' };
    }
  },

  async getAntibotConfig(): Promise<any> {
    return this.getBotProtectionConfig();
  },

  async saveAntibotConfig(cfg: any): Promise<{ success: boolean; data?: any; error?: string }> {
    return this.saveBotProtectionConfig(cfg);
  },

  async getBotStats(): Promise<any> {
    return this.getBotProtectionStats();
  },

  async reloadBotSignatures(): Promise<{ success: boolean; message?: string; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/bot_protection/signatures/reload', {
        method: 'POST',
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { success: false, error: data?.error?.message || data?.error || `HTTP ${res.status}` };
      }
      return { success: true, message: data?.message || 'Signatures reloaded successfully' };
    } catch (err: any) {
      console.error('[Aegis API] reloadBotSignatures error:', err);
      return { success: false, error: err?.message || 'Failed to reload signatures' };
    }
  },

  async rollbackBotConfig(expectedActiveRevision: string): Promise<{ success: boolean; data?: any; error?: string }> {
    try {
      const res = await apiFetch('/api/sections/bot_protection/config/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expected_active_revision: expectedActiveRevision }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { success: false, error: data?.error?.message || data?.error || `HTTP ${res.status}` };
      }
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] rollbackBotConfig error:', err);
      return { success: false, error: err?.message || 'Failed to rollback bot configuration' };
    }
  },

  async testBotRule(rule: any, request: any): Promise<{ success: boolean; matched?: boolean; error?: string }> {
    try {
      const res = await apiFetch('/api/v2/security/bot/rules/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule, request }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { success: false, error: data?.error?.message || data?.error || `HTTP ${res.status}` };
      }
      return { success: true, matched: data.matched };
    } catch (err: any) {
      console.error('[Aegis API] testBotRule error:', err);
      return { success: false, error: err?.message || 'Failed to test bot rule' };
    }
  },

  async validateBotExpression(expression: string): Promise<{ valid: boolean; errors?: any[]; error?: string }> {
    try {
      const res = await apiFetch('/api/v2/security/bot/rules/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ expression }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { valid: false, error: data?.error?.message || data?.error || `HTTP ${res.status}` };
      }
      return { valid: data.valid !== false, errors: data.errors };
    } catch (err: any) {
      console.error('[Aegis API] validateBotExpression error:', err);
      return { valid: false, error: err?.message || 'Failed to validate expression' };
    }
  },

  async getBotRuleTemplates(): Promise<any[]> {
    try {
      const res = await apiFetch('/api/v2/security/bot/rules/templates');
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data?.templates) && data.templates.length > 0) {
          return data.templates;
        }
      }
    } catch (err) {
      console.warn('[Aegis API] getBotRuleTemplates error:', err);
    }
    // High-fidelity fallback presets covering common bot mitigation scenarios
    return [
      {
        name: 'Block Aggressive Scraping',
        description: 'Challenge or block clients triggering high request velocity with low bot score',
        priority: 100,
        action: 'block',
        expression: 'aegis.bot.score lt 30 and aegis.bot.headless eq true',
        tags: ['template', 'scraping', 'headless'],
        enabled: true,
      },
      {
        name: 'Credential Stuffing Protection',
        description: 'Challenge repeated authentication attempts from automated or high threat sources',
        priority: 150,
        action: 'challenge',
        expression: 'http.request.uri.path starts_with "/api/v1/auth" and ip.reputation.score gt 60',
        tags: ['template', 'credential-stuffing', 'auth'],
        enabled: true,
      },
      {
        name: 'AI Crawler & LLM Scraper Block',
        description: 'Block commercial LLM crawlers, data harvesting scrapers, and headless agents',
        priority: 200,
        action: 'block',
        expression: 'http.user_agent contains "GPTBot" or http.user_agent contains "ClaudeBot" or http.user_agent contains "Bytespider"',
        tags: ['template', 'ai-crawler'],
        enabled: true,
      },
      {
        name: 'Detect Automated Scanners',
        description: 'Drop traffic from common security vulnerability scanners and recon tools',
        priority: 250,
        action: 'block',
        expression: 'http.user_agent contains "sqlmap" or http.user_agent contains "Nikto" or http.user_agent contains "Nmap"',
        tags: ['template', 'scanner', 'recon'],
        enabled: true,
      },
    ];
  },

  async getBotVisitors(): Promise<any[]> {
    try {
      const res = await apiFetch('/api/sections/bot_protection/visitors');
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getBotVisitors error:', err);
    }
    return [];
  },

  async getBotVisitor(hash: string): Promise<any | null> {
    try {
      const res = await apiFetch(`/api/sections/bot_protection/visitors/${encodeURIComponent(hash)}`);
      if (res.ok) return await res.json();
    } catch (err) {
      console.warn('[Aegis API] getBotVisitor error:', err);
    }
    return null;
  },

  async getProfile(): Promise<ProfileDetails | null> {
    try {
      const res = await apiFetch('/api/profile');
      if (!res.ok) return null;
      return (await res.json()) as ProfileDetails;
    } catch (err) {
      console.warn('[Aegis API] getProfile error:', err);
      return null;
    }
  },

  async updateProfilePassword(password: string): Promise<{ success: boolean; error?: string; reauth_required?: boolean }> {
    try {
      const res = await apiFetch('/api/profile', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      });
      const rawText = await res.text().catch(() => '');
      let data: any = null;
      try {
        data = rawText ? JSON.parse(rawText) : null;
      } catch {
        // Response is plaintext (e.g. Go http.Error)
      }
      if (!res.ok) {
        const errorMsg = data?.error || data?.message || (rawText ? rawText.trim() : null) || `HTTP ${res.status}`;
        return { success: false, error: errorMsg };
      }
      return { success: true, reauth_required: data?.reauth_required ?? true };
    } catch (err: any) {
      console.error('[Aegis API] updateProfilePassword error:', err);
      return { success: false, error: err?.message || 'Failed to update password' };
    }
  },

  async setupMFA(): Promise<{ success: boolean; data?: MFASecretData; error?: string }> {
    try {
      const res = await apiFetch('/api/mfa/setup', {
        method: 'POST',
      });
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
      }
      const data = (await res.json()) as MFASecretData;
      return { success: true, data };
    } catch (err: any) {
      console.error('[Aegis API] setupMFA error:', err);
      return { success: false, error: err?.message || 'Failed to initialize MFA' };
    }
  },

  async enableMFA(code: string): Promise<{ success: boolean; error?: string; reauth_required?: boolean }> {
    try {
      const res = await apiFetch('/api/mfa/enable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
      }
      return { success: true, reauth_required: data?.reauth_required ?? false };
    } catch (err: any) {
      console.error('[Aegis API] enableMFA error:', err);
      return { success: false, error: err?.message || 'Failed to enable MFA' };
    }
  },

  async disableMFA(code: string): Promise<{ success: boolean; error?: string; reauth_required?: boolean }> {
    try {
      const res = await apiFetch('/api/mfa/disable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { success: false, error: data?.error || data?.message || `HTTP ${res.status}` };
      }
      return { success: true, reauth_required: data?.reauth_required ?? false };
    } catch (err: any) {
      console.error('[Aegis API] disableMFA error:', err);
      return { success: false, error: err?.message || 'Failed to disable MFA' };
    }
  },

  async login(username: string, password: string, rememberMe = false): Promise<LoginResult> {
    try {
      const res = await fetch('/api/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ username, password, remember_me: rememberMe }),
      });
      const raw = await res.text().catch(() => '');
      let data: any = null;
      try {
        data = JSON.parse(raw);
      } catch {
      }

      if (res.status === 200 && data?.status === 'mfa_required') {
        return { success: true, mfaRequired: true };
      }

      if (res.ok) {
        if (data?.csrf_token) {
          cachedCsrfToken = data.csrf_token;
        }
        const user = await this.verifySession();
        return {
          success: true,
          user: user || { status: 'active', username, id: data?.id || username },
        };
      }

      const errMsg =
        data?.error ||
        data?.message ||
        (raw && raw.length < 150 ? raw.trim() : null) ||
        'Invalid username or password.';
      return { success: false, error: errMsg };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Connection error. Please try again.' };
    }
  },

  async verifyMFA(code: string): Promise<LoginResult> {
    try {
      const cleanCode = code.replace(/\s/g, '');
      const res = await fetch('/api/login/mfa', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ code: cleanCode }),
      });
      const raw = await res.text().catch(() => '');
      let data: any = null;
      try {
        data = JSON.parse(raw);
      } catch {
      }

      if (res.ok) {
        if (data?.csrf_token) {
          cachedCsrfToken = data.csrf_token;
        }
        const user = await this.verifySession();
        return {
          success: true,
          user: user || { status: 'active', username: data?.username || 'admin', id: data?.id || 'admin' },
        };
      }

      const errMsg =
        data?.error ||
        data?.message ||
        (raw && raw.length < 150 ? raw.trim() : null) ||
        'Invalid verification code. Please check your app.';
      return { success: false, error: errMsg };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Connection error. Please try again.' };
    }
  },

  async logout(): Promise<boolean> {
    try {
      const token = cachedCsrfToken;
      cachedCsrfToken = null;
      await fetch('/api/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
          ...(token ? { 'X-CSRF-Token': token } : {}),
        },
      });
      return true;
    } catch {
      return false;
    }
  },

  async verifySession(): Promise<UserSession | null> {
    try {
      const res = await fetch('/api/verify_session', {
        method: 'GET',
        credentials: 'include',
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.status === 'active') {
          if (data.csrf_token) {
            cachedCsrfToken = data.csrf_token;
          }
          return data as UserSession;
        }
      }
      return null;
    } catch {
      return null;
    }
  },

  async requestPasswordReset(email: string): Promise<{ success: boolean; message?: string; error?: string }> {
    try {
      const res = await fetch('/api/request-reset', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ email: email.trim() }),
      });
      const raw = await res.text().catch(() => '');
      let data: any = null;
      try {
        data = JSON.parse(raw);
      } catch {
      }
      if (res.ok) {
        return {
          success: true,
          message:
            data?.message ||
            (raw && raw.length < 150 ? raw.trim() : null) ||
            'If an account exists with this email, a reset link will be sent shortly.',
        };
      }
      const errMsg =
        data?.error ||
        data?.message ||
        (raw && raw.length < 150 ? raw.trim() : null) ||
        'Failed to request password reset.';
      return { success: false, error: errMsg };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Connection error. Please try again.' };
    }
  },

  async confirmPasswordReset(token: string, password: string): Promise<{ success: boolean; message?: string; error?: string }> {
    try {
      const res = await fetch('/api/reset-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ token: token.trim(), password }),
      });
      const raw = await res.text().catch(() => '');
      let data: any = null;
      try {
        data = JSON.parse(raw);
      } catch {
      }
      if (res.ok) {
        return {
          success: true,
          message: data?.message || 'Password updated successfully.',
        };
      }
      const errMsg =
        data?.error ||
        data?.message ||
        (raw && raw.length < 150 ? raw.trim() : null) ||
        'Invalid or expired password reset link.';
      return { success: false, error: errMsg };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Connection error. Please try again.' };
    }
  },

  async getAppSecurityEffectiveState(): Promise<AppSecurityEffectiveState | null> {
    try {
      const res = await apiFetch('/api/sections/http_security/effective-state');
      if (res.ok) {
        return await res.json();
      }
      return null;
    } catch (err) {
      console.warn('Failed to fetch App Security effective state:', err);
      return null;
    }
  },

  async getAppSecurityConfig(): Promise<AppSecurityConfig | null> {
    try {
      const [res, sysRes] = await Promise.allSettled([
        apiFetch('/api/sections/http_security/config'),
        apiFetch('/api/config'),
      ]);
      if (res.status === 'fulfilled' && res.value.ok) {
        const cfg: AppSecurityConfig = await res.value.json();
        if (sysRes.status === 'fulfilled' && sysRes.value.ok) {
          const sysData = await sysRes.value.json().catch(() => null);
          const contact =
            sysData?.security_txt?.contact ??
            sysData?.['security_txt.contact'] ??
            cfg.security_txt?.contact ??
            '';
          cfg.security_txt = { contact: String(contact || '') };
          cfg['security_txt.contact'] = String(contact || '');
        }
        return cfg;
      }
      return null;
    } catch (err) {
      console.warn('Failed to fetch App Security config:', err);
      return null;
    }
  },

  async saveAppSecurityConfig(updates: Partial<AppSecurityConfig>): Promise<{ success: boolean; error?: string }> {
    try {
      const patchPayload: Record<string, any> = { ...updates };

      let securityTxtContact: string | undefined;
      if (patchPayload.security_txt && typeof patchPayload.security_txt === 'object') {
        securityTxtContact = String(patchPayload.security_txt.contact ?? '').trim();
        delete patchPayload.security_txt;
      }
      if ('security_txt.contact' in patchPayload) {
        securityTxtContact = String(patchPayload['security_txt.contact'] ?? '').trim();
        delete patchPayload['security_txt.contact'];
      }

      if (securityTxtContact !== undefined) {
        const cfgRes = await apiFetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 'security_txt.contact': securityTxtContact }),
        });
        if (!cfgRes.ok) {
          const errData = await cfgRes.json().catch(() => null);
          return {
            success: false,
            error: errData?.message || errData?.error?.message || errData?.error || `HTTP ${cfgRes.status}`,
          };
        }
      }

      if (patchPayload.header_manager && typeof patchPayload.header_manager === 'object') {
        const hm = patchPayload.header_manager;
        if (
          hm.add_request_headers === undefined ||
          hm.remove_request_headers === undefined ||
          hm.add_response_headers === undefined ||
          hm.remove_response_headers === undefined
        ) {
          try {
            const curRes = await apiFetch('/api/sections/http_security/config');
            if (curRes.ok) {
              const curCfg = await curRes.json();
              const curHm = curCfg?.header_manager || {};
              patchPayload.header_manager = {
                enabled: hm.enabled ?? curHm.enabled ?? false,
                add_request_headers: hm.add_request_headers ?? curHm.add_request_headers ?? {},
                remove_request_headers: hm.remove_request_headers ?? curHm.remove_request_headers ?? [],
                add_response_headers: hm.add_response_headers ?? curHm.add_response_headers ?? {},
                remove_response_headers: hm.remove_response_headers ?? curHm.remove_response_headers ?? [],
              };
            }
          } catch {
          }
        }
      }

      if (patchPayload.request_body_guard && patchPayload.upload_limit) {
        try {
          const eff = await this.getAppSecurityEffectiveState();
          const funcs = eff?.functions;
          const rbgState = Array.isArray(funcs)
            ? (funcs as any[]).find((f: any) => f?.name === 'request_body_guard' || f?.id === 'request_body_guard' || f?.function_id === 'request_body_guard')
            : (funcs as any)?.request_body_guard;
          if (rbgState && (rbgState as any).entitled === false) {
            delete patchPayload.request_body_guard;
          }
        } catch {
        }
      }

      if (patchPayload.request_body_guard && typeof patchPayload.request_body_guard === 'object') {
        const rbg = { ...patchPayload.request_body_guard };
        delete rbg.graphql;
        delete rbg.max_findings;
        patchPayload.request_body_guard = rbg;
      }

      if (Object.keys(patchPayload).length === 0) {
        return { success: true };
      }

      let res = await apiFetch('/api/sections/http_security/config', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patchPayload),
      });

      if (res.status === 403 && patchPayload.request_body_guard && patchPayload.upload_limit) {
        const clone = res.clone();
        const errBody = await clone.json().catch(() => null);
        const errCode = errBody?.error?.code || errBody?.code || '';
        if (errCode === 'FEATURE_NOT_ENTITLED' || /not entitled/i.test(JSON.stringify(errBody || ''))) {
          const retryPayload = { ...patchPayload };
          delete retryPayload.request_body_guard;
          res = await apiFetch('/api/sections/http_security/config', {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(retryPayload),
          });
        }
      }

      if (res.ok) {
        return { success: true };
      }
      const data = await res.json().catch(() => null);
      return { success: false, error: data?.message || data?.error?.message || `HTTP ${res.status}` };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error saving App Security config' };
    }
  },

  async toggleAppSecurityFunction(functionId: string, enabled: boolean): Promise<boolean> {
    try {
      const res = await apiFetch(`/api/sections/http_security/functions/${encodeURIComponent(functionId)}/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      return res.ok;
    } catch {
      return false;
    }
  },

  async getAppSecurityStats(): Promise<AppSecurityStats> {
    try {
      const res = await apiFetch('/api/sections/http_security/stats');
      if (res.ok) {
        const data = await res.json();
        return {
          total: Number(data.total || data.total_requests || 0),
          blocked: Number(data.blocked || data.blocked_requests || 0),
          allowed: Number(data.allowed || 0),
          compressed: Number(data.compressed || 0),
        };
      }
    } catch (err) {
      console.warn('Failed to fetch App Security stats:', err);
    }
    return { total: 0, blocked: 0, allowed: 0, compressed: 0 };
  },

  async getAlerts(): Promise<AlertsResponse> {
    try {
      const res = await apiFetch('/api/alerts');
      if (res.ok) {
        return await res.json();
      }
    } catch (err) {
      console.warn('[Aegis API] getAlerts error:', err);
    }
    return { alerts: [], unread_count: 0 };
  },

  async markAlertRead(id: string): Promise<{ success: boolean; marked?: number; error?: string }> {
    try {
      const res = await apiFetch('/api/alerts/read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ all: false, ids: [id] }),
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, marked: data.marked };
      }
      const errData = await res.json().catch(() => null);
      return { success: false, error: errData?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error marking alert read' };
    }
  },

  async markAllAlertsRead(): Promise<{ success: boolean; marked?: number; error?: string }> {
    try {
      const res = await apiFetch('/api/alerts/read', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ all: true, ids: [] }),
      });
      if (res.ok) {
        const data = await res.json();
        return { success: true, marked: data.marked };
      }
      const errData = await res.json().catch(() => null);
      return { success: false, error: errData?.error || `HTTP ${res.status}` };
    } catch (err: any) {
      return { success: false, error: err?.message || 'Network error marking all alerts read' };
    }
  },

  async getUsers(page: number = 1, limit: number = 10): Promise<UsersListResponse> {
    const res = await apiFetch(`/api/users?page=${page}&limit=${limit}`);
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to fetch users (HTTP ${res.status})`);
    }
    return res.json();
  },

  async createUser(payload: UserPayload): Promise<{ status: string; id: string }> {
    const res = await apiFetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to create user (HTTP ${res.status})`);
    }
    return res.json();
  },

  async updateUser(payload: UserPayload): Promise<{ status: string }> {
    const res = await apiFetch('/api/users', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to update user (HTTP ${res.status})`);
    }
    return res.json();
  },

  async deleteUser(id: string): Promise<{ status: string }> {
    const res = await apiFetch(`/api/users?id=${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to deactivate user (HTTP ${res.status})`);
    }
    return res.json();
  },

  async getRoles(): Promise<RolesListResponse> {
    const res = await apiFetch('/api/roles');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to fetch roles (HTTP ${res.status})`);
    }
    return res.json();
  },

  async createRole(payload: RolePayload): Promise<{ status: string; id: string }> {
    const res = await apiFetch('/api/roles', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to create role (HTTP ${res.status})`);
    }
    return res.json();
  },

  async updateRole(payload: RolePayload): Promise<{ status: string; id: string }> {
    const res = await apiFetch('/api/roles', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to update role (HTTP ${res.status})`);
    }
    return res.json();
  },

  async deleteRole(id: string): Promise<void> {
    const res = await apiFetch('/api/roles', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to delete role (HTTP ${res.status})`);
    }
  },

  async getPermissions(): Promise<PermissionsListResponse> {
    const res = await apiFetch('/api/permissions');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error || `Failed to fetch permissions (HTTP ${res.status})`);
    }
    return res.json();
  },

  async getSetupStatus(): Promise<SetupStatusResponse> {
    const res = await apiFetch('/api/setup/status');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error?.code || errData?.error || `Failed to fetch setup status (HTTP ${res.status})`);
    }
    return res.json();
  },

  async getSetupBootstrap(): Promise<SetupBootstrapResponse> {
    const res = await apiFetch('/api/setup/bootstrap');
    if (!res.ok) {
      const errData = await res.json().catch(() => null);
      throw new Error(errData?.error?.code || errData?.error || `Failed to fetch setup bootstrap (HTTP ${res.status})`);
    }
    return res.json();
  },

  async createSetupFirstAdmin(payload: SetupFirstAdminRequest): Promise<SetupFirstAdminResponse> {
    const res = await apiFetch('/api/setup/first-admin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status !== 'ok') {
      throw new Error(data?.error?.code || data?.error || `Failed to create setup administrator (HTTP ${res.status})`);
    }
    if (data.csrf_token) {
      cachedCsrfToken = data.csrf_token;
    }
    return data;
  },

  async preflightSetupStoragePostgreSQL(payload: PostgreSQLPreflightRequest): Promise<{ status: string; connection?: any; error?: any }> {
    const res = await apiFetch('/api/setup/storage/control/postgresql/preflight', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status !== 'ok') {
      return { status: 'error', error: data?.error?.code || data?.error || 'PostgreSQL connection failed' };
    }
    return data;
  },

  async saveSetupStoragePostgreSQLPending(payload: PostgreSQLControlPendingRequest): Promise<{ status: string; restart_required?: boolean; error?: string }> {
    const res = await apiFetch('/api/setup/storage/control/postgresql/pending', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status !== 'pending') {
      return { status: 'error', error: data?.error?.code || data?.error || 'Failed to save pending PostgreSQL settings' };
    }
    return data;
  },

  async preflightSetupStorageClickHouse(payload: ClickHousePreflightRequest): Promise<{ status: string; connection?: any; error?: any }> {
    const res = await apiFetch('/api/setup/storage/analytics/clickhouse/preflight', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status !== 'ok') {
      return { status: 'error', error: data?.error?.code || data?.error || 'ClickHouse connection failed' };
    }
    return data;
  },

  async saveSetupStorageClickHousePending(payload: ClickHouseAnalyticsPendingRequest): Promise<{ status: string; restart_required?: boolean; error?: string }> {
    const res = await apiFetch('/api/setup/storage/analytics/clickhouse/pending', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || (data?.status !== 'pending' && data?.status !== 'active')) {
      return { status: 'error', error: data?.error?.code || data?.error || 'Failed to save pending ClickHouse settings' };
    }
    return data;
  },

  async completeSetup(): Promise<SetupCompleteResponse> {
    const res = await apiFetch('/api/setup/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
    const data = await res.json().catch(() => null);
    if (!res.ok || data?.status !== 'ok') {
      throw new Error(data?.error?.code || data?.error || `Failed to complete setup (HTTP ${res.status})`);
    }
    return data;
  },
};

