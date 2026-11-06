import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Tabs,
  TabList,
  Tab,
  TabPanels,
  TabPanel,
  TextInput,
  TextArea,
  Select,
  SelectItem,
  Toggle,
  Button,
  Tag,
  InlineNotification,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  ContentSwitcher,
  Switch,
  CodeSnippet,
} from '@carbon/react';
import {
  Security,
  ArrowLeft,
  View,
  Cookie,
  SettingsAdjust,
  Add,
  TrashCan,
  CheckmarkOutline,
  WarningAlt,
  Renew,
  DocumentSecurity,
  Globe,
  Locked,
} from '@carbon/icons-react';
import {
  PageHeader,
  SectionCard,
  StatusToggle,
  SaveActionBar,
  RadioCardGroup,
} from '../components/common';
import { apiService } from '../services/api';
import type {
  NavItemKey,
  AppSecurityConfig,
  AppSecuritySecurityHeadersConfig,
  AppSecurityInfoHidingConfig,
  AppSecurityCookieHardenerConfig,
  AppSecurityHeaderManagerConfig,
} from '../types';

interface AppSecurityResponsePageProps {
  onNavigate?: (key: NavItemKey) => void;
}

const RESPONSE_POSTURE_PRESETS: Record<string, { label: string; desc: string; icon: any }> = {
  baseline: {
    label: 'Standard',
    desc: 'Safe default headers for modern web applications.',
    icon: Security,
  },
  strict_browser: {
    label: 'Strict',
    desc: 'HSTS with preloading, framing blocked (DENY), and strict referrer policy.',
    icon: Locked,
  },
  compatibility: {
    label: 'Permissive',
    desc: 'Same-origin framing with relaxed browser permissions.',
    icon: Globe,
  },
  custom: {
    label: 'Custom',
    desc: 'Manually configure browser security headers.',
    icon: SettingsAdjust,
  },
};

const COOKIE_PRESETS: Record<string, { label: string; desc: string; icon: any }> = {
  balanced: {
    label: 'Balanced',
    desc: 'Enforce Secure, HttpOnly, and SameSite=Lax.',
    icon: Cookie,
  },
  strict: {
    label: 'Strict',
    desc: 'Enforce Secure, HttpOnly, and SameSite=Strict.',
    icon: Security,
  },
  preserve: {
    label: 'Pass-through',
    desc: 'Preserve upstream Set-Cookie attributes unchanged.',
    icon: Renew,
  },
  custom: {
    label: 'Custom',
    desc: 'Manually configure cookie security flags.',
    icon: SettingsAdjust,
  },
};

interface DirectiveMeta {
  key: string;
  name: string;
  desc: string;
  standardSources: string[];
}

const DIRECTIVE_METADATA: DirectiveMeta[] = [
  {
    key: 'default-src',
    name: 'Default fallback',
    desc: 'Fallback rule for all unspecified resource directives',
    standardSources: ["'self'", "'none'", 'https:', 'data:'],
  },
  {
    key: 'script-src',
    name: 'JavaScript execution',
    desc: 'Governs valid sources for JavaScript execution',
    standardSources: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https:', "'none'"],
  },
  {
    key: 'style-src',
    name: 'CSS stylesheets',
    desc: 'Origins permitted for stylesheets and style tags',
    standardSources: ["'self'", "'unsafe-inline'", 'https:', 'data:'],
  },
  {
    key: 'img-src',
    name: 'Images & Favicons',
    desc: 'Permitted origins for image assets, icons, and media',
    standardSources: ["'self'", 'data:', 'https:', 'blob:'],
  },
  {
    key: 'connect-src',
    name: 'API & WebSocket targets',
    desc: 'Endpoints permitted for fetch, XHR, and WebSocket requests',
    standardSources: ["'self'", 'https:', 'wss:', "'none'"],
  },
  {
    key: 'frame-ancestors',
    name: 'Embedding parents',
    desc: 'Origins permitted to embed this application in an iframe',
    standardSources: ["'self'", "'none'", 'https:'],
  },
  {
    key: 'font-src',
    name: 'Web fonts',
    desc: 'Origins permitted to load web fonts',
    standardSources: ["'self'", 'data:', 'https:'],
  },
  {
    key: 'object-src',
    name: 'Plugins & Objects',
    desc: 'Origins for legacy objects, applets, and Flash embeds',
    standardSources: ["'none'", "'self'"],
  },
];

const CSP_PRESET_DEFINITIONS: Record<string, { label: string; desc: string; value: string }> = {
  strict: {
    label: 'Strict / Zero-Trust',
    desc: "Single-page apps: denies iframe embedding ('none'), blocks inline scripts and eval.",
    value: "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; object-src 'none'",
  },
  balanced: {
    label: 'Standard (Recommended)',
    desc: "Standard web apps: same-origin framing, safe data/blob assets, and secure HTTPS calls.",
    value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'",
  },
  compatibility: {
    label: 'Permissive (Legacy Sites)',
    desc: "Permits inline scripts, styles, and external HTTPS assets for legacy CMS or widget support.",
    value: "default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'self'",
  },
};

type ScriptPolicy = 'strict' | 'balanced' | 'permissive' | 'off';

const PERMISSION_FEATURES = ['camera', 'microphone', 'geolocation', 'payment', 'usb', 'fullscreen', 'autoplay'];

const PERMISSIONS_PRESETS: Record<string, { label: string; desc: string; value: string }> = {
  baseline: {
    label: 'Baseline',
    desc: 'Privacy-first with self fullscreen allowed',
    value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(self), autoplay=()',
  },
  strict: {
    label: 'Strict',
    desc: 'Denies all hardware and sensitive browser capabilities',
    value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), fullscreen=(), autoplay=()',
  },
  compatibility: {
    label: 'Compatibility',
    desc: 'Permits self-origin geolocation, payments, and fullscreen',
    value: 'camera=(), microphone=(), geolocation=(self), payment=(self), usb=(), fullscreen=(self), autoplay=(self)',
  },
};

const SUGGESTED_STRIP_HEADERS = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Generator'];

const parseCSP = (val: string): Record<string, string[]> => {
  const result: Record<string, string[]> = {};
  val.split(';').forEach((part) => {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) return;
    const [directive, ...sources] = tokens;
    result[directive] = sources;
  });
  return result;
};

const serializeCSP = (map: Record<string, string[]>): string => {
  return Object.entries(map)
    .filter(([_, sources]) => Array.isArray(sources) && sources.length > 0)
    .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
    .join('; ');
};

const parsePermissionsPolicy = (val: string): Record<string, string> => {
  const result: Record<string, string> = {};
  val.split(',').forEach((part) => {
    const [rawFeature, rawAllow] = part.split('=');
    const feature = String(rawFeature || '').trim();
    const allow = String(rawAllow || '').trim();
    if (!feature) return;
    result[feature] = allow || '()';
  });
  return result;
};

const serializePermissionsPolicy = (map: Record<string, string>): string => {
  return PERMISSION_FEATURES
    .filter((feature) => map[feature])
    .map((feature) => `${feature}=${map[feature]}`)
    .join(', ');
};

export const AppSecurityResponsePage: React.FC<AppSecurityResponsePageProps> = ({ onNavigate }) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    type: 'success' | 'error' | 'info';
    message: string;
  } | null>(null);

  const [serverConfig, setServerConfig] = useState<AppSecurityConfig>({ enabled: true });

  const [shEnabled, setShEnabled] = useState<boolean>(true);
  const [xFrameOptions, setXFrameOptions] = useState<string>('SAMEORIGIN');
  const [hsts, setHsts] = useState<string>('max-age=31536000; includeSubDomains');
  const [customHsts, setCustomHsts] = useState<string>('');
  const [xContentTypeOptions, setXContentTypeOptions] = useState<string>('nosniff');
  const [referrerPolicy, setReferrerPolicy] = useState<string>('strict-origin-when-cross-origin');
  const [permissionsPolicy, setPermissionsPolicy] = useState<string>(PERMISSIONS_PRESETS.baseline.value);

  const [csp, setCsp] = useState<string>(CSP_PRESET_DEFINITIONS.balanced.value);
  const [cspTier, setCspTier] = useState<'simple' | 'expert'>('simple');
  const [cspExpertView, setCspExpertView] = useState<'visual' | 'raw'>('visual');
  const [cspCustomInput, setCspCustomInput] = useState<Record<string, string>>({});

  const [scriptPolicy, setScriptPolicy] = useState<ScriptPolicy>('balanced');
  const [simpleAllowDataUris, setSimpleAllowDataUris] = useState<boolean>(true);
  const [simpleFramingPolicy, setSimpleFramingPolicy] = useState<'deny' | 'self' | 'allow'>('self');
  const [simpleAllowedDomains, setSimpleAllowedDomains] = useState<string[]>([]);
  const [simpleNewDomainInput, setSimpleNewDomainInput] = useState<string>('');

  const [ihEnabled, setIhEnabled] = useState<boolean>(true);
  const [stripHeaders, setStripHeaders] = useState<string[]>([
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-Generator',
  ]);
  const [newStripHeaderInput, setNewStripHeaderInput] = useState<string>('');

  const [securityTxtContact, setSecurityTxtContact] = useState<string>('');
  const [securityTxtStatus, setSecurityTxtStatus] = useState<{
    status: 'idle' | 'checking' | 'published' | 'mismatch' | 'unavailable' | 'not_configured';
    message?: string;
  }>({ status: 'idle' });

  const [chEnabled, setChEnabled] = useState<boolean>(true);
  const [forceSecure, setForceSecure] = useState<boolean>(true);
  const [forceHttpOnly, setForceHttpOnly] = useState<boolean>(true);
  const [forceSameSite, setForceSameSite] = useState<string>('Lax');

  const [hmEnabled, setHmEnabled] = useState<boolean>(false);
  const [addResponseHeaders, setAddResponseHeaders] = useState<Record<string, string>>({});
  const [removeResponseHeaders, setRemoveResponseHeaders] = useState<string[]>([]);
  const [newHeaderName, setNewHeaderName] = useState<string>('');
  const [newHeaderValue, setNewHeaderValue] = useState<string>('');
  const [newRemoveHeaderInput, setNewRemoveHeaderInput] = useState<string>('');

  // Helper to re-synthesize CSP from Simple Mode Intent States
  const synthesizeCspFromSimple = useCallback(
    (
      policy: ScriptPolicy,
      allowData: boolean,
      framing: 'deny' | 'self' | 'allow',
      domains: string[]
    ) => {
      const map: Record<string, string[]> = {};

      if (policy === 'strict') {
        map['default-src'] = ["'self'"];
        map['script-src'] = ["'self'"];
        map['style-src'] = ["'self'"];
        map['connect-src'] = ["'self'"];
      } else if (policy === 'balanced') {
        map['default-src'] = ["'self'"];
        map['script-src'] = ["'self'"];
        map['style-src'] = ["'self'", "'unsafe-inline'"];
        map['connect-src'] = ["'self'"];
      } else if (policy === 'permissive') {
        map['default-src'] = ["'self'"];
        map['script-src'] = ["'self'", "'unsafe-inline'", "'unsafe-eval'"];
        map['style-src'] = ["'self'", "'unsafe-inline'"];
        map['connect-src'] = ["'self'", 'https:'];
      } else {
        map['default-src'] = ['*'];
        map['script-src'] = ['*'];
        map['style-src'] = ['*'];
        map['connect-src'] = ['*'];
      }

      const imgSources = policy === 'off' ? ['*'] : ["'self'"];
      const fontSources = policy === 'off' ? ['*'] : ["'self'"];
      if (allowData) {
        if (!imgSources.includes('data:')) imgSources.push('data:', 'https:');
        if (!fontSources.includes('data:')) fontSources.push('data:');
      }
      map['img-src'] = imgSources;
      map['font-src'] = fontSources;

      if (framing === 'deny') {
        map['frame-ancestors'] = ["'none'"];
      } else if (framing === 'self') {
        map['frame-ancestors'] = ["'self'"];
      }

      map['object-src'] = ["'none'"];

      domains.forEach((d) => {
        const trimmed = d.trim();
        if (!trimmed) return;
        ['script-src', 'style-src', 'img-src', 'connect-src'].forEach((dName) => {
          if (!map[dName]) map[dName] = ["'self'"];
          if (!map[dName].includes(trimmed)) map[dName].push(trimmed);
        });
      });

      return serializeCSP(map);
    },
    []
  );

  const parseCspIntoSimple = useCallback((cspString: string) => {
    const map = parseCSP(cspString);
    const scriptSources = map['script-src'] || map['default-src'] || [];
    const hasUnsafeInline = scriptSources.includes("'unsafe-inline'");
    const hasUnsafeEval = scriptSources.includes("'unsafe-eval'");
    const isWildcard = scriptSources.includes('*');

    if (isWildcard) {
      setScriptPolicy('off');
    } else if (hasUnsafeInline && hasUnsafeEval) {
      setScriptPolicy('permissive');
    } else if (hasUnsafeInline) {
      setScriptPolicy('balanced');
    } else {
      setScriptPolicy('strict');
    }

    const hasData = (map['img-src'] || []).includes('data:') || (map['font-src'] || []).includes('data:');
    setSimpleAllowDataUris(hasData);

    const framing = map['frame-ancestors'] || [];
    if (framing.includes("'none'")) {
      setSimpleFramingPolicy('deny');
    } else if (framing.includes("'self'")) {
      setSimpleFramingPolicy('self');
    } else {
      setSimpleFramingPolicy('allow');
    }

    const standardKeywords = [
      "'self'",
      "'unsafe-inline'",
      "'unsafe-eval'",
      "'none'",
      'https:',
      'http:',
      'data:',
      'blob:',
      'wss:',
      'ws:',
      '*',
    ];
    const customDoms = new Set<string>();
    Object.values(map).forEach((sources) => {
      sources.forEach((s) => {
        if (!standardKeywords.includes(s) && !s.startsWith("'")) {
          customDoms.add(s);
        }
      });
    });
    setSimpleAllowedDomains(Array.from(customDoms));
  }, []);

  const populateFromConfig = useCallback((cfg: AppSecurityConfig) => {
    const sh = cfg.security_headers || ({} as AppSecuritySecurityHeadersConfig);
    setShEnabled(sh.enabled !== false);
    setXFrameOptions(sh.x_frame_options ?? 'SAMEORIGIN');

    const hstsVal = sh.hsts ?? 'max-age=31536000; includeSubDomains';
    if (
      hstsVal === '' ||
      hstsVal === 'max-age=31536000; includeSubDomains' ||
      hstsVal === 'max-age=63072000; includeSubDomains; preload'
    ) {
      setHsts(hstsVal);
      setCustomHsts('');
    } else {
      setHsts('custom');
      setCustomHsts(hstsVal);
    }

    setXContentTypeOptions(sh.x_content_type_options ?? sh.x_content_type_opts ?? 'nosniff');
    setReferrerPolicy(sh.referrer_policy ?? 'strict-origin-when-cross-origin');

    const loadedCsp = sh.csp || CSP_PRESET_DEFINITIONS.balanced.value;
    setCsp(loadedCsp);
    parseCspIntoSimple(loadedCsp);

    setPermissionsPolicy(sh.permissions_policy || PERMISSIONS_PRESETS.baseline.value);

    const ih = cfg.info_hiding || ({} as AppSecurityInfoHidingConfig);
    setIhEnabled(ih.enabled !== false);
    setStripHeaders(Array.isArray(ih.strip_headers) ? [...ih.strip_headers] : ['Server', 'X-Powered-By']);

    const contact = cfg.security_txt?.contact || cfg['security_txt.contact'] || '';
    setSecurityTxtContact(contact);
    if (!contact) {
      setSecurityTxtStatus({ status: 'not_configured', message: 'No disclosure contact published' });
    } else {
      setSecurityTxtStatus({ status: 'idle', message: 'Saved contact' });
    }

    const ch = cfg.cookie_hardener || ({} as AppSecurityCookieHardenerConfig);
    setChEnabled(ch.enabled !== false);
    setForceSecure(ch.force_secure ?? true);
    setForceHttpOnly(ch.force_httponly ?? true);
    setForceSameSite(ch.force_samesite ?? 'Lax');

    const hm = cfg.header_manager || ({} as AppSecurityHeaderManagerConfig);
    setHmEnabled(hm.enabled === true);
    setAddResponseHeaders(hm.add_response_headers ? { ...hm.add_response_headers } : {});
    setRemoveResponseHeaders(Array.isArray(hm.remove_response_headers) ? [...hm.remove_response_headers] : []);
  }, [parseCspIntoSimple]);

  const loadData = useCallback(async () => {
    setLoading(true);
    setNotification(null);
    try {
      const cfg = await apiService.getAppSecurityConfig();
      if (cfg) {
        setServerConfig(cfg);
        populateFromConfig(cfg);
      }
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: err?.message || 'Failed to load Response Protection configuration.',
      });
    } finally {
      setLoading(false);
    }
  }, [populateFromConfig]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const effectiveHsts = hsts === 'custom' ? customHsts : hsts;

  const detectedPosture = useMemo(() => {
    if (
      xFrameOptions === 'DENY' &&
      effectiveHsts === 'max-age=63072000; includeSubDomains; preload' &&
      referrerPolicy === 'no-referrer'
    ) {
      return 'strict_browser';
    }
    if (
      xFrameOptions === 'SAMEORIGIN' &&
      !effectiveHsts &&
      referrerPolicy === 'strict-origin-when-cross-origin'
    ) {
      return 'compatibility';
    }
    if (
      xFrameOptions === 'DENY' &&
      effectiveHsts === 'max-age=31536000; includeSubDomains' &&
      xContentTypeOptions === 'nosniff' &&
      referrerPolicy === 'strict-origin-when-cross-origin'
    ) {
      return 'baseline';
    }
    return 'custom';
  }, [xFrameOptions, effectiveHsts, xContentTypeOptions, referrerPolicy]);

  const handleApplyResponsePosture = (presetKey: string) => {
    if (presetKey === 'strict_browser') {
      setXFrameOptions('DENY');
      setHsts('max-age=63072000; includeSubDomains; preload');
      setCustomHsts('');
      setXContentTypeOptions('nosniff');
      setReferrerPolicy('no-referrer');
    } else if (presetKey === 'compatibility') {
      setXFrameOptions('SAMEORIGIN');
      setHsts('');
      setCustomHsts('');
      setXContentTypeOptions('nosniff');
      setReferrerPolicy('strict-origin-when-cross-origin');
    } else if (presetKey === 'baseline') {
      setXFrameOptions('DENY');
      setHsts('max-age=31536000; includeSubDomains');
      setCustomHsts('');
      setXContentTypeOptions('nosniff');
      setReferrerPolicy('strict-origin-when-cross-origin');
    }
  };

  const handleChangeScriptPolicy = (policy: ScriptPolicy) => {
    setScriptPolicy(policy);
    let nextFraming = simpleFramingPolicy;
    let nextDataUris = simpleAllowDataUris;

    if (policy === 'strict') {
      nextFraming = 'deny';
      nextDataUris = false;
      setSimpleFramingPolicy('deny');
      setSimpleAllowDataUris(false);
    } else if (policy === 'balanced' || policy === 'permissive') {
      nextFraming = 'self';
      nextDataUris = true;
      setSimpleFramingPolicy('self');
      setSimpleAllowDataUris(true);
    }

    const nextCsp = synthesizeCspFromSimple(
      policy,
      nextDataUris,
      nextFraming,
      simpleAllowedDomains
    );
    setCsp(nextCsp);
  };

  const handleToggleSimpleAllowData = (val: boolean) => {
    setSimpleAllowDataUris(val);
    const nextCsp = synthesizeCspFromSimple(
      scriptPolicy,
      val,
      simpleFramingPolicy,
      simpleAllowedDomains
    );
    setCsp(nextCsp);
  };

  const handleChangeSimpleFraming = (val: 'deny' | 'self' | 'allow') => {
    setSimpleFramingPolicy(val);
    const nextCsp = synthesizeCspFromSimple(
      scriptPolicy,
      simpleAllowDataUris,
      val,
      simpleAllowedDomains
    );
    setCsp(nextCsp);
  };

  const handleAddSimpleAllowedDomain = () => {
    const trimmed = simpleNewDomainInput.trim();
    if (!trimmed || simpleAllowedDomains.includes(trimmed)) return;
    const nextDomains = [...simpleAllowedDomains, trimmed];
    setSimpleAllowedDomains(nextDomains);
    setSimpleNewDomainInput('');
    const nextCsp = synthesizeCspFromSimple(
      scriptPolicy,
      simpleAllowDataUris,
      simpleFramingPolicy,
      nextDomains
    );
    setCsp(nextCsp);
  };

  const handleRemoveSimpleAllowedDomain = (domain: string) => {
    const nextDomains = simpleAllowedDomains.filter((d) => d !== domain);
    setSimpleAllowedDomains(nextDomains);
    const nextCsp = synthesizeCspFromSimple(
      scriptPolicy,
      simpleAllowDataUris,
      simpleFramingPolicy,
      nextDomains
    );
    setCsp(nextCsp);
  };

  const detectedCookiePreset = useMemo(() => {
    if (!chEnabled) return 'preserve';
    if (forceSecure && forceHttpOnly && forceSameSite === 'Strict') return 'strict';
    if (forceSecure && forceHttpOnly && (forceSameSite === 'Lax' || !forceSameSite)) return 'balanced';
    return 'custom';
  }, [chEnabled, forceSecure, forceHttpOnly, forceSameSite]);

  const handleApplyCookiePreset = (presetKey: string) => {
    if (presetKey === 'balanced') {
      setChEnabled(true);
      setForceSecure(true);
      setForceHttpOnly(true);
      setForceSameSite('Lax');
    } else if (presetKey === 'strict') {
      setChEnabled(true);
      setForceSecure(true);
      setForceHttpOnly(true);
      setForceSameSite('Strict');
    } else if (presetKey === 'preserve') {
      setChEnabled(false);
    } else {
      setChEnabled(true);
    }
  };

  const parsedCspMap = useMemo(() => parseCSP(csp), [csp]);
  const parsedPermissionsMap = useMemo(() => parsePermissionsPolicy(permissionsPolicy), [permissionsPolicy]);

  const permissionsHasWildcard = useMemo(() => {
    return permissionsPolicy.includes('*');
  }, [permissionsPolicy]);

  const sameSiteNoneWithoutSecure = useMemo(() => {
    return chEnabled && forceSameSite === 'None' && !forceSecure;
  }, [chEnabled, forceSameSite, forceSecure]);

  const isDirty = useMemo(() => {
    if (loading) return false;

    const origSh = serverConfig.security_headers || ({} as AppSecuritySecurityHeadersConfig);
    const origShEnabled = origSh.enabled !== false;
    const origXfo = origSh.x_frame_options ?? 'SAMEORIGIN';
    const origHsts = origSh.hsts ?? 'max-age=31536000; includeSubDomains';
    const origSniff = origSh.x_content_type_options ?? origSh.x_content_type_opts ?? 'nosniff';
    const origRef = origSh.referrer_policy ?? 'strict-origin-when-cross-origin';
    const origCsp = origSh.csp || CSP_PRESET_DEFINITIONS.balanced.value;
    const origPerm = origSh.permissions_policy || PERMISSIONS_PRESETS.baseline.value;

    if (
      shEnabled !== origShEnabled ||
      xFrameOptions !== origXfo ||
      effectiveHsts !== origHsts ||
      xContentTypeOptions !== origSniff ||
      referrerPolicy !== origRef ||
      csp !== origCsp ||
      permissionsPolicy !== origPerm
    ) {
      return true;
    }

    const origIh = serverConfig.info_hiding || ({} as AppSecurityInfoHidingConfig);
    const origIhEnabled = origIh.enabled !== false;
    const origStripHeaders = Array.isArray(origIh.strip_headers) ? origIh.strip_headers : ['Server', 'X-Powered-By'];
    const origContact = serverConfig.security_txt?.contact || serverConfig['security_txt.contact'] || '';

    if (
      ihEnabled !== origIhEnabled ||
      securityTxtContact !== origContact ||
      JSON.stringify([...stripHeaders].sort()) !== JSON.stringify([...origStripHeaders].sort())
    ) {
      return true;
    }

    const origCh = serverConfig.cookie_hardener || ({} as AppSecurityCookieHardenerConfig);
    const origChEnabled = origCh.enabled !== false;
    const origSec = origCh.force_secure ?? true;
    const origHttp = origCh.force_httponly ?? true;
    const origSs = origCh.force_samesite ?? 'Lax';

    if (
      chEnabled !== origChEnabled ||
      forceSecure !== origSec ||
      forceHttpOnly !== origHttp ||
      forceSameSite !== origSs
    ) {
      return true;
    }

    const origHm = serverConfig.header_manager || ({} as AppSecurityHeaderManagerConfig);
    const origHmEnabled = origHm.enabled === true;
    const origAddHeaders = origHm.add_response_headers || {};
    const origRemoveHeaders = Array.isArray(origHm.remove_response_headers) ? origHm.remove_response_headers : [];

    if (
      hmEnabled !== origHmEnabled ||
      JSON.stringify(addResponseHeaders) !== JSON.stringify(origAddHeaders) ||
      JSON.stringify([...removeResponseHeaders].sort()) !== JSON.stringify([...origRemoveHeaders].sort())
    ) {
      return true;
    }

    return false;
  }, [
    loading,
    serverConfig,
    shEnabled,
    xFrameOptions,
    effectiveHsts,
    xContentTypeOptions,
    referrerPolicy,
    csp,
    permissionsPolicy,
    ihEnabled,
    stripHeaders,
    securityTxtContact,
    chEnabled,
    forceSecure,
    forceHttpOnly,
    forceSameSite,
    hmEnabled,
    addResponseHeaders,
    removeResponseHeaders,
  ]);

  const handleReset = () => {
    populateFromConfig(serverConfig);
    setNotification(null);
  };

  const handleSave = async () => {
    setSaving(true);
    setNotification(null);

    try {
      const updates: Partial<AppSecurityConfig> = {
        security_headers: {
          enabled: shEnabled,
          x_frame_options: xFrameOptions,
          hsts: effectiveHsts,
          x_content_type_options: xContentTypeOptions,
          x_content_type_opts: xContentTypeOptions,
          referrer_policy: referrerPolicy,
          csp: csp.trim(),
          permissions_policy: permissionsPolicy.trim(),
        },
        info_hiding: {
          enabled: ihEnabled,
          strip_headers: stripHeaders,
        },
        security_txt: {
          contact: securityTxtContact.trim(),
        },
        cookie_hardener: {
          enabled: chEnabled,
          force_secure: forceSecure,
          force_httponly: forceHttpOnly,
          force_samesite: forceSameSite,
        },
        header_manager: {
          enabled: hmEnabled,
          add_request_headers: serverConfig.header_manager?.add_request_headers || {},
          remove_request_headers: serverConfig.header_manager?.remove_request_headers || [],
          add_response_headers: addResponseHeaders,
          remove_response_headers: removeResponseHeaders,
        },
      };

      const result = await apiService.saveAppSecurityConfig(updates);
      if (result.success) {
        setServerConfig((prev) => ({
          ...prev,
          ...updates,
        }));
        setNotification({
          type: 'success',
          message: 'Response Protection configuration successfully saved.',
        });
      } else {
        setNotification({
          type: 'error',
          message: result.error || 'Failed to save configuration updates.',
        });
      }
    } catch (err: any) {
      setNotification({
        type: 'error',
        message: err?.message || 'Unexpected error while saving Response Protection.',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleVerifySecurityTxt = async () => {
    const trimmed = securityTxtContact.trim();
    if (!trimmed) {
      setSecurityTxtStatus({
        status: 'not_configured',
        message: 'Add a contact email or HTTPS URL before verifying disclosure.',
      });
      return;
    }
    setSecurityTxtStatus({
      status: 'checking',
      message: 'Checking /.well-known/security.txt...',
    });
    try {
      const res = await fetch('/.well-known/security.txt', {
        headers: { Accept: 'text/plain' },
        cache: 'no-store',
      });
      if (!res.ok) {
        setSecurityTxtStatus({
          status: 'unavailable',
          message: `Public route returned HTTP ${res.status}.`,
        });
        return;
      }
      const text = await res.text();
      const expectedNormalized = trimmed.startsWith('http')
        ? trimmed
        : `mailto:${trimmed.replace(/^mailto:/i, '')}`;
      const expected = `Contact: ${expectedNormalized}`;
      const lines = text.split(/\r?\n/).map((l) => l.trim());
      if (lines.includes(expected)) {
        setSecurityTxtStatus({
          status: 'published',
          message: 'Public disclosure route is verified and active.',
        });
      } else {
        setSecurityTxtStatus({
          status: 'mismatch',
          message: 'File exists but does not match current contact value.',
        });
      }
    } catch {
      setSecurityTxtStatus({
        status: 'unavailable',
        message: 'Could not connect to /.well-known/security.txt.',
      });
    }
  };

  const handleAddStripHeader = (headerName: string) => {
    const trimmed = headerName.trim();
    if (!trimmed || stripHeaders.includes(trimmed)) return;
    setStripHeaders((prev) => [...prev, trimmed]);
    setNewStripHeaderInput('');
  };

  const handleRemoveStripHeader = (headerName: string) => {
    setStripHeaders((prev) => prev.filter((h) => h !== headerName));
  };

  const handleToggleStandardSource = (directive: string, source: string) => {
    const map = parseCSP(csp);
    const currentSources = map[directive] || [];

    let nextSources: string[];
    if (source === "'none'") {
      if (currentSources.includes("'none'")) {
        nextSources = [];
      } else {
        nextSources = ["'none'"];
      }
    } else {
      const withoutNone = currentSources.filter((s) => s !== "'none'");
      if (withoutNone.includes(source)) {
        nextSources = withoutNone.filter((s) => s !== source);
      } else {
        nextSources = [...withoutNone, source];
      }
    }

    if (nextSources.length === 0) {
      delete map[directive];
    } else {
      map[directive] = nextSources;
    }

    const nextCsp = serializeCSP(map);
    setCsp(nextCsp);
    parseCspIntoSimple(nextCsp);
  };

  const handleAddCustomOrigin = (directive: string, origin: string) => {
    const trimmed = origin.trim();
    if (!trimmed) return;
    const map = parseCSP(csp);
    const currentSources = (map[directive] || []).filter((s) => s !== "'none'");
    if (!currentSources.includes(trimmed)) {
      map[directive] = [...currentSources, trimmed];
      const nextCsp = serializeCSP(map);
      setCsp(nextCsp);
      parseCspIntoSimple(nextCsp);
    }
  };

  const handleRemoveCustomOrigin = (directive: string, origin: string) => {
    const map = parseCSP(csp);
    if (!map[directive]) return;
    map[directive] = map[directive].filter((s) => s !== origin);
    if (map[directive].length === 0) {
      delete map[directive];
    }
    const nextCsp = serializeCSP(map);
    setCsp(nextCsp);
    parseCspIntoSimple(nextCsp);
  };

  const handleSetPermissionsFeature = (feature: string, allowValue: string) => {
    const map = parsePermissionsPolicy(permissionsPolicy);
    map[feature] = allowValue;
    setPermissionsPolicy(serializePermissionsPolicy(map));
  };

  const handleAddResponseHeader = () => {
    const name = newHeaderName.trim();
    const value = newHeaderValue.trim();
    if (!name || !value) return;
    setAddResponseHeaders((prev) => ({
      ...prev,
      [name]: value,
    }));
    setNewHeaderName('');
    setNewHeaderValue('');
  };

  const handleRemoveResponseHeader = (name: string) => {
    setAddResponseHeaders((prev) => {
      const copy = { ...prev };
      delete copy[name];
      return copy;
    });
  };

  const handleAddRemoveHeader = (name: string) => {
    const trimmed = name.trim();
    if (!trimmed || removeResponseHeaders.includes(trimmed)) return;
    setRemoveResponseHeaders((prev) => [...prev, trimmed]);
    setNewRemoveHeaderInput('');
  };

  const handleRemoveRemoveHeader = (name: string) => {
    setRemoveResponseHeaders((prev) => prev.filter((h) => h !== name));
  };

  return (
    <div style={{ padding: '24px 32px 80px' }}>
      <PageHeader
        kicker="Application security"
        title="Response protection"
        icon={Security}
        action={
          onNavigate ? (
            <Button
              kind="ghost"
              size="sm"
              renderIcon={ArrowLeft}
              onClick={() => onNavigate('app-security-overview')}
            >
              Back to Overview
            </Button>
          ) : undefined
        }
      />

      {notification && (
        <div style={{ marginBottom: '16px' }}>
          <InlineNotification
            kind={notification.type}
            title={notification.type === 'success' ? 'Success' : notification.type === 'error' ? 'Error' : 'Notice'}
            subtitle={notification.message}
            onClose={() => setNotification(null)}
          />
        </div>
      )}

      <Tabs>
          <TabList aria-label="Response Protection Areas" contained>
            <Tab renderIcon={Security}>Browser Headers</Tab>
            <Tab renderIcon={DocumentSecurity}>Content Security (CSP)</Tab>
            <Tab renderIcon={View}>Server Cloaking</Tab>
            <Tab renderIcon={Cookie}>Cookie Hardening</Tab>
            <Tab renderIcon={SettingsAdjust}>Response Headers</Tab>
          </TabList>

          <TabPanels>
            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Browser Security Headers"
                description="Set HTTP headers to protect clients against clickjacking, MIME sniffing, and insecure transport."
                action={
                  <StatusToggle
                    id="toggle-security-headers"
                    toggled={shEnabled}
                    onToggle={(val) => setShEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Browser Security Headers"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'var(--cds-text-secondary)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      marginBottom: '12px',
                    }}
                  >
                    Protection Posture
                  </label>
                  <RadioCardGroup
                    name="response-posture-preset-group"
                    valueSelected={detectedPosture}
                    onChange={(val) => handleApplyResponsePosture(val)}
                    options={Object.entries(RESPONSE_POSTURE_PRESETS).map(([id, p]) => ({
                      value: id,
                      title: p.label,
                      description: p.desc,
                      icon: p.icon,
                    }))}
                  />
                </div>

                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
                    gap: '20px',
                    padding: '20px',
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    marginBottom: '28px',
                  }}
                >
                  <div>
                    <Select
                      id="select-x-frame-options"
                      labelText="Clickjacking Protection (X-Frame-Options)"
                      value={xFrameOptions}
                      onChange={(e) => setXFrameOptions(e.target.value)}
                      disabled={!shEnabled}
                    >
                      <SelectItem value="" text="Do not restrict framing" />
                      <SelectItem value="SAMEORIGIN" text="Same-origin only (SAMEORIGIN)" />
                      <SelectItem value="DENY" text="Block all framing (DENY)" />
                    </Select>
                  </div>

                  <div>
                    <Select
                      id="select-hsts"
                      labelText="HTTPS Enforcement (HSTS)"
                      value={hsts}
                      onChange={(e) => setHsts(e.target.value)}
                      disabled={!shEnabled}
                    >
                      <SelectItem value="" text="Do not send HSTS" />
                      <SelectItem value="max-age=31536000; includeSubDomains" text="1 year with subdomains" />
                      <SelectItem value="max-age=63072000; includeSubDomains; preload" text="2 years with preload" />
                      <SelectItem value="custom" text="Custom HSTS value" />
                    </Select>
                    {hsts === 'custom' && (
                      <div style={{ marginTop: '8px' }}>
                        <TextInput
                          id="input-custom-hsts"
                          labelText="Custom HSTS Header"
                          hideLabel
                          placeholder="max-age=31536000"
                          value={customHsts}
                          onChange={(e) => setCustomHsts(e.target.value)}
                          disabled={!shEnabled}
                        />
                      </div>
                    )}
                  </div>

                  <div>
                    <Select
                      id="select-referrer-policy"
                      labelText="Referrer Policy"
                      value={referrerPolicy}
                      onChange={(e) => setReferrerPolicy(e.target.value)}
                      disabled={!shEnabled}
                    >
                      <SelectItem value="strict-origin-when-cross-origin" text="Strict-origin-when-cross-origin" />
                      <SelectItem value="no-referrer" text="No-referrer (Maximum privacy)" />
                      <SelectItem value="same-origin" text="Same-origin only" />
                      <SelectItem value="origin" text="Origin only" />
                      <SelectItem value="" text="Do not enforce" />
                    </Select>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                      <div>
                        <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                          MIME type protection
                        </span>
                        <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                          Send X-Content-Type-Options: nosniff
                        </p>
                      </div>
                      <Toggle
                        id="toggle-mime-nosniff"
                        size="sm"
                        labelText=""
                        hideLabel
                        toggled={xContentTypeOptions === 'nosniff'}
                        onToggle={(checked) => setXContentTypeOptions(checked ? 'nosniff' : '')}
                        disabled={!shEnabled}
                        aria-label="Toggle nosniff"
                      />
                    </div>
                  </div>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
                    <div>
                      <strong style={{ fontSize: '16px', color: 'var(--cds-text-primary)' }}>
                        Permissions Policy
                      </strong>
                      <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                        Restrict browser hardware access such as camera, microphone, and geolocation.
                      </p>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      {Object.entries(PERMISSIONS_PRESETS).map(([key, p]) => (
                        <Button
                          key={key}
                          kind={permissionsPolicy === p.value ? 'primary' : 'tertiary'}
                          size="sm"
                          onClick={() => setPermissionsPolicy(p.value)}
                          disabled={!shEnabled}
                        >
                          {p.label}
                        </Button>
                      ))}
                    </div>
                  </div>

                  {permissionsHasWildcard && (
                    <div style={{ marginBottom: '12px' }}>
                      <InlineNotification
                        kind="warning"
                        lowContrast
                        title="Wildcard Permissions"
                        subtitle="Granting wildcard (*) permissions allows any third-party frame full capability access."
                        hideCloseButton
                      />
                    </div>
                  )}

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div
                      style={{
                        display: 'grid',
                        gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
                        gap: '16px',
                        marginBottom: '20px',
                      }}
                    >
                      {PERMISSION_FEATURES.map((feature) => {
                        const current = parsedPermissionsMap[feature] || '()';
                        const label = feature
                          .split('-')
                          .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
                          .join(' ');
                        return (
                          <div key={feature}>
                            <Select
                              id={`perm-select-${feature}`}
                              labelText={label}
                              value={current}
                              onChange={(e) => handleSetPermissionsFeature(feature, e.target.value)}
                              disabled={!shEnabled}
                            >
                              <SelectItem value="()" text="Denied ()" />
                              <SelectItem value="(self)" text="Same origin (self)" />
                              <SelectItem value="*" text="Wildcard (*)" />
                            </Select>
                          </div>
                        );
                      })}
                    </div>

                    <TextArea
                      id="raw-permissions-policy-textarea"
                      labelText="Raw Permissions Policy string"
                      rows={2}
                      value={permissionsPolicy}
                      onChange={(e) => setPermissionsPolicy(e.target.value)}
                      disabled={!shEnabled}
                    />
                  </div>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Content Security Policy (CSP)"
                description="Mitigate Cross-Site Scripting (XSS) and data injection by specifying allowed content sources."
                action={
                  <div style={{ width: '260px' }}>
                    <ContentSwitcher
                      selectedIndex={cspTier === 'simple' ? 0 : 1}
                      onChange={(item) => setCspTier((item.name || 'simple') as 'simple' | 'expert')}
                    >
                      <Switch name="simple" text="Simple Guardrails" />
                      <Switch name="expert" text="Expert Directives" />
                    </ContentSwitcher>
                  </div>
                }
              >
                {cspTier === 'simple' ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <div
                      style={{
                        background: 'var(--cds-layer-02)',
                        border: '1px solid var(--cds-border-subtle)',
                        padding: '20px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '20px',
                      }}
                    >
                      <div>
                        <Select
                          id="select-code-execution-guardrail"
                          labelText="Core Code Execution Guardrails"
                          value={scriptPolicy}
                          onChange={(e) => handleChangeScriptPolicy(e.target.value as ScriptPolicy)}
                          disabled={!shEnabled}
                          helperText="Governs script execution, inline styles, and eval() permissions."
                        >
                          <SelectItem
                            value="strict"
                            text="Strict — Block inline scripts, styles, eval(), and framing"
                          />
                          <SelectItem
                            value="balanced"
                            text="Balanced (Recommended) — Block eval() & remote scripts; permit same-origin and inline styles"
                          />
                          <SelectItem
                            value="permissive"
                            text="Permissive — Permit inline scripts and third-party assets (legacy compatibility)"
                          />
                          <SelectItem
                            value="off"
                            text="Disabled — Do not send Content-Security-Policy header"
                          />
                        </Select>
                      </div>

                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px', alignItems: 'center' }}>
                        <div>
                          <Select
                            id="select-simple-framing"
                            labelText="Clickjacking & Framing Defense"
                            value={simpleFramingPolicy}
                            onChange={(e) => handleChangeSimpleFraming(e.target.value as 'deny' | 'self' | 'allow')}
                            disabled={!shEnabled}
                          >
                            <SelectItem value="deny" text="Block all embedding ('none') — Highest security" />
                            <SelectItem value="self" text="Allow same origin only ('self') — Recommended" />
                            <SelectItem value="allow" text="Open / Unrestricted embedding" />
                          </Select>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--cds-layer-01)' }}>
                          <div>
                            <strong style={{ fontSize: '13px', color: 'var(--cds-text-primary)' }}>
                              Allow Base64 images & fonts
                            </strong>
                            <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                              Permits embedded data: and blob: assets
                            </p>
                          </div>
                          <Toggle
                            id="toggle-simple-allow-data"
                            size="sm"
                            labelText=""
                            hideLabel
                            toggled={simpleAllowDataUris}
                            onToggle={(val) => handleToggleSimpleAllowData(val)}
                            disabled={!shEnabled}
                            aria-label="Allow data URIs"
                          />
                        </div>
                      </div>
                    </div>

                    <div
                      style={{
                        background: 'var(--cds-layer-02)',
                        border: '1px solid var(--cds-border-subtle)',
                        padding: '20px',
                      }}
                    >
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)', display: 'block', marginBottom: '4px' }}>
                        Allowed Domains ({simpleAllowedDomains.length})
                      </strong>
                      <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '0 0 12px' }}>
                        Permit external API endpoints, CDNs, or payment gateways.
                      </p>

                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '12px' }}>
                        {simpleAllowedDomains.length > 0 ? (
                          simpleAllowedDomains.map((dom) => (
                            <Tag
                              key={dom}
                              type="cyan"
                              filter
                              onClose={() => handleRemoveSimpleAllowedDomain(dom)}
                              disabled={!shEnabled}
                              style={{ fontFamily: 'monospace' }}
                            >
                              {dom}
                            </Tag>
                          ))
                        ) : (
                          <span style={{ fontSize: '12px', color: 'var(--cds-text-placeholder)', fontStyle: 'italic' }}>
                            No external domains added. Only own domain is permitted.
                          </span>
                        )}
                      </div>

                      <div style={{ display: 'flex', gap: '8px', maxWidth: '440px' }}>
                        <TextInput
                          id="simple-new-domain-input"
                          labelText="Add external domain"
                          hideLabel
                          size="md"
                          placeholder="e.g. https://api.mycompany.com"
                          value={simpleNewDomainInput}
                          onChange={(e) => setSimpleNewDomainInput(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') {
                              e.preventDefault();
                              handleAddSimpleAllowedDomain();
                            }
                          }}
                          disabled={!shEnabled}
                        />
                        <Button
                          kind="secondary"
                          size="md"
                          renderIcon={Add}
                          onClick={handleAddSimpleAllowedDomain}
                          disabled={!shEnabled || !simpleNewDomainInput.trim()}
                        >
                          Add Domain
                        </Button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-secondary)' }}>
                        EXPERT DIRECTIVE CONFIGURATION
                      </span>

                      <div style={{ width: '220px' }}>
                        <ContentSwitcher
                          selectedIndex={cspExpertView === 'visual' ? 0 : 1}
                          onChange={(item) => setCspExpertView((item.name || 'visual') as 'visual' | 'raw')}
                        >
                          <Switch name="visual" text="Directives" />
                          <Switch name="raw" text="Raw String" />
                        </ContentSwitcher>
                      </div>
                    </div>

                    {cspExpertView === 'visual' ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                        {DIRECTIVE_METADATA.map((meta) => {
                          const allDirectiveSources = parsedCspMap[meta.key] || [];
                          const customOrigins = allDirectiveSources.filter(
                            (src) => !meta.standardSources.includes(src)
                          );

                          return (
                            <div
                              key={meta.key}
                              style={{
                                background: 'var(--cds-layer-02)',
                                border: '1px solid var(--cds-border-subtle)',
                                padding: '16px 20px',
                                display: 'flex',
                                flexDirection: 'column',
                                gap: '12px',
                              }}
                            >
                              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                                <div>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <strong style={{ fontFamily: 'monospace', fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                                      {meta.key}
                                    </strong>
                                    <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', fontWeight: 600 }}>
                                      {meta.name}
                                    </span>
                                  </div>
                                  <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                                    {meta.desc}
                                  </p>
                                </div>
                                <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)' }}>
                                  {allDirectiveSources.length} {allDirectiveSources.length === 1 ? 'source' : 'sources'}
                                </span>
                              </div>

                              <div>
                                <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--cds-text-secondary)', display: 'block', marginBottom: '6px', fontWeight: 600 }}>
                                  Standard Sources
                                </span>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                                  {meta.standardSources.map((src) => {
                                    const isSelected = allDirectiveSources.includes(src);
                                    const isUnsafe = src.includes('unsafe');
                                    return (
                                      <Button
                                        key={src}
                                        kind={isSelected ? (isUnsafe ? 'danger--tertiary' : 'primary') : 'ghost'}
                                        size="sm"
                                        onClick={() => handleToggleStandardSource(meta.key, src)}
                                        disabled={!shEnabled}
                                        style={{ fontFamily: 'monospace', fontSize: '12px' }}
                                      >
                                        {src}
                                      </Button>
                                    );
                                  })}
                                </div>
                              </div>

                              <div>
                                <span style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--cds-text-secondary)', display: 'block', marginBottom: '6px', fontWeight: 600 }}>
                                  Custom Origins & Endpoints
                                </span>
                                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', marginBottom: '8px' }}>
                                  {customOrigins.length > 0 ? (
                                    customOrigins.map((orig) => (
                                      <Tag
                                        key={orig}
                                        type="cyan"
                                        filter
                                        onClose={() => handleRemoveCustomOrigin(meta.key, orig)}
                                        disabled={!shEnabled}
                                        style={{ fontFamily: 'monospace' }}
                                      >
                                        {orig}
                                      </Tag>
                                    ))
                                  ) : (
                                    <span style={{ fontSize: '12px', color: 'var(--cds-text-placeholder)', fontStyle: 'italic' }}>
                                      No custom origins configured
                                    </span>
                                  )}
                                </div>

                                <div style={{ display: 'flex', gap: '8px', maxWidth: '420px' }}>
                                  <TextInput
                                    id={`custom-origin-${meta.key}`}
                                    labelText={`Add custom origin to ${meta.key}`}
                                    hideLabel
                                    size="sm"
                                    placeholder="e.g. https://api.example.com"
                                    value={cspCustomInput[meta.key] || ''}
                                    onChange={(e) => setCspCustomInput((prev) => ({ ...prev, [meta.key]: e.target.value }))}
                                    onKeyDown={(e) => {
                                      if (e.key === 'Enter') {
                                        e.preventDefault();
                                        handleAddCustomOrigin(meta.key, cspCustomInput[meta.key] || '');
                                        setCspCustomInput((prev) => ({ ...prev, [meta.key]: '' }));
                                      }
                                    }}
                                    disabled={!shEnabled}
                                  />
                                  <Button
                                    kind="secondary"
                                    size="sm"
                                    renderIcon={Add}
                                    onClick={() => {
                                      handleAddCustomOrigin(meta.key, cspCustomInput[meta.key] || '');
                                      setCspCustomInput((prev) => ({ ...prev, [meta.key]: '' }));
                                    }}
                                    disabled={!shEnabled || !cspCustomInput[meta.key]?.trim()}
                                  >
                                    Add
                                  </Button>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div
                        style={{
                          background: 'var(--cds-layer-02)',
                          border: '1px solid var(--cds-border-subtle)',
                          padding: '20px',
                        }}
                      >
                        <TextArea
                          id="raw-csp-editor-textarea"
                          labelText="Raw Content-Security-Policy String"
                          rows={6}
                          value={csp}
                          onChange={(e) => {
                            setCsp(e.target.value);
                            parseCspIntoSimple(e.target.value);
                          }}
                          disabled={!shEnabled}
                          style={{ fontFamily: 'monospace', fontSize: '13px', lineHeight: '1.5' }}
                        />
                      </div>
                    )}
                  </div>
                )}

                <div style={{ marginTop: '24px' }}>
                  <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em', display: 'block', marginBottom: '8px' }}>
                    Synthesized Wire Header
                  </span>
                  <CodeSnippet type="multi" feedback="Copied to clipboard">
                    {`Content-Security-Policy: ${csp || "default-src 'self'"}`}
                  </CodeSnippet>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                <SectionCard
                  title="Server Cloaking"
                  description="Strip server headers and software version banners from outgoing responses."
                  action={
                    <StatusToggle
                      id="toggle-info-hiding"
                      toggled={ihEnabled}
                      onToggle={(val) => setIhEnabled(val)}
                      hideLabel
                      size="sm"
                      ariaLabel="Toggle Server Identity Cloaking"
                    />
                  }
                >
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div style={{ marginBottom: '16px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Suppressed headers ({stripHeaders.length})
                      </span>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginTop: '8px' }}>
                        {stripHeaders.length > 0 ? (
                          stripHeaders.map((header) => (
                            <Tag
                              key={header}
                              type="magenta"
                              filter
                              onClose={() => handleRemoveStripHeader(header)}
                              disabled={!ihEnabled}
                            >
                              {header}
                            </Tag>
                          ))
                        ) : (
                          <span style={{ fontSize: '12px', color: 'var(--cds-text-placeholder)', fontStyle: 'italic' }}>
                            No response headers are currently suppressed.
                          </span>
                        )}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '12px', maxWidth: '460px', marginBottom: '16px' }}>
                      <TextInput
                        id="strip-header-input"
                        labelText="Add a response header to suppress"
                        hideLabel
                        placeholder="e.g. X-Powered-By"
                        size="md"
                        value={newStripHeaderInput}
                        onChange={(e) => setNewStripHeaderInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAddStripHeader(newStripHeaderInput);
                          }
                        }}
                        disabled={!ihEnabled}
                      />
                      <Button
                        kind="secondary"
                        size="md"
                        renderIcon={Add}
                        onClick={() => handleAddStripHeader(newStripHeaderInput)}
                        disabled={!ihEnabled || !newStripHeaderInput.trim()}
                      >
                        Add
                      </Button>
                    </div>

                    {SUGGESTED_STRIP_HEADERS.some((h) => !stripHeaders.includes(h)) && (
                      <div>
                        <span style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', display: 'block', marginBottom: '6px' }}>
                          Common headers:
                        </span>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                          {SUGGESTED_STRIP_HEADERS.filter((h) => !stripHeaders.includes(h)).map((h) => (
                            <Button
                              key={h}
                              kind="ghost"
                              size="sm"
                              renderIcon={Add}
                              onClick={() => handleAddStripHeader(h)}
                              disabled={!ihEnabled}
                            >
                              {h}
                            </Button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </SectionCard>

                <SectionCard
                  title="Vulnerability Disclosure (security.txt)"
                  description="Host RFC 9116 contact information at /.well-known/security.txt for vulnerability reporting."
                  action={
                    <Tag
                      type={
                        securityTxtStatus.status === 'published'
                          ? 'green'
                          : securityTxtStatus.status === 'checking'
                          ? 'blue'
                          : securityTxtStatus.status === 'mismatch'
                          ? 'warm-gray'
                          : securityTxtStatus.status === 'unavailable'
                          ? 'red'
                          : 'cool-gray'
                      }
                    >
                      {securityTxtStatus.status === 'published'
                        ? 'Published'
                        : securityTxtStatus.status === 'checking'
                        ? 'Checking...'
                        : securityTxtStatus.status === 'mismatch'
                        ? 'Mismatch'
                        : securityTxtStatus.status === 'unavailable'
                        ? 'Unavailable'
                        : securityTxtContact.trim()
                        ? 'Saved'
                        : 'Not configured'}
                    </Tag>
                  }
                >
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '16px', alignItems: 'end', marginBottom: '16px' }}>
                      <div>
                        <TextInput
                          id="securitytxt-contact-input"
                          labelText="Contact Email or HTTPS URL"
                          placeholder="security@example.com or https://example.com/security"
                          value={securityTxtContact}
                          onChange={(e) => setSecurityTxtContact(e.target.value)}
                        />
                      </div>
                      <Button
                        kind="tertiary"
                        renderIcon={Renew}
                        onClick={handleVerifySecurityTxt}
                        disabled={!securityTxtContact.trim()}
                      >
                        Verify public file
                      </Button>
                    </div>

                    {securityTxtStatus.message && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                        {securityTxtStatus.status === 'published' ? (
                          <CheckmarkOutline size={16} style={{ color: 'var(--cds-support-success)' }} />
                        ) : securityTxtStatus.status === 'unavailable' || securityTxtStatus.status === 'mismatch' ? (
                          <WarningAlt size={16} style={{ color: 'var(--cds-support-warning)' }} />
                        ) : null}
                        <span>{securityTxtStatus.message}</span>
                      </div>
                    )}
                  </div>
                </SectionCard>
              </div>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Cookie Hardening"
                description="Enforce Secure, HttpOnly, and SameSite flags on Set-Cookie headers from upstream servers."
                action={
                  <StatusToggle
                    id="toggle-cookie-hardener"
                    toggled={chEnabled}
                    onToggle={(val) => setChEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Cookie Hardening"
                  />
                }
              >
                <div style={{ marginBottom: '24px' }}>
                  <label
                    style={{
                      display: 'block',
                      fontSize: '12px',
                      fontWeight: 600,
                      color: 'var(--cds-text-secondary)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      marginBottom: '12px',
                    }}
                  >
                    Cookie Posture Presets
                  </label>
                  <RadioCardGroup
                    name="cookie-preset-group"
                    valueSelected={detectedCookiePreset}
                    onChange={(val) => handleApplyCookiePreset(val)}
                    options={Object.entries(COOKIE_PRESETS).map(([id, p]) => ({
                      value: id,
                      title: p.label,
                      description: p.desc,
                      icon: p.icon,
                    }))}
                  />
                </div>

                {sameSiteNoneWithoutSecure && (
                  <div style={{ marginBottom: '16px' }}>
                    <InlineNotification
                      kind="warning"
                      lowContrast
                      title="SameSite=None requires Secure"
                      subtitle="Modern browsers will reject cookies configured with SameSite=None unless the Secure flag is also enforced."
                      hideCloseButton
                    />
                  </div>
                )}

                <div
                  style={{
                    background: 'var(--cds-layer-02)',
                    border: '1px solid var(--cds-border-subtle)',
                    padding: '20px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '20px',
                  }}
                >
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', background: 'var(--cds-layer-01)' }}>
                      <div>
                        <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                          Secure flag (HTTPS only)
                        </strong>
                        <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                          Require TLS encryption for cookie transmission.
                        </p>
                      </div>
                      <Toggle
                        id="toggle-cookie-secure"
                        size="sm"
                        labelText=""
                        hideLabel
                        toggled={forceSecure}
                        onToggle={(checked) => setForceSecure(checked)}
                        disabled={!chEnabled}
                        aria-label="Toggle Force Secure"
                      />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px', background: 'var(--cds-layer-01)' }}>
                      <div>
                        <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                          HttpOnly flag
                        </strong>
                        <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                          Block client-side JavaScript access to reduce XSS impact.
                        </p>
                      </div>
                      <Toggle
                        id="toggle-cookie-httponly"
                        size="sm"
                        labelText=""
                        hideLabel
                        toggled={forceHttpOnly}
                        onToggle={(checked) => setForceHttpOnly(checked)}
                        disabled={!chEnabled}
                        aria-label="Toggle Force HttpOnly"
                      />
                    </div>
                  </div>

                  <div>
                    <label
                      style={{
                        display: 'block',
                        fontSize: '12px',
                        fontWeight: 600,
                        color: 'var(--cds-text-secondary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.05em',
                        marginBottom: '8px',
                      }}
                    >
                      SameSite policy
                    </label>
                    <Select
                      id="select-cookie-samesite"
                      labelText="SameSite Attribute"
                      hideLabel
                      value={forceSameSite}
                      onChange={(e) => setForceSameSite(e.target.value)}
                      disabled={!chEnabled}
                    >
                      <SelectItem value="Lax" text="Lax (Recommended baseline cross-site protection)" />
                      <SelectItem value="Strict" text="Strict (Same-site navigation only)" />
                      <SelectItem value="None" text="None (Permit cross-site requests, requires Secure)" />
                      <SelectItem value="" text="Do not force (Preserve original cookie attribute)" />
                    </Select>
                  </div>
                </div>
              </SectionCard>
            </TabPanel>

            <TabPanel style={{ padding: '24px 0 0' }}>
              <SectionCard
                title="Response Header Transformation"
                description="Add or strip response headers before returning traffic to clients."
                action={
                  <StatusToggle
                    id="toggle-header-manager"
                    toggled={hmEnabled}
                    onToggle={(val) => setHmEnabled(val)}
                    hideLabel
                    size="sm"
                    ariaLabel="Toggle Header Manager"
                  />
                }
              >
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div style={{ marginBottom: '16px' }}>
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Add headers ({Object.keys(addResponseHeaders).length})
                      </strong>
                      <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                        Inject static headers into outgoing responses.
                      </p>
                    </div>

                    {Object.keys(addResponseHeaders).length > 0 ? (
                      <div style={{ marginBottom: '16px' }}>
                        <Table size="sm">
                          <TableHead>
                            <TableRow>
                              <TableHeader>Header Name</TableHeader>
                              <TableHeader>Header Value</TableHeader>
                              <TableHeader style={{ width: '40px' }} />
                            </TableRow>
                          </TableHead>
                          <TableBody>
                            {Object.entries(addResponseHeaders).map(([k, v]) => (
                              <TableRow key={k}>
                                <TableCell style={{ fontFamily: 'monospace', fontWeight: 600 }}>{k}</TableCell>
                                <TableCell style={{ fontFamily: 'monospace' }}>{v}</TableCell>
                                <TableCell>
                                  <Button
                                    kind="ghost"
                                    size="sm"
                                    hasIconOnly
                                    renderIcon={TrashCan}
                                    iconDescription="Remove header"
                                    onClick={() => handleRemoveResponseHeader(k)}
                                    disabled={!hmEnabled}
                                  />
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    ) : (
                      <div style={{ padding: '12px', background: 'var(--cds-layer-01)', color: 'var(--cds-text-placeholder)', fontSize: '12px', marginBottom: '16px' }}>
                        No injected response headers configured.
                      </div>
                    )}

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <TextInput
                        id="new-header-name-input"
                        labelText="Header Name"
                        placeholder="e.g. X-Content-Security"
                        size="sm"
                        value={newHeaderName}
                        onChange={(e) => setNewHeaderName(e.target.value)}
                        disabled={!hmEnabled}
                      />
                      <TextInput
                        id="new-header-value-input"
                        labelText="Header Value"
                        placeholder="e.g. secure-payload"
                        size="sm"
                        value={newHeaderValue}
                        onChange={(e) => setNewHeaderValue(e.target.value)}
                        disabled={!hmEnabled}
                      />
                      <Button
                        kind="secondary"
                        size="sm"
                        renderIcon={Add}
                        onClick={handleAddResponseHeader}
                        disabled={!hmEnabled || !newHeaderName.trim() || !newHeaderValue.trim()}
                        style={{ alignSelf: 'flex-start', marginTop: '4px' }}
                      >
                        Add Header
                      </Button>
                    </div>
                  </div>

                  <div
                    style={{
                      background: 'var(--cds-layer-02)',
                      border: '1px solid var(--cds-border-subtle)',
                      padding: '20px',
                    }}
                  >
                    <div style={{ marginBottom: '16px' }}>
                      <strong style={{ fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                        Strip headers ({removeResponseHeaders.length})
                      </strong>
                      <p style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', margin: '2px 0 0' }}>
                        Strip specific upstream headers before returning responses.
                      </p>
                    </div>

                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', minHeight: '40px', marginBottom: '16px' }}>
                      {removeResponseHeaders.length > 0 ? (
                        removeResponseHeaders.map((hdr) => (
                          <Tag
                            key={hdr}
                            type="teal"
                            filter
                            onClose={() => handleRemoveRemoveHeader(hdr)}
                            disabled={!hmEnabled}
                          >
                            {hdr}
                          </Tag>
                        ))
                      ) : (
                        <span style={{ fontSize: '12px', color: 'var(--cds-text-placeholder)', fontStyle: 'italic' }}>
                          No headers are set to be removed.
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      <TextInput
                        id="new-remove-header-input"
                        labelText="Header to remove"
                        hideLabel
                        placeholder="e.g. Set-Cookie"
                        size="sm"
                        value={newRemoveHeaderInput}
                        onChange={(e) => setNewRemoveHeaderInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAddRemoveHeader(newRemoveHeaderInput);
                          }
                        }}
                        disabled={!hmEnabled}
                      />
                      <Button
                        kind="secondary"
                        size="sm"
                        renderIcon={Add}
                        onClick={() => handleAddRemoveHeader(newRemoveHeaderInput)}
                        disabled={!hmEnabled || !newRemoveHeaderInput.trim()}
                      >
                        Add
                      </Button>
                    </div>
                  </div>
                </div>
              </SectionCard>
            </TabPanel>
          </TabPanels>
        </Tabs>

      <SaveActionBar
        isDirty={isDirty}
        onSave={handleSave}
        onReset={handleReset}
        isSaving={saving}
      />
    </div>
  );
};
