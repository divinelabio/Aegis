import React, { useEffect, useState, useMemo, useRef } from 'react';
import {
  Tile,
  Grid,
  Column,
  Tag,
  Button,
  InlineNotification,
  Loading,
  DataTableSkeleton,
  ContentSwitcher,
  Switch,
  Select,
  SelectItem,
  TextInput,
  TextArea,
  NumberInput,
  Breadcrumb,
  BreadcrumbItem,
  Modal,
  Table,
  TableHead,
  TableRow,
  TableHeader,
  TableBody,
  TableCell,
  Search,
  Pagination,
} from '@carbon/react';
import {
  Renew,
  Enterprise,
  Security,
  ArrowRight,
  Information,
  Add,
  TrashCan,
  UserAdmin,
  Bot,
  Document as DocumentIcon,
  DataBaseAlt,
  Launch,
} from '@carbon/icons-react';
import type {
  CaptchaModuleConfig,
  ChallengeModuleConfig,
  ErrorPagesModuleConfig,
  InteractiveVerificationMethod,
  NavItemKey,
} from '../types';
import { apiService } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { FEATURES } from '../utils/features';
import {
  PageHeader,
  SectionCard,
  MetricStrip,
  KpiCard,
  HeaderSwitcher,
  SaveActionBar,
} from '../components/common';

export interface ThreatIndicator {
  indicator: string;
  score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  category: string;
  confidence?: string;
  threat_name?: string;
  malware_family?: string;
  threat_actor?: string;
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
        last_success?: string;
        failures?: number;
      };
    };
  };
  cti?: {
    status?: {
      last_error?: string;
      last_success?: string;
      failures?: number;
    };
  };
  indicators?: ThreatIndicator[];
}

interface ModulesPageProps {
  onNavigate?: (key: NavItemKey) => void;
}

type ModuleSubView = 'overview' | 'captcha' | 'challenge' | 'error_pages' | 'reputation';

const CAPTCHA_PROVIDERS = [
  { id: 'recaptcha_v2', name: 'ReCaptcha V2', desc: 'Google' },
  { id: 'recaptcha_v3', name: 'ReCaptcha V3', desc: 'Google (Invisible)' },
  { id: 'turnstile', name: 'Turnstile', desc: 'Cloudflare' },
  { id: 'hcaptcha', name: 'hCaptcha', desc: 'Intuition Machines' },
  { id: 'mtcaptcha', name: 'MTCaptcha', desc: 'MTCaptcha' },
  { id: 'friendlycaptcha', name: 'Friendly Captcha', desc: 'Privacy-first verification' },
] as const;

const CAPTCHA_LOGOS: Record<string, React.ReactNode> = {
  recaptcha_v2: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#ffffff" />
      <path d="M20 7a13 13 0 0 1 12 8" fill="none" stroke="#4285f4" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M32 15a13 13 0 0 1-2 13" fill="none" stroke="#34a853" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M30 28a13 13 0 0 1-13 4" fill="none" stroke="#fbbc05" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M17 32A13 13 0 0 1 8 12" fill="none" stroke="#ea4335" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M13.5 19.5l4.2 4.2 8.8-9.4" fill="none" stroke="#4285f4" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  recaptcha_v3: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#ffffff" />
      <path d="M20 7a13 13 0 0 1 12 8" fill="none" stroke="#4285f4" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M32 15a13 13 0 0 1-2 13" fill="none" stroke="#34a853" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M30 28a13 13 0 0 1-13 4" fill="none" stroke="#fbbc05" strokeWidth="3.5" strokeLinecap="round" />
      <path d="M17 32A13 13 0 0 1 8 12" fill="none" stroke="#ea4335" strokeWidth="3.5" strokeLinecap="round" />
      <text x="20" y="24" textAnchor="middle" fontFamily="Arial, sans-serif" fontSize="12" fontWeight="700" fill="#4285f4">v3</text>
    </svg>
  ),
  turnstile: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#262626" />
      <path d="M12 24.5h18.3a5.1 5.1 0 0 0-1.3-10 7.6 7.6 0 0 0-14.7 2 4.2 4.2 0 0 0-2.3 8z" fill="#f38020" />
      <path d="M15 26.2h13.7c2 0 3.7-.9 4.8-2.3-.8 3.7-4.1 6.5-8 6.5H14.8a4.8 4.8 0 0 1 .2-4.2z" fill="#faae40" />
    </svg>
  ),
  hcaptcha: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#161616" />
      <circle cx="20" cy="20" r="12" fill="#346df1" />
      <path d="M15 13v14M25 13v14M15 20h10" fill="none" stroke="#ffffff" strokeWidth="3" strokeLinecap="round" />
    </svg>
  ),
  mtcaptcha: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#161616" />
      <rect x="9" y="10" width="22" height="20" rx="4" fill="#0f766e" />
      <text x="20" y="24" textAnchor="middle" fontFamily="Arial, sans-serif" fontSize="11" fontWeight="800" fill="#ffffff">MT</text>
    </svg>
  ),
  friendlycaptcha: (
    <svg viewBox="0 0 40 40" width="40" height="40" aria-hidden="true" focusable="false">
      <rect x="5" y="5" width="30" height="30" rx="4" fill="#262626" />
      <path d="M29.5 18.5a10.5 10.5 0 1 1-19 0" fill="none" stroke="#f5c400" strokeWidth="3.5" strokeLinecap="round" />
      <circle cx="15.5" cy="17" r="1.8" fill="#ffffff" />
      <circle cx="24.5" cy="17" r="1.8" fill="#ffffff" />
    </svg>
  ),
};

const INTERACTIVE_METHODS: ReadonlyArray<{
  id: InteractiveVerificationMethod;
  label: string;
}> = [
  { id: 'hold', label: 'Hold to verify' },
  { id: 'click', label: 'Click to verify' },
  { id: 'slide', label: 'Slide to verify' },
  { id: 'sequence', label: 'Number sequence' },
  { id: 'match', label: 'Symbol match' },
];

interface ProviderCredentialRequirements {
  siteKeyLabel: string;
  siteKeyPlaceholder: string;
  siteKeyHelper: string;
  secretKeyLabel: string;
  secretKeyPlaceholder: string;
  secretKeyHelper: string;
  requiresScoreThreshold: boolean;
}

const PROVIDER_CREDENTIAL_CONFIG: Record<string, ProviderCredentialRequirements> = {
  recaptcha_v2: {
    siteKeyLabel: 'Site key',
    siteKeyPlaceholder: '6Le... (Public site key)',
    siteKeyHelper: 'Public site key from Google reCAPTCHA v2 admin console.',
    secretKeyLabel: 'Secret key reference',
    secretKeyPlaceholder: 'env:AEGIS_RECAPTCHA_SECRET',
    secretKeyHelper: 'Reference to the environment variable containing your reCAPTCHA v2 secret key.',
    requiresScoreThreshold: false,
  },
  recaptcha_v3: {
    siteKeyLabel: 'Site key',
    siteKeyPlaceholder: '6Le... (Public site key)',
    siteKeyHelper: 'Public site key from Google reCAPTCHA v3 admin console.',
    secretKeyLabel: 'Secret key reference',
    secretKeyPlaceholder: 'env:AEGIS_RECAPTCHA_SECRET',
    secretKeyHelper: 'Reference to the environment variable containing your reCAPTCHA v3 secret key.',
    requiresScoreThreshold: true,
  },
  turnstile: {
    siteKeyLabel: 'Site key',
    siteKeyPlaceholder: '0x4AAAAAA... (Public site key)',
    siteKeyHelper: 'Cloudflare Turnstile site key created in your Cloudflare dashboard.',
    secretKeyLabel: 'Secret key reference',
    secretKeyPlaceholder: 'env:AEGIS_TURNSTILE_SECRET',
    secretKeyHelper: 'Reference to the environment variable containing your Turnstile secret key.',
    requiresScoreThreshold: false,
  },
  hcaptcha: {
    siteKeyLabel: 'Site key',
    siteKeyPlaceholder: '10000000-ffff-ffff-ffff-000000000001',
    siteKeyHelper: 'hCaptcha site key (UUID format) from Intuition Machines dashboard.',
    secretKeyLabel: 'Secret key reference',
    secretKeyPlaceholder: 'env:AEGIS_HCAPTCHA_SECRET',
    secretKeyHelper: 'Reference to the environment variable containing your hCaptcha secret key.',
    requiresScoreThreshold: false,
  },
  mtcaptcha: {
    siteKeyLabel: 'Site key',
    siteKeyPlaceholder: 'MTCaptcha Public Site Key',
    siteKeyHelper: 'Public site key from your MTCaptcha admin portal.',
    secretKeyLabel: 'Private key reference',
    secretKeyPlaceholder: 'env:AEGIS_MTCAPTCHA_PRIVATE_KEY',
    secretKeyHelper: 'Reference to the environment variable containing your MTCaptcha private key.',
    requiresScoreThreshold: false,
  },
  friendlycaptcha: {
    siteKeyLabel: 'Site key (Puzzle / App key)',
    siteKeyPlaceholder: 'FCM... (Site key)',
    siteKeyHelper: 'Application / puzzle site key from your Friendly Captcha dashboard.',
    secretKeyLabel: 'API key reference',
    secretKeyPlaceholder: 'env:AEGIS_FRIENDLYCAPTCHA_API_KEY',
    secretKeyHelper: 'Reference to the environment variable containing your Friendly Captcha API key.',
    requiresScoreThreshold: false,
  },
};

const ERROR_STATUS_DEFINITIONS: Record<string, {
  status: string;
  title: string;
  message: string;
  category: string;
  nextStep: string;
  state: string;
}> = {
  '403': {
    status: '403',
    title: 'Access denied',
    message: "You don't have permission to view this page.",
    category: 'Access',
    nextStep: 'Contact support if you believe this is a mistake.',
    state: 'Restricted',
  },
  '404': {
    status: '404',
    title: 'Page not found',
    message: 'The page you are looking for could not be found.',
    category: 'Not found',
    nextStep: 'Check the address or return to the home page.',
    state: 'Missing',
  },
  '503': {
    status: '503',
    title: 'Service unavailable',
    message: 'The service is temporarily down for maintenance.',
    category: 'Maintenance',
    nextStep: 'Please try again in a few moments.',
    state: 'Busy',
  },
};

function renderCarbonIcon(status: string): string {
  switch (status) {
    case '403':
      return `<svg width="48" height="48" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true"><path d="M16,2C8.3,2,2,8.3,2,16s6.3,14,14,14s14-6.3,14-14S23.7,2,16,2z M21.4,20L20,21.4l-4-4l-4,4L10.6,20l4-4l-4-4L12,10.6l4,4l4-4L21.4,12l-4,4L21.4,20z"/></svg>`;
    case '404':
      return `<svg width="48" height="48" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true"><path d="M25.7,9.3l-7-7C18.5,2.1,18.3,2,18,2H8C6.9,2,6,2.9,6,4v24c0,1.1,0.9,2,2,2h16c1.1,0,2-0.9,2-2V10C26,9.7,25.9,9.5,25.7,9.3z M18,4.4l5.6,5.6H18V4.4z M24,28H8V4h8v7c0,0.6,0.4,1,1,1h7V28z"/><path d="M15 19H17V21H15zM16 13c-1.1 0-2 .9-2 2h2c0-.6.4-1 1-1s1 .4 1 1c0 1-2 .9-2 2v1h2v-.3c0-.6 2-.8 2-2.7C18 13.9 17.1 13 16 13z"/></svg>`;
    default:
      return `<svg width="48" height="48" viewBox="0 0 32 32" fill="currentColor" aria-hidden="true"><path d="M16 2C8.3 2 2 8.3 2 16s6.3 14 14 14 14-6.3 14-14S23.7,2 16 2zm0 26C9.4 28 4 22.6 4 16S9.4 4 16 4s12 5.4 12 12-5.4 12-12 12z"/><path d="M15 8h2v11h-2zm0 13h2v2h-2z"/></svg>`;
  }
}

function getErrorPageHtml(
  templateId: string,
  statusCode: string,
  themeMode: 'auto' | 'light' | 'dark',
  customTemplates: Array<{ id: string; name: string; html: string }> = []
): string {
  const def = ERROR_STATUS_DEFINITIONS[statusCode] || ERROR_STATUS_DEFINITIONS['403'];

  const custom = customTemplates.find((t) => t.id === templateId);
  if (custom && custom.html) {
    return custom.html
      .replace(/\{\{\s*status\s*\}\}/gi, def.status)
      .replace(/\{\{\s*title\s*\}\}/gi, def.title)
      .replace(/\{\{\s*message\s*\}\}/gi, def.message)
      .replace(/\{\{\s*category\s*\}\}/gi, def.category)
      .replace(/\{\{\s*next_step\s*\}\}/gi, def.nextStep);
  }

  const isLight = themeMode === 'light';

  if (templateId === 'minimal') {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${def.status} - ${def.title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: ${isLight ? 'light' : 'dark'};
    --cds-bg: ${isLight ? '#ffffff' : '#161616'};
    --cds-border: ${isLight ? '#e0e0e0' : '#393939'};
    --cds-text-primary: ${isLight ? '#161616' : '#f4f4f4'};
    --cds-text-secondary: ${isLight ? '#525252' : '#c6c6c6'};
    --cds-text-helper: ${isLight ? '#6f6f6f' : '#8d8d8d'};
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; padding: 40px 24px; display: flex; align-items: center; justify-content: center;
    background: var(--cds-bg); color: var(--cds-text-primary);
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .wrap { width: min(100%, 480px); }
  .code-eyebrow {
    font-size: 12px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase;
    color: var(--cds-text-helper); font-family: 'IBM Plex Mono', monospace; margin-bottom: 12px;
  }
  h1 {
    font-size: 32px; font-weight: 300; letter-spacing: -0.02em; line-height: 1.2;
    color: var(--cds-text-primary); margin-bottom: 16px;
  }
  .rule { height: 1px; background: var(--cds-border); margin-bottom: 20px; }
  .desc {
    font-size: 14px; line-height: 1.6; color: var(--cds-text-secondary); margin-bottom: 16px;
  }
  .action {
    font-size: 13px; line-height: 1.5; color: var(--cds-text-helper); margin-bottom: 24px;
  }
  .ref {
    font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--cds-text-helper);
  }
</style>
</head>
<body>
  <div class="wrap">
    <div class="code-eyebrow">HTTP ${def.status}</div>
    <h1>${def.title}</h1>
    <div class="rule"></div>
    <p class="desc">${def.message}</p>
    <p class="action">${def.nextStep}</p>
    <div class="ref">HTTP ${def.status} &bull; Request ID: req_8f3a921d</div>
  </div>
</body>
</html>`;
  }

  if (templateId === 'status') {
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${def.status} - ${def.title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: ${isLight ? 'light' : 'dark'};
    --cds-bg: ${isLight ? '#ffffff' : '#161616'};
    --cds-text-primary: ${isLight ? '#161616' : '#f4f4f4'};
    --cds-text-secondary: ${isLight ? '#525252' : '#c6c6c6'};
    --cds-text-helper: ${isLight ? '#6f6f6f' : '#8d8d8d'};
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; padding: 32px 24px; display: flex; align-items: center; justify-content: center;
    background: var(--cds-bg); color: var(--cds-text-primary);
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    -webkit-font-smoothing: antialiased; text-align: center;
  }
  .wrap { width: min(100%, 480px); }
  .code {
    font-family: 'IBM Plex Mono', monospace; font-size: 56px; font-weight: 500;
    line-height: 1; letter-spacing: -0.02em; color: var(--cds-text-primary); margin-bottom: 20px;
  }
  h1 { font-size: 22px; font-weight: 600; line-height: 1.3; margin-bottom: 12px; color: var(--cds-text-primary); }
  .desc { font-size: 14px; line-height: 1.55; color: var(--cds-text-secondary); margin-bottom: 12px; }
  .action { font-size: 13px; line-height: 1.5; color: var(--cds-text-helper); margin-bottom: 24px; }
  .ref { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--cds-text-helper); }
</style>
</head>
<body>
  <div class="wrap">
    <div class="code">${def.status}</div>
    <h1>${def.title}</h1>
    <p class="desc">${def.message}</p>
    <p class="action">${def.nextStep}</p>
    <div class="ref">Request ID: req_8f3a921d</div>
  </div>
</body>
</html>`;
  }

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${def.status} - ${def.title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {
    color-scheme: ${isLight ? 'light' : 'dark'};
    --cds-bg: ${isLight ? '#ffffff' : '#161616'};
    --cds-text-primary: ${isLight ? '#161616' : '#f4f4f4'};
    --cds-text-secondary: ${isLight ? '#525252' : '#c6c6c6'};
    --cds-text-helper: ${isLight ? '#6f6f6f' : '#8d8d8d'};
    --status-color: ${def.status === '403' ? (isLight ? '#da1e28' : '#fa4d56') : def.status === '503' ? (isLight ? '#b28600' : '#f1c21b') : (isLight ? '#eb6200' : '#ff832b')};
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh; padding: 32px 24px; display: flex; align-items: center; justify-content: center;
    background: var(--cds-bg); color: var(--cds-text-primary);
    font-family: 'IBM Plex Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    -webkit-font-smoothing: antialiased; text-align: center;
  }
  .wrap { width: min(100%, 500px); }
  .icon { width: 48px; height: 48px; margin: 0 auto 24px; color: var(--status-color); }
  h1 { font-size: 24px; font-weight: 600; line-height: 1.25; margin-bottom: 12px; color: var(--cds-text-primary); }
  .desc { font-size: 14px; line-height: 1.55; color: var(--cds-text-secondary); margin-bottom: 12px; }
  .action { font-size: 13px; line-height: 1.5; color: var(--cds-text-helper); margin-bottom: 24px; }
  .ref { font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: var(--cds-text-helper); }
</style>
</head>
<body>
  <div class="wrap">
    <div class="icon">${renderCarbonIcon(def.status)}</div>
    <h1>${def.title}</h1>
    <p class="desc">${def.message}</p>
    <p class="action">${def.nextStep}</p>
    <div class="ref">HTTP ${def.status} &bull; Request ID: req_8f3a921d</div>
  </div>
</body>
</html>`;
}

export const ModulesPage: React.FC<ModulesPageProps> = ({ onNavigate: _onNavigate }) => {
  const { hasFeature } = useAuth();
  const isReputationEntitled = hasFeature(FEATURES.TRAFFIC_REPUTATION);

  const [subView, setSubView] = useState<ModuleSubView>('overview');
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [notification, setNotification] = useState<{
    kind: 'success' | 'error' | 'info' | 'warning';
    message: string;
  } | null>(null);

  const [captchaConfig, setCaptchaConfig] = useState<CaptchaModuleConfig>({
    enabled: false,
    provider_name: 'recaptcha_v2',
    site_key: '',
    secret_key_ref: '',
    score_threshold: 0.5,
  });
  const [initialCaptcha, setInitialCaptcha] = useState<CaptchaModuleConfig>({});

  const [challengeConfig, setChallengeConfig] = useState<ChallengeModuleConfig>({
    enabled: true,
    theme: 'dark',
    custom_title: 'Checking your browser...',
    custom_message: 'Please wait a moment while we verify your request.',
    mode: 'managed',
    invisible_enabled: false,
    managed_enabled: true,
    interactive_enabled: false,
    interactive_style: 'hold',
    captcha_enabled: false,
  });
  const [initialChallenge, setInitialChallenge] = useState<ChallengeModuleConfig>({});

  const [errorPagesConfig, setErrorPagesConfig] = useState<ErrorPagesModuleConfig>({
    enabled: true,
    theme: 'dark',
    active_template_id: 'carbon',
    templates: [],
  });
  const [initialErrorPages, setInitialErrorPages] = useState<ErrorPagesModuleConfig>({});

  const [errorPreviewStatus, setErrorPreviewStatus] = useState<'403' | '404' | '503'>('403');
  const [previewReloadKey, setPreviewReloadKey] = useState<number>(0);
  const [customTemplateModalOpen, setCustomTemplateModalOpen] = useState<boolean>(false);
  const [newTemplateName, setNewTemplateName] = useState<string>('');
  const [newTemplateHtml, setNewTemplateHtml] = useState<string>('');

  const [holdProgress, setHoldProgress] = useState<number>(0);
  const [holdVerified, setHoldVerified] = useState<boolean>(false);
  const holdIntervalRef = useRef<any>(null);

  const [clickVerified, setClickVerified] = useState<boolean>(false);
  const [slideVerified, setSlideVerified] = useState<boolean>(false);

  const [sequenceStep, setSequenceStep] = useState<number>(0);
  const [sequenceVerified, setSequenceVerified] = useState<boolean>(false);
  const sequenceTarget = useMemo(() => [4, 1, 8], []);

  const [symbolTarget] = useState<string>('◆');
  const [symbolVerified, setSymbolVerified] = useState<boolean>(false);

  const [threatFeedData, setThreatFeedData] = useState<UnifiedThreatFeedData | null>(null);
  const [feedLoading, setFeedLoading] = useState<boolean>(false);
  const [feedRefreshing, setFeedRefreshing] = useState<boolean>(false);
  const [feedSearch, setFeedSearch] = useState<string>('');
  const [feedSevFilter, setFeedSevFilter] = useState<string>('all');
  const [feedSortBy, setFeedSortBy] = useState<'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence'>('score');
  const [feedSortOrder, setFeedSortOrder] = useState<'asc' | 'desc'>('desc');
  const [feedPage, setFeedPage] = useState<number>(1);
  const [feedPageSize, setFeedPageSize] = useState<number>(25);
  const [lastFeedUpdate, setLastFeedUpdate] = useState<string>('');
  const [repEngineEnabled, setRepEngineEnabled] = useState<boolean>(true);
  const [isTogglingRepEngine, setIsTogglingRepEngine] = useState<boolean>(false);

  useEffect(() => {
    const handleHash = () => {
      const h = window.location.hash.toLowerCase();
      if (h.includes('captcha')) {
        setSubView('captcha');
      } else if (h.includes('challenge')) {
        setSubView('challenge');
      } else if (h.includes('error-page') || h.includes('errorpage') || h.includes('error_page')) {
        setSubView('error_pages');
      } else if (h.includes('reputation')) {
        setSubView('reputation');
      } else if (h === '#modules' || h === '') {
        setSubView('overview');
      }
      window.scrollTo({ top: 0, behavior: 'instant' });
    };
    handleHash();
    window.addEventListener('hashchange', handleHash);
    return () => window.removeEventListener('hashchange', handleHash);
  }, []);

  const loadModuleConfigs = async () => {
    setLoading(true);
    try {
      const [captcha, challenge, errorPages] = await Promise.all([
        apiService.getCaptchaConfig(),
        apiService.getChallengeConfig(),
        apiService.getErrorPagesConfig(),
      ]);

      setCaptchaConfig(captcha);
      setInitialCaptcha(captcha);

      const normalizedChallenge: ChallengeModuleConfig = {
        ...challenge,
        mode: (challenge.mode === 'captcha' && !(captcha.site_key || '').trim()) ? 'managed' : (challenge.mode || 'managed'),
        managed_enabled: (challenge.mode === 'captcha' && !(captcha.site_key || '').trim()) ? true : challenge.managed_enabled,
        captcha_enabled: (challenge.mode === 'captcha' && !(captcha.site_key || '').trim()) ? false : challenge.captcha_enabled,
      };

      setChallengeConfig(normalizedChallenge);
      setInitialChallenge(normalizedChallenge);

      const normalizedErrorPages: ErrorPagesModuleConfig = {
        ...errorPages,
        active_template_id: (errorPages.active_template_id && errorPages.active_template_id !== 'aegis')
          ? errorPages.active_template_id
          : 'carbon',
      };

      setErrorPagesConfig(normalizedErrorPages);
      setInitialErrorPages(normalizedErrorPages);
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load modules directory configuration' });
    } finally {
      setLoading(false);
    }
  };

  const loadReputationData = async (forceRefresh = false) => {
    if (!forceRefresh && threatFeedData) return;
    setFeedLoading(true);
    try {
      const [feed, repCfg] = await Promise.all([
        apiService.getThreatFeed().catch(() => null),
        apiService.getReputationConfig().catch(() => null),
      ]);

      if (repCfg) {
        setRepEngineEnabled(repCfg.enabled !== false);
      }

      if (feed) {
        setThreatFeedData(feed);
        const lastSuccess = feed?.sources?.cti?.status?.last_success || feed?.cti?.status?.last_success;
        if (lastSuccess) {
          try {
            const d = new Date(lastSuccess);
            if (!isNaN(d.getTime())) {
              setLastFeedUpdate(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
            }
          } catch {}
        }
      }
    } catch {
      setNotification({ kind: 'error', message: 'Failed to load IP reputation feed' });
    } finally {
      setFeedLoading(false);
    }
  };

  const loadAllData = async () => {
    await loadModuleConfigs();
    if (subView === 'reputation') {
      await loadReputationData(true);
    }
  };

  useEffect(() => {
    if (subView === 'reputation' && !threatFeedData && !feedLoading) {
      loadReputationData();
    }
  }, [subView, threatFeedData, feedLoading]);

  const handleToggleRepEngine = async (checked: boolean) => {
    if (!isReputationEntitled) {
      setNotification({
        kind: 'warning',
        message: 'IP Reputation threat intelligence requires an active Professional or Enterprise license.',
      });
      return;
    }

    setIsTogglingRepEngine(true);
    const prev = repEngineEnabled;
    setRepEngineEnabled(checked);
    try {
      const ok = await apiService.saveReputationConfig({ enabled: checked });
      if (ok) {
        setNotification({
          kind: 'success',
          message: `IP reputation engine ${checked ? 'enabled' : 'disabled'}.`,
        });
      } else {
        throw new Error('Failed to update engine status');
      }
    } catch (err: any) {
      setRepEngineEnabled(prev);
      const isEntitlementErr = err?.message?.includes('license') || err?.message?.includes('entitle') || err?.message?.includes('403');
      const msg = isEntitlementErr
        ? 'IP Reputation & DivineLab CTI require an active Professional or Enterprise license.'
        : (err?.message || 'Failed to update engine status');
      setNotification({ kind: 'error', message: msg });
    } finally {
      setIsTogglingRepEngine(false);
    }
  };

  const handleRefreshFeed = async () => {
    if (!isReputationEntitled) {
      setNotification({
        kind: 'warning',
        message: 'DivineLab CTI threat feeds require an active Professional or Enterprise license.',
      });
      return;
    }

    setFeedRefreshing(true);
    try {
      const refreshed = await apiService.refreshThreatFeed();
      if (refreshed && Array.isArray(refreshed.indicators)) {
        setThreatFeedData(refreshed);
        const total = refreshed?.total_indicators ?? refreshed?.indicators?.length ?? 0;
        setLastFeedUpdate(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));

        setNotification({
          kind: 'success',
          message: `DivineLab CTI feeds synchronized successfully (${total.toLocaleString()} indicators).`,
        });
      } else {
        setNotification({ kind: 'warning', message: 'CTI threat intelligence requires an active Professional or Enterprise license.' });
      }
    } catch (err: any) {
      const isEntitlementErr = err?.message?.includes('license') || err?.message?.includes('entitle') || err?.message?.includes('403');
      const msg = isEntitlementErr
        ? 'DivineLab CTI threat feeds require an active Professional or Enterprise license.'
        : 'Network error refreshing threat feed.';
      setNotification({ kind: 'error', message: msg });
    } finally {
      setFeedRefreshing(false);
    }
  };

  const handleSortThreatColumn = (col: 'indicator' | 'score' | 'severity' | 'category' | 'protocol' | 'confidence') => {
    if (feedSortBy === col) {
      setFeedSortOrder((prev) => (prev === 'asc' ? 'desc' : 'asc'));
    } else {
      setFeedSortBy(col);
      setFeedSortOrder(col === 'score' ? 'desc' : 'asc');
    }
    setFeedPage(1);
  };

  const {
    feedTotalCount,
    isCtiDisconnected,
    filteredIndicators,
    pagedIndicators,
  } = useMemo(() => {
    if (subView !== 'reputation' || !threatFeedData) {
      const total = threatFeedData?.total_indicators ?? threatFeedData?.indicators?.length ?? 0;
      return {
        feedTotalCount: total,
        isCtiDisconnected: false,
        filteredIndicators: [],
        pagedIndicators: [],
      };
    }

    const raw = threatFeedData.indicators || [];
    const total = threatFeedData.total_indicators ?? raw.length;
    const ctiSource = threatFeedData.sources?.cti || threatFeedData.cti;
    const ctiStatus = ctiSource?.status;
    const ctiError = ctiStatus?.last_error;
    const isDisconnected = Boolean(
      !threatFeedData ||
      (ctiError && total === 0) ||
      ((ctiStatus?.failures ?? 0) > 0 && total === 0)
    );

    let filtered = raw;
    if (feedSevFilter === 'critical') {
      filtered = filtered.filter((i) => (i.score || 0) >= 90 || i.severity === 'CRITICAL');
    } else if (feedSevFilter === 'high') {
      filtered = filtered.filter((i) => ((i.score || 0) >= 70 && (i.score || 0) < 90) || i.severity === 'HIGH');
    } else if (feedSevFilter === 'malware') {
      filtered = filtered.filter(
        (i) =>
          (i.category || '').toLowerCase().includes('malware') ||
          (i.category || '').toLowerCase().includes('c2') ||
          (i.threat_name || '').toLowerCase().includes('malware')
      );
    } else if (feedSevFilter === 'botnet') {
      filtered = filtered.filter(
        (i) =>
          (i.category || '').toLowerCase().includes('botnet') ||
          (i.threat_name || '').toLowerCase().includes('botnet')
      );
    } else if (feedSevFilter === 'phishing') {
      filtered = filtered.filter((i) => (i.category || '').toLowerCase().includes('phish'));
    } else if (feedSevFilter === 'scanner') {
      filtered = filtered.filter(
        (i) =>
          (i.category || '').toLowerCase().includes('scan') ||
          (i.category || '').toLowerCase().includes('exploit')
      );
    } else if (feedSevFilter === 'cybercrime') {
      filtered = filtered.filter(
        (i) =>
          (i.category || '').toLowerCase().includes('cybercrime') ||
          (i.category || '').toLowerCase().includes('hijack')
      );
    } else if (feedSevFilter === 'relay') {
      filtered = filtered.filter(
        (i) =>
          (i.category || '').toLowerCase().includes('relay') ||
          (i.category || '').toLowerCase().includes('anonym')
      );
    }

    const q = feedSearch.trim().toLowerCase();
    if (q) {
      filtered = filtered.filter(
        (i) =>
          (i.indicator && i.indicator.toLowerCase().includes(q)) ||
          (i.category && i.category.toLowerCase().includes(q)) ||
          (i.severity && i.severity.toLowerCase().includes(q)) ||
          (i.confidence && i.confidence.toLowerCase().includes(q)) ||
          (i.threat_name && i.threat_name.toLowerCase().includes(q)) ||
          (i.malware_family && i.malware_family.toLowerCase().includes(q)) ||
          (i.threat_actor && i.threat_actor.toLowerCase().includes(q))
      );
    }

    const sorted = [...filtered].sort((a, b) => {
      let cmp = 0;
      if (feedSortBy === 'score') {
        cmp = (a.score || 0) - (b.score || 0);
      } else if (feedSortBy === 'severity') {
        const mapSev = (s?: string) => (s === 'CRITICAL' ? 3 : s === 'HIGH' ? 2 : 1);
        cmp = mapSev(a.severity) - mapSev(b.severity);
      } else if (feedSortBy === 'indicator') {
        cmp = (a.indicator || '').localeCompare(b.indicator || '');
      } else if (feedSortBy === 'category') {
        cmp = (a.category || '').localeCompare(b.category || '');
      } else if (feedSortBy === 'confidence') {
        cmp = (a.confidence || '').localeCompare(b.confidence || '');
      } else if (feedSortBy === 'protocol') {
        const aProto = (a.indicator || '').includes(':') ? 'IPv6' : 'IPv4';
        const bProto = (b.indicator || '').includes(':') ? 'IPv6' : 'IPv4';
        cmp = aProto.localeCompare(bProto);
      }
      return feedSortOrder === 'desc' ? -cmp : cmp;
    });

    const start = (feedPage - 1) * feedPageSize;
    const paged = sorted.slice(start, start + feedPageSize);

    return {
      feedTotalCount: total,
      isCtiDisconnected: isDisconnected,
      filteredIndicators: sorted,
      pagedIndicators: paged,
    };
  }, [subView, threatFeedData, feedSevFilter, feedSearch, feedSortBy, feedSortOrder, feedPage, feedPageSize]);

  useEffect(() => {
    loadModuleConfigs();
  }, []);

  const isCaptchaDirty = useMemo(() => {
    return JSON.stringify(captchaConfig) !== JSON.stringify(initialCaptcha);
  }, [captchaConfig, initialCaptcha]);

  const isChallengeDirty = useMemo(() => {
    return JSON.stringify(challengeConfig) !== JSON.stringify(initialChallenge);
  }, [challengeConfig, initialChallenge]);

  const isErrorPagesDirty = useMemo(() => {
    return JSON.stringify(errorPagesConfig) !== JSON.stringify(initialErrorPages);
  }, [errorPagesConfig, initialErrorPages]);

  const handleSaveCaptcha = async () => {
    setSaving(true);
    try {
      const isEnabled = captchaConfig.enabled === true;
      const siteKey = (captchaConfig.site_key || '').trim();
      const secretKeyRef = (captchaConfig.secret_key_ref || '').trim();

      if (isEnabled) {
        if (!siteKey) {
          setNotification({ kind: 'error', message: 'A Site Key is required when CAPTCHA is enabled.' });
          setSaving(false);
          return;
        }
        if (!secretKeyRef && !captchaConfig.secret_key_configured) {
          setNotification({
            kind: 'error',
            message: 'An environment credential reference (env:KEY) is required when CAPTCHA is enabled.',
          });
          setSaving(false);
          return;
        }
      }

      if (secretKeyRef && !/^env:[A-Z_][A-Z0-9_]*$/.test(secretKeyRef)) {
        setNotification({
          kind: 'error',
          message: 'Secret key reference must use format env:VARIABLE_NAME (uppercase and underscores).',
        });
        setSaving(false);
        return;
      }

      if (captchaConfig.provider_name === 'recaptcha_v3') {
        const score = Number(captchaConfig.score_threshold ?? 0.5);
        if (isNaN(score) || score < 0 || score > 1) {
          setNotification({
            kind: 'error',
            message: 'Score threshold must be between 0.0 and 1.0',
          });
          setSaving(false);
          return;
        }
      }

      const res = await apiService.saveCaptchaConfig(captchaConfig);
      if (res.success) {
        setInitialCaptcha(captchaConfig);
        setNotification({ kind: 'success', message: 'CAPTCHA module settings saved successfully.' });
      } else {
        setNotification({ kind: 'error', message: res.error || 'Failed to save CAPTCHA module settings.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'An unexpected error occurred while saving.' });
    } finally {
      setSaving(false);
    }
  };

  const handleSaveChallenge = async () => {
    setSaving(true);
    try {
      const res = await apiService.saveChallengeConfig(challengeConfig);
      if (res.success) {
        setInitialChallenge(challengeConfig);
        setNotification({ kind: 'success', message: 'Smart Challenge settings saved successfully.' });
      } else {
        setNotification({ kind: 'error', message: res.error || 'Failed to save Smart Challenge settings.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'An unexpected error occurred while saving.' });
    } finally {
      setSaving(false);
    }
  };

  const handleSaveErrorPages = async () => {
    setSaving(true);
    try {
      const activeId = errorPagesConfig.active_template_id || 'carbon';
      const theme = errorPagesConfig.theme || 'dark';
      const templates = errorPagesConfig.templates || [];

      const page_403 = getErrorPageHtml(activeId, '403', theme, templates);
      const page_404 = getErrorPageHtml(activeId, '404', theme, templates);
      const page_503 = getErrorPageHtml(activeId, '503', theme, templates);

      const payload: ErrorPagesModuleConfig = {
        ...errorPagesConfig,
        page_403,
        page_404,
        page_503,
      };

      const res = await apiService.saveErrorPagesConfig(payload);
      if (res.success) {
        setInitialErrorPages(errorPagesConfig);
        setNotification({ kind: 'success', message: 'Error pages settings and templates saved successfully.' });
      } else {
        setNotification({ kind: 'error', message: res.error || 'Failed to save error pages settings.' });
      }
    } catch (err: any) {
      setNotification({ kind: 'error', message: err?.message || 'An unexpected error occurred while saving.' });
    } finally {
      setSaving(false);
    }
  };

  const handleHoldStart = () => {
    if (holdVerified) return;
    clearInterval(holdIntervalRef.current);
    holdIntervalRef.current = setInterval(() => {
      setHoldProgress((prev) => {
        if (prev >= 100) {
          clearInterval(holdIntervalRef.current);
          setHoldVerified(true);
          return 100;
        }
        return prev + 10;
      });
    }, 100);
  };

  const handleHoldEnd = () => {
    if (holdVerified) return;
    clearInterval(holdIntervalRef.current);
    setHoldProgress(0);
  };

  if (subView === 'reputation') {
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem
            href="#modules"
            onClick={(e: React.MouseEvent) => {
              e.preventDefault();
              setSubView('overview');
              window.location.hash = '#modules';
            }}
          >
            Modules
          </BreadcrumbItem>
          <BreadcrumbItem isCurrentPage>IP reputation</BreadcrumbItem>
        </Breadcrumb>

        <PageHeader
          title="IP reputation"
          icon={Security}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <Button
                kind="ghost"
                size="sm"
                renderIcon={Renew}
                disabled={feedRefreshing || feedLoading || !isReputationEntitled}
                onClick={handleRefreshFeed}
              >
                {feedRefreshing ? 'Refreshing...' : 'Refresh'}
              </Button>
              <HeaderSwitcher
                id="modules-reputation-engine-toggle"
                ariaLabel="IP reputation status"
                toggled={repEngineEnabled}
                onToggle={handleToggleRepEngine}
                disabled={isTogglingRepEngine || !isReputationEntitled}
              />
            </div>
          }
        />

        {!isReputationEntitled && (
          <InlineNotification
            kind="info"
            title="License required"
            subtitle="IP reputation threat intelligence requires an active Professional or Enterprise license."
            lowContrast
          />
        )}

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onClose={() => setNotification(null)}
          />
        )}

        <MetricStrip minColWidth="180px">
          <KpiCard
            label="Total indicators"
            value={Number(feedTotalCount).toLocaleString()}
            icon={DataBaseAlt}
          />
          <KpiCard
            label="Feed source"
            value={
              <a
                href="https://cti.divinelab.io"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  color: 'inherit',
                  textDecoration: 'none',
                }}
              >
                cti.divinelab.io
              </a>
            }
            icon={Launch}
            onClick={() => window.open('https://cti.divinelab.io', '_blank', 'noopener,noreferrer')}
          />
          <KpiCard
            label="Feed status"
            value={isCtiDisconnected ? 'Disconnected' : repEngineEnabled ? 'Active' : 'Standby'}
            icon={Security}
            status={isCtiDisconnected ? 'error' : repEngineEnabled ? 'success' : 'default'}
          />
          <KpiCard
            label="Last synced"
            value={lastFeedUpdate || (isCtiDisconnected ? 'Unavailable' : feedLoading ? 'Syncing...' : 'Current')}
            icon={Renew}
          />
        </MetricStrip>

        <SectionCard title="Threat indicators">
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '12px',
              marginBottom: '16px',
            }}
          >
            <div style={{ width: '200px' }}>
              <Select
                id="threat-feed-category-filter"
                labelText="Filter category"
                hideLabel
                size="sm"
                value={feedSevFilter}
                onChange={(e) => {
                  setFeedSevFilter(e.target.value);
                  setFeedPage(1);
                }}
              >
                <SelectItem value="all" text="All categories" />
                <SelectItem value="critical" text="Critical risk (90–100)" />
                <SelectItem value="high" text="High risk (70–89)" />
                <SelectItem value="malware" text="Malware / C2" />
                <SelectItem value="botnet" text="Botnet C2" />
                <SelectItem value="phishing" text="Phishing" />
                <SelectItem value="scanner" text="Scanners / Exploits" />
                <SelectItem value="cybercrime" text="Hijacked networks" />
                <SelectItem value="relay" text="Relays / Proxies" />
              </Select>
            </div>

            <div style={{ width: '280px' }}>
              <Search
                id="threat-feed-search"
                labelText="Search indicators"
                placeholder="Search IP, CIDR, category..."
                size="sm"
                value={feedSearch}
                onChange={(e) => {
                  setFeedSearch(e.target.value);
                  setFeedPage(1);
                }}
                onClear={() => {
                  setFeedSearch('');
                  setFeedPage(1);
                }}
              />
            </div>
          </div>

          {feedLoading ? (
            <DataTableSkeleton columnCount={6} rowCount={8} showHeader={false} showToolbar={false} />
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <Table size="md" aria-label="Threat indicators table">
                <TableHead>
                  <TableRow>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'indicator' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('indicator')}
                    >
                      Indicator
                    </TableHeader>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'severity' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('severity')}
                    >
                      Severity
                    </TableHeader>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'score' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('score')}
                    >
                      Risk score
                    </TableHeader>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'protocol' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('protocol')}
                    >
                      Protocol
                    </TableHeader>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'category' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('category')}
                    >
                      Classification
                    </TableHeader>
                    <TableHeader
                      isSortable
                      sortDirection={feedSortBy === 'confidence' ? (feedSortOrder === 'asc' ? 'ASC' : 'DESC') : 'NONE'}
                      onClick={() => handleSortThreatColumn('confidence')}
                    >
                      Confidence
                    </TableHeader>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {pagedIndicators.length > 0 ? (
                    pagedIndicators.map((item, idx) => {
                      const isIpv6 = item.indicator.includes(':');
                      const scoreVal = item.score || (item.severity === 'CRITICAL' ? 98 : 80);
                      const isCritical = scoreVal >= 90 || item.severity === 'CRITICAL';
                      const isHigh = !isCritical && (scoreVal >= 70 || item.severity === 'HIGH');
                      const sevBadge = isCritical ? 'CRITICAL' : isHigh ? 'HIGH' : item.severity ? item.severity.toUpperCase() : 'MEDIUM';
                      const sevTagType = isCritical ? 'red' : isHigh ? 'warm-gray' : 'cyan';
                      const scoreBarColor = isCritical ? 'var(--cds-support-error, #da1e28)' : isHigh ? 'var(--cds-support-warning, #f1c21b)' : 'var(--cds-link-primary, #ff832b)';
                      const categoryText = item.category || (isCritical ? 'Cybercrime / Threat' : 'Anonymized Exit Relay');
                      const confidenceText = item.confidence || (isCritical ? '99% Verified' : '94% Verified');

                      return (
                        <TableRow key={`${item.indicator}-${item.category || ''}-${idx}`}>
                          <TableCell>
                            <div style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontWeight: 600, fontSize: '13px' }}>
                              {item.indicator}
                            </div>
                            {(item.threat_name || item.malware_family || item.threat_actor) && (
                              <div style={{ fontSize: '11px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                                {[item.threat_name, item.malware_family, item.threat_actor].filter(Boolean).join(' • ')}
                              </div>
                            )}
                          </TableCell>
                          <TableCell>
                            <Tag type={sevTagType} size="sm">
                              {sevBadge}
                            </Tag>
                          </TableCell>
                          <TableCell>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: '100px', maxWidth: '140px' }}>
                              <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px', fontFamily: 'var(--cds-font-mono, monospace)' }}>
                                <span style={{ fontWeight: 700, fontSize: '13px', color: scoreBarColor }}>
                                  {scoreVal}
                                </span>
                                <span style={{ fontSize: '11px', color: 'var(--cds-text-helper)' }}>/100</span>
                              </div>
                              <div style={{ width: '100%', height: '4px', backgroundColor: 'var(--cds-border-subtle, rgba(255,255,255,0.1))' }}>
                                <div style={{ width: `${Math.min(100, Math.max(0, scoreVal))}%`, height: '100%', backgroundColor: scoreBarColor }} />
                              </div>
                            </div>
                          </TableCell>
                          <TableCell>
                            <Tag type="outline" size="sm">
                              {isIpv6 ? 'IPv6' : 'IPv4'}
                            </Tag>
                          </TableCell>
                          <TableCell style={{ fontSize: '13px', fontWeight: 500 }}>
                            {categoryText}
                          </TableCell>
                          <TableCell style={{ fontFamily: 'var(--cds-font-mono, monospace)', fontSize: '12px', color: 'var(--cds-text-helper)' }}>
                            {confidenceText}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  ) : (
                    <TableRow>
                      <TableCell colSpan={6} style={{ textAlign: 'center', padding: '48px 16px' }}>
                        <Security size={32} style={{ marginBottom: '8px', fill: 'var(--cds-icon-secondary)' }} />
                        <div style={{ fontWeight: 600, fontSize: '14px', marginBottom: '4px', color: 'var(--cds-text-primary)' }}>
                          {feedSearch ? 'No matching indicators' : 'No threat indicators loaded'}
                        </div>
                        <div style={{ color: 'var(--cds-text-secondary)', fontSize: '13px', maxWidth: '400px', margin: '0 auto 16px' }}>
                          {feedSearch
                            ? `No indicators match "${feedSearch}".`
                            : isCtiDisconnected
                            ? 'Threat intelligence feed is offline or unreachable.'
                            : 'Click Refresh to synchronize indicators.'}
                        </div>
                        {!feedSearch && (
                          <Button
                            kind="tertiary"
                            size="sm"
                            renderIcon={Renew}
                            onClick={handleRefreshFeed}
                            disabled={feedRefreshing || feedLoading}
                          >
                            Refresh
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </div>
          )}

          {!feedLoading && filteredIndicators.length > 0 && (
            <Pagination
              page={feedPage}
              pageSize={feedPageSize}
              pageSizes={[10, 25, 50, 100]}
              totalItems={filteredIndicators.length}
              onChange={({ page, pageSize }) => {
                if (page) setFeedPage(page);
                if (pageSize) setFeedPageSize(pageSize);
              }}
            />
          )}
        </SectionCard>
      </div>
    );
  }

  if (subView === 'captcha') {
    const selectedProviderId = captchaConfig.provider_name || 'recaptcha_v2';
    const selectedProvider = CAPTCHA_PROVIDERS.find((p) => p.id === selectedProviderId) || CAPTCHA_PROVIDERS[0];
    const currentCredConfig =
      PROVIDER_CREDENTIAL_CONFIG[selectedProviderId] || PROVIDER_CREDENTIAL_CONFIG.recaptcha_v2;

    const secretKeyHelperText = captchaConfig.secret_key_migration_required
      ? 'Add a secret reference before saving to keep this credential protected.'
      : `${currentCredConfig.secretKeyHelper} Use format ${currentCredConfig.secretKeyPlaceholder}. Leave blank to retain configured reference.`;

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem
            href="#modules"
            onClick={(e: any) => {
              e.preventDefault();
              setSubView('overview');
              window.location.hash = '#modules';
            }}
          >
            Modules
          </BreadcrumbItem>
          <BreadcrumbItem isCurrentPage>CAPTCHA</BreadcrumbItem>
        </Breadcrumb>

        <PageHeader
          kicker="System modules"
          title="CAPTCHA"
          icon={Bot}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <Button
                kind="ghost"
                size="md"
                onClick={() => {
                  setSubView('overview');
                  window.location.hash = '#modules';
                }}
              >
                Back to Modules
              </Button>
              <HeaderSwitcher
                id="captcha-module-toggle"
                ariaLabel="Enable or disable Captcha module"
                toggled={captchaConfig.enabled === true}
                onToggle={(c) => setCaptchaConfig((prev) => ({ ...prev, enabled: c }))}
              />
            </div>
          }
        />

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        )}

        <Grid narrow fullWidth style={{ padding: 0 }}>
          <Column sm={4} md={8} lg={16} style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <SectionCard
                title="Provider selection"
              >
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
                    gap: '16px',
                  }}
                >
                  {CAPTCHA_PROVIDERS.map((provider) => {
                    const isSelected = selectedProviderId === provider.id;
                    return (
                      <Tile
                        key={provider.id}
                        style={{
                          padding: '20px',
                          cursor: 'pointer',
                          border: isSelected
                            ? '2px solid var(--cds-focus, #ff832b)'
                            : '1px solid var(--cds-border-subtle, #393939)',
                          backgroundColor: isSelected
                            ? 'var(--cds-layer-02, #262626)'
                            : 'var(--cds-layer-01, #161616)',
                          borderRadius: 0,
                          position: 'relative',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '16px',
                          boxSizing: 'border-box',
                          transition: 'border-color 0.15s ease, background-color 0.15s ease',
                        }}
                        onClick={() =>
                          setCaptchaConfig((prev) => ({ ...prev, provider_name: provider.id }))
                        }
                      >
                        <div style={{ flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          {CAPTCHA_LOGOS[provider.id]}
                        </div>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--cds-text-primary)', marginBottom: '2px' }}>
                            {provider.name}
                          </div>
                          <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                            {provider.desc}
                          </div>
                        </div>
                        {isSelected && (
                          <div
                            style={{
                              position: 'absolute',
                              top: '10px',
                              right: '10px',
                              width: '20px',
                              height: '20px',
                              backgroundColor: 'var(--cds-focus, #ff832b)',
                              color: '#ffffff',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              fontSize: '12px',
                              fontWeight: 700,
                            }}
                          >
                            ✓
                          </div>
                        )}
                      </Tile>
                    );
                  })}
                </div>
              </SectionCard>

              <SectionCard
                title={`${selectedProvider.name} credentials`}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div
                    style={{
                      display: 'grid',
                      gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
                      gap: '20px',
                    }}
                  >
                    <TextInput
                      id="captcha-site-key"
                      labelText={currentCredConfig.siteKeyLabel}
                      placeholder={currentCredConfig.siteKeyPlaceholder}
                      value={captchaConfig.site_key || ''}
                      onChange={(e) => setCaptchaConfig((prev) => ({ ...prev, site_key: e.target.value }))}
                      helperText={currentCredConfig.siteKeyHelper}
                    />

                    <TextInput
                      id="captcha-secret-key-ref"
                      labelText={currentCredConfig.secretKeyLabel}
                      placeholder={currentCredConfig.secretKeyPlaceholder}
                      value={captchaConfig.secret_key_ref || ''}
                      onChange={(e) =>
                        setCaptchaConfig((prev) => ({ ...prev, secret_key_ref: e.target.value }))
                      }
                      helperText={secretKeyHelperText}
                    />
                  </div>

                  {currentCredConfig.requiresScoreThreshold && (
                    <div style={{ maxWidth: '420px' }}>
                      <NumberInput
                        id="captcha-score-threshold"
                        label="Score threshold"
                        helperText="Requests below this score are treated as automated (0.0 to 1.0, default 0.5)."
                        min={0}
                        max={1}
                        step={0.1}
                        value={captchaConfig.score_threshold ?? 0.5}
                        onChange={(_e: any, { value }: any) =>
                          setCaptchaConfig((prev) => ({ ...prev, score_threshold: Number(value) }))
                        }
                      />
                    </div>
                  )}

                  <Tile
                    style={{
                      padding: '16px 20px',
                      borderRadius: 0,
                      backgroundColor: 'var(--cds-layer-02)',
                      borderLeft: '4px solid var(--cds-focus, #ff832b)',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '12px',
                      marginTop: '4px',
                    }}
                  >
                    <Information size={18} style={{ fill: 'var(--cds-link-primary)', flexShrink: 0 }} />
                    <span style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', lineHeight: '1.4' }}>
                      Provider credentials are resolved strictly from the server environment to ensure secrets are never exposed to client browsers.
                    </span>
                  </Tile>
                </div>
              </SectionCard>
            </div>
          </Column>
        </Grid>

        <SaveActionBar
          isDirty={isCaptchaDirty}
          isSaving={saving}
          onSave={handleSaveCaptcha}
          onReset={() => setCaptchaConfig(initialCaptcha)}
          saveLabel="Save Changes"
        />
      </div>
    );
  }

  if (subView === 'challenge') {
    const isCaptchaReady = Boolean((captchaConfig.site_key || '').trim());
    const isDarkPreview = (challengeConfig.theme || 'dark') === 'dark';

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem href="#modules" onClick={(e: any) => { e.preventDefault(); setSubView('overview'); window.location.hash = '#modules'; }}>
            Modules
          </BreadcrumbItem>
          <BreadcrumbItem isCurrentPage>Smart Challenge</BreadcrumbItem>
        </Breadcrumb>

        <PageHeader
          kicker="System modules"
          title="Smart challenge"
          icon={Enterprise}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <Button kind="ghost" size="md" onClick={() => { setSubView('overview'); window.location.hash = '#modules'; }}>
                Back to Modules
              </Button>
              <HeaderSwitcher
                id="challenge-module-toggle"
                ariaLabel="Enable or disable Smart Challenge module"
                toggled={challengeConfig.enabled !== false}
                onToggle={(c) => setChallengeConfig((prev) => ({ ...prev, enabled: c }))}
              />
            </div>
          }
        />

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        )}

        <Grid narrow fullWidth style={{ padding: 0, alignItems: 'stretch' }}>
          <Column sm={4} md={8} lg={7} style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', height: '100%' }}>
              <SectionCard
                title="Verification policy"
                style={{ marginBottom: 0 }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <Select
                    id="challenge-mode-select"
                    labelText="Challenge type"
                    value={challengeConfig.mode || 'managed'}
                    onChange={(e) => {
                      const mode = e.target.value;
                      if (mode === 'captcha' && !isCaptchaReady) {
                        setNotification({
                          kind: 'info',
                          message: 'Captcha-based mode requires the Captcha module to be configured first.',
                        });
                        return;
                      }
                      setChallengeConfig((prev) => ({
                        ...prev,
                        mode,
                        preset: 'custom',
                        invisible_enabled: mode === 'invisible',
                        managed_enabled: mode === 'managed' || mode === 'captcha',
                        interactive_enabled: mode === 'interactive',
                        captcha_enabled: mode === 'captcha' && isCaptchaReady,
                        escalation_policy: 'fixed',
                      }));
                    }}
                  >
                    <SelectItem value="managed" text="Managed proof-of-work" />
                    <SelectItem value="invisible" text="Invisible check" />
                    <SelectItem value="interactive" text="Interactive challenge" />
                    <SelectItem
                      value="captcha"
                      text={isCaptchaReady ? 'Captcha' : 'Captcha (configure Captcha module first)'}
                      disabled={!isCaptchaReady}
                    />
                  </Select>

                  {challengeConfig.mode === 'interactive' && (
                    <Select
                      id="challenge-interactive-method"
                      labelText="Verification method"
                      value={challengeConfig.interactive_style || 'hold'}
                      onChange={(e) =>
                        setChallengeConfig((prev) => ({
                          ...prev,
                          interactive_style: e.target.value as InteractiveVerificationMethod,
                        }))
                      }
                    >
                      {INTERACTIVE_METHODS.map((method) => (
                        <SelectItem key={method.id} value={method.id} text={method.label} />
                      ))}
                    </Select>
                  )}
                </div>
              </SectionCard>

              <SectionCard
                title="Visitor experience"
                style={{ marginBottom: 0 }}
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <TextInput
                    id="challenge-custom-title"
                    labelText="Page title"
                    placeholder="Checking your browser..."
                    value={challengeConfig.custom_title || ''}
                    onChange={(e) => setChallengeConfig((prev) => ({ ...prev, custom_title: e.target.value }))}
                  />

                  <TextArea
                    id="challenge-custom-message"
                    labelText="User message"
                    placeholder="Explain why the visitor is waiting..."
                    value={challengeConfig.custom_message || ''}
                    onChange={(e) => setChallengeConfig((prev) => ({ ...prev, custom_message: e.target.value }))}
                  />

                  <div>
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)', display: 'block', marginBottom: '8px' }}>
                      Challenge Appearance Theme
                    </label>
                    <ContentSwitcher
                      selectedIndex={challengeConfig.theme === 'light' ? 1 : 0}
                      onChange={(e: any) => setChallengeConfig((prev) => ({ ...prev, theme: e.name }))}
                    >
                      <Switch name="dark" text="Dark Mode" />
                      <Switch name="light" text="Light Mode" />
                    </ContentSwitcher>
                  </div>
                </div>
              </SectionCard>
            </div>
          </Column>

          <Column sm={4} md={8} lg={9} style={{ marginBottom: '24px' }}>
            <SectionCard
              title={challengeConfig.mode === 'invisible' ? 'No Live Preview' : 'Live Preview'}
              description={
                challengeConfig.mode === 'invisible'
                  ? 'Invisible checks run silently via telemetry without displaying an interstitial screen.'
                  : 'Interactive preview reflecting current configuration, verification widgets, and styling.'
              }
              style={{ height: '100%', marginBottom: 0, display: 'flex', flexDirection: 'column' }}
            >
              {challengeConfig.mode === 'invisible' ? (
                <Tile style={{ flex: 1, padding: '32px', textAlign: 'center', backgroundColor: 'var(--cds-layer-02)', borderRadius: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                  <Security size={32} style={{ fill: 'var(--cds-icon-secondary)', marginBottom: '12px' }} />
                  <h4 style={{ fontSize: '15px', fontWeight: 600, margin: '0 0 6px' }}>Invisible Background Check</h4>
                  <p style={{ fontSize: '13px', color: 'var(--cds-text-secondary)', margin: 0 }}>
                    Suspicious requests are verified silently via telemetry without presenting an interstitial challenge screen.
                  </p>
                </Tile>
              ) : (
                <div
                  style={{
                    flex: 1,
                    width: '100%',
                    minHeight: '440px',
                    padding: '36px 32px 20px',
                    borderRadius: 0,
                    backgroundColor: isDarkPreview ? '#0f141c' : '#f4f6f8',
                    color: isDarkPreview ? '#f4f6f8' : '#171b22',
                    border: '1px solid var(--cds-border-subtle)',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    boxSizing: 'border-box',
                    position: 'relative',
                  }}
                >
                  <div
                    style={{
                      flex: 1,
                      display: 'flex',
                      flexDirection: 'column',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: '100%',
                    }}
                  >
                    {(!challengeConfig.mode || challengeConfig.mode === 'managed') ? (
                      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
                        <div style={{ marginBottom: '22px', display: 'flex', justifyContent: 'center' }}>
                          <Loading
                            description="Checking your browser..."
                            withOverlay={false}
                            style={{
                              width: '46px',
                              height: '46px',
                              inlineSize: '46px',
                              blockSize: '46px',
                            }}
                          />
                        </div>
                        <h3
                          style={{
                            fontSize: '18px',
                            fontWeight: 600,
                            margin: '0 0 8px',
                            color: isDarkPreview ? '#f4f6f8' : '#171b22',
                            textAlign: 'center',
                          }}
                        >
                          {challengeConfig.custom_title || 'Checking your browser...'}
                        </h3>
                        <p
                          style={{
                            fontSize: '13px',
                            color: isDarkPreview ? '#a2aab6' : '#606a78',
                            margin: 0,
                            textAlign: 'center',
                            maxWidth: '380px',
                            lineHeight: '1.4',
                          }}
                        >
                          {challengeConfig.custom_message || 'Please wait a moment while we verify your request.'}
                        </p>
                      </div>
                    ) : (
                      <>
                        <h3
                          style={{
                            fontSize: '18px',
                            fontWeight: 600,
                            margin: '0 0 8px',
                            color: isDarkPreview ? '#f4f6f8' : '#171b22',
                            textAlign: 'center',
                          }}
                        >
                          {challengeConfig.custom_title || 'Checking your browser...'}
                        </h3>
                        <p
                          style={{
                            fontSize: '13px',
                            color: isDarkPreview ? '#a2aab6' : '#606a78',
                            margin: '0 0 24px',
                            textAlign: 'center',
                            maxWidth: '380px',
                            lineHeight: '1.4',
                          }}
                        >
                          {challengeConfig.custom_message || 'Please wait a moment while we verify your request.'}
                        </p>

                        {challengeConfig.mode === 'interactive' ? (
                          <div>
                            {challengeConfig.interactive_style === 'hold' && (
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                                <button
                                  type="button"
                                  onMouseDown={handleHoldStart}
                                  onMouseUp={handleHoldEnd}
                                  onMouseLeave={handleHoldEnd}
                                  onTouchStart={handleHoldStart}
                                  onTouchEnd={handleHoldEnd}
                                  style={{
                                    padding: '12px 28px',
                                    borderRadius: 0,
                                    backgroundColor: holdVerified ? '#198038' : isDarkPreview ? '#262626' : '#e0e0e0',
                                    color: holdVerified ? '#fff' : isDarkPreview ? '#fff' : '#161616',
                                    border: '1px solid var(--cds-border-subtle)',
                                    cursor: holdVerified ? 'default' : 'pointer',
                                    fontWeight: 600,
                                    fontSize: '14px',
                                    position: 'relative',
                                    overflow: 'hidden',
                                    minWidth: '220px',
                                  }}
                                >
                                  <span style={{ position: 'relative', zIndex: 2 }}>
                                    {holdVerified ? '✓ Verified' : holdProgress > 0 ? `Holding (${holdProgress}%)…` : 'Hold to verify'}
                                  </span>
                                  {!holdVerified && (
                                    <div
                                      style={{
                                        position: 'absolute',
                                        top: 0,
                                        left: 0,
                                        bottom: 0,
                                        width: `${holdProgress}%`,
                                        backgroundColor: '#ff832b',
                                        transition: 'width 0.1s linear',
                                        zIndex: 1,
                                      }}
                                    />
                                  )}
                                </button>
                                <small style={{ fontSize: '11px', color: isDarkPreview ? '#8d8d8d' : '#525252' }}>
                                  {holdVerified ? 'Verification passed' : 'Click & hold to test interaction'}
                                </small>
                              </div>
                            )}

                            {challengeConfig.interactive_style === 'click' && (
                              <Button
                                kind={clickVerified ? 'primary' : 'tertiary'}
                                size="md"
                                onClick={() => setClickVerified(!clickVerified)}
                              >
                                {clickVerified ? '✓ Verified' : 'Click to verify you are human'}
                              </Button>
                            )}

                            {challengeConfig.interactive_style === 'slide' && (
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', width: '260px' }}>
                                <div
                                  style={{
                                    width: '100%',
                                    height: '42px',
                                    backgroundColor: isDarkPreview ? '#262626' : '#e0e0e0',
                                    position: 'relative',
                                    display: 'flex',
                                    alignItems: 'center',
                                    padding: '0 4px',
                                    boxSizing: 'border-box',
                                  }}
                                >
                                  <span style={{ width: '100%', textAlign: 'center', fontSize: '12px', fontWeight: 600, color: isDarkPreview ? '#c6c6c6' : '#525252' }}>
                                    {slideVerified ? '✓ Verified' : 'Slide to verify →'}
                                  </span>
                                  <div
                                    onClick={() => {
                                      setSlideVerified(true);
                                    }}
                                    style={{
                                      position: 'absolute',
                                      left: slideVerified ? 'calc(100% - 38px)' : '4px',
                                      width: '34px',
                                      height: '34px',
                                      backgroundColor: slideVerified ? '#198038' : '#ff832b',
                                      cursor: 'pointer',
                                      display: 'flex',
                                      alignItems: 'center',
                                      justifyContent: 'center',
                                      color: '#fff',
                                      fontWeight: 700,
                                      transition: 'left 0.2s ease',
                                    }}
                                  >
                                    ›
                                  </div>
                                </div>
                                {slideVerified && (
                                  <Button size="sm" kind="ghost" onClick={() => { setSlideVerified(false); }}>
                                    Reset Slide
                                  </Button>
                                )}
                              </div>
                            )}

                            {challengeConfig.interactive_style === 'sequence' && (
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '13px', fontWeight: 600 }}>
                                  {sequenceVerified
                                    ? '✓ Verified'
                                    : `Select sequence: ${sequenceTarget.join(' → ')} (Next: ${sequenceTarget[sequenceStep]})`}
                                </span>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                  {[1, 4, 8, 3].map((num) => (
                                    <Button
                                      key={num}
                                      size="sm"
                                      kind="secondary"
                                      disabled={sequenceVerified}
                                      onClick={() => {
                                        if (num === sequenceTarget[sequenceStep]) {
                                          if (sequenceStep + 1 === sequenceTarget.length) {
                                            setSequenceVerified(true);
                                          } else {
                                            setSequenceStep(sequenceStep + 1);
                                          }
                                        } else {
                                          setSequenceStep(0);
                                        }
                                      }}
                                    >
                                      {num}
                                    </Button>
                                  ))}
                                </div>
                                {sequenceVerified && (
                                  <Button size="sm" kind="ghost" onClick={() => { setSequenceStep(0); setSequenceVerified(false); }}>
                                    Reset Sequence
                                  </Button>
                                )}
                              </div>
                            )}

                            {challengeConfig.interactive_style === 'match' && (
                              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
                                <span style={{ fontSize: '13px', fontWeight: 600 }}>
                                  {symbolVerified ? '✓ Verified' : `Click matching target symbol: ${symbolTarget}`}
                                </span>
                                <div style={{ display: 'flex', gap: '8px' }}>
                                  {['▲', '◆', '●', '★'].map((sym) => (
                                    <Button
                                      key={sym}
                                      size="sm"
                                      kind="secondary"
                                      disabled={symbolVerified}
                                      onClick={() => {
                                        if (sym === symbolTarget) {
                                          setSymbolVerified(true);
                                        }
                                      }}
                                    >
                                      {sym}
                                    </Button>
                                  ))}
                                </div>
                                {symbolVerified && (
                                  <Button size="sm" kind="ghost" onClick={() => setSymbolVerified(false)}>
                                    Reset Match
                                  </Button>
                                )}
                              </div>
                            )}
                          </div>
                        ) : challengeConfig.mode === 'captcha' ? (
                          <Tile style={{ padding: '12px 20px', borderRadius: 0, backgroundColor: isDarkPreview ? '#161616' : '#fff', border: '1px solid var(--cds-border-subtle)', display: 'flex', alignItems: 'center', gap: '12px' }}>
                            <input type="checkbox" id="preview-captcha-check" style={{ width: '18px', height: '18px' }} />
                            <label htmlFor="preview-captcha-check" style={{ fontSize: '13px', fontWeight: 500, cursor: 'pointer' }}>
                              I&apos;m not a robot
                            </label>
                          </Tile>
                        ) : null}
                      </>
                    )}
                  </div>

                  <div style={{ marginTop: 'auto', paddingTop: '20px', display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: isDarkPreview ? '#737d8c' : '#8d8d8d' }}>
                    <Security size={12} style={{ fill: 'currentColor' }} />
                    <span>DDoS Protection by <strong>Aegis</strong></span>
                  </div>
                </div>
              )}
            </SectionCard>
          </Column>
        </Grid>

        <SaveActionBar
          isDirty={isChallengeDirty}
          isSaving={saving}
          onSave={handleSaveChallenge}
          onReset={() => setChallengeConfig(initialChallenge)}
          saveLabel="Save Changes"
        />
      </div>
    );
  }

  if (subView === 'error_pages') {
    const errorTheme = (errorPagesConfig.theme || 'dark') as 'auto' | 'light' | 'dark';
    const activeTemplateId = errorPagesConfig.active_template_id || 'carbon';
    const customTemplatesList = errorPagesConfig.templates || [];
    const isCustomTemplate = customTemplatesList.some((t) => t.id === activeTemplateId);
    const activeCustomTemplate = customTemplatesList.find((t) => t.id === activeTemplateId);

    const builtInTemplates = [
      { id: 'carbon', name: 'Default' },
      { id: 'minimal', name: 'Minimal' },
      { id: 'status', name: 'Status Code' },
    ];

    const previewErrorHtml = getErrorPageHtml(
      activeTemplateId,
      errorPreviewStatus,
      errorTheme,
      customTemplatesList
    );

    const handleCreateCustomTemplate = () => {
      if (!newTemplateName.trim()) return;
      const newId = `custom_${Date.now().toString(36)}`;
      const starterHtml = newTemplateHtml.trim() || `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{status}} - {{title}}</title>
<style>
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: #11141a; color: #f4f6f8; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    padding: 24px; box-sizing: border-box;
  }
  .card { max-width: 480px; width: 100%; text-align: center; }
  h1 { margin: 0 0 12px; font-size: 24px; font-weight: 600; }
  p { margin: 0 0 16px; color: #a2aab6; font-size: 14px; line-height: 1.5; }
  .ref { font-size: 12px; color: #737d8c; }
</style>
</head>
<body>
  <div class="card">
    <h1>{{status}} - {{title}}</h1>
    <p>{{message}}</p>
    <div class="ref">{{next_step}}</div>
  </div>
</body>
</html>`;

      const newTemplate = {
        id: newId,
        name: newTemplateName.trim(),
        html: starterHtml,
        source: 'custom' as const,
      };

      setErrorPagesConfig((prev) => ({
        ...prev,
        active_template_id: newId,
        templates: [...(prev.templates || []), newTemplate],
      }));

      setNewTemplateName('');
      setNewTemplateHtml('');
      setCustomTemplateModalOpen(false);
    };

    const handleDeleteCustomTemplate = (templateId: string) => {
      setErrorPagesConfig((prev) => ({
        ...prev,
        active_template_id: prev.active_template_id === templateId ? 'carbon' : prev.active_template_id,
        templates: (prev.templates || []).filter((t) => t.id !== templateId),
      }));
    };

    const handleUpdateCustomTemplateHtml = (templateId: string, html: string) => {
      setErrorPagesConfig((prev) => ({
        ...prev,
        templates: (prev.templates || []).map((t) => (t.id === templateId ? { ...t, html } : t)),
      }));
    };

    const handleUpdateCustomTemplateName = (templateId: string, name: string) => {
      setErrorPagesConfig((prev) => ({
        ...prev,
        templates: (prev.templates || []).map((t) => (t.id === templateId ? { ...t, name } : t)),
      }));
    };

    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
        <Breadcrumb noTrailingSlash style={{ marginBottom: '-8px' }}>
          <BreadcrumbItem href="#modules" onClick={(e: any) => { e.preventDefault(); setSubView('overview'); window.location.hash = '#modules'; }}>
            Modules
          </BreadcrumbItem>
          <BreadcrumbItem isCurrentPage>Error Pages</BreadcrumbItem>
        </Breadcrumb>

        <PageHeader
          kicker="System modules"
          title="Error pages"
          icon={DocumentIcon}
          action={
            <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
              <Button kind="ghost" size="md" onClick={() => { setSubView('overview'); window.location.hash = '#modules'; }}>
                Back to Modules
              </Button>
              <HeaderSwitcher
                id="errorpages-module-toggle"
                ariaLabel="Enable custom browser error pages"
                toggled={errorPagesConfig.enabled !== false}
                onToggle={(c) => setErrorPagesConfig((prev) => ({ ...prev, enabled: c }))}
              />
            </div>
          }
        />

        {notification && (
          <InlineNotification
            kind={notification.kind}
            title={notification.message}
            onCloseButtonClick={() => setNotification(null)}
          />
        )}

        <Grid narrow fullWidth style={{ padding: 0, alignItems: 'stretch' }}>
          <Column sm={4} md={4} lg={6} style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <SectionCard
                title="Appearance"
              >
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <Select
                    id="error-pages-template-select"
                    labelText="Template"
                    value={activeTemplateId}
                    onChange={(e) => setErrorPagesConfig((prev) => ({ ...prev, active_template_id: e.target.value }))}
                  >
                    <optgroup label="Built-in templates">
                      {builtInTemplates.map((t) => (
                        <SelectItem key={t.id} value={t.id} text={t.name} />
                      ))}
                    </optgroup>
                    {customTemplatesList.length > 0 && (
                      <optgroup label="Custom templates">
                        {customTemplatesList.map((t) => (
                          <SelectItem key={t.id} value={t.id} text={t.name} />
                        ))}
                      </optgroup>
                    )}
                  </Select>

                  <div>
                    <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cds-text-secondary)', display: 'block', marginBottom: '8px' }}>
                      Color mode
                    </label>
                    <ContentSwitcher
                      selectedIndex={errorPagesConfig.theme === 'light' ? 1 : errorPagesConfig.theme === 'auto' ? 2 : 0}
                      onChange={(e: any) => setErrorPagesConfig((prev) => ({ ...prev, theme: e.name }))}
                    >
                      <Switch name="dark" text="Dark" />
                      <Switch name="light" text="Light" />
                      <Switch name="auto" text="Auto" />
                    </ContentSwitcher>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '16px', borderTop: '1px solid var(--cds-border-subtle)' }}>
                    <div>
                      <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cds-text-primary)' }}>
                        Custom templates
                      </div>
                      <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary)', marginTop: '2px' }}>
                        {customTemplatesList.length} of 12 configured
                      </div>
                    </div>
                    <Button
                      kind="ghost"
                      size="sm"
                      renderIcon={Add}
                      onClick={() => setCustomTemplateModalOpen(true)}
                    >
                      Add template
                    </Button>
                  </div>
                </div>
              </SectionCard>

              {isCustomTemplate && activeCustomTemplate && (
                <SectionCard
                  title="Edit custom template"
                  action={
                    <Button
                      kind="danger--ghost"
                      size="sm"
                      renderIcon={TrashCan}
                      onClick={() => handleDeleteCustomTemplate(activeCustomTemplate.id)}
                    >
                      Delete template
                    </Button>
                  }
                >
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <TextInput
                      id="custom-template-name-input"
                      labelText="Template name"
                      value={activeCustomTemplate.name}
                      onChange={(e) => handleUpdateCustomTemplateName(activeCustomTemplate.id, e.target.value)}
                    />

                    <div>
                      <TextArea
                        id="custom-template-html-input"
                        labelText="HTML document"
                        rows={12}
                        value={activeCustomTemplate.html}
                        onChange={(e) => handleUpdateCustomTemplateHtml(activeCustomTemplate.id, e.target.value)}
                        style={{ fontFamily: 'monospace', fontSize: '12px', lineHeight: '1.4' }}
                        helperText="Available placeholders: {{status}}, {{title}}, {{message}}, {{next_step}}, {{category}}"
                      />
                    </div>
                  </div>
                </SectionCard>
              )}
            </div>
          </Column>

          <Column sm={4} md={4} lg={10} style={{ marginBottom: '24px' }}>
            <SectionCard
              title="Live preview"
              description={`Simulated HTTP ${errorPreviewStatus} browser response.`}
              action={
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <ContentSwitcher
                    size="sm"
                    selectedIndex={errorPreviewStatus === '403' ? 0 : errorPreviewStatus === '404' ? 1 : 2}
                    onChange={(e: any) => setErrorPreviewStatus(e.name)}
                  >
                    <Switch name="403" text="403" />
                    <Switch name="404" text="404" />
                    <Switch name="503" text="503" />
                  </ContentSwitcher>
                  <Button
                    kind="ghost"
                    size="sm"
                    renderIcon={Renew}
                    hasIconOnly
                    iconDescription="Refresh preview"
                    onClick={() => setPreviewReloadKey((k: number) => k + 1)}
                  />
                </div>
              }
              style={{ height: '100%', display: 'flex', flexDirection: 'column' }}
            >
              <div
                style={{
                  flex: 1,
                  minHeight: '520px',
                  border: '1px solid var(--cds-border-subtle)',
                  backgroundColor: 'var(--cds-layer-01)',
                  position: 'relative',
                  overflow: 'hidden',
                }}
              >
                <iframe
                  key={previewReloadKey}
                  title={`Error Page Preview - ${errorPreviewStatus}`}
                  srcDoc={previewErrorHtml}
                  style={{
                    width: '100%',
                    height: '100%',
                    minHeight: '520px',
                    border: 'none',
                    display: 'block',
                  }}
                  sandbox="allow-same-origin"
                />
              </div>
            </SectionCard>
          </Column>
        </Grid>

        <Modal
          open={customTemplateModalOpen}
          modalHeading="Create custom error template"
          primaryButtonText="Create template"
          secondaryButtonText="Cancel"
          onRequestClose={() => setCustomTemplateModalOpen(false)}
          onRequestSubmit={handleCreateCustomTemplate}
        >
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', paddingTop: '16px' }}>
            <TextInput
              id="new-template-name"
              labelText="Template name"
              placeholder="e.g. Minimal maintenance"
              value={newTemplateName}
              onChange={(e) => setNewTemplateName(e.target.value)}
            />
            <div>
              <TextArea
                id="new-template-html"
                labelText="HTML document"
                rows={10}
                placeholder="Leave blank to use default template..."
                value={newTemplateHtml}
                onChange={(e) => setNewTemplateHtml(e.target.value)}
                style={{ fontFamily: 'monospace', fontSize: '12px' }}
                helperText="Placeholders: {{status}}, {{title}}, {{message}}, {{next_step}}"
              />
            </div>
          </div>
        </Modal>

        <SaveActionBar
          isDirty={isErrorPagesDirty}
          isSaving={saving}
          onSave={handleSaveErrorPages}
          onReset={() => setErrorPagesConfig(initialErrorPages)}
          saveLabel="Save Changes"
        />
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '24px', padding: '32px', width: '100%', boxSizing: 'border-box' }}>
      <PageHeader
        kicker="System modules"
        title="Modules"
        icon={Enterprise}
        action={
          <Button kind="ghost" size="md" renderIcon={Renew} onClick={loadAllData} disabled={loading}>
            Refresh
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
        title="Available modules"
        padded={false}
      >
        {[
          {
            id: 'reputation',
            title: 'IP Reputation',
            description: 'Threat intelligence feed and indicator directory',
            icon: Security,
            hash: '#modules-reputation',
          },
          {
            id: 'captcha',
            title: 'CAPTCHA',
            description: 'Third-party verification providers (Turnstile, reCAPTCHA)',
            icon: UserAdmin,
            hash: '#modules-captcha',
          },
          {
            id: 'challenge',
            title: 'Smart Challenge',
            description: 'Proof-of-work and interactive client verification',
            icon: Bot,
            hash: '#modules-challenge',
          },
          {
            id: 'error_pages',
            title: 'Error Pages',
            description: 'Custom HTTP 403, 404, and 503 response templates',
            icon: DocumentIcon,
            hash: '#modules-errorpages',
          },
        ].map((mod, index, arr) => {
          const IconComponent = mod.icon;
          const isLast = index === arr.length - 1;

          return (
            <div
              key={mod.id}
              role="button"
              tabIndex={0}
              onClick={() => {
                setSubView(mod.id as ModuleSubView);
                window.location.hash = mod.hash;
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setSubView(mod.id as ModuleSubView);
                  window.location.hash = mod.hash;
                }
              }}
              className="module-list-row"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '18px 24px',
                borderBottom: isLast ? 'none' : '1px solid var(--cds-border-subtle)',
                cursor: 'pointer',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, rgba(141, 141, 141, 0.12))';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flex: 1 }}>
                <IconComponent size={20} style={{ color: 'var(--cds-interactive)', flexShrink: 0 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)', marginBottom: '3px' }}>
                    {mod.title}
                  </div>
                  <div style={{ fontSize: '13px', color: 'var(--cds-text-secondary)' }}>
                    {mod.description}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', color: 'var(--cds-icon-secondary)' }}>
                <ArrowRight size={20} />
              </div>
            </div>
          );
        })}
      </SectionCard>
    </div>
  );
};
