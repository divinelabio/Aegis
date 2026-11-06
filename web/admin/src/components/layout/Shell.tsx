import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  Header,
  HeaderName,
  HeaderGlobalBar,
  HeaderGlobalAction,
  HeaderPanel,
  HeaderMenuButton,
  SideNav,
  SideNavItems,
  SideNavLink,
  SideNavMenuItem,
  Search,
  Tag,
  Theme,
  ContentSwitcher,
  Switch,
} from '@carbon/react';
import {
  Security,
  Activity,
  Document,
  Firewall,
  Application,
  Network_3,
  Globe,
  Datastore,
  Certificate,
  Enterprise,
  Settings,
  Notification,
  UserAvatar,
  UserMultiple,
  Sun,
  Moon,
  Bot,
  Locked,
  Logout,
  ChevronDown,
  Menu,
  Checkmark,
  Close,
  Launch,
} from '@carbon/icons-react';
import type { NavItemKey, AlertItem } from '../../types';
import { apiService } from '../../services/api';
import { useAuth, isRouteEntitled } from '../../utils/features';
import { prefetchRoute } from '../../App';

interface ShellProps {
  activeNav: NavItemKey;
  onSelectNav: (key: NavItemKey) => void;
  onPreloadNav?: (key: NavItemKey) => void;
  theme: 'g100' | 'g10';
  onToggleTheme: () => void;
  licenseTier?: string;
  isPending?: boolean;
  children: React.ReactNode;
}

interface NavSubItem {
  key: NavItemKey;
  label: string;
}

interface NavGroupItem {
  id: string;
  type: 'menu';
  title: string;
  icon: React.ComponentType<{ size?: number }>;
  items: NavSubItem[];
}

interface NavDirectItem {
  type: 'link';
  key: NavItemKey;
  label: string;
  icon: React.ComponentType<{ size?: number }>;
  permission?: string;
}

type NavItemDef = NavDirectItem | NavGroupItem;

interface NavCategoryDef {
  id: string;
  label: string;
  items: NavItemDef[];
}

const NAV_CATEGORIES: NavCategoryDef[] = [
  {
    id: 'overview',
    label: 'Overview',
    items: [
      { type: 'link', key: 'security-events', label: 'Security Events', icon: Security },
      { type: 'link', key: 'traffic-events', label: 'Traffic Events', icon: Activity },
      { type: 'link', key: 'threat-logs', label: 'Threat Logs', icon: Document },
    ],
  },
  {
    id: 'configuration',
    label: 'Configuration',
    items: [
      {
        id: 'waf',
        type: 'menu',
        title: 'Application Firewall',
        icon: Firewall,
        items: [
          { key: 'waf-overview', label: 'Overview' },
          { key: 'waf-leak', label: 'Leak Protection' },
          { key: 'waf-rulesets', label: 'Managed Rulesets' },
          { key: 'waf-custom', label: 'Custom Rules' },
          { key: 'waf-exclusions', label: 'Exclusions' },
        ],
      },
      {
        id: 'traffic',
        type: 'menu',
        title: 'Traffic Control',
        icon: Activity,
        items: [
          { key: 'traffic-control', label: 'Overview' },
          { key: 'traffic-blacklist', label: 'IP Blacklist' },
          { key: 'traffic-reputation', label: 'IP Reputation' },
          { key: 'traffic-ratelimit', label: 'Rate Limiting' },
          { key: 'traffic-geo', label: 'Geo-Blocking' },
          { key: 'traffic-ddos', label: 'Application Flood' },
          { key: 'traffic-priority', label: 'Trusted Exceptions' },
        ],
      },
      {
        id: 'app-security',
        type: 'menu',
        title: 'Application Security',
        icon: Security,
        items: [
          { key: 'app-security', label: 'Overview' },
          { key: 'app-security-request', label: 'Request Policy' },
          { key: 'app-security-payload', label: 'Payload Protection' },
          { key: 'app-security-upload', label: 'Upload Security' },
          { key: 'app-security-response', label: 'Response Protection' },
        ],
      },
      {
        id: 'bot',
        type: 'menu',
        title: 'Bot Protection',
        icon: Bot,
        items: [
          { key: 'bot-overview', label: 'Overview' },
          { key: 'bot-managed', label: 'Managed Protection' },
          { key: 'bot-rules', label: 'Custom Rules' },
          { key: 'bot-classification', label: 'Classification' },
          { key: 'bot-ai', label: 'AI Crawlers' },
          { key: 'bot-exceptions', label: 'Exceptions' },
        ],
      },
      {
        id: 'api',
        type: 'menu',
        title: 'API Shield',
        icon: Application,
        items: [
          { key: 'api-security', label: 'Overview' },
          { key: 'api-inventory', label: 'API Inventory' },
          { key: 'api-contracts', label: 'Contracts' },
          { key: 'api-authorization', label: 'Authorization' },
          { key: 'api-graphql', label: 'GraphQL' },
        ],
      },
      {
        id: 'access',
        type: 'menu',
        title: 'Edge Access',
        icon: Locked,
        items: [
          { key: 'edge-access', label: 'Overview' },
          { key: 'access-apps', label: 'Applications' },
          { key: 'access-policies', label: 'Access policies' },
          { key: 'access-identity', label: 'Identity & trust' },
          { key: 'access-roles', label: 'Roles' },
          { key: 'access-decisions', label: 'Decisions' },
          { key: 'access-runtime', label: 'Runtime settings' },
        ],
      },
    ],
  },
  {
    id: 'network',
    label: 'Network',
    items: [
      { type: 'link', key: 'proxy-settings', label: 'Proxy Settings', icon: Network_3 },
      { type: 'link', key: 'routing', label: 'Routing', icon: Globe },
      { type: 'link', key: 'origins', label: 'Origins', icon: Datastore },
      { type: 'link', key: 'ssl', label: 'SSL Certificates', icon: Certificate },
    ],
  },
  {
    id: 'system',
    label: 'System',
    items: [
      { type: 'link', key: 'users', label: 'Users', icon: UserMultiple, permission: 'users:read' },
      { type: 'link', key: 'audit', label: 'Audit Logs', icon: Document },
      { type: 'link', key: 'modules', label: 'Modules', icon: Enterprise },
      { type: 'link', key: 'settings', label: 'Settings', icon: Settings },
    ],
  },
];

const isItemActive = (key: NavItemKey, current: NavItemKey): boolean => {
  if (key === current) return true;
  if (key === 'waf-leak' && current === 'waf-leak-protection') return true;
  if (key === 'traffic-control' && current === 'traffic-overview') return true;
  if (key === 'app-security' && current === 'app-security-overview') return true;
  return false;
};

const isGroupActive = (items: NavSubItem[], current: NavItemKey): boolean => {
  return items.some((item) => isItemActive(item.key, current));
};

interface ControlledSideNavMenuProps {
  id: string;
  title: string;
  renderIcon?: React.ComponentType<{ size?: number }>;
  isExpanded: boolean;
  isActive?: boolean;
  onToggle: () => void;
  children: React.ReactNode;
}

const ControlledSideNavMenu: React.FC<ControlledSideNavMenuProps> = ({
  title,
  renderIcon: Icon,
  isExpanded,
  isActive,
  onToggle,
  children,
}) => {
  return (
    <li
      className={`cds--side-nav__item cds--side-nav__item--icon ${
        isActive && !isExpanded ? 'cds--side-nav__item--active' : ''
      }`}
    >
      <button
        type="button"
        title={title}
        aria-expanded={isExpanded}
        className="cds--side-nav__submenu sidebar-big-title sidebar-menu-header"
        onClick={onToggle}
      >
        {Icon && (
          <div className="cds--side-nav__icon">
            <Icon size={18} />
          </div>
        )}
        <span
          className="cds--side-nav__submenu-title"
          style={{
            flex: '1 1 auto',
            textAlign: 'left',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {title}
        </span>
        <div
          className="cds--side-nav__icon cds--side-nav__submenu-chevron"
          style={{
            flex: '0 0 20px',
            width: '20px',
            minWidth: '20px',
            maxWidth: '20px',
            marginLeft: 'auto',
            marginRight: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <ChevronDown size={16} />
        </div>
      </button>
      <ul
        className="cds--side-nav__menu sidebar-nav-children"
        style={{ display: isExpanded ? 'block' : 'none' }}
      >
        {children}
      </ul>
    </li>
  );
};

export const Shell: React.FC<ShellProps> = ({
  activeNav,
  onSelectNav,
  theme,
  onToggleTheme,
  licenseTier: propTier,
  isPending,
  children,
}) => {
  const { user, logout, hasFeature, tier: authTier } = useAuth();
  const [tier, setTier] = useState<string>(propTier || authTier || 'community');

  const [expandedMenu, setExpandedMenu] = useState<string | null>(null);

  // Quick search box at top of sidebar
  const [searchQuery, setSearchQuery] = useState('');

  // Collapsible sidebar state: persisted in localStorage
  const [isSideNavExpanded, setIsSideNavExpanded] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem('aegis_sidebar_expanded');
      if (saved !== null) {
        return saved === 'true';
      }
      return typeof window !== 'undefined' ? window.innerWidth >= 1056 : true;
    } catch {
      return true;
    }
  });

  const [isMobileOrTablet, setIsMobileOrTablet] = useState<boolean>(() => {
    if (typeof window !== 'undefined') {
      return window.innerWidth < 1056;
    }
    return false;
  });

  useEffect(() => {
    const handleResize = () => {
      setIsMobileOrTablet(window.innerWidth < 1056);
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Synchronize CSS variable for sidebar width across the application
  useEffect(() => {
    const width = isSideNavExpanded ? '256px' : '48px';
    document.documentElement.style.setProperty('--aegis-sidebar-width', width);
  }, [isSideNavExpanded]);

  const handleToggleSideNav = useCallback(() => {
    setIsSideNavExpanded((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('aegis_sidebar_expanded', String(next));
      } catch {
      }
      return next;
    });
  }, []);

  const handleSectionClick = useCallback((menuId: string) => {
    if (!isSideNavExpanded) {
      setIsSideNavExpanded(true);
      try {
        localStorage.setItem('aegis_sidebar_expanded', 'true');
      } catch {
      }
      setExpandedMenu(menuId);
    } else {
      setExpandedMenu((prev) => (prev === menuId ? null : menuId));
    }
  }, [isSideNavExpanded]);

  const handleNavSelect = useCallback((key: NavItemKey) => {
    onSelectNav(key);
    if (isMobileOrTablet) {
      setIsSideNavExpanded(false);
    }
  }, [onSelectNav, isMobileOrTablet]);

  useEffect(() => {
    if (propTier) {
      setTier(propTier);
      return;
    }
    if (authTier) {
      setTier(authTier);
      return;
    }
    const loadLicense = async () => {
      try {
        const lic = await apiService.getLicense();
        if (lic?.effective_tier) {
          setTier(lic.effective_tier.toLowerCase());
        }
      } catch {
      }
    };
    loadLicense();

    const handleLicenseChanged = () => {
      loadLicense();
    };
    window.addEventListener('aegis:license-changed', handleLicenseChanged);
    return () => window.removeEventListener('aegis:license-changed', handleLicenseChanged);
  }, [propTier, authTier]);

  const effectiveTier = (propTier || authTier || tier || 'community').toLowerCase();
  const isEnterprise = effectiveTier.includes('enterprise');
  const isProfessional = effectiveTier.includes('pro');

  const tierLabel = isEnterprise ? 'Enterprise' : isProfessional ? 'Professional' : 'Community';

  // Alerts and in-app notifications
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [isAlertsOpen, setIsAlertsOpen] = useState<boolean>(false);
  const [markingAllRead, setMarkingAllRead] = useState<boolean>(false);
  const [alertsTab, setAlertsTab] = useState<'unread' | 'all'>('unread');
  const [dismissedAlertIds, setDismissedAlertIds] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem('aegis_dismissed_alerts') || '[]');
    } catch {
      return [];
    }
  });

  const loadAlerts = async () => {
    try {
      const res = await apiService.getAlerts();
      setAlerts(res.alerts || []);
    } catch {
      // Non-blocking operational check
    }
  };

  useEffect(() => {
    loadAlerts();
    const interval = setInterval(loadAlerts, 20000);
    return () => clearInterval(interval);
  }, []);

  const handleMarkAlertRead = async (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    try {
      const res = await apiService.markAlertRead(id);
      if (res.success) {
        setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, read: true } : a)));
      }
    } catch {
    }
  };

  const handleMarkAllAlertsRead = async () => {
    setMarkingAllRead(true);
    try {
      const res = await apiService.markAllAlertsRead();
      if (res.success) {
        setAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
      }
    } catch {
    } finally {
      setMarkingAllRead(false);
    }
  };

  const handleDismissAlert = (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setDismissedAlertIds((prev) => {
      const next = prev.includes(id) ? prev : [...prev, id];
      try {
        localStorage.setItem('aegis_dismissed_alerts', JSON.stringify(next));
      } catch {
      }
      return next;
    });
  };

  const activeAlerts = useMemo(() => {
    return alerts.filter((a) => !dismissedAlertIds.includes(a.id));
  }, [alerts, dismissedAlertIds]);

  const unreadAlerts = useMemo(() => {
    return activeAlerts.filter((a) => !a.read);
  }, [activeAlerts]);

  const displayedAlerts = alertsTab === 'unread' ? unreadAlerts : activeAlerts;

  const handleOpenAlert = (alert: AlertItem) => {
    if (!alert.read) {
      void handleMarkAlertRead(alert.id);
    }
    setIsAlertsOpen(false);
    if (alert.route) {
      handleNavSelect(alert.route as NavItemKey);
    }
  };

  const normalizedQuery = searchQuery.trim().toLowerCase();

  const entitledCategories = useMemo(() => {
    return NAV_CATEGORIES.map((cat) => {
      const entitledItems: NavItemDef[] = [];

      cat.items.forEach((item) => {
        if (item.type === 'link') {
          const hasPerm =
            !item.permission ||
            !user?.permissions ||
            user.permissions.includes(item.permission) ||
            user.permissions.includes('*');
          if (isRouteEntitled(item.key, hasFeature) && hasPerm) {
            entitledItems.push(item);
          }
        } else if (item.type === 'menu') {
          const entitledSubItems = item.items.filter((sub) =>
            isRouteEntitled(sub.key, hasFeature)
          );
          if (entitledSubItems.length > 0) {
            entitledItems.push({
              ...item,
              items: entitledSubItems,
            });
          }
        }
      });

      return {
        ...cat,
        items: entitledItems,
      };
    }).filter((cat) => cat.items.length > 0);
  }, [hasFeature, user?.permissions]);

  const filteredCategories = useMemo(() => {
    if (!normalizedQuery) return entitledCategories;

    return entitledCategories.map((cat) => {
      const matchingItems: NavItemDef[] = [];

      cat.items.forEach((item) => {
        if (item.type === 'link') {
          if (item.label.toLowerCase().includes(normalizedQuery)) {
            matchingItems.push(item);
          }
        } else {
          const titleMatches = item.title.toLowerCase().includes(normalizedQuery);
          const matchingSubItems = item.items.filter(
            (sub) => titleMatches || sub.label.toLowerCase().includes(normalizedQuery)
          );
          if (matchingSubItems.length > 0) {
            matchingItems.push({
              ...item,
              items: matchingSubItems,
            });
          }
        }
      });

      return {
        ...cat,
        items: matchingItems,
      };
    }).filter((cat) => cat.items.length > 0);
  }, [entitledCategories, normalizedQuery]);

  const isMenuOpen = (menuId: string) => {
    if (normalizedQuery) {
      // While actively searching, auto-expand menus with matching items
      return true;
    }
    return expandedMenu === menuId;
  };

  return (
    <Theme theme={theme}>
      <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: 'var(--cds-background)' }}>
        <Header aria-label={`Aegis ${tierLabel} Platform`}>
          <HeaderMenuButton
            aria-label={isSideNavExpanded ? 'Collapse side navigation' : 'Expand side navigation'}
            aria-expanded={isSideNavExpanded}
            isActive={false}
            renderMenuIcon={<Menu size={20} />}
            renderCloseIcon={<Menu size={20} />}
            isCollapsible
            onClick={handleToggleSideNav}
          />
          <HeaderName
            prefix="AEGIS"
            href="#settings"
            onClick={(e: React.MouseEvent) => {
              e.preventDefault();
              onSelectNav('settings');
              window.location.hash = '#settings';
            }}
            title={`Edition: Aegis ${tierLabel} — click to manage licensing`}
          >
            {tierLabel}
          </HeaderName>

          <HeaderGlobalBar>
            <HeaderGlobalAction
              aria-label={theme === 'g100' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
              onClick={onToggleTheme}
              tooltipAlignment="end"
            >
              {theme === 'g100' ? <Sun size={20} /> : <Moon size={20} />}
            </HeaderGlobalAction>

            <HeaderGlobalAction
              aria-label={`Notifications (${unreadAlerts.length} unread)`}
              tooltipAlignment="end"
              isActive={isAlertsOpen}
              onClick={() => setIsAlertsOpen(!isAlertsOpen)}
            >
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Notification size={20} />
                {unreadAlerts.length > 0 && (
                  <span
                    style={{
                      position: 'absolute',
                      top: '-4px',
                      right: '-6px',
                      minWidth: '16px',
                      height: '16px',
                      borderRadius: '8px',
                      backgroundColor: '#da1e28',
                      color: '#ffffff',
                      fontSize: '10px',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      padding: '0 3px',
                      lineHeight: 1,
                      pointerEvents: 'none',
                    }}
                  >
                    {unreadAlerts.length > 99 ? '99+' : unreadAlerts.length}
                  </span>
                )}
              </div>
            </HeaderGlobalAction>

            <HeaderGlobalAction
              aria-label={`My profile (${user?.username || 'admin'})`}
              tooltipAlignment="end"
              onClick={() => onSelectNav('profile')}
            >
              <UserAvatar size={20} />
            </HeaderGlobalAction>

            <HeaderGlobalAction
              aria-label={`Sign out (${user?.username || 'admin'})`}
              tooltipAlignment="end"
              onClick={() => logout()}
            >
              <Logout size={20} />
            </HeaderGlobalAction>
          </HeaderGlobalBar>

          <HeaderPanel
            expanded={isAlertsOpen}
            aria-label="Operational Notifications"
            className="aegis-alerts-panel"
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '16px 20px 12px',
                borderBottom: '1px solid var(--cds-border-subtle, #393939)',
                backgroundColor: 'var(--cds-layer-01, #262626)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <span style={{ fontWeight: 600, fontSize: '14px', letterSpacing: '0.16px', color: 'var(--cds-text-primary, #f4f4f4)' }}>
                  Operational Alerts
                </span>
                <Tag
                  type={unreadAlerts.length > 0 ? 'red' : 'cool-gray'}
                  size="sm"
                  style={{ margin: 0 }}
                >
                  {unreadAlerts.length} unread
                </Tag>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {unreadAlerts.length > 0 && (
                  <button
                    type="button"
                    disabled={markingAllRead}
                    onClick={handleMarkAllAlertsRead}
                    style={{
                      padding: '4px 8px',
                      fontSize: '12px',
                      color: 'var(--cds-interactive, #ff832b)',
                      backgroundColor: 'transparent',
                      border: 'none',
                      cursor: 'pointer',
                      fontWeight: 500,
                    }}
                  >
                    Mark all read
                  </button>
                )}
                <button
                  type="button"
                  aria-label="Close notifications"
                  onClick={() => setIsAlertsOpen(false)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: '28px',
                    height: '28px',
                    backgroundColor: 'transparent',
                    border: 'none',
                    color: 'var(--cds-text-secondary, #c6c6c6)',
                    cursor: 'pointer',
                    borderRadius: '2px',
                  }}
                >
                  <Close size={18} />
                </button>
              </div>
            </div>

            <div
              style={{
                padding: '10px 16px',
                borderBottom: '1px solid var(--cds-border-subtle, #393939)',
                backgroundColor: 'var(--cds-layer-01, #262626)',
              }}
            >
              <ContentSwitcher
                size="sm"
                selectedIndex={alertsTab === 'unread' ? 0 : 1}
                onChange={(e) => setAlertsTab((e.name as 'unread' | 'all') || (e.index === 0 ? 'unread' : 'all'))}
              >
                <Switch name="unread" text={`Unread (${unreadAlerts.length})`} />
                <Switch name="all" text={`All (${activeAlerts.length})`} />
              </ContentSwitcher>
            </div>

            {/* List Content */}
            <div
              style={{
                flex: 1,
                overflowY: 'auto',
                display: 'flex',
                flexDirection: 'column',
                backgroundColor: 'var(--cds-layer-01, #161616)',
              }}
            >
              {displayedAlerts.length === 0 ? (
                <div
                  style={{
                    padding: '48px 24px',
                    textAlign: 'center',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '12px',
                    color: 'var(--cds-text-secondary, #8d8d8d)',
                  }}
                >
                  <Checkmark size={32} style={{ color: '#24a148' }} />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary, #f4f4f4)' }}>
                      {alertsTab === 'unread' ? 'All systems operational' : 'No operational alerts'}
                    </div>
                    <div style={{ fontSize: '12px', marginTop: '6px', maxWidth: '280px', lineHeight: 1.4, color: 'var(--cds-text-secondary, #c6c6c6)' }}>
                      {alertsTab === 'unread'
                        ? 'No unread operational alerts. All protection sections are running normally.'
                        : 'No active alerts reported by runtime engines.'}
                    </div>
                  </div>
                </div>
              ) : (
                displayedAlerts.map((alert) => {
                  const isCrit = alert.level === 'critical';
                  const isWarn = alert.level === 'warning';
                  const borderCol = isCrit ? '#da1e28' : isWarn ? '#f1c21b' : 'var(--cds-interactive, #ff832b)';
                  const tagType = isCrit ? 'red' : isWarn ? 'warm-gray' : 'teal';

                  return (
                    <div
                      key={alert.id}
                      style={{
                        padding: '14px 16px',
                        borderBottom: '1px solid var(--cds-border-subtle, #393939)',
                        borderLeft: `4px solid ${borderCol}`,
                        backgroundColor: alert.read
                          ? 'transparent'
                          : 'rgba(255, 255, 255, 0.04)',
                        opacity: alert.read ? 0.75 : 1,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                        transition: 'background-color 0.15s ease',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Tag type={tagType} size="sm" style={{ margin: 0, textTransform: 'uppercase', fontSize: '10px' }}>
                            {alert.level}
                          </Tag>
                          {alert.source && (
                            <span style={{ fontSize: '11px', color: 'var(--cds-text-secondary, #8d8d8d)', fontWeight: 500 }}>
                              {alert.source}
                            </span>
                          )}
                        </div>
                        {alert.created_at && (
                          <span style={{ fontSize: '11px', color: 'var(--cds-text-muted, #6f6f6f)' }}>
                            {new Date(alert.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                          </span>
                        )}
                      </div>

                      <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--cds-text-primary, #f4f4f4)', marginTop: '2px' }}>
                        {alert.title}
                      </div>

                      <div style={{ fontSize: '12px', color: 'var(--cds-text-secondary, #c6c6c6)', lineHeight: 1.4 }}>
                        {alert.message}
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '8px' }}>
                        {alert.route ? (
                          <button
                            type="button"
                            onClick={() => handleOpenAlert(alert)}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '6px',
                              padding: '5px 12px',
                              fontSize: '12px',
                              fontWeight: 500,
                              color: '#ffffff',
                              backgroundColor: 'var(--cds-button-primary, #eb6200)',
                              border: 'none',
                              borderRadius: '2px',
                              cursor: 'pointer',
                            }}
                          >
                            <span>{alert.action_label || 'Open Section'}</span>
                            <Launch size={14} />
                          </button>
                        ) : (
                          <div />
                        )}

                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          {!alert.read ? (
                            <button
                              type="button"
                              onClick={(e) => handleMarkAlertRead(alert.id, e)}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                                padding: '4px 10px',
                                fontSize: '12px',
                                color: 'var(--cds-text-primary, #f4f4f4)',
                                backgroundColor: 'transparent',
                                border: '1px solid var(--cds-border-subtle, #525252)',
                                borderRadius: '2px',
                                cursor: 'pointer',
                              }}
                            >
                              <Checkmark size={14} style={{ color: '#24a148' }} />
                              <span>Mark read</span>
                            </button>
                          ) : (
                            <span style={{ fontSize: '11px', color: 'var(--cds-text-muted, #8d8d8d)', fontWeight: 500 }}>
                              Acknowledged
                            </span>
                          )}

                          <button
                            type="button"
                            title="Dismiss from list"
                            onClick={(e) => handleDismissAlert(alert.id, e)}
                            style={{
                              padding: '4px 8px',
                              fontSize: '12px',
                              color: 'var(--cds-text-muted, #8d8d8d)',
                              backgroundColor: 'transparent',
                              border: 'none',
                              cursor: 'pointer',
                            }}
                          >
                            Dismiss
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </HeaderPanel>
        </Header>

        {/* Workspace Body: SideNav + Content */}
        <div style={{ display: 'flex', flex: 1, marginTop: '48px', position: 'relative' }}>
          <SideNav
            isFixedNav
            expanded={isSideNavExpanded}
            isChildOfHeader={false}
            aria-label="Side navigation"
            onOverlayClick={() => setIsSideNavExpanded(false)}
            className={`aegis-shell-sidenav ${isSideNavExpanded ? 'is-expanded' : 'is-collapsed'}`}
            style={{
              top: '48px',
              height: 'calc(100vh - 48px)',
              display: 'flex',
              flexDirection: 'column',
              zIndex: 7000,
            }}
          >
            <div className="sidebar-search-wrapper">
              <Search
                size="sm"
                id="sidebar-quick-search"
                labelText="Quick search navigation"
                placeholder="Quick search..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onClear={() => setSearchQuery('')}
                closeButtonLabelText="Clear search input"
                className="sidebar-search-carbon sidebar-search-box"
              />
            </div>

            <SideNavItems className="sidebar-nav-items">
              {filteredCategories.length === 0 ? (
                <li className="sidebar-no-results">
                  <p>No matches for &ldquo;{searchQuery}&rdquo;</p>
                  <button type="button" onClick={() => setSearchQuery('')}>
                    Clear search
                  </button>
                </li>
              ) : (
                filteredCategories.map((cat, catIdx) => (
                  <React.Fragment key={cat.id}>
                    <li className={`sidebar-category-item ${catIdx === 0 ? 'sidebar-category-first' : ''}`} role="separator">
                      <div className="sidebar-category-label">{cat.label}</div>
                    </li>
                    {cat.items.map((entry) => {
                      if (entry.type === 'link') {
                        const active = isItemActive(entry.key, activeNav);
                        return (
                          <SideNavLink
                            key={entry.key}
                            className="sidebar-big-title sidebar-nav-direct-link"
                            renderIcon={entry.icon}
                            isActive={active}
                            title={entry.label}
                            onMouseEnter={() => prefetchRoute(entry.key)}
                            onClick={(e: React.MouseEvent) => {
                              e.preventDefault();
                              handleNavSelect(entry.key);
                            }}
                          >
                            {entry.label}
                          </SideNavLink>
                        );
                      }

                      const activeGroup = isGroupActive(entry.items, activeNav);
                      const open = isMenuOpen(entry.id);

                      return (
                        <ControlledSideNavMenu
                          key={entry.id}
                          id={entry.id}
                          title={entry.title}
                          renderIcon={entry.icon}
                          isExpanded={open}
                          isActive={activeGroup}
                          onToggle={() => handleSectionClick(entry.id)}
                        >
                          {entry.items.map((sub) => {
                            const activeSub = isItemActive(sub.key, activeNav);
                            return (
                              <SideNavMenuItem
                                key={sub.key}
                                className="sidebar-nav-sub-item"
                                isActive={activeSub}
                                onMouseEnter={() => prefetchRoute(sub.key)}
                                onClick={(e: React.MouseEvent) => {
                                  e.preventDefault();
                                  handleNavSelect(sub.key);
                                }}
                              >
                                {sub.label}
                              </SideNavMenuItem>
                            );
                          })}
                        </ControlledSideNavMenu>
                      );
                    })}
                  </React.Fragment>
                ))
              )}
            </SideNavItems>
          </SideNav>

          {/* Main Content Area */}
          <main
            id="aegis-main-content"
            style={{
              flex: 1,
              marginLeft: isSideNavExpanded ? '256px' : '48px',
              minWidth: 0,
              width: isSideNavExpanded ? 'calc(100% - 256px)' : 'calc(100% - 48px)',
              height: 'calc(100vh - 48px)',
              overflowY: 'auto',
              overflowX: 'hidden',
              backgroundColor: 'var(--cds-background)',
              boxSizing: 'border-box',
              transition: 'margin-left 150ms cubic-bezier(0.2, 0, 0.38, 0.9), width 150ms cubic-bezier(0.2, 0, 0.38, 0.9)',
            }}
          >
            {isPending && <div className="aegis-top-loader-bar" />}
            <div className={`aegis-page-container ${isPending ? 'is-navigating' : ''}`}>
              {children}
            </div>
          </main>
        </div>
      </div>
    </Theme>
  );
};
