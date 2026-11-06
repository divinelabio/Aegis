import React from 'react';
import { Tile, Button, Tag, Grid, Column } from '@carbon/react';
import { Locked, ArrowRight, Launch, ArrowLeft } from '@carbon/icons-react';
import { getRequiredFeatureForRoute, getRequiredTierForFeature } from '../../utils/features';
import type { NavItemKey } from '../../types';

export interface FeatureLockedViewProps {
  navKey: NavItemKey;
  onNavigate?: (key: NavItemKey) => void;
  actionIcon?: 'launch' | 'arrow';
}

const ROUTE_NAME_MAP: Partial<Record<NavItemKey, string>> = {
  // WAF Leak Protection
  'waf-leak': 'WAF Leak Protection',
  'waf-leak-protection': 'WAF Leak Protection',

  'traffic-ddos': 'Application Flood (DDoS)',
  'traffic-priority': 'Trusted Exceptions',
  'traffic-reputation': 'IP Reputation',

  // Bot Protection Suite
  'bot-overview': 'Bot Protection',
  'bot-managed': 'Bot Protection',
  'bot-rules': 'Bot Protection',
  'bot-classification': 'Bot Protection',
  'bot-ai': 'Bot Protection',
  'bot-exceptions': 'Bot Protection',

  'api-security': 'API Shield',
  'api-inventory': 'API Shield',
  'api-contracts': 'API Shield',
  'api-authorization': 'API Shield',
  'api-graphql': 'API Shield',

  // Edge Access Control Suite
  'edge-access': 'Edge Access',
  'access-apps': 'Edge Access',
  'access-policies': 'Edge Access',
  'access-identity': 'Edge Access',
  'access-roles': 'Edge Access',
  'access-decisions': 'Edge Access',
  'access-runtime': 'Edge Access',

  'audit': 'Audit Logs',
};

function getRouteTitle(navKey: NavItemKey): string {
  if (ROUTE_NAME_MAP[navKey]) {
    return ROUTE_NAME_MAP[navKey]!;
  }
  if (navKey.startsWith('bot-')) return 'Bot Protection';
  if (navKey.startsWith('api-')) return 'API Shield';
  if (navKey.startsWith('access-') || navKey === 'edge-access') return 'Edge Access';
  if (navKey === 'waf-leak' || navKey === 'waf-leak-protection') return 'WAF Leak Protection';
  if (navKey === 'audit') return 'Audit Logs';
  if (navKey === 'traffic-reputation') return 'IP Reputation';

  return navKey
    .split('-')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

export const FeatureLockedView: React.FC<FeatureLockedViewProps> = ({
  navKey,
  onNavigate,
  actionIcon = 'launch',
}) => {
  const feature = getRequiredFeatureForRoute(navKey);
  const rawTier = feature ? getRequiredTierForFeature(feature) : 'enterprise';
  const tier = rawTier === 'enterprise' ? 'enterprise' : 'professional';
  const tierLabel = tier === 'enterprise' ? 'Enterprise' : 'Professional';
  const title = getRouteTitle(navKey);
  const PrimaryActionIcon = actionIcon === 'arrow' ? ArrowRight : Launch;

  const handleActivateLicense = () => {
    if (onNavigate) {
      onNavigate('settings');
    }
    window.location.hash = '#settings';
  };

  const handleBackToDashboard = () => {
    if (onNavigate) {
      onNavigate('security-events');
    }
    window.location.hash = '#security-events';
  };

  return (
    <Grid
      fullWidth
      className="aegis-feature-locked-grid"
      style={{
        padding: '2.5rem 1.5rem',
        maxWidth: '1440px',
        margin: '0 auto',
      }}
    >
      <Column sm={4} md={8} lg={16}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '1rem',
            marginBottom: '2.5rem',
            paddingBottom: '1rem',
            borderBottom: '1px solid var(--cds-border-subtle, #393939)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <h1
              style={{
                fontSize: '1.75rem',
                fontWeight: 400,
                margin: 0,
                color: 'var(--cds-text-primary, #f4f4f4)',
                letterSpacing: '0.16px',
              }}
            >
              {title}
            </h1>
            <Tag type={tier === 'enterprise' ? 'purple' : 'teal'} size="md">
              Requires {tierLabel} Edition
            </Tag>
          </div>
        </div>
      </Column>

      <Column sm={4} md={8} lg={{ span: 10, offset: 3 }}>
        <Tile
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            textAlign: 'center',
            padding: '3.5rem 2rem',
            backgroundColor: 'var(--cds-layer-01, #262626)',
            border: '1px solid var(--cds-border-subtle, #393939)',
            borderRadius: '4px',
            boxShadow: '0 4px 16px rgba(0, 0, 0, 0.2)',
          }}
        >
          <div
            style={{
              width: '88px',
              height: '88px',
              borderRadius: '50%',
              backgroundColor:
                tier === 'enterprise'
                  ? 'rgba(165, 110, 255, 0.12)'
                  : 'rgba(0, 157, 154, 0.12)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginBottom: '1.5rem',
              color: tier === 'enterprise' ? '#a56eff' : '#009d9a',
            }}
          >
            <Locked size={48} />
          </div>

          <h2
            style={{
              fontSize: '1.5rem',
              fontWeight: 600,
              margin: '0 0 0.75rem 0',
              color: 'var(--cds-text-primary, #f4f4f4)',
              letterSpacing: '0.16px',
            }}
          >
            Feature Not Included in Current Plan
          </h2>

          <p
            style={{
              fontSize: '0.9375rem',
              lineHeight: '1.5',
              color: 'var(--cds-text-secondary, #c6c6c6)',
              maxWidth: '540px',
              margin: '0 0 2rem 0',
            }}
          >
            This capability requires Aegis {tierLabel} Edition. Upgrade your license or enter an activation key to enable it.
          </p>

          <div
            style={{
              display: 'flex',
              gap: '1rem',
              flexWrap: 'wrap',
              justifyContent: 'center',
            }}
          >
            <Button
              kind="primary"
              renderIcon={PrimaryActionIcon}
              onClick={handleActivateLicense}
            >
              Activate License
            </Button>
            <Button
              kind="secondary"
              renderIcon={ArrowLeft}
              onClick={handleBackToDashboard}
            >
              Back to Dashboard
            </Button>
          </div>
        </Tile>
      </Column>
    </Grid>
  );
};

export default FeatureLockedView;
