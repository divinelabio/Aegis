import React from 'react';
import { Tile, SkeletonText } from '@carbon/react';

export type KpiStatus = 'default' | 'error' | 'warning' | 'success' | 'info' | 'interactive';

export interface KpiCardProps {
  label: string;
  value: React.ReactNode;
  subtext?: React.ReactNode;
  status?: KpiStatus;
  valueColor?: string;
  icon?: React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }>;
  onClick?: () => void;
  style?: React.CSSProperties;
  loading?: boolean;
}

export const KpiCard: React.FC<KpiCardProps> = ({
  label,
  value,
  subtext,
  status: _status = 'default',
  valueColor: _valueColor,
  icon: IconComponent,
  onClick,
  style,
  loading = false,
}) => {
  return (
    <Tile
      onClick={loading ? undefined : onClick}
      style={{
        background: 'var(--cds-layer-01)',
        border: '1px solid var(--cds-border-subtle)',
        borderRadius: 0,
        padding: '16px',
        minHeight: '110px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        cursor: onClick && !loading ? 'pointer' : 'default',
        boxSizing: 'border-box',
        height: '100%',
        transition: onClick && !loading ? 'border-color 0.15s ease, background-color 0.15s ease' : undefined,
        ...style,
      }}
    >
      <div>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '8px',
            marginBottom: '6px',
          }}
        >
          <div
            style={{
              fontSize: '11px',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              color: 'var(--cds-text-secondary)',
              fontFamily: 'var(--cds-font-family, "IBM Plex Sans", sans-serif)',
            }}
          >
            {label}
          </div>
          {IconComponent && (
            <div style={{ color: 'var(--cds-icon-secondary, var(--cds-text-secondary))' }}>
              <IconComponent size={16} />
            </div>
          )}
        </div>

        <div
          style={{
            fontSize: '28px',
            fontWeight: 600,
            color: 'var(--cds-text-primary)',
            lineHeight: 1.2,
            letterSpacing: '-0.3px',
          }}
        >
          {loading ? (
            <div style={{ margin: '4px 0 6px 0' }}>
              <SkeletonText heading width="65%" />
            </div>
          ) : (
            value
          )}
        </div>
      </div>

      {loading ? (
        <div style={{ marginTop: '8px' }}>
          <SkeletonText width="45%" />
        </div>
      ) : subtext ? (
        <div
          style={{
            fontSize: '12px',
            color: 'var(--cds-text-helper)',
            marginTop: '8px',
            lineHeight: 1.3,
          }}
        >
          {subtext}
        </div>
      ) : null}
    </Tile>
  );
};