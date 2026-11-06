import React from 'react';
import { Tag } from '@carbon/react';

export type PolicyStrategy =
  | 'round_robin'
  | 'weighted_rr'
  | 'least_conn'
  | 'ip_hash'
  | 'random'
  | 'origin_pool'
  | 'default_proxy'
  | string;

export interface PolicyTagProps {
  strategy?: PolicyStrategy;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  className?: string;
  style?: React.CSSProperties;
}

export interface PolicyConfig {
  label: string;
  type: 'warm-gray' | 'purple' | 'blue' | 'teal' | 'magenta' | 'cyan' | 'cool-gray' | 'gray';
  isOrange: boolean;
}

export const getPolicyConfig = (strat: string = 'round_robin'): PolicyConfig => {
  const normalized = (strat || '').toLowerCase().trim();
  switch (normalized) {
    case 'round_robin':
      return {
        label: 'Round robin',
        type: 'warm-gray',
        isOrange: true,
      };
    case 'weighted_rr':
      return {
        label: 'Weighted round robin',
        type: 'purple',
        isOrange: false,
      };
    case 'least_conn':
      return {
        label: 'Least connections',
        type: 'blue',
        isOrange: false,
      };
    case 'ip_hash':
      return {
        label: 'IP hash',
        type: 'teal',
        isOrange: false,
      };
    case 'random':
      return {
        label: 'Random',
        type: 'magenta',
        isOrange: false,
      };
    case 'origin_pool':
      return {
        label: 'Origin pool',
        type: 'cyan',
        isOrange: false,
      };
    case 'default_proxy':
    case 'default':
      return {
        label: 'Default proxy',
        type: 'cool-gray',
        isOrange: false,
      };
    default: {
      const formatted = normalized.replace(/_/g, ' ');
      const capitalized = formatted.charAt(0).toUpperCase() + formatted.slice(1);
      return {
        label: capitalized || 'Round robin',
        type: 'cool-gray',
        isOrange: false,
      };
    }
  }
};

export const PolicyTag: React.FC<PolicyTagProps> = ({
  strategy = 'round_robin',
  label,
  size = 'sm',
  className = '',
  style = {},
}) => {
  const config = getPolicyConfig(strategy);
  const displayLabel = label || config.label;

  if (config.isOrange) {
    return (
      <Tag
        size={size}
        type="warm-gray"
        className={`cds--tag--orange ${className}`.trim()}
        style={{
          backgroundColor: 'var(--cds-tag-background-orange, #eb6200)',
          color: 'var(--cds-tag-color-orange, #ffffff)',
          fontWeight: 600,
          border: 'none',
          ...style,
        }}
      >
        {displayLabel}
      </Tag>
    );
  }

  return (
    <Tag size={size} type={config.type} className={className} style={style}>
      {displayLabel}
    </Tag>
  );
};
