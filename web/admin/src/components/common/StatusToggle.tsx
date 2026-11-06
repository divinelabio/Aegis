import React from 'react';
import { Toggle } from '@carbon/react';

export interface StatusToggleProps {
  id: string;
  toggled: boolean;
  onToggle: (checked: boolean) => void;
  label?: string;
  labelA?: string;
  labelB?: string;
  size?: 'sm' | 'md';
  disabled?: boolean;
  ariaLabel?: string;
  hideLabel?: boolean;
  description?: string;
  style?: React.CSSProperties;
}

export const StatusToggle: React.FC<StatusToggleProps> = ({
  id,
  toggled,
  onToggle,
  label = '',
  labelA: _labelA = '',
  labelB: _labelB = '',
  size = 'sm',
  disabled = false,
  ariaLabel,
  hideLabel = false,
  description,
  style,
}) => {
  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', gap: '4px', ...style }}>
      <Toggle
        id={id}
        labelText={hideLabel ? '' : label}
        labelA=""
        labelB=""
        toggled={toggled}
        onToggle={onToggle}
        size={size}
        disabled={disabled}
        hideLabel={hideLabel}
        aria-label={ariaLabel || label || id}
      />
      {description && (
        <span style={{ fontSize: '12px', color: 'var(--cds-text-helper)' }}>
          {description}
        </span>
      )}
    </div>
  );
};