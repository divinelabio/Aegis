import React from 'react';
import { ContentSwitcher, Switch } from '@carbon/react';
import './HeaderSwitcher.scss';

export interface HeaderSwitcherProps {
  /** Current state: true for 'On' (index 0), false for 'Off' (index 1) */
  toggled?: boolean;
  /** Alias for toggled */
  enabled?: boolean;
  /** Callback invoked when toggled with the new boolean state */
  onToggle?: (toggled: boolean) => void;
  /** Alias for onToggle */
  onChange?: (toggled: boolean) => void;
  /** Optional custom label for the ON state (defaults to 'On') */
  labelOn?: string;
  /** Optional custom label for the OFF state (defaults to 'Off') */
  labelOff?: string;
  /** Control size (sm or md), defaults to 'sm' */
  size?: 'sm' | 'md';
  /** Whether the switcher is disabled */
  disabled?: boolean;
  /** Accessible label for screen readers */
  ariaLabel?: string;
  /** Additional custom class name */
  className?: string;
  /** Optional element id */
  id?: string;
  /** Custom inline styles */
  style?: React.CSSProperties;
}

export const HeaderSwitcher: React.FC<HeaderSwitcherProps> = ({
  toggled,
  enabled,
  onToggle,
  onChange,
  labelOn = 'On',
  labelOff = 'Off',
  size = 'sm',
  disabled = false,
  ariaLabel = 'Enable or disable',
  className = '',
  id,
  style,
}) => {
  const isToggled = toggled !== undefined ? Boolean(toggled) : enabled !== undefined ? Boolean(enabled) : false;
  const handleChange = onToggle || onChange;

  const rootClasses = ['aegis-header-switcher', className].filter(Boolean).join(' ');

  return (
    <ContentSwitcher
      id={id}
      size={size}
      className={rootClasses}
      selectedIndex={isToggled ? 0 : 1}
      onChange={(item: any) => {
        if (!disabled && handleChange) {
          handleChange(item.name === 'on' || item.index === 0);
        }
      }}
      aria-label={ariaLabel}
      style={style}
    >
      <Switch name="on" text={labelOn} disabled={disabled} />
      <Switch name="off" text={labelOff} disabled={disabled} />
    </ContentSwitcher>
  );
};

export const EngineSwitcher = HeaderSwitcher;
