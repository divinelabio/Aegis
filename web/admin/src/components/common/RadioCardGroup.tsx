import React from 'react';
import { TileGroup, RadioTile } from '@carbon/react';

export interface RadioCardOption {
  value: string;
  title: string;
  description?: string;
  icon?: React.ComponentType<{ size?: number; style?: React.CSSProperties; className?: string }>;
  disabled?: boolean;
}

export interface RadioCardGroupProps {
  name: string;
  legend?: string;
  valueSelected?: string;
  onChange: (value: string) => void;
  options: RadioCardOption[];
  minColumnWidth?: string;
  disabled?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export const RadioCardGroup: React.FC<RadioCardGroupProps> = ({
  name,
  legend = '',
  valueSelected,
  onChange,
  options,
  minColumnWidth = '260px',
  disabled = false,
  className,
  style,
}) => {
  return (
    <TileGroup
      name={name}
      legend={legend}
      valueSelected={valueSelected}
      onChange={(val) => onChange(String(val))}
      className={className}
      style={{
        display: 'grid',
        gridTemplateColumns: `repeat(auto-fit, minmax(${minColumnWidth}, 1fr))`,
        gap: '1rem',
        ...style,
      }}
    >
      {options.map((opt) => {
        const isSelected = valueSelected === opt.value;
        const Icon = opt.icon;
        return (
          <RadioTile
            key={opt.value}
            id={`${name}-${opt.value}`}
            value={opt.value}
            disabled={disabled || opt.disabled}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', padding: '0.25rem' }}>
              {Icon && (
                <Icon
                  size={24}
                  style={{
                    color: isSelected ? 'var(--cds-interactive)' : 'var(--cds-icon-secondary)',
                    flexShrink: 0,
                    marginTop: '2px',
                  }}
                />
              )}
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--cds-text-primary)' }}>
                  {opt.title}
                </div>
                {opt.description && (
                  <div
                    style={{
                      fontSize: '12px',
                      color: 'var(--cds-text-secondary)',
                      marginTop: '2px',
                      lineHeight: 1.4,
                    }}
                  >
                    {opt.description}
                  </div>
                )}
              </div>
            </div>
          </RadioTile>
        );
      })}
    </TileGroup>
  );
};