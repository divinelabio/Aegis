import React from 'react';
import { trafficCountryFlag, normalizeToCountryCode, COUNTRIES_MAP } from '../../data/geoData';

export function countryCodeToFlag(code?: string): string {
  return trafficCountryFlag(code);
}

export interface CountryBadgeProps {
  code?: string;
  className?: string;
  style?: React.CSSProperties;
  showFlag?: boolean;
}

export const CountryBadge: React.FC<CountryBadgeProps> = ({
  code,
  className,
  style,
  showFlag = true,
}) => {
  if (!code) return null;
  const upper = normalizeToCountryCode(code);
  if (!upper) return null;

  const flag = countryCodeToFlag(upper);
  const countryName = COUNTRIES_MAP[upper] || upper;

  return (
    <span
      className={className}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        fontFamily: 'var(--cds-font-mono, monospace)',
        fontWeight: 600,
        fontSize: '11px',
        color: 'var(--cds-text-secondary, #8d8d8d)',
        letterSpacing: '0.3px',
        ...style,
      }}
      title={`${countryName} (${upper})`}
    >
      {showFlag && flag && (
        <span
          className="country-flag"
          role="img"
          aria-label={countryName}
          style={{
            fontSize: '13px',
            lineHeight: 1,
            display: 'inline-flex',
            alignItems: 'center',
            fontFamily: '"Twemoji Mozilla", "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif',
          }}
        >
          {flag}
        </span>
      )}
      <span>{upper}</span>
    </span>
  );
};
