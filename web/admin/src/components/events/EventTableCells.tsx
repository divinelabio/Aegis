import React from 'react';
import { Tag, Button } from '@carbon/react';
import { View } from '@carbon/icons-react';
import { COUNTRIES_MAP, countryNames, normalizeToCountryCode } from '../../data/geoData';
import { countryCodeToFlag } from '../common/CountryBadge';

export function isPrivateOrLoopbackIp(ip?: string): boolean {
  if (!ip) return false;
  const trimmed = ip.trim();
  return (
    trimmed === '127.0.0.1' ||
    trimmed === '::1' ||
    trimmed === 'localhost' ||
    trimmed.startsWith('10.') ||
    trimmed.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(trimmed) ||
    trimmed.startsWith('fc00:') ||
    trimmed.startsWith('fe80:')
  );
}

export function getValidCountryCode(code?: string, ip?: string): string | null {
  if (ip && isPrivateOrLoopbackIp(ip)) return null;
  return normalizeToCountryCode(code);
}

export function parseEventDate(ts?: number | string): Date {
  if (typeof ts === 'number') {
    return new Date(ts > 0 && ts < 1e12 ? ts * 1000 : ts);
  }
  const num = Number(ts);
  if (!Number.isNaN(num) && num > 0) {
    return new Date(num < 1e12 ? num * 1000 : num);
  }
  return new Date(ts || '');
}

/** Formatted Time cell: Monospace single-line compact timestamp with crisp date */
export const EventTimeCell: React.FC<{
  timestamp?: string | number;
  inline?: boolean;
}> = ({ timestamp, inline: _inline = false }) => {
  const dateObj = parseEventDate(timestamp);
  const isValid = !Number.isNaN(dateObj.getTime());

  if (!isValid) {
    return (
      <span
        style={{
          fontFamily: 'var(--cds-font-mono, monospace)',
          fontSize: '12px',
          color: 'var(--cds-text-secondary)',
          whiteSpace: 'nowrap',
        }}
      >
        {String(timestamp || '—')}
      </span>
    );
  }

  const timeStr = dateObj.toLocaleTimeString([], {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
  const dateStr = dateObj.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
  const fullStr = `${dateObj.toLocaleString()} (${dateObj.toISOString()})`;

  return (
    <span
      style={{
        fontFamily: 'var(--cds-font-mono, monospace)',
        fontSize: '12px',
        whiteSpace: 'nowrap',
        display: 'inline-flex',
        alignItems: 'baseline',
        gap: '6px',
      }}
      title={fullStr}
    >
      <span style={{ color: 'var(--cds-text-primary)', fontWeight: 600 }}>{timeStr}</span>
      {' '}
      <span style={{ color: 'var(--cds-text-secondary)', fontSize: '11px' }}>{dateStr}</span>
    </span>
  );
};

export const EventMethodTag: React.FC<{ method?: string }> = ({ method = 'GET' }) => {
  const m = (method || 'GET').toUpperCase();
  return (
    <Tag
      type="cool-gray"
      size="sm"
      style={{ margin: 0, fontWeight: 600, letterSpacing: '0.3px' }}
    >
      {m}
    </Tag>
  );
};

/** Path Cell: Clean normal monospace text as it was, but in link color */
export const EventPathCell: React.FC<{ path?: string; maxWidth?: string }> = ({
  path = '/',
  maxWidth = '280px',
}) => {
  return (
    <span
      style={{
        fontFamily: 'var(--cds-font-mono, monospace)',
        fontSize: '12px',
        color: 'var(--cds-text-primary, #ffffff)',
        maxWidth,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        display: 'block',
      }}
      title={path}
    >
      {path}
    </span>
  );
};

/** Rule / Reason Cell: Bold text header */
export const EventRuleCell: React.FC<{ rule?: string; id?: string; maxWidth?: string }> = ({
  rule,
  id,
  maxWidth = '260px',
}) => {
  const text = rule || id || 'Detection';
  return (
    <span
      style={{
        maxWidth,
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        whiteSpace: 'nowrap',
        fontSize: '13px',
        fontWeight: 600,
        color: 'var(--cds-text-primary)',
        display: 'block',
      }}
      title={text}
    >
      {text}
    </span>
  );
};

export const EventActionBadge: React.FC<{ action?: string }> = ({ action = 'BLOCK' }) => {
  const act = (action || 'BLOCK').toUpperCase();
  if (act.includes('BLOCK') || act.includes('DENY') || act.includes('DROP')) {
    return <Tag type="red" size="sm" style={{ margin: 0, fontWeight: 600 }}>{act}</Tag>;
  }
  if (act.includes('CHALLENGE')) {
    return <Tag type="blue" size="sm" style={{ margin: 0, fontWeight: 600 }}>{act}</Tag>;
  }
  if (act.includes('DETECT') || act.includes('LOG')) {
    return <Tag type="cool-gray" size="sm" style={{ margin: 0, fontWeight: 600 }}>{act}</Tag>;
  }
  if (act.includes('ALLOW') || act.includes('PASS')) {
    return <Tag type="green" size="sm" style={{ margin: 0, fontWeight: 600 }}>{act}</Tag>;
  }
  if (act.includes('REDIRECT')) {
    return (
      <Tag
        type="warm-gray"
        size="sm"
        className="cds--tag--orange"
        style={{
          margin: 0,
          fontWeight: 600,
          backgroundColor: 'var(--cds-tag-background-orange, #ba4e00)',
          color: 'var(--cds-tag-color-orange, #fff2e8)',
          border: 'none',
        }}
      >
        {act}
      </Tag>
    );
  }
  return <Tag type="gray" size="sm" style={{ margin: 0, fontWeight: 600 }}>{act}</Tag>;
};

/** HTTP Status Code Tag: 2xx Green, 3xx Grey, 4xx/5xx Red */
export const EventStatusTag: React.FC<{ status?: number; showLabel?: boolean }> = ({
  status = 200,
  showLabel = false,
}) => {
  const s = Number(status) || 200;
  const type = s >= 400 ? 'red' : s >= 300 ? 'cool-gray' : 'green';
  const labelText = showLabel
    ? s >= 500
      ? ' Server Error'
      : s >= 400
      ? ' Client Error'
      : s >= 300
      ? ' Redirect'
      : ' OK'
    : '';

  const hoverTitle = `${s}${labelText ? ` - ${labelText.trim()}` : (s >= 500 ? ' - Server Error' : s >= 400 ? ' - Client Error' : s >= 300 ? ' - Redirect' : ' - OK')}`;

  return (
    <Tag
      type={type}
      size="sm"
      title={hoverTitle}
      style={{
        margin: 0,
        fontWeight: 600,
      }}
    >
      {s}{labelText}
    </Tag>
  );
};

/** Combined Method + Path Cell: Compact, space-saving request representation */
export const EventRequestCell: React.FC<{
  method?: string;
  path?: string;
  maxWidth?: string;
}> = ({ method = 'GET', path = '/', maxWidth = '320px' }) => {
  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '8px',
        maxWidth: '100%',
        minWidth: 0,
      }}
    >
      <EventMethodTag method={method} />
      <span
        style={{
          fontFamily: 'var(--cds-font-mono, monospace)',
          fontSize: '12px',
          color: 'var(--cds-text-primary, #ffffff)',
          maxWidth,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          display: 'inline-block',
        }}
        title={path}
      >
        {path}
      </span>
    </div>
  );
};

/** Source IP with country flag before the IP, using geoblocklist country DB */
export const EventSourceCell: React.FC<{ ip?: string; country?: string }> = ({
  ip = '—',
  country,
}) => {
  const countryCode = getValidCountryCode(country, ip);
  const flag = countryCode ? countryCodeToFlag(countryCode) : '';
  const countryName = countryCode ? (COUNTRIES_MAP[countryCode] || countryNames[countryCode] || countryCode) : '';

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '7px',
        fontFamily: 'var(--cds-font-mono, monospace)',
        fontSize: '12px',
      }}
    >
      {flag ? (
        <span
          className="country-flag"
          role="img"
          aria-label={countryName || countryCode || ''}
          title={countryName ? `${countryName} (${countryCode})` : (countryCode || '')}
          style={{
            fontSize: '16px',
            lineHeight: 1,
            display: 'inline-flex',
            alignItems: 'center',
            cursor: 'default',
            flexShrink: 0,
            fontFamily: '"Twemoji Mozilla", "Apple Color Emoji", "Segoe UI Emoji", "Noto Color Emoji", sans-serif',
          }}
        >
          {flag}
        </span>
      ) : countryCode ? (
        <span
          style={{
            fontSize: '10px',
            fontWeight: 700,
            color: 'var(--cds-text-secondary)',
            letterSpacing: '0.4px',
            padding: '1px 5px',
            borderRadius: '2px',
            backgroundColor: 'var(--cds-layer-02, #262626)',
            border: '1px solid var(--cds-border-subtle, #393939)',
            lineHeight: 1.2,
          }}
          title={countryName || countryCode}
        >
          {countryCode}
        </span>
      ) : null}
      <span style={{ color: 'var(--cds-text-primary)' }}>{ip}</span>
    </div>
  );
};

export const EventScoreText: React.FC<{ score?: number; severity?: string }> = ({
  score,
  severity,
}) => {
  const s = Number(score) || 0;
  const sev = String(severity || '').toLowerCase();

  if (s <= 0 && sev !== 'critical' && sev !== 'high') {
    return (
      <span
        style={{
          fontFamily: 'var(--cds-font-mono, monospace)',
          fontSize: '12px',
          color: 'var(--cds-text-secondary)',
        }}
      >
        0
      </span>
    );
  }

  if (s >= 15 || sev === 'critical') {
    return (
      <span
        style={{
          fontFamily: 'var(--cds-font-mono, monospace)',
          fontSize: '12px',
          fontWeight: 700,
          color: 'var(--cds-support-error, #da1e28)',
        }}
      >
        {s}
      </span>
    );
  }

  if (s >= 10 || sev === 'high') {
    return (
      <span
        style={{
          fontFamily: 'var(--cds-font-mono, monospace)',
          fontSize: '12px',
          fontWeight: 600,
          color: 'var(--cds-support-warning, #ff832b)',
        }}
      >
        {s}
      </span>
    );
  }

  return (
    <span
      style={{
        fontFamily: 'var(--cds-font-mono, monospace)',
        fontSize: '12px',
        fontWeight: 600,
        color: 'var(--cds-text-primary)',
      }}
    >
      {s}
    </span>
  );
};

/** Row inspect action button */
export const EventInspectButton: React.FC<{ onClick: (e: React.MouseEvent) => void }> = ({
  onClick,
}) => (
  <Button
    kind="ghost"
    size="sm"
    renderIcon={View}
    hasIconOnly
    iconDescription="Inspect event details"
    style={{ color: 'var(--cds-icon-secondary)' }}
    onClick={onClick}
  />
);
