import React, { useState } from 'react';
import { Tile, Layer, Button } from '@carbon/react';
import { ChevronDown, ChevronUp } from '@carbon/icons-react';

export interface SectionCardProps {
  title?: React.ReactNode;
  kicker?: string;
  description?: string;
  icon?: React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }>;
  action?: React.ReactNode;
  children: React.ReactNode;
  padded?: boolean;
  style?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
  collapsible?: boolean;
  expanded?: boolean;
  defaultExpanded?: boolean;
  onToggleExpanded?: (expanded: boolean) => void;
}

export const SectionCard: React.FC<SectionCardProps> = ({
  title,
  kicker,
  description,
  icon: IconComponent,
  action,
  children,
  padded = true,
  style,
  bodyStyle,
  collapsible = false,
  expanded: controlledExpanded,
  defaultExpanded = false,
  onToggleExpanded,
}) => {
  const [internalExpanded, setInternalExpanded] = useState<boolean>(defaultExpanded);
  const isExpanded = controlledExpanded !== undefined ? controlledExpanded : internalExpanded;

  const handleToggle = () => {
    if (!collapsible) return;
    const next = !isExpanded;
    if (controlledExpanded === undefined) {
      setInternalExpanded(next);
    }
    onToggleExpanded?.(next);
  };

  const hasHeader = Boolean(title || kicker || description || action || IconComponent || collapsible);

  const headerMarginBottom = collapsible
    ? (isExpanded && padded ? '20px' : 0)
    : '20px';

  const headerPadding = !padded
    ? (collapsible ? '20px 24px' : '20px 24px 0')
    : 0;

  const headerBorderBottom = collapsible && isExpanded && !padded
    ? '1px solid var(--cds-border-subtle)'
    : 'none';

  return (
    <Tile
      style={{
        background: 'var(--cds-layer-01)',
        border: '1px solid var(--cds-border-subtle)',
        borderRadius: 0,
        padding: padded ? '24px' : 0,
        marginBottom: '24px',
        width: '100%',
        boxSizing: 'border-box',
        ...style,
      }}
    >
      {hasHeader && (
        <div
          aria-expanded={collapsible ? isExpanded : undefined}
          onClick={
            collapsible
              ? (e) => {
                  if ((e.target as HTMLElement).closest('.section-card-action')) return;
                  handleToggle();
                }
              : undefined
          }
          onKeyDown={
            collapsible
              ? (e) => {
                  if ((e.target as HTMLElement).closest('.section-card-action')) return;
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    handleToggle();
                  }
                }
              : undefined
          }
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: collapsible ? 'center' : 'flex-start',
            flexWrap: 'wrap',
            gap: '12px',
            marginBottom: headerMarginBottom,
            padding: headerPadding,
            borderBottom: headerBorderBottom,
            cursor: collapsible ? 'pointer' : undefined,
            userSelect: collapsible ? 'none' : undefined,
            transition: 'background-color 0.15s ease',
          }}
          onMouseEnter={(e) => {
            if (collapsible) {
              e.currentTarget.style.backgroundColor = 'var(--cds-layer-hover, rgba(141, 141, 141, 0.08))';
            }
          }}
          onMouseLeave={(e) => {
            if (collapsible) {
              e.currentTarget.style.backgroundColor = 'transparent';
            }
          }}
        >
          <div>
            {kicker && (
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.1em',
                  color: 'var(--cds-text-helper)',
                  marginBottom: '4px',
                }}
              >
                {kicker}
              </div>
            )}
            {title && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {IconComponent && (
                  <IconComponent size={20} style={{ color: 'var(--cds-icon-primary)', flexShrink: 0 }} />
                )}
                {typeof title === 'string' ? (
                  <h2
                    style={{
                      fontSize: '16px',
                      fontWeight: 600,
                      color: 'var(--cds-text-primary)',
                      margin: 0,
                      lineHeight: 1.3,
                    }}
                  >
                    {title}
                  </h2>
                ) : (
                  title
                )}
              </div>
            )}
            {description && (
              <p
                style={{
                  fontSize: '13px',
                  color: 'var(--cds-text-secondary)',
                  margin: '4px 0 0 0',
                  lineHeight: 1.4,
                }}
              >
                {description}
              </p>
            )}
          </div>

          {(action || collapsible) && (
            <div
              className="section-card-action"
              style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              onClick={collapsible ? (e) => e.stopPropagation() : undefined}
            >
              {action}
              {collapsible && (
                <Button
                  kind="ghost"
                  size="sm"
                  hasIconOnly
                  renderIcon={isExpanded ? ChevronUp : ChevronDown}
                  iconDescription={isExpanded ? 'Collapse section' : 'Expand section'}
                  onClick={handleToggle}
                />
              )}
            </div>
          )}
        </div>
      )}

      {(!collapsible || isExpanded) && (
        <Layer style={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column', ...bodyStyle }}>
          {children}
        </Layer>
      )}
    </Tile>
  );
};