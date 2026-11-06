import React from 'react';
import './PageHeader.scss';

export interface PageHeaderProps {
  /** Optional kicker / category eyebrow */
  kicker?: string;
  /* * Primary page title */
  title: string;
  /** Optional subtitle or description (body-long-01) */
  subtitle?: string;
  /** Optional status badge or filter indicator element */
  badge?: React.ReactNode;
  /** Optional unboxed icon */
  icon?: React.ComponentType<{ size?: number; className?: string; style?: React.CSSProperties }> | React.ReactNode;
  /** Right-aligned action toolbar (Buttons, toggles, controls) */
  action?: React.ReactNode;
  /** Auxiliary bottom slot (Tabs, filter bars) */
  children?: React.ReactNode;
  /** Custom inline style override */
  style?: React.CSSProperties;
  /** Optional additional class name */
  className?: string;
}

export const PageHeader: React.FC<PageHeaderProps> = ({
  kicker,
  title,
  subtitle,
  badge,
  icon,
  action,
  children,
  style,
  className = '',
}) => {
  const renderIcon = () => {
    if (!icon) return null;
    if (React.isValidElement(icon)) return icon;
    const IconComp = icon as any;
    return <IconComp size={24} />;
  };

  const rootClasses = ['aegis-page-header', className].filter(Boolean).join(' ');

  return (
    <header className={rootClasses} style={style}>
      {kicker && (
        <div className="aegis-page-header__kicker">
          {kicker}
        </div>
      )}

      <div className="aegis-page-header__row">
        <div className="aegis-page-header__left">
          <div className="aegis-page-header__title-row">
            {icon && (
              <span className="aegis-page-header__icon" aria-hidden="true">
                {renderIcon()}
              </span>
            )}
            <h1 className="aegis-page-header__title">{title}</h1>
            {badge && <div className="aegis-page-header__badge">{badge}</div>}
          </div>
          {subtitle && <p className="aegis-page-header__subtitle">{subtitle}</p>}
        </div>

        {action && (
          <div className="aegis-page-header__actions">
            {action}
          </div>
        )}
      </div>

      {children && (
        <div className="aegis-page-header__bottom">
          {children}
        </div>
      )}
    </header>
  );
};
