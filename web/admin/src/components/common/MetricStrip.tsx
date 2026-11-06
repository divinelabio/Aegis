import React from 'react';

export interface MetricStripProps {
  children: React.ReactNode;
  columns?: 2 | 3 | 4 | 5 | 6;
  minColWidth?: string;
  gap?: string;
  style?: React.CSSProperties;
}

export const MetricStrip: React.FC<MetricStripProps> = ({
  children,
  columns,
  minColWidth = '220px',
  gap = '16px',
  style,
}) => {
  const gridTemplate = columns
    ? `repeat(${columns}, minmax(0, 1fr))`
    : `repeat(auto-fit, minmax(${minColWidth}, 1fr))`;

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: gridTemplate,
        gap,
        width: '100%',
        marginBottom: '32px',
        boxSizing: 'border-box',
        ...style,
      }}
    >
      {children}
    </div>
  );
};