import React from 'react';

/**
 * Reusable MetricCard Component for SOC Overview KPIs
 * @param {string} title - Card title label
 * @param {number|string} value - Metric value (number or string)
 * @param {string} subtitle - Subtitle/context string
 * @param {React.ElementType} icon - Lucide React Icon component
 * @param {string} variant - Accent variant ("default" | "critical" | "high" | "warning" | "accent")
 */
const MetricCard = ({ title, value, subtitle, icon: Icon, variant = 'default' }) => {
  const formattedValue = typeof value === 'number' ? value.toLocaleString() : (value ?? '0');

  let accentColor = 'var(--color-accent)';
  let iconBg = 'rgba(6, 182, 212, 0.1)';
  let iconBorder = 'rgba(6, 182, 212, 0.2)';

  if (variant === 'critical') {
    accentColor = 'var(--color-critical)';
    iconBg = 'rgba(244, 63, 94, 0.12)';
    iconBorder = 'rgba(244, 63, 94, 0.3)';
  } else if (variant === 'high') {
    accentColor = 'var(--color-high)';
    iconBg = 'rgba(251, 146, 60, 0.12)';
    iconBorder = 'rgba(251, 146, 60, 0.3)';
  } else if (variant === 'warning') {
    accentColor = 'var(--color-warning)';
    iconBg = 'rgba(245, 158, 11, 0.12)';
    iconBorder = 'rgba(245, 158, 11, 0.3)';
  }

  return (
    <div className="card" style={styles.cardContainer}>
      <div style={styles.cardHeader}>
        <span style={styles.titleText}>{title}</span>
        {Icon && (
          <div style={{ ...styles.iconWrapper, backgroundColor: iconBg, borderColor: iconBorder }}>
            <Icon size={18} color={accentColor} />
          </div>
        )}
      </div>

      <div style={styles.cardBody}>
        <div style={{ ...styles.valueText, color: variant !== 'default' ? accentColor : 'var(--text-primary)' }}>
          {formattedValue}
        </div>
        {subtitle && <div style={styles.subtitleText}>{subtitle}</div>}
      </div>
    </div>
  );
};

const styles = {
  cardContainer: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    minHeight: '120px',
    gap: '0.75rem'
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  titleText: {
    fontSize: '0.75rem',
    fontWeight: '600',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em',
    textTransform: 'uppercase'
  },
  iconWrapper: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    borderRadius: '6px',
    border: '1px solid transparent'
  },
  cardBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  valueText: {
    fontSize: '1.85rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    lineHeight: '1.1'
  },
  subtitleText: {
    fontSize: '0.75rem',
    color: 'var(--text-secondary)'
  }
};

export default MetricCard;
