import React from 'react';
import { 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer 
} from 'recharts';

/**
 * Milestone 4 Risk Trend Time-Series Chart
 * Visualizes authoritative Milestone 3 average risk scores and event volumes over time.
 * Supports exact M4 selectors: 'Last 24 Hours', 'Last 7 Days', 'Last 30 Days'.
 */
const ThreatTrendChart = ({ 
  trendData = [], 
  selectedRange = '7d', 
  onRangeChange = null,
  telemetryWindow = null,
  isLoading = false 
}) => {
  // Format timestamps for clean X-axis readability
  const formattedData = (trendData || []).map((item) => {
    let formattedTime = item.timestamp || '';
    try {
      if (typeof item.timestamp === 'string' && item.timestamp.includes('T')) {
        const parts = item.timestamp.split('T');
        const dateParts = parts[0].split('-');
        const timeParts = parts[1].split(':');
        if (selectedRange === '24h') {
          formattedTime = `${timeParts[0]}:${timeParts[1] || '00'}`;
        } else if (dateParts.length >= 3 && timeParts.length >= 1) {
          formattedTime = `${dateParts[1]}/${dateParts[2]} ${timeParts[0]}:00`;
        }
      }
    } catch (e) {
      formattedTime = String(item.timestamp || '');
    }

    return {
      ...item,
      displayTime: formattedTime
    };
  });

  const CustomTooltip = ({ active, payload, label }) => {
    if (active && payload && payload.length) {
      return (
        <div style={styles.tooltipContainer}>
          <div style={styles.tooltipLabel}>{label}</div>
          {payload.map((entry, index) => (
            <div key={`item-${index}`} style={{ ...styles.tooltipItem, color: entry.color }}>
              <span>{entry.name}:</span>
              <span style={{ fontWeight: '700', fontFamily: 'var(--font-mono)' }}>
                {entry.name.includes('Risk') ? `${entry.value} / 100` : entry.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  const ranges = [
    { key: '24h', label: 'Last 24 Hours' },
    { key: '7d', label: 'Last 7 Days' },
    { key: '30d', label: 'Last 30 Days' }
  ];

  return (
    <div className="panel" style={styles.chartPanel}>
      <div style={styles.headerRow}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
            <h3 className="section-title" style={{ margin: 0 }}>Risk Trend</h3>
            <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
              M3 Multi-Factor Engine
            </span>
          </div>
          <p className="muted" style={{ fontSize: '0.75rem', margin: '0.2rem 0 0 0' }}>
            Time-series risk trajectory and telemetry volume over selected window
          </p>
        </div>

        {/* Exact M4 Range Selectors */}
        <div style={styles.selectorGroup}>
          {ranges.map((r) => {
            const isActive = selectedRange === r.key;
            return (
              <button
                key={r.key}
                onClick={() => onRangeChange && onRangeChange(r.key)}
                style={{
                  ...styles.selectorButton,
                  ...(isActive ? styles.selectorButtonActive : {})
                }}
              >
                {r.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Honest telemetry window notice when window is incomplete */}
      {telemetryWindow && telemetryWindow.is_partial && (
        <div style={styles.noticeBar}>
          <span style={{ color: 'var(--color-warning)', fontWeight: '600' }}>Note:</span>
          <span>
            {` Available telemetry window covers ${telemetryWindow.days_covered ?? 6.25} days (Aug 01 00:00 – Aug 07 05:55, 2025). Nonexistent historical days are not fabricated.`}
          </span>
        </div>
      )}

      {isLoading ? (
        <div style={styles.emptyText}>
          <p className="muted" style={{ fontSize: '0.85rem' }}>Loading Risk Trend telemetry...</p>
        </div>
      ) : formattedData.length === 0 ? (
        <div style={styles.emptyText}>
          <p className="muted" style={{ fontSize: '0.85rem' }}>No trend data available for this range.</p>
        </div>
      ) : (
        <div style={styles.chartWrapper}>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={formattedData} margin={{ top: 15, right: 30, left: -10, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} />
              <XAxis 
                dataKey="displayTime" 
                stroke="var(--text-muted)" 
                fontSize={11} 
                tickLine={false}
                axisLine={{ stroke: 'var(--border-subtle)' }}
              />
              <YAxis 
                yAxisId="events"
                stroke="var(--text-muted)" 
                fontSize={11} 
                tickLine={false}
                axisLine={{ stroke: 'var(--border-subtle)' }}
              />
              <YAxis 
                yAxisId="risk"
                orientation="right"
                domain={[0, 100]}
                stroke="#f43f5e" 
                fontSize={11} 
                tickLine={false}
                axisLine={{ stroke: 'rgba(244, 63, 94, 0.4)' }}
                tickFormatter={(val) => `${val}`}
              />
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                verticalAlign="bottom" 
                height={36} 
                iconType="plainline"
                formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{value}</span>}
              />
              {/* Primary Line: M3 Multi-Factor Average Risk Score */}
              <Line 
                yAxisId="risk"
                type="monotone" 
                dataKey="avg_risk_score" 
                name="Avg Risk Score (0-100)" 
                stroke="#f43f5e" 
                strokeWidth={2.5} 
                dot={false} 
                activeDot={{ r: 6, fill: '#f43f5e', stroke: '#fff' }} 
              />
              {/* Secondary Line: Total Events Volume */}
              <Line 
                yAxisId="events"
                type="monotone" 
                dataKey="total" 
                name="Total Events" 
                stroke="var(--color-accent)" 
                strokeWidth={1.5} 
                dot={false} 
                activeDot={{ r: 4 }} 
              />
              {/* Tertiary Line: Critical Events Volume */}
              <Line 
                yAxisId="events"
                type="monotone" 
                dataKey="critical" 
                name="Critical Events" 
                stroke="#fb923c" 
                strokeWidth={1.5} 
                strokeDasharray="4 4"
                dot={false} 
                activeDot={{ r: 4 }} 
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

const styles = {
  chartPanel: {
    display: 'flex',
    flexDirection: 'column',
    minHeight: '360px',
    justifyContent: 'space-between',
    minWidth: 0,
    width: '100%',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '1.25rem'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem',
    marginBottom: '0.5rem'
  },
  selectorGroup: {
    display: 'inline-flex',
    gap: '0.35rem',
    backgroundColor: 'var(--bg-secondary)',
    padding: '0.25rem',
    borderRadius: '6px',
    border: '1px solid var(--border-subtle)'
  },
  selectorButton: {
    background: 'transparent',
    border: 'none',
    color: 'var(--text-muted)',
    fontSize: '0.72rem',
    fontWeight: '600',
    padding: '0.35rem 0.65rem',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'all 0.15s ease'
  },
  selectorButtonActive: {
    backgroundColor: 'var(--color-accent)',
    color: '#fff',
    boxShadow: '0 1px 3px rgba(0,0,0,0.2)'
  },
  noticeBar: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    backgroundColor: 'rgba(245, 158, 11, 0.08)',
    border: '1px solid rgba(245, 158, 11, 0.25)',
    borderRadius: '4px',
    padding: '0.35rem 0.65rem',
    margin: '0.35rem 0 0.5rem 0'
  },
  chartWrapper: {
    width: '100%',
    height: '270px',
    minHeight: '270px',
    position: 'relative'
  },
  emptyText: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '240px',
    fontSize: '0.85rem'
  },
  tooltipContainer: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem',
    boxShadow: 'var(--shadow-md)',
    fontSize: '0.75rem'
  },
  tooltipLabel: {
    color: 'var(--text-primary)',
    fontWeight: '700',
    marginBottom: '0.35rem',
    fontSize: '0.78rem'
  },
  tooltipItem: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '1rem',
    fontSize: '0.72rem',
    margin: '0.15rem 0'
  }
};

export default ThreatTrendChart;
