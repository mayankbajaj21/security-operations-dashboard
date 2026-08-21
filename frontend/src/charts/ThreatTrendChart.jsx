import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

/**
 * Security Event Time-Series Hourly Trend Line Chart
 * @param {Array} trendData - Array of trend objects [{ timestamp, total, critical, high, medium, low }]
 */
const ThreatTrendChart = ({ trendData }) => {
  if (!trendData || trendData.length === 0) {
    return (
      <div className="panel" style={styles.chartPanel}>
        <h3 className="section-title">Event Trend</h3>
        <p className="muted" style={styles.emptyText}>Loading event trend data...</p>
      </div>
    );
  }

  // Format ISO timestamps for clean X-axis readability (e.g., "08/01 04:00")
  const formattedData = (trendData || []).map((item) => {
    let formattedTime = item.timestamp || '';
    try {
      if (typeof item.timestamp === 'string' && item.timestamp.includes('T')) {
        const parts = item.timestamp.split('T');
        const dateParts = parts[0].split('-');
        const timeParts = parts[1].split(':');
        if (dateParts.length >= 3 && timeParts.length >= 1) {
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
                {entry.value.toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      );
    }
    return null;
  };

  return (
    <div className="panel" style={styles.chartPanel}>
      <div>
        <h3 className="section-title">Events Over Time</h3>
        <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>Hourly security event activity</p>
      </div>

      <div style={styles.chartWrapper}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={formattedData} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" vertical={false} />
            <XAxis 
              dataKey="displayTime" 
              stroke="var(--text-muted)" 
              fontSize={11} 
              tickLine={false}
              axisLine={{ stroke: 'var(--border-color)' }}
            />
            <YAxis 
              stroke="var(--text-muted)" 
              fontSize={11} 
              tickLine={false}
              axisLine={{ stroke: 'var(--border-color)' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Legend 
              verticalAlign="bottom" 
              height={36} 
              iconType="plainline"
              formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{value}</span>}
            />
            <Line 
              type="monotone" 
              dataKey="total" 
              name="Total Events" 
              stroke="var(--color-accent)" 
              strokeWidth={2} 
              dot={false} 
              activeDot={{ r: 5 }} 
            />
            <Line 
              type="monotone" 
              dataKey="critical" 
              name="Critical" 
              stroke="var(--color-critical)" 
              strokeWidth={2} 
              dot={false} 
              activeDot={{ r: 5 }} 
            />
            <Line 
              type="monotone" 
              dataKey="high" 
              name="High Severity" 
              stroke="#0077B6" 
              strokeWidth={2} 
              dot={false} 
              activeDot={{ r: 5 }} 
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};

const styles = {
  chartPanel: {
    display: 'flex',
    flexDirection: 'column',
    height: '320px',
    justifyContent: 'space-between',
    minWidth: 0,
    width: '100%'
  },
  chartWrapper: {
    width: '100%',
    height: '235px',
    minHeight: '235px',
    position: 'relative'
  },
  emptyText: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '200px',
    fontSize: '0.85rem'
  },
  tooltipContainer: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
    fontSize: '0.75rem'
  },
  tooltipLabel: {
    color: 'var(--text-secondary)',
    marginBottom: '0.35rem',
    fontFamily: 'var(--font-mono)'
  },
  tooltipItem: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '1rem',
    margin: '0.15rem 0'
  }
};

export default ThreatTrendChart;
