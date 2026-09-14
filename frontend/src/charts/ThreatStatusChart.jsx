import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

/**
 * M3 Incident Lifecycle Threat Status Distribution Donut Chart
 * @param {Object} statusData - Object with counts: { Open, Investigating, Resolved, 'False Positive' }
 */
const ThreatStatusChart = ({ statusData }) => {
  if (!statusData) {
    return (
      <div className="panel" style={styles.chartPanel}>
        <h3 className="section-title">Threat Status</h3>
        <p className="muted" style={styles.emptyText}>Loading threat status distribution...</p>
      </div>
    );
  }

  const chartData = [
    { name: 'Open', value: statusData.Open || 0, color: '#f59e0b' },
    { name: 'Investigating', value: statusData.Investigating || 0, color: '#3b82f6' },
    { name: 'Resolved', value: statusData.Resolved || 0, color: '#10b981' },
    { name: 'False Positive', value: statusData['False Positive'] || 0, color: '#64748b' }
  ];

  const totalValue = chartData.reduce((acc, curr) => acc + curr.value, 0);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      const pct = totalValue > 0 ? ((data.value / totalValue) * 100).toFixed(1) : '0.0';
      return (
        <div style={styles.tooltipContainer}>
          <div style={{ color: data.payload.color, fontWeight: '700' }}>
            {data.name}
          </div>
          <div style={styles.tooltipValue}>
            {data.value.toLocaleString()} incidents ({pct}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="panel" style={styles.chartPanel}>
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h3 className="section-title">Threat Status</h3>
          <span className="badge status-open" style={{ fontSize: '0.68rem' }}>
            M3 Lifecycle
          </span>
        </div>
        <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
          Incident lifecycle resolution status
        </p>
      </div>

      {totalValue === 0 ? (
        <div style={styles.emptyText}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No incident status data available.</p>
        </div>
      ) : (
        <div style={styles.chartWrapper}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={chartData}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={3}
                dataKey="value"
                stroke="var(--bg-secondary)"
                strokeWidth={2}
              >
                {chartData.map((entry, index) => (
                  <Cell key={`status-cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend 
                verticalAlign="bottom" 
                height={36} 
                iconType="circle"
                formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{value}</span>}
              />
            </PieChart>
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
    height: '320px',
    justifyContent: 'space-between',
    minWidth: 0,
    width: '100%'
  },
  chartWrapper: {
    width: '100%',
    height: '240px',
    minHeight: '240px',
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
    fontSize: '0.75rem',
    boxShadow: 'var(--shadow-md)'
  },
  tooltipValue: {
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
    marginTop: '0.2rem'
  }
};

export default ThreatStatusChart;
