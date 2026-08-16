import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

/**
 * Security Event Severity Distribution Donut Chart
 * @param {Object} overviewData - metrics.overview object ({ critical_events, high_events, medium_events, low_events })
 */
const SeverityPieChart = ({ overviewData }) => {
  if (!overviewData) {
    return (
      <div className="panel" style={styles.chartPanel}>
        <h3 className="section-title">Threat Distribution</h3>
        <p className="muted" style={styles.emptyText}>Loading threat distribution...</p>
      </div>
    );
  }

  const chartData = [
    { name: 'Critical', value: overviewData.critical_events || 0, color: '#f43f5e' },
    { name: 'High', value: overviewData.high_events || 0, color: '#fb923c' },
    { name: 'Medium', value: overviewData.medium_events || 0, color: '#facc15' },
    { name: 'Low', value: overviewData.low_events || 0, color: '#38bdf8' }
  ];

  const totalValue = chartData.reduce((acc, curr) => acc + curr.value, 0);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      const pct = totalValue > 0 ? ((data.value / totalValue) * 100).toFixed(1) : '0.0';
      return (
        <div style={styles.tooltipContainer}>
          <div style={{ color: data.payload.color, fontWeight: '700' }}>
            {data.name} Severity
          </div>
          <div style={styles.tooltipValue}>
            {data.value.toLocaleString()} events ({pct}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="panel" style={styles.chartPanel}>
      <div>
        <h3 className="section-title">Threat Distribution</h3>
        <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
          Current severity breakdown
        </p>
      </div>

      {totalValue === 0 ? (
        <div style={styles.emptyText}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No severity data available.</p>
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
                  <Cell key={`cell-${index}`} fill={entry.color} />
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
    fontSize: '0.75rem',
    fontFamily: 'var(--font-mono)'
  },
  tooltipValue: {
    color: 'var(--text-primary)',
    marginTop: '0.25rem'
  }
};

export default SeverityPieChart;
