import React, { useMemo } from 'react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer,
  Cell 
} from 'recharts';

/**
 * Custom Tooltip for Threat Type Distribution Chart
 */
const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const item = payload[0];
    return (
      <div style={styles.tooltipContainer}>
        <div style={styles.tooltipTitle}>{item.payload.threat_type}</div>
        <div style={styles.tooltipValue}>
          Frequency: <strong style={{ color: 'var(--color-accent)' }}>{item.value.toLocaleString()}</strong> events
        </div>
      </div>
    );
  }
  return null;
};

const TopAttackTypesChart = ({ threatTypes = null, allEvents = null }) => {
  // Consume authoritative M2 threat_types aggregation directly from backend
  const chartData = useMemo(() => {
    if (threatTypes && typeof threatTypes === 'object') {
      return Object.entries(threatTypes)
        .map(([type, count]) => ({
          threat_type: type,
          count: Number(count) || 0
        }))
        .filter((item) => item.threat_type && item.threat_type !== 'Normal Activity')
        .sort((a, b) => b.count - a.count)
        .slice(0, 6);
    }
    return [];
  }, [threatTypes]);

  const isLoading = threatTypes === null && allEvents === null;

  return (
    <div className="panel" style={styles.panel}>
      <div style={styles.header}>
        <div>
          <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
            Threat Type
          </h3>
          <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
            Distribution across threat categories
          </p>
        </div>
        <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
          Authoritative M2 ML
        </span>
      </div>

      {isLoading ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>Loading threat type analytics...</p>
        </div>
      ) : chartData.length === 0 ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No threat type data available.</p>
        </div>
      ) : (
        <div style={styles.chartWrapper}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              layout="vertical"
              data={chartData}
              margin={{ top: 10, right: 35, left: 40, bottom: 5 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} />
              <XAxis
                type="number"
                stroke="var(--text-muted)"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: 'var(--border-subtle)' }}
              />
              <YAxis
                type="category"
                dataKey="threat_type"
                stroke="var(--text-primary)"
                fontSize={11}
                tickLine={false}
                axisLine={{ stroke: 'var(--border-subtle)' }}
                width={150}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.03)' }} />
              <Bar dataKey="count" fill="var(--color-accent)" radius={[0, 4, 4, 0]} barSize={18}>
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`bar-cell-${index}`} 
                    fill={index === 0 ? 'var(--color-critical)' : index === 1 ? 'var(--color-high)' : index === 2 ? '#38bdf8' : 'rgba(6, 182, 212, 0.75)'} 
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  );
};

const styles = {
  panel: {
    padding: '1.15rem 1.25rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
    minWidth: 0,
    width: '100%'
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  chartWrapper: {
    width: '100%',
    height: '280px',
    minHeight: '280px',
    marginTop: '0.25rem',
    position: 'relative'
  },
  stateContainer: {
    height: '220px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center'
  },
  tooltipContainer: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 12px rgba(0,0,0,0.3)',
    fontSize: '0.75rem'
  },
  tooltipTitle: {
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '0.2rem'
  },
  tooltipValue: {
    color: 'var(--text-secondary)',
    fontFamily: 'var(--font-mono)'
  }
};

export default TopAttackTypesChart;
