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
 * Custom Tooltip for Top Attack Types Chart
 */
const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const item = payload[0];
    return (
      <div style={styles.tooltipContainer}>
        <div style={styles.tooltipTitle}>{item.payload.event_type}</div>
        <div style={styles.tooltipValue}>
          Frequency: <strong style={{ color: 'var(--color-accent)' }}>{item.value.toLocaleString()}</strong> events
        </div>
      </div>
    );
  }
  return null;
};

const TopAttackTypesChart = ({ allEvents = null }) => {
  // Compute attack type frequencies directly from pre-fetched dataset
  const chartData = useMemo(() => {
    if (!allEvents || !Array.isArray(allEvents)) return [];

    const counts = {};

    allEvents.forEach((evt) => {
      const type = evt.event_type || 'Unknown Event';
      counts[type] = (counts[type] || 0) + 1;
    });

    const sorted = Object.keys(counts)
      .map((type) => ({
        event_type: type,
        count: counts[type]
      }))
      .sort((a, b) => b.count - a.count);

    // Select top 5
    return sorted.slice(0, 5);
  }, [allEvents]);

  const isLoading = allEvents === null;

  return (
    <div className="panel" style={styles.panel}>
      <div style={styles.header}>
        <div>
          <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
            Top Attack Types
          </h3>
          <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
            Most frequent security event types
          </p>
        </div>
        <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
          Live Frequency
        </span>
      </div>

      {isLoading ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>Loading attack type analytics...</p>
        </div>
      ) : chartData.length === 0 ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No attack type data available.</p>
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
                dataKey="event_type"
                stroke="var(--text-primary)"
                fontSize={12}
                tickLine={false}
                axisLine={{ stroke: 'var(--border-subtle)' }}
                width={140}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255, 255, 255, 0.03)' }} />
              <Bar dataKey="count" fill="var(--color-accent)" radius={[0, 4, 4, 0]} barSize={20}>
                {chartData.map((entry, index) => (
                  <Cell 
                    key={`bar-cell-${index}`} 
                    fill={index === 0 ? 'var(--color-accent)' : index === 1 ? '#38bdf8' : 'rgba(6, 182, 212, 0.75)'} 
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
