import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  getEventTrend, 
  getThreatSummary, 
  getEvents 
} from '../services/api';
import AttackHeatmap from '../components/AttackHeatmap';
import { 
  Clock, 
  BarChart2, 
  RefreshCw 
} from 'lucide-react';
import { 
  LineChart, 
  Line, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend, 
  ResponsiveContainer, 
  Cell 
} from 'recharts';

/**
 * Custom Tooltip for Events Over Time Line Chart
 */
const EventsOverTimeTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div style={styles.tooltipContainer}>
        <div style={styles.tooltipLabel}>{label}</div>
        {payload.map((entry, index) => (
          <div key={`item-${index}`} style={{ ...styles.tooltipItem, color: entry.color }}>
            <span style={{ fontSize: '0.75rem', fontWeight: '500' }}>{entry.name}:</span>
            <strong style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)' }}>
              {entry.value.toLocaleString()}
            </strong>
          </div>
        ))}
      </div>
    );
  }
  return null;
};

/**
 * Custom Tooltip for Threat Type Horizontal Bar Chart
 */
const ThreatTypeHorizontalTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const item = payload[0];
    return (
      <div style={styles.tooltipContainer}>
        <div style={styles.tooltipLabel}>{item.payload.name}</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginTop: '0.2rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Detected Events:</span>
          <strong style={{ fontSize: '0.85rem', color: 'var(--color-accent)', fontFamily: 'var(--font-mono)' }}>
            {item.value.toLocaleString()}
          </strong>
        </div>
      </div>
    );
  }
  return null;
};

/**
 * Threat Intelligence Page — Threat Activity & Security Risk Analytics
 * Layout Hierarchy:
 * - Row 1 (50% / 50% side-by-side):
 *     1. Events Over Time (Compact Line Chart from GET /events/trend)
 *     2. Threat Type Distribution (Compact Horizontal Bar Chart from GET /threat-summary)
 * - Row 2 (100% full available width):
 *     3. Attack Activity Heatmap (7x24 Grid with 6 filters from GET /events)
 */
const ThreatIntelPage = ({ 
  allEvents: propAllEvents = null, 
  trendData: propTrendData = null 
}) => {
  const [trendData, setTrendData] = useState(propTrendData);
  const [threatSummary, setThreatSummary] = useState(null);
  const [allEvents, setAllEvents] = useState(propAllEvents);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchThreatAnalyticsData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const promises = [
        getThreatSummary({ forceRefresh: true }).catch(() => null)
      ];

      if (!propTrendData) {
        promises.push(getEventTrend({ forceRefresh: true }).catch(() => null));
      }

      const results = await Promise.all(promises);
      const summaryRes = results[0];
      const trendRes = results[1];

      if (summaryRes) setThreatSummary(summaryRes);
      if (trendRes?.trend) setTrendData(trendRes.trend);

      // If allEvents not passed as prop, fetch telemetry batch for heatmap
      if (!propAllEvents && !allEvents) {
        try {
          const firstPage = await getEvents({ page: 1, limit: 100 });
          const totalPages = firstPage?.pagination?.total_pages || 1;
          let records = [...(firstPage?.data || [])];

          if (totalPages > 1) {
            const batchSize = 4;
            for (let p = 2; p <= Math.min(totalPages, 5); p += batchSize) {
              const batchPromises = [];
              for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
                batchPromises.push(getEvents({ page: b, limit: 100 }));
              }
              const batchResults = await Promise.all(batchPromises);
              batchResults.forEach((res) => {
                if (res?.data) records = records.concat(res.data);
              });
            }
          }
          setAllEvents(records);
        } catch (e) {
          console.warn('Heatmap telemetry fetch skipped:', e);
        }
      }
    } catch (err) {
      console.error('Failed to fetch threat intelligence analytics:', err);
      setError('Unable to load threat intelligence analytics.');
    } finally {
      setLoading(false);
    }
  }, [propAllEvents, propTrendData, allEvents]);

  useEffect(() => {
    fetchThreatAnalyticsData();
  }, [fetchThreatAnalyticsData]);

  useEffect(() => {
    if (propTrendData) setTrendData(propTrendData);
  }, [propTrendData]);

  useEffect(() => {
    if (propAllEvents) setAllEvents(propAllEvents);
  }, [propAllEvents]);

  // Formatted data for Events Over Time Line Chart
  const formattedTrendData = useMemo(() => {
    if (!trendData || !Array.isArray(trendData)) return [];

    return trendData.map((item) => {
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
  }, [trendData]);

  // Dynamic Horizontal Bar Chart Data derived strictly from real API data
  const threatTypeChartData = useMemo(() => {
    const counts = {};

    const getColorForThreatType = (name) => {
      const lower = name.toLowerCase();
      if (lower.includes('brute force') || lower.includes('failed login')) return '#f43f5e';
      if (lower.includes('malware') || lower.includes('ransomware')) return '#ea580c';
      if (lower.includes('phishing')) return '#eab308';
      if (lower.includes('sql injection') || lower.includes('sqli')) return '#0284c7';
      if (lower.includes('privilege escalation') || lower.includes('privilege')) return '#a855f7';
      if (lower.includes('port scan') || lower.includes('scan')) return '#06b6d4';
      if (lower.includes('usb') || lower.includes('removable')) return '#ec4899';
      if (lower.includes('unauthorized') || lower.includes('file access')) return '#6366f1';
      if (lower.includes('normal')) return '#22c55e';
      return '#38bdf8';
    };

    // 1. Primary Source: Real threat_types dictionary from GET /threat-summary API
    if (threatSummary?.threat_types && typeof threatSummary.threat_types === 'object') {
      Object.entries(threatSummary.threat_types).forEach(([typeName, count]) => {
        const cleanName = typeName.trim();
        if (cleanName) {
          counts[cleanName] = (counts[cleanName] || 0) + Number(count || 0);
        }
      });
    }

    // 2. Fallback: Aggregate from actual loaded event telemetry if summary empty
    if (Object.keys(counts).length === 0 && Array.isArray(allEvents) && allEvents.length > 0) {
      allEvents.forEach((evt) => {
        const type = (evt.event_type || evt.threat_type || 'Unclassified Event').trim();
        counts[type] = (counts[type] || 0) + 1;
      });
    }

    // Default canonical fallback if no records loaded yet
    if (Object.keys(counts).length === 0) {
      counts['Brute Force'] = 0;
      counts['SQL Injection'] = 0;
      counts['Privilege Escalation'] = 0;
      counts['Port Scan'] = 0;
      counts['Malware'] = 0;
      counts['Phishing'] = 0;
    }

    // Sort descending by count
    return Object.entries(counts)
      .map(([name, count]) => ({
        name,
        count: Number(count) || 0,
        color: getColorForThreatType(name)
      }))
      .sort((a, b) => b.count - a.count);
  }, [threatSummary, allEvents]);

  const totalThreatTypesCount = threatTypeChartData.reduce((sum, item) => sum + item.count, 0);

  return (
    <div style={styles.container}>
      {/* TOP ACTION BAR: REFRESH ONLY (NO DUPLICATE HEADING) */}
      <div style={styles.topActionBar}>
        <button 
          className="soc-button" 
          onClick={fetchThreatAnalyticsData}
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.4rem', marginLeft: 'auto' }}
          title="Refresh Threat Intelligence Analytics"
        >
          <RefreshCw size={13} />
          <span>Refresh</span>
        </button>
      </div>

      {loading && !threatSummary && !trendData && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading threat activity & security analytics...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {/* ──────────────────────────────────────────────────
          ROW 1: EVENTS OVER TIME (50%) + THREAT TYPE DISTRIBUTION (50%)
         ────────────────────────────────────────────────── */}
      <div className="soc-threat-intel-grid" style={styles.rowOneGrid}>
        {/* LEFT COLUMN: EVENTS OVER TIME */}
        <div className="panel" style={styles.chartPanel}>
          <div style={styles.chartPanelHeader}>
            <div>
              <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Clock size={16} color="var(--color-accent)" />
                <span>Events Over Time</span>
              </h3>
              <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
                Hourly security event activity
              </p>
            </div>
            <span className="badge status-detected" style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
              Hourly Trend
            </span>
          </div>

          <div style={styles.lineChartWrapper}>
            {formattedTrendData.length === 0 ? (
              <div style={styles.emptyChartPlaceholder}>
                <p className="muted">No event trend data available.</p>
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart 
                  data={formattedTrendData} 
                  margin={{ top: 10, right: 15, left: -20, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" vertical={false} opacity={0.5} />
                  <XAxis 
                    dataKey="displayTime" 
                    stroke="var(--text-muted)" 
                    fontSize={10} 
                    tickLine={false}
                    axisLine={{ stroke: 'var(--border-color)' }}
                  />
                  <YAxis 
                    stroke="var(--text-muted)" 
                    fontSize={10} 
                    tickLine={false}
                    axisLine={{ stroke: 'var(--border-color)' }}
                  />
                  <Tooltip content={<EventsOverTimeTooltip />} />
                  <Legend 
                    verticalAlign="bottom" 
                    height={30} 
                    iconType="plainline"
                    formatter={(value) => (
                      <span style={{ color: 'var(--text-secondary)', fontSize: '0.72rem', fontWeight: '500' }}>
                        {value}
                      </span>
                    )}
                  />
                  <Line 
                    type="monotone" 
                    dataKey="total" 
                    name="Total Events" 
                    stroke="var(--color-accent)" 
                    strokeWidth={2} 
                    dot={false} 
                    activeDot={{ r: 4 }} 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="critical" 
                    name="Critical" 
                    stroke="var(--color-critical)" 
                    strokeWidth={2} 
                    dot={false} 
                    activeDot={{ r: 4 }} 
                  />
                  <Line 
                    type="monotone" 
                    dataKey="high" 
                    name="High Severity" 
                    stroke="#0077B6" 
                    strokeWidth={2} 
                    dot={false} 
                    activeDot={{ r: 4 }} 
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: THREAT TYPE DISTRIBUTION */}
        <div className="panel" style={styles.chartPanel}>
          <div style={styles.chartPanelHeader}>
            <div>
              <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <BarChart2 size={16} color="var(--color-accent)" />
                <span>Threat Type Distribution</span>
              </h3>
              <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
                Security threat classification breakdown
              </p>
            </div>
            <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
              {totalThreatTypesCount.toLocaleString()} Events
            </span>
          </div>

          <div style={styles.barChartWrapper}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart 
                layout="vertical"
                data={threatTypeChartData} 
                margin={{ top: 5, right: 25, left: 5, bottom: 5 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" horizontal={false} opacity={0.5} />
                <XAxis 
                  type="number" 
                  tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                  axisLine={{ stroke: 'var(--border-color)' }}
                />
                <YAxis 
                  type="category" 
                  dataKey="name" 
                  width={130}
                  tick={{ fontSize: 11, fill: 'var(--text-primary)', fontWeight: 600 }}
                  axisLine={{ stroke: 'var(--border-color)' }}
                />
                <Tooltip content={<ThreatTypeHorizontalTooltip />} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {threatTypeChartData.map((entry, idx) => (
                    <Cell key={`bar-${idx}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Compact Legend Summary */}
          <div style={styles.threatTypeLegendCompact}>
            {threatTypeChartData.slice(0, 5).map((item, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.72rem' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: item.color, flexShrink: 0 }} />
                <span style={{ color: 'var(--text-muted)' }}>{item.name}:</span>
                <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{item.count}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ──────────────────────────────────────────────────
          ROW 2: ATTACK ACTIVITY HEATMAP (100% FULL WIDTH)
         ────────────────────────────────────────────────── */}
      <div style={{ width: '100%' }}>
        <AttackHeatmap allEvents={allEvents} />
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem',
    width: '100%'
  },
  topActionBar: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'center',
    width: '100%',
    marginBottom: '-0.25rem'
  },
  rowOneGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '1.25rem',
    width: '100%'
  },
  chartPanel: {
    padding: '1.15rem 1.25rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    height: '350px',
    boxSizing: 'border-box',
    width: '100%',
    minWidth: 0
  },
  chartPanelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem',
    paddingBottom: '0.4rem',
    borderBottom: '1px solid var(--border-subtle)'
  },
  lineChartWrapper: {
    width: '100%',
    height: '245px',
    minHeight: '245px',
    position: 'relative',
    marginTop: '0.4rem'
  },
  barChartWrapper: {
    width: '100%',
    height: '215px',
    minHeight: '215px',
    position: 'relative',
    marginTop: '0.4rem'
  },
  threatTypeLegendCompact: {
    display: 'flex',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem',
    paddingTop: '0.4rem',
    borderTop: '1px solid var(--border-subtle)'
  },
  emptyChartPlaceholder: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    height: '100%',
    width: '100%'
  },
  statePanel: {
    minHeight: '160px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center',
    width: '100%'
  },
  tooltipContainer: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 14px rgba(0,0,0,0.25)',
    fontSize: '0.75rem'
  },
  tooltipLabel: {
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '0.25rem',
    fontSize: '0.78rem'
  },
  tooltipItem: {
    display: 'flex',
    justifyContent: 'space-between',
    gap: '1rem',
    margin: '0.15rem 0'
  }
};

export default ThreatIntelPage;
