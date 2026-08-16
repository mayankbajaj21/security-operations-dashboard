import React, { useState, useEffect } from 'react';
import { getMitre } from '../services/api';
import MetricCard from '../components/MetricCard';
import Badge from '../components/Badge';
import { Activity, Target, ShieldAlert, Percent, Info } from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

const MitreCoveragePage = () => {
  const [mitreData, setMitreData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    getMitre()
      .then((data) => {
        if (isMounted) {
          setMitreData(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.error('Failed to fetch MITRE ATT&CK data:', err);
          setError('Unable to load MITRE ATT&CK coverage telemetry.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const summary = mitreData?.summary;
  const mappings = mitreData?.mappings || [];

  const chartData = summary ? [
    { name: 'Mapped Events', value: summary.mapped_events || 0, color: '#06b6d4' },
    { name: 'Unmapped Telemetry', value: summary.unmapped_events || 0, color: '#334155' }
  ] : [];

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0];
      return (
        <div style={styles.tooltipContainer}>
          <div style={{ color: item.payload.color, fontWeight: '700' }}>{item.name}</div>
          <div style={styles.tooltipValue}>{item.value.toLocaleString()} events</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={styles.container}>
      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading MITRE ATT&CK coverage telemetry...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && mitreData && (
        <div style={styles.contentSection}>
          {/* Summary KPI Cards */}
          <div style={styles.kpiGrid}>
            <MetricCard
              title="Total Security Events"
              value={summary?.total_events}
              subtitle="Total telemetry records"
              icon={Activity}
              variant="accent"
            />
            <MetricCard
              title="MITRE Mapped Events"
              value={summary?.mapped_events}
              subtitle="Events linked to MITRE technique"
              icon={Target}
              variant="high"
            />
            <MetricCard
              title="Unmapped Telemetry"
              value={summary?.unmapped_events}
              subtitle="Events without MITRE entry"
              icon={ShieldAlert}
              variant="default"
            />
            <MetricCard
              title="Mapping Coverage %"
              value={`${summary?.mapping_percentage !== undefined ? summary.mapping_percentage.toFixed(2) : '0.00'}%`}
              subtitle="ATT&CK framework coverage"
              icon={Percent}
              variant="warning"
            />
          </div>

          {/* Visual Coverage Donut Chart & Dataset Callout Row */}
          <div style={styles.coverageRow}>
            {/* Donut Chart Panel */}
            <div className="panel" style={styles.chartPanel}>
              <div>
                <h3 className="section-title">Framework Coverage Ratio</h3>
                <p className="muted" style={{ fontSize: '0.75rem' }}>
                  {summary?.mapping_percentage?.toFixed(2)}% mapped to ATT&CK techniques
                </p>
              </div>

              <div style={styles.chartWrapper}>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={75}
                      paddingAngle={3}
                      dataKey="value"
                      stroke="#0f172a"
                      strokeWidth={2}
                    >
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Explanatory Dataset Info Panel */}
            <div className="panel" style={styles.infoPanel}>
              <div style={styles.infoTitleGroup}>
                <Info size={18} color="var(--color-accent)" />
                <h3 className="section-title" style={{ margin: 0 }}>Reference Dataset Mapping Coverage</h3>
              </div>
              
              <p style={styles.infoText}>
                The reference security dataset currently provides explicit MITRE ATT&CK mapping for 
                <strong style={{ color: 'var(--color-accent)' }}> {summary?.mapped_events} Failed Login events</strong> mapped to technique 
                <span className="badge status-detected" style={{ margin: '0 0.35rem' }}>T1110 (Brute Force)</span> 
                under the <span className="badge status-blocked" style={{ margin: '0 0.35rem' }}>Credential Access</span> tactic.
              </p>

              <div style={styles.unmappedNotice}>
                <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                  Unmapped Telemetry Notice:
                </span>{' '}
                {summary?.unmapped_events?.toLocaleString()} remaining events (90.06%) cover other event types 
                (Unauthorized Access, Port Scans, Malware, etc.) which are unmapped in the current MITRE reference dataset. 
                In compliance with strict data integrity guidelines, unmapped events are reported accurately without synthetic mappings.
              </div>
            </div>
          </div>

          {/* Mapped Techniques Table */}
          <div style={{ marginTop: '0.5rem' }}>
            <h3 className="section-title" style={{ marginBottom: '0.75rem' }}>
              Mapped MITRE ATT&CK Techniques
            </h3>

            {mappings.length === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No MITRE ATT&CK mappings available in reference database.</p>
              </div>
            ) : (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Event Type</th>
                      <th>MITRE ID</th>
                      <th>Technique Name</th>
                      <th>Tactic</th>
                      <th>Mapped Event Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mappings.map((item, idx) => (
                      <tr key={item.mitre_id || idx} style={{ backgroundColor: 'rgba(6, 182, 212, 0.04)' }}>
                        <td style={{ fontWeight: '600' }}>{item.event_type}</td>
                        <td style={styles.monoCell}>
                          <span className="badge status-detected">{item.mitre_id}</span>
                        </td>
                        <td style={{ fontWeight: '600', color: 'var(--color-accent)' }}>{item.technique_name}</td>
                        <td>
                          <span className="badge status-blocked">{item.tactic}</span>
                        </td>
                        <td style={styles.monoCell}>
                          <strong style={{ color: 'var(--text-primary)' }}>{item.event_count?.toLocaleString()}</strong>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.5rem'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '1.25rem'
  },
  coverageRow: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: '1.25rem'
  },
  chartPanel: {
    display: 'flex',
    flexDirection: 'column',
    height: '240px',
    justifyContent: 'space-between'
  },
  chartWrapper: {
    width: '100%',
    height: '160px'
  },
  infoPanel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
    justifyContent: 'center'
  },
  infoTitleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  infoText: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    lineHeight: '1.6'
  },
  unmappedNotice: {
    padding: '0.75rem 1rem',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    fontSize: '0.8rem',
    color: 'var(--text-muted)',
    lineHeight: '1.5'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  statePanel: {
    minHeight: '200px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  },
  tooltipContainer: {
    backgroundColor: '#131c2e',
    border: '1px solid #334155',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
    fontSize: '0.75rem'
  },
  tooltipValue: {
    color: '#f8fafc',
    marginTop: '0.25rem',
    fontFamily: 'var(--font-mono)'
  }
};

export default MitreCoveragePage;
