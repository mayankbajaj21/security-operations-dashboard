import React, { useState, useEffect } from 'react';
import { getThreatIntel } from '../services/api';
import MetricCard from '../components/MetricCard';
import Badge from '../components/Badge';
import { Radar, ShieldAlert, ShieldCheck, Percent } from 'lucide-react';

const ThreatIntelPage = () => {
  const [intelData, setIntelData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    getThreatIntel()
      .then((data) => {
        if (isMounted) {
          setIntelData(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.error('Failed to fetch threat intelligence data:', err);
          setError('Unable to load threat intelligence telemetry.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const summary = intelData?.summary;
  const indicators = intelData?.indicators || [];

  return (
    <div style={styles.container}>
      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading threat intelligence feed...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && intelData && (
        <div style={styles.contentSection}>
          {/* Summary KPI Cards */}
          <div style={styles.kpiGrid}>
            <MetricCard
              title="Total Indicators"
              value={summary?.total_indicators}
              subtitle="Registered IoC entries"
              icon={Radar}
              variant="accent"
            />
            <MetricCard
              title="Matched Indicators"
              value={summary?.matched_indicators}
              subtitle="IoCs with event matches"
              icon={ShieldAlert}
              variant="critical"
            />
            <MetricCard
              title="Unmatched Indicators"
              value={summary?.unmatched_indicators}
              subtitle="IoCs with zero matches"
              icon={ShieldCheck}
              variant="default"
            />
            <MetricCard
              title="Match Percentage"
              value={`${summary?.match_percentage !== undefined ? summary.match_percentage.toFixed(1) : '0.0'}%`}
              subtitle="Telemetry hit rate"
              icon={Percent}
              variant="warning"
            />
          </div>

          {/* Indicators Table */}
          <div style={{ marginTop: '0.5rem' }}>
            <h3 className="section-title" style={{ marginBottom: '0.75rem' }}>
              Threat Intelligence Indicators (IoCs)
            </h3>

            {indicators.length === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No threat intelligence indicators available in database.</p>
              </div>
            ) : (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Indicator ID</th>
                      <th>Type</th>
                      <th>Indicator Value</th>
                      <th>Threat Name</th>
                      <th>Threat Actor</th>
                      <th>Confidence</th>
                      <th>Severity</th>
                      <th>Event Matches</th>
                    </tr>
                  </thead>
                  <tbody>
                    {indicators.map((ioc) => (
                      <tr key={ioc.indicator_id || Math.random()}>
                        <td style={styles.monoCell}>{ioc.indicator_id}</td>
                        <td>{ioc.indicator_type}</td>
                        <td style={styles.monoCell}>{ioc.indicator_value}</td>
                        <td style={{ fontWeight: '600' }}>{ioc.threat_name}</td>
                        <td style={{ color: 'var(--text-secondary)' }}>{ioc.threat_actor || 'Unknown'}</td>
                        <td>
                          <Badge type="severity" value={ioc.confidence} />
                        </td>
                        <td>
                          <Badge type="severity" value={ioc.severity} />
                        </td>
                        <td>
                          {ioc.event_match_count > 0 ? (
                            <span className="badge severity-critical">
                              {ioc.event_match_count} {ioc.event_match_count === 1 ? 'Match' : 'Matches'}
                            </span>
                          ) : (
                            <span className="badge status-blocked" style={{ opacity: 0.8 }}>
                              0 Matches
                            </span>
                          )}
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
  }
};

export default ThreatIntelPage;
