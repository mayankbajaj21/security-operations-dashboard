import React, { useState, useEffect, useMemo } from 'react';
import { getEvents } from '../services/api';
import MetricCard from '../components/MetricCard';
import Badge from '../components/Badge';
import { ShieldAlert, Clock, CheckCircle2, AlertOctagon, Info } from 'lucide-react';

const IncidentResponsePage = ({ allEvents = null }) => {
  // Derive incident records and total count using useMemo when allEvents is passed
  const derivedData = useMemo(() => {
    if (!Array.isArray(allEvents)) return null;
    const incidentRecords = allEvents.filter(
      (evt) => evt.incident_id && String(evt.incident_id).trim() !== '' && evt.incident_id !== 'null'
    );
    return {
      incidents: incidentRecords,
      totalScannedEvents: allEvents.length
    };
  }, [allEvents]);

  // Fallback standalone state if allEvents prop is not provided (standalone usage)
  const [standaloneIncidents, setStandaloneIncidents] = useState([]);
  const [standaloneScannedEvents, setStandaloneScannedEvents] = useState(0);
  const [standaloneLoading, setStandaloneLoading] = useState(false);
  const [standaloneError, setStandaloneError] = useState(null);

  useEffect(() => {
    // Only execute standalone API fetching if allEvents prop was NOT supplied at all
    if (allEvents !== undefined) return;

    let isMounted = true;
    setStandaloneLoading(true);
    setStandaloneError(null);

    const fetchAllEvents = async () => {
      try {
        const firstPage = await getEvents({ page: 1, limit: 100 });
        const totalPages = firstPage?.pagination?.total_pages || 1;
        const totalEvents = firstPage?.pagination?.total || 0;

        let allRecords = [...(firstPage?.data || [])];

        if (totalPages > 1) {
          const batchSize = 4;
          for (let p = 2; p <= totalPages; p += batchSize) {
            const batchPromises = [];
            for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
              batchPromises.push(getEvents({ page: b, limit: 100 }));
            }
            const batchResults = await Promise.all(batchPromises);
            batchResults.forEach((res) => {
              if (res?.data) {
                allRecords = allRecords.concat(res.data);
              }
            });
          }
        }

        if (isMounted) {
          const incidentRecords = allRecords.filter(
            (evt) => evt.incident_id && String(evt.incident_id).trim() !== '' && evt.incident_id !== 'null'
          );

          setStandaloneScannedEvents(totalEvents || allRecords.length);
          setStandaloneIncidents(incidentRecords);
          setStandaloneLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to fetch incident response data:', err);
          setStandaloneError('Unable to load incident response telemetry.');
          setStandaloneLoading(false);
        }
      }
    };

    fetchAllEvents();

    return () => {
      isMounted = false;
    };
  }, [allEvents]);

  const incidents = allEvents !== undefined ? (derivedData?.incidents || []) : standaloneIncidents;
  const totalScannedEvents = allEvents !== undefined ? (derivedData?.totalScannedEvents || 0) : standaloneScannedEvents;
  const loading = allEvents !== undefined ? (derivedData === null) : standaloneLoading;
  const error = allEvents !== undefined ? null : standaloneError;

  // Compute metrics from actual incident records
  const totalIncidents = incidents.length;
  
  const openIncidents = incidents.filter(
    (inc) => inc.incident_status && String(inc.incident_status).toLowerCase() === 'open'
  ).length;

  const closedIncidents = incidents.filter(
    (inc) => inc.incident_status && (
      String(inc.incident_status).toLowerCase() === 'closed' || 
      String(inc.incident_status).toLowerCase() === 'resolved'
    )
  ).length;

  // Calculate average response time in minutes
  const responseTimes = incidents
    .map((inc) => Number(inc.response_time_minutes || inc.response_time))
    .filter((num) => !isNaN(num) && num > 0);

  const avgResponseTime = responseTimes.length > 0
    ? (responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length).toFixed(1)
    : 0;

  return (
    <div style={styles.container}>
      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Scanning telemetry for incident response records...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && (
        <div style={styles.contentSection}>
          {/* Summary KPI Cards */}
          <div style={styles.kpiGrid}>
            <MetricCard
              title="Incident-Linked Events"
              value={totalIncidents}
              subtitle={`Out of ${totalScannedEvents.toLocaleString()} total events`}
              icon={AlertOctagon}
              variant="accent"
            />
            <MetricCard
              title="Open Incidents"
              value={openIncidents}
              subtitle="Active investigation required"
              icon={ShieldAlert}
              variant={openIncidents > 0 ? 'critical' : 'default'}
            />
            <MetricCard
              title="Closed / Resolved"
              value={closedIncidents}
              subtitle="Successfully remediated"
              icon={CheckCircle2}
              variant="default"
            />
            <MetricCard
              title="Avg Response Time"
              value={avgResponseTime > 0 ? `${avgResponseTime} min` : 'N/A'}
              subtitle="Mean time to respond"
              icon={Clock}
              variant="warning"
            />
          </div>

          {/* Dataset Coverage Callout Banner */}
          <div className="panel" style={styles.infoBanner}>
            <div style={styles.infoIconWrapper}>
              <Info size={18} color="var(--color-accent)" />
            </div>
            <div>
              <h4 style={styles.infoTitle}>Incident Telemetry Overview</h4>
              <p style={styles.infoDescription}>
                Displaying all {totalIncidents} historical incidents currently identified across the{' '}
                {totalScannedEvents.toLocaleString()} security events in the MongoDB telemetry collection.
              </p>
            </div>
          </div>

          {/* Incident Response Table */}
          <div style={{ marginTop: '0.5rem' }}>
            <h3 className="section-title" style={{ marginBottom: '0.75rem' }}>
              Incident Response Logs
            </h3>

            {totalIncidents === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No incident-linked events identified in current telemetry dataset.</p>
              </div>
            ) : (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Incident Type</th>
                      <th>Event ID</th>
                      <th>Assigned To</th>
                      <th>Status</th>
                      <th>Response Time</th>
                      <th>Resolution</th>
                      <th>Event Severity</th>
                      <th>Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidents.map((inc) => (
                      <tr 
                        key={inc.incident_id || inc.event_id || Math.random()}
                        style={{
                          backgroundColor: inc.event_severity === 'Critical' 
                            ? 'rgba(244, 63, 94, 0.05)' 
                            : undefined
                        }}
                      >
                        <td style={styles.monoCell}>
                          <span className="badge status-detected">{inc.incident_id}</span>
                        </td>
                        <td style={{ fontWeight: '600' }}>{inc.incident_type || inc.event_type}</td>
                        <td style={styles.monoCell}>{inc.event_id}</td>
                        <td>{inc.assigned_to || 'Unassigned'}</td>
                        <td>
                          <Badge type="status" value={inc.incident_status || 'Open'} />
                        </td>
                        <td style={styles.monoCell}>
                          {inc.response_time 
                            ? inc.response_time 
                            : inc.response_time_minutes 
                            ? `${inc.response_time_minutes} mins` 
                            : 'N/A'}
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>{inc.resolution || 'Under Investigation'}</td>
                        <td>
                          <Badge type="severity" value={inc.event_severity} />
                        </td>
                        <td style={styles.monoCell}>
                          {inc.timestamp ? String(inc.timestamp).replace('T', ' ') : 'N/A'}
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
  infoBanner: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.85rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-subtle)'
  },
  infoIconWrapper: {
    marginTop: '0.15rem'
  },
  infoTitle: {
    fontSize: '0.85rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    marginBottom: '0.25rem'
  },
  infoDescription: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
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
  }
};

export default IncidentResponsePage;
