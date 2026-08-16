import React, { useMemo } from 'react';
import Badge from './Badge';
import { ArrowRight } from 'lucide-react';

const IncidentTable = ({ allEvents = null, onNavigateToIncidents }) => {
  // Deduplicate and select top 5 prioritized incident records
  const topIncidents = useMemo(() => {
    if (!allEvents || !Array.isArray(allEvents)) return [];

    // 1. Filter events linked to valid incident IDs
    const incidentEvents = allEvents.filter(
      (evt) => evt.incident_id && String(evt.incident_id).trim() !== '' && String(evt.incident_id) !== 'null'
    );

    // 2. Deduplicate by incident_id, preserving the most recent event record for each incident
    const incidentMap = new Map();
    incidentEvents.forEach((evt) => {
      const id = String(evt.incident_id).trim();
      const existing = incidentMap.get(id);

      if (!existing) {
        incidentMap.set(id, evt);
      } else {
        const timeA = new Date(evt.timestamp || 0).getTime();
        const timeB = new Date(existing.timestamp || 0).getTime();
        if (timeA > timeB) {
          incidentMap.set(id, evt);
        }
      }
    });

    const uniqueIncidents = Array.from(incidentMap.values());

    // 3. Prioritize sorting:
    //    a. Open / Active incidents first
    //    b. Critical severity > High > Medium > Low
    //    c. Newest timestamp first
    const severityRank = { Critical: 4, High: 3, Medium: 2, Low: 1 };

    uniqueIncidents.sort((a, b) => {
      const statusA = (a.incident_status || 'Open').toLowerCase();
      const statusB = (b.incident_status || 'Open').toLowerCase();

      const isOpenA = statusA === 'open' || statusA === 'active' || statusA === 'detected';
      const isOpenB = statusB === 'open' || statusB === 'active' || statusB === 'detected';

      if (isOpenA && !isOpenB) return -1;
      if (!isOpenA && isOpenB) return 1;

      // Compare severity
      const sevA = severityRank[a.event_severity] || 0;
      const sevB = severityRank[b.event_severity] || 0;
      if (sevA !== sevB) return sevB - sevA;

      // Compare timestamp (newest first)
      const timeA = new Date(a.timestamp || 0).getTime();
      const timeB = new Date(b.timestamp || 0).getTime();
      return timeB - timeA;
    });

    // 4. Return top 5
    return uniqueIncidents.slice(0, 5);
  }, [allEvents]);

  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    try {
      const date = new Date(ts);
      if (isNaN(date.getTime())) return String(ts).replace('T', ' ').slice(0, 16);
      return date.toLocaleDateString('en-US', {
        month: 'short',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
    } catch (e) {
      return String(ts).replace('T', ' ').slice(0, 16);
    }
  };

  const formatResponseTime = (evt) => {
    if (evt.response_time && String(evt.response_time).trim() !== '' && evt.response_time !== 'null') {
      return evt.response_time;
    }
    if (evt.response_time_minutes !== undefined && evt.response_time_minutes !== null && evt.response_time_minutes !== '') {
      return `${evt.response_time_minutes} min`;
    }
    return '—';
  };

  const isLoading = allEvents === null;

  return (
    <div className="panel" style={styles.panel}>
      <div style={styles.headerRow}>
        <div>
          <h3 className="section-title" style={styles.title}>
            Recent & Active Incidents
          </h3>
          <p className="muted" style={styles.subtitle}>
            Incident-linked security telemetry
          </p>
        </div>
        {onNavigateToIncidents && (
          <button
            className="soc-button"
            onClick={onNavigateToIncidents}
            style={styles.navButton}
          >
            <span>View All Incidents</span>
            <ArrowRight size={13} />
          </button>
        )}
      </div>

      {isLoading ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.82rem' }}>Loading incident telemetry...</p>
        </div>
      ) : topIncidents.length === 0 ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.82rem' }}>No incident-linked telemetry available.</p>
        </div>
      ) : (
        <div className="soc-table-container" style={{ marginTop: '0.5rem' }}>
          <table className="soc-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Incident Type</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Assigned To</th>
                <th>Response Time</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {topIncidents.map((inc) => {
                const isCritical = inc.event_severity === 'Critical';
                const isOpen = (inc.incident_status || 'Open').toLowerCase() === 'open';

                return (
                  <tr
                    key={inc.incident_id || inc.event_id}
                    style={{
                      backgroundColor: isCritical
                        ? 'rgba(244, 63, 94, 0.05)'
                        : isOpen
                        ? 'rgba(6, 182, 212, 0.03)'
                        : undefined
                    }}
                  >
                    <td style={styles.monoCell}>
                      <span className="badge status-detected">{inc.incident_id}</span>
                    </td>
                    <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                      {inc.incident_type || inc.event_type}
                    </td>
                    <td>
                      <Badge type="severity" value={inc.event_severity} />
                    </td>
                    <td>
                      <Badge type="status" value={inc.incident_status || 'Open'} />
                    </td>
                    <td style={{ color: 'var(--text-secondary)' }}>{inc.assigned_to || 'Unassigned'}</td>
                    <td style={styles.monoCell}>{formatResponseTime(inc)}</td>
                    <td style={styles.monoCell}>{formatTimestamp(inc.timestamp)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

const styles = {
  panel: {
    padding: '1rem 1.15rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.25rem'
  },
  title: {
    fontSize: '0.95rem',
    margin: 0
  },
  subtitle: {
    fontSize: '0.75rem',
    margin: '0.15rem 0 0 0'
  },
  navButton: {
    fontSize: '0.72rem',
    padding: '0.3rem 0.65rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  stateContainer: {
    minHeight: '120px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  }
};

export default IncidentTable;
