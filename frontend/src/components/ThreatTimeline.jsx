import React, { useState, useMemo } from 'react';
import Badge from './Badge';
import { ChevronDown, ChevronRight, Clock, Search, Filter } from 'lucide-react';

/**
 * Presentational Chronological Threat Telemetry Timeline
 * Consumes global `allEvents` array passed from App.jsx parent.
 * Performs zero backend API fetches.
 */
const ThreatTimeline = ({ allEvents = null }) => {
  const [severityFilter, setSeverityFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState(null);

  // Process & compute top 15 sorted timeline items using useMemo
  const timelineEvents = useMemo(() => {
    if (!Array.isArray(allEvents)) return [];

    let filtered = [...allEvents];

    // Filter by severity if selected
    if (severityFilter && severityFilter.trim() !== '') {
      filtered = filtered.filter(
        (evt) => evt.event_severity?.toLowerCase() === severityFilter.toLowerCase()
      );
    }

    // Filter by local search term if typed
    if (searchTerm && searchTerm.trim() !== '') {
      const q = searchTerm.trim().toLowerCase();
      filtered = filtered.filter((evt) => {
        return (
          evt.event_id?.toLowerCase().includes(q) ||
          evt.event_type?.toLowerCase().includes(q) ||
          evt.source_ip?.toLowerCase().includes(q) ||
          evt.destination_ip?.toLowerCase().includes(q) ||
          evt.username?.toLowerCase().includes(q) ||
          evt.asset_name?.toLowerCase().includes(q)
        );
      });
    }

    // Sort by timestamp descending (newest event first)
    filtered.sort((a, b) => {
      const timeA = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const timeB = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return timeB - timeA;
    });

    // Limit to latest 15 events
    return filtered.slice(0, 15);
  }, [allEvents, severityFilter, searchTerm]);

  const toggleExpand = (id) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  const getMarkerColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'var(--color-critical)';
      case 'high':
        return 'var(--color-high)';
      case 'medium':
        return 'var(--color-medium)';
      case 'low':
        return 'var(--color-low)';
      default:
        return 'var(--color-accent)';
    }
  };

  if (allEvents === null) {
    return (
      <div className="panel" style={styles.statePanel}>
        <p className="muted">Loading threat timeline...</p>
      </div>
    );
  }

  return (
    <div className="panel" style={styles.container}>
      {/* Panel Header */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <Clock size={18} color="var(--color-accent)" />
          <div>
            <h3 style={styles.title}>Threat Telemetry Timeline</h3>
            <p className="muted" style={styles.subtitle}>
              Chronological sequence of recent security events
            </p>
          </div>
        </div>

        {/* Toolbar Controls */}
        <div style={styles.toolbar}>
          {/* Local Search Input */}
          <div style={styles.searchWrapper}>
            <Search size={13} color="var(--text-muted)" style={styles.searchIcon} />
            <input
              type="text"
              className="soc-select"
              placeholder="Search timeline..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={styles.searchInput}
            />
          </div>

          {/* Local Severity Filter */}
          <div style={styles.filterWrapper}>
            <Filter size={13} color="var(--text-muted)" />
            <select
              className="soc-select"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={styles.selectInput}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>
        </div>
      </div>

      {/* Empty State */}
      {timelineEvents.length === 0 ? (
        <div style={styles.emptyState}>
          <p className="muted">No security events match the selected criteria.</p>
        </div>
      ) : (
        <div className="threat-timeline" style={styles.timelineList}>
          {timelineEvents.map((evt, idx) => {
            const id = evt.event_id || `evt-${idx}`;
            const isExpanded = expandedId === id;
            const markerColor = getMarkerColor(evt.event_severity);
            const timeStr = evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A';

            return (
              <div key={id} className="timeline-item" style={styles.timelineItem}>
                {/* Vertical Connector Line & Marker */}
                <div style={styles.markerColumn}>
                  <div
                    style={{
                      ...styles.markerDot,
                      backgroundColor: markerColor,
                      boxShadow: `0 0 8px ${markerColor}66`
                    }}
                  />
                  {idx < timelineEvents.length - 1 && <div style={styles.verticalLine} />}
                </div>

                {/* Event Content Card */}
                <div style={styles.itemContent}>
                  {/* Collapsed Header Bar */}
                  <div
                    onClick={() => toggleExpand(id)}
                    style={{
                      ...styles.itemHeader,
                      borderLeftColor: markerColor
                    }}
                  >
                    <div style={styles.headerLeft}>
                      {isExpanded ? (
                        <ChevronDown size={15} color="var(--text-muted)" />
                      ) : (
                        <ChevronRight size={15} color="var(--text-muted)" />
                      )}
                      <span style={styles.timestamp}>{timeStr}</span>
                      <strong style={styles.eventType}>{evt.event_type}</strong>
                    </div>

                    <div style={styles.headerRight}>
                      <span style={styles.ipFlow}>
                        {evt.source_ip || 'N/A'} → {evt.destination_ip || 'N/A'}
                      </span>
                      <Badge type="status" value={evt.event_status} />
                      <Badge type="severity" value={evt.event_severity} />
                    </div>
                  </div>

                  {/* Expanded Details Drawer */}
                  {isExpanded && (
                    <div style={styles.detailsDrawer}>
                      <div style={styles.detailsGrid}>
                        <div>
                          <span style={styles.detailLabel}>Event ID:</span>
                          <span style={styles.detailValueMono}>{evt.event_id || 'N/A'}</span>
                        </div>
                        {evt.username && (
                          <div>
                            <span style={styles.detailLabel}>User:</span>
                            <span style={styles.detailValue}>{evt.username}</span>
                          </div>
                        )}
                        {evt.asset_name && (
                          <div>
                            <span style={styles.detailLabel}>Asset:</span>
                            <span style={styles.detailValue}>{evt.asset_name}</span>
                          </div>
                        )}
                        {evt.protocol && (
                          <div>
                            <span style={styles.detailLabel}>Protocol:</span>
                            <span style={styles.detailValueMono}>{evt.protocol}</span>
                          </div>
                        )}
                        {evt.threat_name && (
                          <div>
                            <span style={styles.detailLabel}>Threat Intel:</span>
                            <span style={{ ...styles.detailValue, color: 'var(--color-critical)' }}>
                              {evt.threat_name}
                            </span>
                          </div>
                        )}
                        {evt.mitre_id && (
                          <div>
                            <span style={styles.detailLabel}>MITRE ID:</span>
                            <span style={{ ...styles.detailValueMono, color: 'var(--color-accent)' }}>
                              {evt.mitre_id} ({evt.technique_name || 'N/A'})
                            </span>
                          </div>
                        )}
                        {evt.vulnerability_id && (
                          <div>
                            <span style={styles.detailLabel}>Vulnerability:</span>
                            <span style={{ ...styles.detailValueMono, color: 'var(--color-warning)' }}>
                              {evt.vulnerability_id}
                            </span>
                          </div>
                        )}
                        {evt.resolution && (
                          <div style={{ gridColumn: '1 / -1' }}>
                            <span style={styles.detailLabel}>Resolution Notes:</span>
                            <span style={styles.detailValue}>{evt.resolution}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Footer Metadata */}
      {timelineEvents.length > 0 && (
        <div style={styles.footer}>
          <span style={styles.footerText}>
            Showing latest {timelineEvents.length} security events
          </span>
        </div>
      )}
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    padding: '1.25rem'
  },
  statePanel: {
    minHeight: '140px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center'
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem'
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem'
  },
  title: {
    fontSize: '1rem',
    fontWeight: '600',
    margin: 0,
    color: 'var(--text-primary)'
  },
  subtitle: {
    fontSize: '0.75rem',
    margin: 0
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
  searchWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  searchIcon: {
    position: 'absolute',
    left: '8px',
    pointerEvents: 'none'
  },
  searchInput: {
    paddingLeft: '26px',
    width: '180px',
    height: '30px',
    fontSize: '0.78rem'
  },
  filterWrapper: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem'
  },
  selectInput: {
    height: '30px',
    fontSize: '0.78rem'
  },
  emptyState: {
    padding: '2rem 1rem',
    textAlign: 'center'
  },
  timelineList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem',
    marginTop: '0.5rem'
  },
  timelineItem: {
    display: 'flex',
    gap: '0.85rem'
  },
  markerColumn: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    width: '16px',
    paddingTop: '10px'
  },
  markerDot: {
    width: '10px',
    height: '10px',
    borderRadius: '50%',
    flexShrink: 0
  },
  verticalLine: {
    width: '2px',
    flex: 1,
    backgroundColor: 'var(--border-color)',
    marginTop: '4px',
    marginBottom: '-4px'
  },
  itemContent: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  itemHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderLeft: '3px solid transparent',
    borderRadius: '6px',
    padding: '0.5rem 0.75rem',
    cursor: 'pointer',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  headerLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem'
  },
  timestamp: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)'
  },
  eventType: {
    fontSize: '0.83rem',
    color: 'var(--text-primary)'
  },
  headerRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem'
  },
  ipFlow: {
    fontSize: '0.75rem',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-secondary)'
  },
  detailsDrawer: {
    backgroundColor: 'rgba(15, 23, 42, 0.6)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.75rem 1rem',
    marginTop: '0.2rem'
  },
  detailsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '0.6rem',
    fontSize: '0.78rem'
  },
  detailLabel: {
    color: 'var(--text-muted)',
    marginRight: '0.35rem',
    fontWeight: '500'
  },
  detailValue: {
    color: 'var(--text-primary)',
    fontWeight: '500'
  },
  detailValueMono: {
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    fontWeight: '500'
  },
  footer: {
    display: 'flex',
    justifyContent: 'flex-end',
    paddingTop: '0.25rem',
    borderTop: '1px solid var(--border-color)'
  },
  footerText: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)'
  }
};

export default ThreatTimeline;
