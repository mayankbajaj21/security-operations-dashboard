import React, { useState, useEffect, useCallback } from 'react';
import { getEvents } from '../services/api';
import Badge from '../components/Badge';
import { ChevronLeft, ChevronRight, RotateCcw, Filter, AlertCircle, Search, X, Download } from 'lucide-react';

/**
 * Safely escape values for CSV generation
 */
const escapeCsvCell = (val) => {
  if (val === null || val === undefined) return '""';
  let str = String(val);
  str = str.replace(/"/g, '""');
  return `"${str}"`;
};

const SecurityEventsPage = () => {
  const [eventsData, setEventsData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Filter & Pagination States
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [searchTerm, setSearchTerm] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [ipAddress, setIpAddress] = useState('');

  // CSV Export states
  const [isExporting, setIsExporting] = useState(false);
  const [exportNotice, setExportNotice] = useState(null);

  // 350ms debounce effect for search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(searchTerm);
    }, 350);

    return () => clearTimeout(timer);
  }, [searchTerm]);

  // Reset pagination to page 1 whenever debounced search term changes
  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  const fetchEvents = useCallback(() => {
    // Validate date range
    if (fromDate && toDate && fromDate > toDate) {
      setError('From date cannot be later than To date.');
      setEventsData(null);
      setLoading(false);
      return;
    }

    // Validate IPv4 address syntax if populated
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const trimmedIp = ipAddress.trim();
    if (trimmedIp !== '' && !ipv4Regex.test(trimmedIp)) {
      setError('Enter a valid IPv4 address.');
      setEventsData(null);
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    const params = { page, limit };

    if (debouncedSearch && debouncedSearch.trim() !== '') {
      params.search = debouncedSearch.trim();
    }
    if (severity && severity.trim() !== '') {
      params.severity = severity.trim();
    }
    if (eventType && eventType.trim() !== '') {
      params.event_type = eventType.trim();
    }
    if (statusFilter && statusFilter.trim() !== '') {
      params.status = statusFilter.trim();
    }
    if (fromDate && fromDate.trim() !== '') {
      params.start_date = fromDate.trim();
    }
    if (toDate && toDate.trim() !== '') {
      params.end_date = toDate.trim();
    }
    if (trimmedIp !== '') {
      params.ip_address = trimmedIp;
    }

    getEvents(params)
      .then((data) => {
        setEventsData(data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to fetch security events:', err);
        setError('Unable to load security events telemetry.');
        setLoading(false);
      });
  }, [page, limit, debouncedSearch, severity, eventType, statusFilter, fromDate, toDate, ipAddress]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  // Handle Event Type filter change
  const handleEventTypeChange = (e) => {
    setEventType(e.target.value);
    setPage(1);
  };

  // Handle Severity filter change
  const handleSeverityChange = (e) => {
    setSeverity(e.target.value);
    setPage(1);
  };

  // Handle Status filter change
  const handleStatusChange = (e) => {
    setStatusFilter(e.target.value);
    setPage(1);
  };

  // Handle From Date filter change
  const handleFromDateChange = (e) => {
    setFromDate(e.target.value);
    setPage(1);
  };

  // Handle To Date filter change
  const handleToDateChange = (e) => {
    setToDate(e.target.value);
    setPage(1);
  };

  // Handle IP Address filter change
  const handleIpAddressChange = (e) => {
    setIpAddress(e.target.value);
    setPage(1);
  };

  // Reset all search terms & filters to default empty values and page 1
  const handleResetFilters = () => {
    setSearchTerm('');
    setDebouncedSearch('');
    setSeverity('');
    setEventType('');
    setStatusFilter('');
    setFromDate('');
    setToDate('');
    setIpAddress('');
    setExportNotice(null);
    setPage(1);
  };

  // Handle Export CSV for ALL records matching current search & filters using controlled batching
  const handleExportCSV = async () => {
    if (isExporting) return;
    setIsExporting(true);
    setExportNotice(null);

    try {
      if (fromDate && toDate && fromDate > toDate) {
        setExportNotice('From date cannot be later than To date.');
        setIsExporting(false);
        return;
      }

      const params = { page: 1, limit: 100 };
      const trimmedIp = ipAddress.trim();

      if (debouncedSearch && debouncedSearch.trim() !== '') {
        params.search = debouncedSearch.trim();
      }
      if (severity && severity.trim() !== '') {
        params.severity = severity.trim();
      }
      if (eventType && eventType.trim() !== '') {
        params.event_type = eventType.trim();
      }
      if (statusFilter && statusFilter.trim() !== '') {
        params.status = statusFilter.trim();
      }
      if (fromDate && fromDate.trim() !== '') {
        params.start_date = fromDate.trim();
      }
      if (toDate && toDate.trim() !== '') {
        params.end_date = toDate.trim();
      }
      if (trimmedIp !== '') {
        params.ip_address = trimmedIp;
      }

      // 1. Fetch first page to compute total pages and matching records
      const firstPage = await getEvents(params);
      const total = firstPage?.pagination?.total ?? firstPage?.total ?? 0;
      const totalPages = firstPage?.pagination?.total_pages ?? firstPage?.total_pages ?? 0;

      if (total === 0) {
        setExportNotice('No matching events to export.');
        setIsExporting(false);
        return;
      }

      let allMatchingRecords = [...(firstPage?.data || firstPage?.events || [])];

      // 2. Fetch remaining pages using controlled batching (batch size = 4)
      if (totalPages > 1) {
        const batchSize = 4;
        for (let p = 2; p <= totalPages; p += batchSize) {
          const batchPromises = [];
          for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
            batchPromises.push(getEvents({ ...params, page: b }));
          }
          const batchResults = await Promise.all(batchPromises);
          batchResults.forEach((res) => {
            const resData = res?.data || res?.events || [];
            allMatchingRecords = allMatchingRecords.concat(resData);
          });
        }
      }

      // 3. Complete list of analyst security event columns
      const columns = [
        { label: 'Event ID', key: 'event_id' },
        { label: 'Timestamp', key: 'timestamp' },
        { label: 'Event Type', key: 'event_type' },
        { label: 'Source IP', key: 'source_ip' },
        { label: 'Destination IP', key: 'destination_ip' },
        { label: 'Username', key: 'username' },
        { label: 'Protocol', key: 'protocol' },
        { label: 'Source Country', key: 'source_country' },
        { label: 'Destination Country', key: 'destination_country' },
        { label: 'Device Name', key: 'device_name' },
        { label: 'OS', key: 'os' },
        { label: 'Event Status', key: 'event_status' },
        { label: 'Event Severity', key: 'event_severity' },
        { label: 'Failed Login Attempts', key: 'failed_login_attempts' },
        { label: 'Malware Detected', key: 'malware_detected' },
        { label: 'Vulnerability ID', key: 'vulnerability_id' },
        { label: 'Raw CVSS Score', key: 'raw_cvss_score' },
        { label: 'Asset Name', key: 'asset_name' },
        { label: 'Department', key: 'department' },
        { label: 'Threat Intel Match', key: 'threat_intel_match' },
        { label: 'Threat Name', key: 'threat_name' },
        { label: 'Threat Actor', key: 'threat_actor' },
        { label: 'Threat Confidence', key: 'threat_confidence' },
        { label: 'MITRE ID', key: 'mitre_id' },
        { label: 'Technique Name', key: 'technique_name' },
        { label: 'Tactic', key: 'tactic' },
        { label: 'MITRE Mapping Status', key: 'mitre_mapping_status' },
        { label: 'Incident ID', key: 'incident_id' },
        { label: 'Incident Type', key: 'incident_type' },
        { label: 'Assigned To', key: 'assigned_to' },
        { label: 'Incident Status', key: 'incident_status' },
        { label: 'Response Time', key: 'response_time' },
        { label: 'Response Time Minutes', key: 'response_time_minutes' },
        { label: 'Resolution', key: 'resolution' }
      ];

      // 4. Construct escaped CSV string
      const headerRow = columns.map((col) => escapeCsvCell(col.label)).join(',');
      const bodyRows = allMatchingRecords.map((evt) => {
        return columns
          .map((col) => escapeCsvCell(evt[col.key]))
          .join(',');
      });

      const csvString = [headerRow, ...bodyRows].join('\r\n');

      // 5. Trigger browser Blob download
      const blob = new Blob([csvString], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      const isFiltered = Boolean(debouncedSearch || severity || eventType || statusFilter || fromDate || toDate || ipAddress);
      const dateStr = new Date().toISOString().split('T')[0];
      const filename = isFiltered ? `security_events_filtered_${dateStr}.csv` : `security_events_${dateStr}.csv`;

      link.setAttribute('href', url);
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to export CSV:', err);
      setExportNotice('Export failed. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  // Extract events array and pagination metadata from API response structure:
  // { data: [...], pagination: { page, limit, total, total_pages } }
  const eventsList = eventsData?.data || eventsData?.events || [];
  const totalPages = eventsData?.pagination?.total_pages || eventsData?.total_pages || 1;
  const totalEvents = eventsData?.pagination?.total ?? eventsData?.total_events ?? 0;

  const hasActiveFilters = Boolean(
    searchTerm || debouncedSearch || severity || eventType || statusFilter || fromDate || toDate || ipAddress
  );

  return (
    <div style={styles.container}>
      {/* Filters Toolbar Panel */}
      <div className="panel" style={styles.filterPanel}>
        <div style={styles.filterHeader}>
          <div style={styles.filterTitleGroup}>
            <Filter size={16} color="var(--color-accent)" />
            <span style={styles.filterTitle}>Event Filters & Search</span>
          </div>

          <div style={styles.actionGroup}>
            {hasActiveFilters && (
              <button className="soc-button" onClick={handleResetFilters} style={styles.resetButton}>
                <RotateCcw size={13} />
                <span>Reset Filters</span>
              </button>
            )}

            <button
              className="soc-button"
              onClick={handleExportCSV}
              disabled={isExporting || loading}
              style={{
                ...styles.resetButton,
                borderColor: 'var(--color-accent)',
                color: 'var(--color-accent)',
                backgroundColor: isExporting ? 'rgba(6, 182, 212, 0.1)' : 'transparent'
              }}
              title="Export all records matching active filters to CSV"
            >
              <Download size={13} className={isExporting ? 'spin-icon' : ''} />
              <span>{isExporting ? 'Exporting...' : 'Export CSV'}</span>
            </button>
          </div>
        </div>

        {exportNotice && (
          <div style={styles.noticeBox}>
            <AlertCircle size={14} color="var(--color-warning)" />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-primary)' }}>{exportNotice}</span>
          </div>
        )}

        <div style={styles.filterControls}>
          {/* Server-Side Event Search Input */}
          <div style={styles.controlGroup}>
            <label htmlFor="search-events-input" style={styles.label}>Search Events</label>
            <div style={styles.searchWrapper}>
              <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
              <input 
                id="search-events-input"
                type="text"
                className="soc-select" 
                placeholder="Search event ID, IP, username, type..."
                value={searchTerm} 
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{
                  ...styles.searchInput,
                  paddingLeft: '28px',
                  paddingRight: searchTerm ? '26px' : '10px'
                }}
              />
              {searchTerm && (
                <button
                  onClick={() => setSearchTerm('')}
                  style={styles.clearSearchBtn}
                  title="Clear search"
                  type="button"
                >
                  <X size={12} color="var(--text-muted)" />
                </button>
              )}
            </div>
          </div>

          {/* Severity Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="severity-filter" style={styles.label}>Severity</label>
            <select 
              id="severity-filter"
              className="soc-select" 
              value={severity} 
              onChange={handleSeverityChange}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          {/* Event Type Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="event-type-filter" style={styles.label}>Event Type</label>
            <select 
              id="event-type-filter"
              name="event_type"
              className="soc-select" 
              value={eventType} 
              onChange={handleEventTypeChange}
            >
              <option value="">All Event Types</option>
              <option value="Failed Login">Failed Login</option>
              <option value="Unauthorized Access Attempt">Unauthorized Access Attempt</option>
              <option value="Malware Infection">Malware Infection</option>
              <option value="Port Scan">Port Scan</option>
              <option value="Data Exfiltration">Data Exfiltration</option>
              <option value="Privilege Escalation">Privilege Escalation</option>
              <option value="Phishing Attempt">Phishing Attempt</option>
              <option value="Ransomware Execution">Ransomware Execution</option>
              <option value="DDoS Attack">DDoS Attack</option>
              <option value="System Error">System Error</option>
            </select>
          </div>

          {/* Status Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="status-filter" style={styles.label}>Status</label>
            <select 
              id="status-filter"
              className="soc-select" 
              value={statusFilter} 
              onChange={handleStatusChange}
            >
              <option value="">All Statuses</option>
              <option value="Success">Success</option>
              <option value="Failed">Failed</option>
              <option value="Blocked">Blocked</option>
              <option value="Detected">Detected</option>
            </select>
          </div>

          {/* From Date Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="from-date-filter" style={styles.label}>From Date</label>
            <input 
              id="from-date-filter"
              type="date"
              className="soc-select" 
              value={fromDate} 
              onChange={handleFromDateChange}
              style={styles.dateInput}
            />
          </div>

          {/* To Date Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="to-date-filter" style={styles.label}>To Date</label>
            <input 
              id="to-date-filter"
              type="date"
              className="soc-select" 
              value={toDate} 
              onChange={handleToDateChange}
              style={styles.dateInput}
            />
          </div>

          {/* IP Address Search Filter */}
          <div style={styles.controlGroup}>
            <label htmlFor="ip-address-filter" style={styles.label}>IP Address</label>
            <input 
              id="ip-address-filter"
              type="text"
              className="soc-select" 
              placeholder="Filter IP address..."
              value={ipAddress} 
              onChange={handleIpAddressChange}
              style={styles.ipInput}
            />
          </div>
        </div>
      </div>

      {/* Main Table Content */}
      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading security events...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <div style={styles.errorBox}>
            <AlertCircle size={18} color="var(--color-critical)" />
            <p style={{ color: 'var(--color-critical)', fontWeight: '600', margin: 0 }}>{error}</p>
          </div>
        </div>
      )}

      {!loading && !error && eventsList.length === 0 && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">
            {hasActiveFilters ? 'No events match your search and filters.' : 'No security events found.'}
          </p>
        </div>
      )}

      {!loading && !error && eventsList.length > 0 && (
        <div className="soc-table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Event ID</th>
                <th>Timestamp</th>
                <th>Event Type</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Username</th>
                <th>Status</th>
                <th>Severity</th>
                <th>Malware</th>
                <th>Vulnerability ID</th>
              </tr>
            </thead>
            <tbody>
              {eventsList.map((evt) => (
                <tr key={evt.event_id || Math.random()}>
                  <td style={styles.monoCell}>{evt.event_id}</td>
                  <td style={styles.monoCell}>
                    {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : 'N/A'}
                  </td>
                  <td style={{ fontWeight: '500' }}>{evt.event_type}</td>
                  <td style={styles.monoCell}>{evt.source_ip || 'N/A'}</td>
                  <td style={styles.monoCell}>{evt.destination_ip || 'N/A'}</td>
                  <td>{evt.username || 'N/A'}</td>
                  <td>
                    <Badge type="status" value={evt.event_status} />
                  </td>
                  <td>
                    <Badge type="severity" value={evt.event_severity} />
                  </td>
                  <td>
                    {evt.malware_detected ? (
                      <span className="badge status-detected" style={{ fontSize: '0.7rem' }}>Detected</span>
                    ) : (
                      <span className="muted" style={{ fontSize: '0.78rem' }}>None</span>
                    )}
                  </td>
                  <td style={styles.monoCell}>
                    {evt.vulnerability_id ? (
                      <span style={{ color: 'var(--color-warning)', fontWeight: '600' }}>
                        {evt.vulnerability_id}
                      </span>
                    ) : (
                      <span className="muted">N/A</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Server-Side Pagination Controls */}
      {!loading && !error && eventsData && eventsList.length > 0 && (
        <div style={styles.paginationFooter}>
          <div style={styles.paginationInfo}>
            <span>
              Showing Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong>{' '}
              ({totalEvents.toLocaleString()} total events)
            </span>
          </div>

          <div style={styles.paginationControls}>
            <button
              className="soc-button"
              disabled={page <= 1 || loading}
              onClick={() => setPage((prev) => Math.max(prev - 1, 1))}
            >
              <ChevronLeft size={15} />
              <span>Previous</span>
            </button>

            <button
              className="soc-button"
              disabled={page >= totalPages || loading}
              onClick={() => setPage((prev) => Math.min(prev + 1, totalPages))}
            >
              <span>Next</span>
              <ChevronRight size={15} />
            </button>
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
  filterPanel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    padding: '1rem 1.25rem'
  },
  filterHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  filterTitleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  actionGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  filterTitle: {
    fontSize: '0.85rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em'
  },
  resetButton: {
    fontSize: '0.75rem',
    padding: '0.3rem 0.6rem'
  },
  noticeBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    backgroundColor: 'rgba(250, 204, 21, 0.08)',
    border: '1px solid rgba(250, 204, 21, 0.2)',
    borderRadius: '4px',
    padding: '0.35rem 0.6rem'
  },
  filterControls: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '1rem',
    alignItems: 'center'
  },
  controlGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  label: {
    fontSize: '0.7rem',
    fontWeight: '600',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em'
  },
  searchWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  searchIcon: {
    position: 'absolute',
    left: '9px',
    pointerEvents: 'none'
  },
  searchInput: {
    minWidth: '220px'
  },
  clearSearchBtn: {
    position: 'absolute',
    right: '6px',
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '2px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    outline: 'none'
  },
  dateInput: {
    cursor: 'pointer'
  },
  ipInput: {
    minWidth: '140px'
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
  errorBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  paginationFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.75rem 1rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    fontSize: '0.8rem',
    color: 'var(--text-secondary)'
  },
  paginationInfo: {
    display: 'flex',
    alignItems: 'center'
  },
  paginationControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  }
};

export default SecurityEventsPage;
