import React, { useState, useEffect, useCallback, useRef } from 'react';
import { 
  getPredictions, 
  getPredictionByEventId 
} from '../services/api';
import Badge from '../components/Badge';
import { exportInvestigationReportPdf } from '../utils/pdfExport';
import { 
  Search, 
  ChevronLeft, 
  ChevronRight, 
  CheckCircle2, 
  XCircle, 
  Sparkles, 
  RefreshCw,
  FileText,
  Cpu,
  AlertCircle,
  Download
} from 'lucide-react';

/**
 * Event Investigation — Dedicated SOC Analyst Investigation Hub
 * Consumes:
 * - GET /predictions/{event_id} (Single event lookup with telemetry details & XAI reasons)
 * - GET /predictions (Stored threat predictions in MongoDB)
 * - Export Investigation Report: Client-side dynamic PDF generation
 */
const EventInvestigationPage = ({ initialEventId = null }) => {
  // Event Lookup State — empty by default, user enters an Event ID to investigate
  const [investigateId, setInvestigateId] = useState((initialEventId && initialEventId.trim()) || '');
  const [investigateResult, setInvestigateResult] = useState(null);
  const [investigateLoading, setInvestigateLoading] = useState(false);
  const [investigateError, setInvestigateError] = useState(null);
  const [investigate404, setInvestigate404] = useState(false);
  const [validationError, setValidationError] = useState(null);

  // PDF Export state
  const [isExporting, setIsExporting] = useState(false);
  const [exportError, setExportError] = useState(null);

  // Stored Predictions Table State
  const [predictionsData, setPredictionsData] = useState(null);
  const [tableLoading, setTableLoading] = useState(true);
  const [tableError, setTableError] = useState(null);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [predictionFilter, setPredictionFilter] = useState('');
  const [threatLevelFilter, setThreatLevelFilter] = useState('');
  const [tableSearch, setTableSearch] = useState('');

  const lookupSectionRef = useRef(null);

  // Single shared investigation execution function (GET /predictions/{event_id})
  const executeInvestigation = useCallback(async (targetEventId) => {
    const cleanId = (typeof targetEventId === 'string' ? targetEventId : '').trim();
    
    if (!cleanId) {
      setValidationError('Enter an Event ID to investigate.');
      return;
    }

    setValidationError(null);
    setInvestigateLoading(true);
    setInvestigateError(null);
    setInvestigate404(false);
    setExportError(null);

    try {
      const res = await getPredictionByEventId(cleanId, { noCache: true });
      setInvestigateResult(res);
      setInvestigateId(cleanId);
    } catch (err) {
      if (err.response && err.response.status === 404) {
        setInvestigate404(true);
        setInvestigateResult(null);
      } else {
        setInvestigateError(
          err.response?.data?.detail || `Failed to retrieve prediction details for Event ID "${cleanId}".`
        );
        setInvestigateResult(null);
      }
    } finally {
      setInvestigateLoading(false);
    }
  }, []);

  // Fetch Stored Threat Predictions Table Data (GET /predictions)
  const fetchPredictionsTable = useCallback(async () => {
    setTableLoading(true);
    setTableError(null);
    try {
      const params = { page, limit };
      if (predictionFilter) params.prediction = predictionFilter;
      if (threatLevelFilter) params.threat_level = threatLevelFilter;
      if (tableSearch && tableSearch.trim()) params.search = tableSearch.trim();

      const data = await getPredictions(params);
      setPredictionsData(data);
    } catch (err) {
      console.error('Failed to fetch threat predictions:', err);
      setTableError('Unable to load prediction records from MongoDB storage.');
    } finally {
      setTableLoading(false);
    }
  }, [page, limit, predictionFilter, threatLevelFilter, tableSearch]);

  // Initial load and response to prop change (only executes if initialEventId is explicitly supplied)
  useEffect(() => {
    if (initialEventId && initialEventId.trim()) {
      const idToLoad = initialEventId.trim();
      setInvestigateId(idToLoad);
      executeInvestigation(idToLoad);
    }
  }, [initialEventId, executeInvestigation]);

  useEffect(() => {
    fetchPredictionsTable();
  }, [fetchPredictionsTable]);

  // Form submit handler for manual search
  const handleSearchSubmit = (e) => {
    if (e) e.preventDefault();
    const clean = investigateId.trim();
    if (!clean) {
      setValidationError('Enter an Event ID to investigate.');
      return;
    }
    executeInvestigation(clean);
  };

  // Row-level Investigate button handler from Stored Threat Predictions table
  const handleInspectRow = (eventId) => {
    if (!eventId) return;
    setInvestigateId(eventId);
    executeInvestigation(eventId);
    if (lookupSectionRef.current) {
      lookupSectionRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  // Quick sample pill clicks
  const handleSampleClick = (sampleId) => {
    setInvestigateId(sampleId);
    executeInvestigation(sampleId);
  };

  // Handle PDF Export
  const handleExportReport = async () => {
    if (!investigateResult) return;
    setIsExporting(true);
    setExportError(null);

    try {
      // Small tick to ensure UI state renders before PDF generation
      await new Promise((resolve) => setTimeout(resolve, 50));
      exportInvestigationReportPdf(investigateResult);
    } catch (err) {
      console.error('Failed to export PDF investigation report:', err);
      setExportError('Unable to generate PDF report. Please try again.');
    } finally {
      setIsExporting(false);
    }
  };

  const predictionsList = predictionsData?.data || [];
  const totalPages = predictionsData?.pagination?.total_pages || 1;
  const totalPredictions = predictionsData?.pagination?.total || 0;

  // Extract event details safely
  const details = investigateResult?.event_details || {};

  return (
    <div style={styles.container}>
      {/* TOP ACTION BAR: REFRESH & EXPORT (NO DUPLICATE HEADING) */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', width: '100%', marginBottom: '-0.25rem' }}>
        <div style={styles.actionButtonsGroup}>
          <button 
            className="soc-button" 
            onClick={() => { executeInvestigation(investigateId); fetchPredictionsTable(); }}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <RefreshCw size={13} />
            <span>Refresh Investigation Data</span>
          </button>

          <button
            className="soc-button"
            onClick={handleExportReport}
            disabled={!investigateResult || isExporting}
            style={{
              fontSize: '0.78rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              backgroundColor: investigateResult ? 'var(--color-accent)' : undefined,
              color: investigateResult ? '#ffffff' : undefined,
              borderColor: investigateResult ? 'var(--color-accent)' : undefined,
              cursor: !investigateResult || isExporting ? 'not-allowed' : 'pointer'
            }}
            title={!investigateResult ? "Investigate an event first to export report" : "Export PDF Investigation Report"}
          >
            <Download size={14} />
            <span>{isExporting ? 'Generating Report...' : 'Export Investigation Report'}</span>
          </button>
        </div>
      </div>

      {/* Export Error Alert Banner */}
      {exportError && (
        <div style={styles.errorBanner}>
          <XCircle size={16} color="var(--color-critical)" />
          <span style={{ fontSize: '0.8rem', color: 'var(--color-critical)' }}>{exportError}</span>
        </div>
      )}

      {/* 1. EVENT LOOKUP & INVESTIGATION PANEL */}
      <div className="panel" style={styles.investigatePanel} ref={lookupSectionRef}>
        <div style={styles.panelHeader}>
          <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Search size={16} color="var(--color-accent)" />
            <span>Event Telemetry & AI Prediction Lookup</span>
          </h3>
        </div>

        {/* Search Input Form */}
        <form onSubmit={handleSearchSubmit} style={styles.searchForm}>
          <div style={styles.searchInputGroup}>
            <input
              type="text"
              id="event-investigation-search-input"
              className="soc-select"
              placeholder="Enter Event ID to investigate..."
              value={investigateId}
              onChange={(e) => {
                setInvestigateId(e.target.value);
                if (validationError) setValidationError(null);
              }}
              style={{ minWidth: '280px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}
              autoComplete="off"
            />
            <button 
              type="submit" 
              className="soc-button" 
              disabled={investigateLoading} 
              style={{ fontSize: '0.8rem', padding: '0.4rem 0.9rem' }}
            >
              {investigateLoading ? 'Investigating...' : 'Investigate'}
            </button>
          </div>

          {/* Quick sample event IDs */}
          <div style={styles.sampleEventsRow}>
            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Quick Investigate:</span>
            {['EVT00034', 'EVT00007', 'EVT00012', 'EVT00088', 'EVT00105'].map((id) => (
              <button
                key={id}
                type="button"
                className="badge"
                onClick={() => handleSampleClick(id)}
                style={{ 
                  cursor: 'pointer', 
                  border: `1px solid ${id === investigateId ? 'var(--color-accent)' : 'var(--border-color)'}`, 
                  background: id === investigateId ? 'rgba(6, 182, 212, 0.15)' : 'var(--bg-card)', 
                  color: id === investigateId ? 'var(--color-accent)' : 'var(--text-secondary)',
                  fontSize: '0.7rem', 
                  fontFamily: 'var(--font-mono)' 
                }}
              >
                {id}
              </button>
            ))}
          </div>
        </form>

        {/* Validation Error Message */}
        {validationError && (
          <div style={styles.warningBanner}>
            <AlertCircle size={15} color="var(--color-warning)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--color-warning)', fontWeight: '600' }}>
              {validationError}
            </span>
          </div>
        )}

        {/* Loading Banner */}
        {investigateLoading && (
          <div style={styles.loadingBanner}>
            <p className="muted" style={{ fontSize: '0.8rem', margin: 0 }}>
              Querying security event telemetry and ML prediction record from database...
            </p>
          </div>
        )}

        {/* 404 Not Found Banner */}
        {investigate404 && (
          <div style={styles.errorBanner}>
            <XCircle size={16} color="var(--color-critical)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--color-critical)', fontWeight: '600' }}>
              404 Not Found: No threat prediction record found for Event ID "{investigateId}".
            </span>
          </div>
        )}

        {/* Generic Error Banner */}
        {investigateError && (
          <div style={styles.errorBanner}>
            <XCircle size={16} color="var(--color-critical)" />
            <span style={{ fontSize: '0.8rem', color: 'var(--color-critical)' }}>{investigateError}</span>
          </div>
        )}

        {/* INVESTIGATION RESULTS DETAIL VIEW */}
        {investigateResult && (
          <div style={styles.resultContainer}>
            {/* TOP SUMMARY STRIP: PREDICTION & CONFIDENCE */}
            <div style={styles.topSummaryStrip}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <div style={{
                  padding: '0.5rem 0.75rem',
                  borderRadius: '6px',
                  backgroundColor: investigateResult.prediction === 'Suspicious' ? 'rgba(244, 63, 94, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                  border: `1px solid ${investigateResult.prediction === 'Suspicious' ? 'rgba(244, 63, 94, 0.4)' : 'rgba(34, 197, 94, 0.4)'}`
                }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>
                    ML Verdict
                  </span>
                  <span style={{
                    fontSize: '1.1rem',
                    fontWeight: '800',
                    color: investigateResult.prediction === 'Suspicious' ? 'var(--color-critical)' : 'var(--color-accent)'
                  }}>
                    {investigateResult.prediction}
                  </span>
                </div>

                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: '700' }}>
                    Threat Confidence Score
                  </span>
                  <span style={{
                    fontSize: '1.25rem',
                    fontWeight: '800',
                    fontFamily: 'var(--font-mono)',
                    color: investigateResult.confidence_score >= 70 ? 'var(--color-critical)' : investigateResult.confidence_score >= 40 ? 'var(--color-warning)' : 'var(--color-accent)'
                  }}>
                    {investigateResult.confidence_score}%
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
                <div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>THREAT LEVEL</span>
                  <Badge type="severity" value={investigateResult.threat_level} />
                </div>
                <div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>THREAT TYPE</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>{investigateResult.threat_type}</span>
                </div>
                <div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>ANOMALY SCORE</span>
                  <span style={{ fontSize: '0.85rem', fontWeight: '700', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                    {investigateResult.anomaly_score?.toFixed(6)}
                  </span>
                </div>
                <div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>MODEL VERSION</span>
                  <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                    {investigateResult.model_version}
                  </span>
                </div>
              </div>
            </div>

            {/* TWO COLUMNS: EVENT DETAILS + AI ANALYSIS */}
            <div style={styles.gridTwoColumns}>
              {/* SECTION: EVENT DETAILS */}
              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <FileText size={15} color="var(--color-accent)" />
                  <span>Event Details</span>
                </h4>
                <div style={styles.detailsListGrid}>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Event ID:</span>
                    <span style={styles.detailValueMono}>{investigateResult.event_id}</span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Source IP:</span>
                    <span style={styles.detailValueMono}>
                      {details.source_ip || investigateResult.source_ip || '192.168.1.100'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Destination IP:</span>
                    <span style={styles.detailValueMono}>
                      {details.destination_ip || investigateResult.destination_ip || '10.0.0.1'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>User:</span>
                    <span style={styles.detailValue}>
                      {details.username || details.user || investigateResult.username || 'analyst'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Event Type:</span>
                    <span style={styles.detailValue}>
                      {details.event_type || investigateResult.threat_type || 'Security Event'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Timestamp:</span>
                    <span style={styles.detailValueMono}>
                      {details.timestamp || investigateResult.created_at || 'N/A'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Asset:</span>
                    <span style={styles.detailValue}>
                      {details.asset_name || details.asset_id || 'Production Host'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Severity:</span>
                    <Badge type="severity" value={details.event_severity || details.severity || investigateResult.threat_level} />
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>CVSS:</span>
                    <span style={styles.detailValueMono}>
                      {details.raw_cvss_score ?? details.cvss_score ?? (details.vulnerability_present ? '9.8' : '0.0')}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Status:</span>
                    <Badge type="status" value={details.event_status || details.status || 'Detected'} />
                  </div>
                </div>
              </div>

              {/* SECTION: AI ANALYSIS & EXPLAINABLE REASONS */}
              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <Cpu size={15} color="var(--color-accent)" />
                  <span>AI Analysis</span>
                </h4>
                <div style={styles.detailsListGrid}>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Prediction:</span>
                    <span style={{
                      fontSize: '0.85rem',
                      fontWeight: '700',
                      color: investigateResult.prediction === 'Suspicious' ? 'var(--color-critical)' : 'var(--color-accent)'
                    }}>
                      {investigateResult.prediction}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Threat Confidence Score:</span>
                    <span style={{
                      fontSize: '0.9rem',
                      fontWeight: '800',
                      fontFamily: 'var(--font-mono)',
                      color: investigateResult.confidence_score >= 70 ? 'var(--color-critical)' : 'var(--color-warning)'
                    }}>
                      {investigateResult.confidence_score}%
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Anomaly Score:</span>
                    <span style={styles.detailValueMono}>
                      {investigateResult.anomaly_score?.toFixed(6)}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Threat Type:</span>
                    <span style={{ fontSize: '0.82rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                      {investigateResult.threat_type}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Threat Level:</span>
                    <Badge type="severity" value={investigateResult.threat_level} />
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Model Version:</span>
                    <span style={styles.detailValueMono}>
                      {investigateResult.model_version}
                    </span>
                  </div>
                </div>

                {/* SECTION: AI EXPLAINABLE DETECTION REASONS */}
                <div style={styles.xaiContainer}>
                  <span style={styles.xaiHeading}>
                    <Sparkles size={14} color="var(--color-accent)" />
                    <span>AI Explainable Detection Reasons</span>
                  </span>

                  {investigateResult.reasons && investigateResult.reasons.length > 0 ? (
                    <div style={styles.reasonsList}>
                      {investigateResult.reasons.map((reason, idx) => (
                        <div key={idx} style={styles.reasonItem}>
                          <CheckCircle2 size={14} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '2px' }} />
                          <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
                            {reason}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={styles.reasonItem}>
                      <CheckCircle2 size={14} color="var(--color-accent)" style={{ flexShrink: 0 }} />
                      <span className="muted" style={{ fontSize: '0.78rem' }}>
                        Baseline telemetry within normal operational thresholds. Zero risk anomalies triggered.
                      </span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 2. STORED THREAT PREDICTIONS TABLE (GET /predictions) */}
      <div className="panel" style={styles.tablePanel}>
        <div style={styles.tableToolbar}>
          <div>
            <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
              Stored Threat Predictions
            </h3>
            <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
              Historical predictions stored in MongoDB with AI confidence scoring and instant 1-click investigation
            </p>
          </div>

          {/* Table Filters */}
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              type="text"
              className="soc-select"
              placeholder="Search Event ID, Type..."
              value={tableSearch}
              onChange={(e) => { setTableSearch(e.target.value); setPage(1); }}
              style={{ fontSize: '0.75rem', padding: '0.3rem 0.5rem', minWidth: '170px' }}
            />

            <select
              value={predictionFilter}
              onChange={(e) => { setPredictionFilter(e.target.value); setPage(1); }}
              style={styles.selectFilter}
            >
              <option value="">Prediction: All</option>
              <option value="Suspicious">Prediction: Suspicious</option>
              <option value="Normal">Prediction: Normal</option>
            </select>

            <select
              value={threatLevelFilter}
              onChange={(e) => { setThreatLevelFilter(e.target.value); setPage(1); }}
              style={styles.selectFilter}
            >
              <option value="">Threat Level: All</option>
              <option value="Critical Threat">Critical Threat</option>
              <option value="High Threat">High Threat</option>
              <option value="Medium Threat">Medium Threat</option>
              <option value="Low Threat">Low Threat</option>
              <option value="Normal">Normal</option>
            </select>
          </div>
        </div>

        {tableLoading ? (
          <div className="panel" style={styles.statePanel}>
            <p className="muted">Loading stored threat prediction records...</p>
          </div>
        ) : tableError ? (
          <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
            <p style={{ color: 'var(--color-critical)' }}>{tableError}</p>
          </div>
        ) : predictionsList.length === 0 ? (
          <div className="panel" style={styles.statePanel}>
            <p className="muted">No prediction records match the selected filters.</p>
          </div>
        ) : (
          <div>
            <div className="soc-table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Event ID</th>
                    <th>Prediction</th>
                    <th>Anomaly Score</th>
                    <th>Threat Type</th>
                    <th>Threat Level</th>
                    <th>Threat Confidence Score</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {predictionsList.map((row) => {
                    const isCurrentlyInvestigated = row.event_id === investigateResult?.event_id;
                    return (
                      <tr 
                        key={row.event_id || Math.random()}
                        style={{
                          backgroundColor: isCurrentlyInvestigated ? 'rgba(6, 182, 212, 0.08)' : undefined
                        }}
                      >
                        <td style={styles.monoCell}>
                          <strong style={{ color: isCurrentlyInvestigated ? 'var(--color-accent)' : 'var(--text-primary)' }}>
                            {row.event_id}
                          </strong>
                        </td>
                        <td>
                          <span className={`badge ${row.prediction === 'Suspicious' ? 'severity-critical' : 'status-success'}`}>
                            {row.prediction}
                          </span>
                        </td>
                        <td style={styles.monoCell}>{row.anomaly_score?.toFixed(6)}</td>
                        <td style={{ fontWeight: '500' }}>{row.threat_type}</td>
                        <td>
                          <Badge type="severity" value={row.threat_level} />
                        </td>
                        <td style={styles.monoCell}>
                          <span style={{
                            fontWeight: '800',
                            color: row.confidence_score >= 70 ? 'var(--color-critical)' : row.confidence_score >= 40 ? 'var(--color-warning)' : 'var(--color-accent)'
                          }}>
                            {row.confidence_score}%
                          </span>
                        </td>
                        <td>
                          <button
                            className="soc-button"
                            onClick={() => handleInspectRow(row.event_id)}
                            style={{ 
                              fontSize: '0.72rem', 
                              padding: '0.25rem 0.65rem',
                              backgroundColor: isCurrentlyInvestigated ? 'var(--color-accent)' : undefined,
                              color: isCurrentlyInvestigated ? '#000' : undefined
                            }}
                          >
                            {isCurrentlyInvestigated ? 'Investigating' : 'Investigate'}
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div style={styles.paginationFooter}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
                <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong> ({totalPredictions.toLocaleString()} predictions)
              </span>

              <div style={{ display: 'flex', gap: '0.4rem' }}>
                <button
                  className="soc-button"
                  disabled={page <= 1}
                  onClick={() => setPage((prev) => Math.max(prev - 1, 1))}
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                >
                  <ChevronLeft size={14} />
                  <span>Previous</span>
                </button>
                <button
                  className="soc-button"
                  disabled={page >= totalPages}
                  onClick={() => setPage((prev) => Math.min(prev + 1, totalPages))}
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                >
                  <span>Next</span>
                  <ChevronRight size={14} />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  actionButtonsGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    flexWrap: 'wrap'
  },
  investigatePanel: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  searchForm: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  searchInputGroup: {
    display: 'flex',
    gap: '0.5rem',
    flexWrap: 'wrap'
  },
  sampleEventsRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    flexWrap: 'wrap'
  },
  loadingBanner: {
    padding: '0.75rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '4px',
    border: '1px solid var(--border-subtle)'
  },
  warningBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.55rem 0.75rem',
    backgroundColor: 'rgba(245, 158, 11, 0.1)',
    border: '1px solid rgba(245, 158, 11, 0.3)',
    borderRadius: '4px'
  },
  errorBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.65rem 0.85rem',
    backgroundColor: 'rgba(244, 63, 94, 0.1)',
    border: '1px solid rgba(244, 63, 94, 0.3)',
    borderRadius: '4px'
  },
  resultContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    marginTop: '0.5rem'
  },
  topSummaryStrip: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.85rem 1.15rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    flexWrap: 'wrap',
    gap: '1rem'
  },
  gridTwoColumns: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
    gap: '1.25rem'
  },
  subCard: {
    padding: '1.15rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem'
  },
  subCardTitle: {
    fontSize: '0.9rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0,
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    paddingBottom: '0.5rem',
    borderBottom: '1px solid var(--border-subtle)'
  },
  detailsListGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: '0.75rem'
  },
  detailItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.15rem'
  },
  detailLabel: {
    fontSize: '0.68rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em'
  },
  detailValue: {
    fontSize: '0.82rem',
    fontWeight: '600',
    color: 'var(--text-primary)'
  },
  detailValueMono: {
    fontSize: '0.82rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)'
  },
  xaiContainer: {
    marginTop: '0.5rem',
    padding: '0.85rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  xaiHeading: {
    fontSize: '0.78rem',
    fontWeight: '700',
    color: 'var(--color-accent)',
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem',
    textTransform: 'uppercase',
    letterSpacing: '0.03em'
  },
  reasonsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.4rem'
  },
  reasonItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.45rem'
  },
  tablePanel: {
    padding: '1.25rem'
  },
  tableToolbar: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '1rem',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  selectFilter: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    color: 'var(--text-primary)',
    borderRadius: '4px',
    padding: '0.3rem 0.5rem',
    fontSize: '0.75rem',
    outline: 'none'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  statePanel: {
    minHeight: '160px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  },
  paginationFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: '0.75rem',
    paddingTop: '0.75rem',
    borderTop: '1px solid var(--border-subtle)'
  }
};

export default EventInvestigationPage;
