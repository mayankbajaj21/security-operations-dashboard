import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  getIncidents, 
  getIncident, 
  updateIncidentStatus, 
  getRecommendations,
  submitIncidentFeedback,
  getRiskComparison
} from '../services/api';
import MetricCard from '../components/MetricCard';
import Badge from '../components/Badge';
import { 
  AlertOctagon, 
  ShieldAlert, 
  CheckCircle2, 
  Clock, 
  Search, 
  ChevronLeft, 
  ChevronRight, 
  RefreshCw,
  Flame,
  XCircle,
  Eye,
  ShieldCheck,
  Cpu,
  Target,
  FileText,
  AlertTriangle,
  Lightbulb,
  ArrowRight,
  User,
  Layers,
  HelpCircle,
  ArrowLeft
} from 'lucide-react';

/**
 * Priority Incidents & Incident Investigation Hub
 * 
 * Milestone 3: Operational Risk Prioritization & Incident Response
 * 
 * Modes:
 * 1. Priority Incidents List: Paginated, filterable queue of all M3 incidents
 * 2. Incident Investigation Workspace: Deep-dive view for a clicked/selected incident_id
 *    consuming GET /api/v1/incidents/{incident_id} and GET /api/v1/recommendations/{incident_id}
 */
const IncidentResponsePage = ({ initialIncidentId = null }) => {
  // Incidents Data State
  const [incidentsList, setIncidentsList] = useState([]);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters State
  const [statusFilter, setStatusFilter] = useState('');
  const [riskLevelFilter, setRiskLevelFilter] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('');
  const [assetFilter, setAssetFilter] = useState('');
  const [mitreFilter, setMitreFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected Incident for Full Investigation Workspace (GET /api/v1/incidents/{incident_id})
  const [selectedIncidentId, setSelectedIncidentId] = useState(null);
  const [incidentDetail, setIncidentDetail] = useState(null);
  const [recommendationsData, setRecommendationsData] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(null);

  // Lifecycle Update State (PATCH /api/v1/incidents/{incident_id}/status)
  const [statusUpdateLoading, setStatusUpdateLoading] = useState(false);
  const [statusUpdateError, setStatusUpdateError] = useState(null);
  const [statusUpdateSuccess, setStatusUpdateSuccess] = useState(null);
  const [assigneeInput, setAssigneeInput] = useState('');
  const [notesInput, setNotesInput] = useState('');

  // Dedicated Analyst Feedback State (POST /api/v1/incidents/{incident_id}/feedback)
  const [feedbackLabel, setFeedbackLabel] = useState('');
  const [feedbackComment, setFeedbackComment] = useState('');
  const [feedbackLoading, setFeedbackLoading] = useState(false);
  const [feedbackError, setFeedbackError] = useState(null);
  const [feedbackSuccess, setFeedbackSuccess] = useState(null);

  // Contextual Risk Score Comparison State (GET /api/v1/risk/comparison/{event_id})
  const [incidentComparison, setIncidentComparison] = useState(null);

  // Fetch All Incidents from GET /api/v1/incidents
  const fetchIncidentsData = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      // Fetch full incident dataset so filtering and KPI metrics reflect the global incident state
      const res = await getIncidents({ limit: 100 }, { noCache: isManual });
      const rawData = res?.data || [];
      setIncidentsList(rawData);
    } catch (err) {
      console.error('Failed to query incidents from API:', err);
      setError('Unable to load priority incident records from the backend.');
      setIncidentsList([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIncidentsData();
  }, [fetchIncidentsData]);

  // Load single incident details + recommendations when an incident is clicked/selected
  const loadIncidentDetail = useCallback(async (incidentId) => {
    const cleanId = (typeof incidentId === 'string' ? incidentId : '').trim();
    if (!cleanId) {
      setSelectedIncidentId(null);
      setIncidentDetail(null);
      setDetailError('Invalid or missing Incident ID.');
      return;
    }

    // Immediately isolate and clear local state when switching incidents
    setSelectedIncidentId(cleanId);
    setIncidentDetail(null);
    setRecommendationsData(null);
    setIncidentComparison(null);
    setAssigneeInput('');
    setNotesInput('');
    setFeedbackLabel('');
    setFeedbackComment('');
    setFeedbackError(null);
    setFeedbackSuccess(null);
    setDetailLoading(true);
    setDetailError(null);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    try {
      const [incRes, recsRes] = await Promise.all([
        getIncident(cleanId, { noCache: true }),
        getRecommendations(cleanId, { noCache: true }).catch(() => null)
      ]);

      if (!incRes || !incRes.incident_id) {
        throw new Error(`Incident "${cleanId}" not found in security backend.`);
      }

      setIncidentDetail(incRes);
      setRecommendationsData(recsRes);
      setAssigneeInput(incRes.assigned_to || incRes.assignee || '');
      setNotesInput(incRes.notes || incRes.investigation_notes || '');

      // Initialize feedback state strictly from this incident's saved feedback
      if (incRes.feedback) {
        setFeedbackLabel(incRes.feedback.label || '');
        setFeedbackComment(incRes.feedback.comment || '');
      } else {
        setFeedbackLabel('');
        setFeedbackComment('');
      }

      // Fetch contextual risk score comparison for the primary telemetry event
      const primaryEvt = incRes.related_events?.[0] || incRes.event_ids?.[0] || cleanId;
      getRiskComparison(primaryEvt, { noCache: true })
        .then((comp) => setIncidentComparison(comp))
        .catch(() => setIncidentComparison(null));
    } catch (err) {
      console.error(`Failed to load details for incident ${cleanId}:`, err);
      const errMsg = err.response?.data?.detail || err.message || `Unable to retrieve details for incident ${cleanId}`;
      setDetailError(errMsg);
      setIncidentDetail(null);
      setRecommendationsData(null);
    } finally {
      setDetailLoading(false);
    }
  }, []);

  // Auto-load initialIncidentId if passed as prop
  useEffect(() => {
    if (initialIncidentId && typeof initialIncidentId === 'string' && initialIncidentId.trim()) {
      loadIncidentDetail(initialIncidentId.trim());
    }
  }, [initialIncidentId, loadIncidentDetail]);

  // Return back from Incident Investigation to Priority Incidents list
  const handleBackToIncidents = () => {
    setSelectedIncidentId(null);
    setIncidentDetail(null);
    setRecommendationsData(null);
    setIncidentComparison(null);
    setAssigneeInput('');
    setNotesInput('');
    setFeedbackLabel('');
    setFeedbackComment('');
    setFeedbackError(null);
    setFeedbackSuccess(null);
    setDetailError(null);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);
  };

  // Submit dedicated Analyst Feedback (True Positive / False Positive)
  const handleSubmitFeedback = async (labelToSubmit) => {
    if (!selectedIncidentId || !incidentDetail) return;
    const targetLabel = labelToSubmit || feedbackLabel;
    if (!targetLabel) {
      setFeedbackError('Please select either True Positive or False Positive.');
      return;
    }
    setFeedbackLoading(true);
    setFeedbackError(null);
    setFeedbackSuccess(null);

    try {
      const payload = {
        label: targetLabel,
        comment: feedbackComment ? feedbackComment.trim() : null,
        analyst: assigneeInput.trim() || incidentDetail.assigned_to || 'SOC Analyst'
      };

      const updated = await submitIncidentFeedback(selectedIncidentId, payload);
      setIncidentDetail(updated);
      setFeedbackLabel(updated.feedback?.label || targetLabel);
      setFeedbackComment(updated.feedback?.comment || '');
      setFeedbackSuccess(`Analyst feedback "${targetLabel}" recorded successfully.`);
      fetchIncidentsData(true);
    } catch (err) {
      console.error('Failed to submit analyst feedback:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Failed to submit feedback.';
      setFeedbackError(errMsg);
    } finally {
      setFeedbackLoading(false);
    }
  };

  // Save Analyst Notes and Assignee without modifying status
  const handleSaveMetadata = async () => {
    if (!selectedIncidentId || !incidentDetail) return;
    setStatusUpdateLoading(true);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    try {
      const payload = {
        status: incidentDetail.status,
        assigned_to: assigneeInput.trim(),
        notes: notesInput.trim()
      };

      const updated = await updateIncidentStatus(selectedIncidentId, payload);
      setIncidentDetail(updated);
      setAssigneeInput(updated.assigned_to || updated.assignee || '');
      setNotesInput(updated.notes || updated.investigation_notes || '');
      setStatusUpdateSuccess('Incident assignee and notes saved successfully.');
      fetchIncidentsData(true);
    } catch (err) {
      console.error('Failed to save incident metadata:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Failed to save notes.';
      setStatusUpdateError(errMsg);
    } finally {
      setStatusUpdateLoading(false);
    }
  };

  // Handle Lifecycle Status Transitions (PATCH /api/v1/incidents/{incident_id}/status)
  const handleStatusTransition = async (newStatus) => {
    if (!selectedIncidentId || !incidentDetail) return;
    setStatusUpdateLoading(true);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    try {
      const payload = {
        status: newStatus,
        assigned_to: assigneeInput.trim(),
        notes: notesInput.trim()
      };

      const updated = await updateIncidentStatus(selectedIncidentId, payload);
      setIncidentDetail(updated);
      setAssigneeInput(updated.assigned_to || updated.assignee || '');
      setNotesInput(updated.notes || updated.investigation_notes || '');
      setStatusUpdateSuccess(`Incident status successfully transitioned to "${newStatus}".`);
      fetchIncidentsData(true); // Refresh main table in background
    } catch (err) {
      console.error('Failed to transition incident status:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Status transition failed.';
      setStatusUpdateError(errMsg);
    } finally {
      setStatusUpdateLoading(false);
    }
  };

  // 1. Filter ALL incidents by active filters and search query
  const filteredIncidents = useMemo(() => {
    return incidentsList.filter((inc) => {
      // Status filter
      if (statusFilter && (inc.status || '').toLowerCase() !== statusFilter.toLowerCase()) {
        return false;
      }
      // Risk level filter
      if (riskLevelFilter && (inc.risk_level || '').toLowerCase() !== riskLevelFilter.toLowerCase()) {
        return false;
      }
      // Threat type filter
      if (threatTypeFilter && (inc.threat_type || '').toLowerCase() !== threatTypeFilter.toLowerCase()) {
        return false;
      }
      // Asset filter
      if (assetFilter.trim()) {
        const aTarget = assetFilter.trim().toLowerCase();
        const incAsset = (inc.affected_asset || inc.asset_name || inc.asset_id || '').toLowerCase();
        if (!incAsset.includes(aTarget)) return false;
      }
      // MITRE technique filter
      if (mitreFilter.trim()) {
        const mTarget = mitreFilter.trim().toLowerCase();
        const incMitre = (inc.mitre_techniques || inc.mitre_technique || []).map((t) => String(t).toLowerCase());
        if (!incMitre.some((t) => t.includes(mTarget))) return false;
      }
      // Search query (Incident ID, Threat Type, Affected Asset, Affected User)
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matches = (
          (inc.incident_id && inc.incident_id.toLowerCase().includes(q)) ||
          (inc.threat_type && inc.threat_type.toLowerCase().includes(q)) ||
          (inc.threat_category && inc.threat_category.toLowerCase().includes(q)) ||
          (inc.affected_asset && inc.affected_asset.toLowerCase().includes(q)) ||
          (inc.asset_name && inc.asset_name.toLowerCase().includes(q)) ||
          (inc.affected_user && inc.affected_user.toLowerCase().includes(q)) ||
          (inc.username && inc.username.toLowerCase().includes(q))
        );
        if (!matches) return false;
      }
      return true;
    });
  }, [incidentsList, statusFilter, riskLevelFilter, threatTypeFilter, assetFilter, mitreFilter, searchQuery]);

  // 2. Summary KPI Metrics CALCULATED FROM ENTIRE FILTERED SET (BEFORE PAGINATION)
  const totalCount = filteredIncidents.length;
  const openCount = filteredIncidents.filter((i) => (i.status || '').toLowerCase() === 'open').length;
  const investigatingCount = filteredIncidents.filter((i) => (i.status || '').toLowerCase() === 'investigating').length;
  const resolvedCount = filteredIncidents.filter((i) => (i.status || '').toLowerCase() === 'resolved').length;
  const fpCount = filteredIncidents.filter((i) => (i.status || '').toLowerCase() === 'false positive').length;

  // 3. Paginate ONLY the Table Display
  const totalPages = Math.max(1, Math.ceil(filteredIncidents.length / limit));
  const paginatedIncidents = useMemo(() => {
    const startIndex = (page - 1) * limit;
    return filteredIncidents.slice(startIndex, startIndex + limit);
  }, [filteredIncidents, page, limit]);

  // =========================================================================
  // VIEW MODE A: INCIDENT INVESTIGATION WORKSPACE (When an incident is selected)
  // =========================================================================
  if (selectedIncidentId !== null) {
    return (
      <div style={styles.container}>
        {/* Navigation Breadcrumb Bar */}
        <div style={styles.headerRow}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              className="soc-button"
              onClick={handleBackToIncidents}
              style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              title="Return to Priority Incidents Queue"
            >
              <ArrowLeft size={16} />
              <span>Back to Priority Incidents</span>
            </button>

            <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>/</span>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <AlertTriangle size={18} color="var(--color-accent)" />
              <h2 className="section-title" style={{ fontSize: '1.15rem', margin: 0 }}>
                Incident Investigation: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>{selectedIncidentId}</span>
              </h2>
              {incidentDetail && <Badge type="status" value={incidentDetail.status || 'Open'} />}
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button
              className="soc-button"
              onClick={() => loadIncidentDetail(selectedIncidentId)}
              disabled={detailLoading}
              style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
              title="Refresh Incident Details"
            >
              <RefreshCw size={14} className={detailLoading ? 'spin' : ''} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Investigation Detail Loading State */}
        {detailLoading && (
          <div className="panel" style={styles.statePanel}>
            <p className="muted">Retrieving incident investigation telemetry and recommendations for {selectedIncidentId}...</p>
          </div>
        )}

        {/* Investigation Detail Error State */}
        {detailError && !detailLoading && (
          <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-critical)' }}>
              <XCircle size={22} />
              <strong style={{ fontSize: '0.95rem' }}>Investigation Failed: {detailError}</strong>
            </div>
            <p className="muted" style={{ margin: 0, fontSize: '0.82rem' }}>
              The requested incident identifier does not exist or could not be loaded from the security backend.
            </p>
            <button
              className="soc-button"
              onClick={handleBackToIncidents}
              style={{ fontSize: '0.8rem', marginTop: '0.5rem' }}
            >
              ← Back to Priority Incidents
            </button>
          </div>
        )}

        {/* Incident Investigation Detail Content */}
        {!detailLoading && !detailError && incidentDetail && (
          <div className="panel" style={styles.investigationWorkspace}>
            {/* Status Feedback Banners */}
            {statusUpdateSuccess && (
              <div style={styles.successBanner}>
                <CheckCircle2 size={16} color="var(--color-success)" />
                <span style={{ fontSize: '0.8rem', color: 'var(--color-success)', fontWeight: '600' }}>
                  {statusUpdateSuccess}
                </span>
              </div>
            )}

            {statusUpdateError && (
              <div style={styles.errorBanner}>
                <XCircle size={16} color="var(--color-critical)" />
                <span style={{ fontSize: '0.8rem', color: 'var(--color-critical)', fontWeight: '600' }}>
                  {statusUpdateError}
                </span>
              </div>
            )}

            {/* Core Incident Metadata Strips */}
            <div style={styles.detailGridColumns}>
              {/* Column 1: Core Triage Details */}
              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <FileText size={15} color="var(--color-accent)" />
                  <span>Incident Triage Context</span>
                </h4>
                <div style={styles.detailsListGrid}>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Incident ID:</span>
                    <span style={styles.detailValueMono}>
                      <strong style={{ color: 'var(--color-accent)' }}>{incidentDetail.incident_id}</strong>
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Threat Category:</span>
                    <span style={{ fontWeight: '700', color: 'var(--text-primary)' }}>
                      {incidentDetail.threat_type || incidentDetail.threat_category || 'Unknown Threat'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Risk Score:</span>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: '800',
                      fontSize: '1rem',
                      color: incidentDetail.risk_score >= 81 ? 'var(--color-critical)' : incidentDetail.risk_score >= 61 ? 'var(--color-high)' : 'var(--color-accent)'
                    }}>
                      {incidentDetail.risk_score} <span style={{ fontSize: '0.68rem', opacity: 0.7 }}>/ 100</span>
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Risk Level:</span>
                    <Badge type="severity" value={incidentDetail.risk_level} />
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Priority:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700' }}>
                      {incidentDetail.priority ? incidentDetail.priority : '—'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>ML Confidence:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)' }}>
                      {(incidentDetail.ml_confidence !== undefined && incidentDetail.ml_confidence !== null)
                        ? `${incidentDetail.ml_confidence}%`
                        : (incidentDetail.confidence_score !== undefined && incidentDetail.confidence_score !== null)
                          ? `${incidentDetail.confidence_score}%`
                          : '—'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>IoC Intel Match:</span>
                    <span className={`badge ${incidentDetail.ioc_status === 'Hit' || incidentDetail.ioc_status === true ? 'severity-critical' : 'status-success'}`}>
                      {incidentDetail.ioc_status === 'Hit' || incidentDetail.ioc_status === true ? 'Hit' : incidentDetail.ioc_status || 'Clean / None'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Created Timestamp:</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {incidentDetail.created_at ? String(incidentDetail.created_at).replace('T', ' ').slice(0, 19) : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Column 2: Affected Entities & Network */}
              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <Target size={15} color="var(--color-accent)" />
                  <span>Affected Entities & Telemetry</span>
                </h4>
                <div style={styles.detailsListGrid}>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Affected Asset:</span>
                    <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                      {incidentDetail.affected_asset || incidentDetail.asset_name || incidentDetail.asset_id || 'N/A'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Target User:</span>
                    <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                      {incidentDetail.affected_user || incidentDetail.username || 'N/A'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Source IP:</span>
                    <span style={styles.detailValueMono}>{incidentDetail.source_ip || 'N/A'}</span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Destination IP:</span>
                    <span style={styles.detailValueMono}>{incidentDetail.destination_ip || 'N/A'}</span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Attack Chain Link:</span>
                    <span style={styles.detailValueMono}>
                      {incidentDetail.attack_chain_id ? (
                        <span className="badge status-detected">{incidentDetail.attack_chain_id}</span>
                      ) : 'None'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Assigned Analyst:</span>
                    <span style={{ color: 'var(--color-accent)', fontWeight: '600' }}>
                      {incidentDetail.assigned_to || 'Unassigned'}
                    </span>
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Current Status:</span>
                    <Badge type="status" value={incidentDetail.status || 'Open'} />
                  </div>
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Last Updated:</span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {incidentDetail.updated_at ? String(incidentDetail.updated_at).replace('T', ' ').slice(0, 19) : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* MITRE Techniques & Related Events Badges */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem', marginTop: '0.5rem' }}>
              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <Layers size={15} color="var(--color-accent)" />
                  <span>Mapped MITRE ATT&CK Techniques</span>
                </h4>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {(incidentDetail.mitre_techniques || incidentDetail.mitre_technique || []).length > 0 ? (
                    (incidentDetail.mitre_techniques || incidentDetail.mitre_technique).map((tech, idx) => (
                      <span key={idx} className="badge severity-high" style={{ fontSize: '0.72rem' }}>
                        {tech}
                      </span>
                    ))
                  ) : (
                    <span className="muted" style={{ fontSize: '0.78rem' }}>No direct MITRE technique mapping attached.</span>
                  )}
                </div>
              </div>

              <div style={styles.subCard}>
                <h4 style={styles.subCardTitle}>
                  <Cpu size={15} color="var(--color-accent)" />
                  <span>Correlated Telemetry Event IDs ({(incidentDetail.related_events || incidentDetail.event_ids || []).length})</span>
                </h4>
                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', maxHeight: '90px', overflowY: 'auto' }}>
                  {(incidentDetail.related_events || incidentDetail.event_ids || []).length > 0 ? (
                    (incidentDetail.related_events || incidentDetail.event_ids).map((evtId, idx) => (
                      <span key={idx} className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                        {evtId}
                      </span>
                    ))
                  ) : (
                    <span className="muted" style={{ fontSize: '0.78rem' }}>No individual event IDs attached.</span>
                  )}
                </div>
              </div>
            </div>

            {/* Explainable Risk Reasons (XAI) */}
            {(incidentDetail.reasons && incidentDetail.reasons.length > 0) && (
              <div style={{ marginTop: '0.5rem', padding: '0.85rem 1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--color-accent)', display: 'block', marginBottom: '0.4rem' }}>
                  DETECTION & RISK ENGINE EXPLANATIONS:
                </span>
                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                  {incidentDetail.reasons.map((r, idx) => (
                    <span key={idx} className="badge status-detected" style={{ fontSize: '0.72rem' }}>
                      • {r}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Prescriptive Analyst Mitigation Recommendations (GET /api/v1/recommendations/{incident_id}) */}
            <div style={{ marginTop: '0.5rem', padding: '1rem', backgroundColor: 'rgba(6, 182, 212, 0.04)', borderRadius: '6px', border: '1px solid rgba(6, 182, 212, 0.25)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Lightbulb size={17} color="var(--color-accent)" />
                  <h4 style={{ margin: 0, fontSize: '0.88rem', fontWeight: '700', color: 'var(--color-accent)' }}>
                    Prescriptive Analyst Mitigation Recommendations
                  </h4>
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  Decision-Support Guidance Only (Non-Destructive)
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', marginTop: '0.5rem' }}>
                {(recommendationsData?.recommendations || incidentDetail.recommendations || []).length > 0 ? (
                  (recommendationsData?.recommendations || incidentDetail.recommendations).map((rec, idx) => (
                    <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
                      <ArrowRight size={13} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '3px' }} />
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
                        {rec}
                      </span>
                    </div>
                  ))
                ) : (
                  <span className="muted" style={{ fontSize: '0.78rem' }}>No specific prescriptive mitigation actions available.</span>
                )}
              </div>
            </div>

            {/* Saved Investigation & Resolution Notes (if any) */}
            {(incidentDetail.notes || incidentDetail.investigation_notes) && (
              <div style={{ marginTop: '0.5rem', padding: '0.85rem 1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--color-accent)', display: 'block', marginBottom: '0.4rem' }}>
                  PERSISTED INVESTIGATION & RESOLUTION NOTES:
                </span>
                <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-primary)', whiteSpace: 'pre-wrap' }}>
                  {incidentDetail.notes || incidentDetail.investigation_notes}
                </p>
              </div>
            )}

            {/* Lifecycle Action State Machine Form (PATCH /api/v1/incidents/{incident_id}/status) */}
            <div style={{ marginTop: '0.75rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
              <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block', marginBottom: '0.6rem' }}>
                LIFECYCLE STATUS & ANALYST WORKSPACE (PATCH /api/v1/incidents/{incidentDetail.incident_id}/status)
              </span>

              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <label style={styles.formLabel}>Assignee</label>
                  <input
                    type="text"
                    placeholder="e.g. analyst@soc.internal"
                    className="soc-select"
                    value={assigneeInput}
                    onChange={(e) => setAssigneeInput(e.target.value)}
                  />
                </div>

                <div style={{ flex: 2, minWidth: '280px' }}>
                  <label style={styles.formLabel}>Investigation & Resolution Notes</label>
                  <input
                    type="text"
                    placeholder="Document containment, remediation, or false positive rationale..."
                    className="soc-select"
                    value={notesInput}
                    onChange={(e) => setNotesInput(e.target.value)}
                  />
                </div>

                <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                  {/* State Machine Action Transitions */}
                  {incidentDetail.status === 'Open' && (
                    <>
                      <button
                        className="soc-button"
                        disabled={statusUpdateLoading}
                        onClick={() => handleStatusTransition('Investigating')}
                        style={{ backgroundColor: 'var(--color-accent)', color: '#000', fontWeight: '700' }}
                      >
                        {statusUpdateLoading ? 'Transitioning...' : 'Start Investigation →'}
                      </button>

                      <button
                        className="soc-button"
                        disabled={statusUpdateLoading}
                        onClick={() => handleStatusTransition('False Positive')}
                        style={{ color: 'var(--text-muted)' }}
                      >
                        Mark False Positive
                      </button>
                    </>
                  )}

                  {incidentDetail.status === 'Investigating' && (
                    <>
                      <button
                        className="soc-button"
                        disabled={statusUpdateLoading}
                        onClick={() => handleStatusTransition('Resolved')}
                        style={{ backgroundColor: 'var(--color-success)', color: '#000', fontWeight: '700' }}
                      >
                        {statusUpdateLoading ? 'Resolving...' : 'Resolve Investigation ✓'}
                      </button>

                      <button
                        className="soc-button"
                        disabled={statusUpdateLoading}
                        onClick={() => handleStatusTransition('False Positive')}
                        style={{ color: 'var(--text-muted)' }}
                      >
                        Mark False Positive
                      </button>
                    </>
                  )}

                  {(incidentDetail.status === 'Resolved' || incidentDetail.status === 'False Positive') && (
                    <button
                      className="soc-button"
                      disabled={statusUpdateLoading}
                      onClick={() => handleStatusTransition('Investigating')}
                      style={{ backgroundColor: 'var(--color-accent)', color: '#000', fontWeight: '700' }}
                      title={`Reopen incident investigation (${incidentDetail.status} → Investigating)`}
                    >
                      {statusUpdateLoading ? 'Reopening...' : 'Reopen Investigation ↺'}
                    </button>
                  )}

                  <button
                    className="soc-button"
                    disabled={statusUpdateLoading}
                    onClick={handleSaveMetadata}
                    style={{ borderColor: 'var(--border-subtle)', color: 'var(--text-primary)', fontWeight: '600' }}
                    title="Save current assignee and investigation notes"
                  >
                    Save Notes & Assignee
                  </button>
                </div>
              </div>
            </div>

            {/* DEDICATED ANALYST FEEDBACK SECTION (POST /api/v1/incidents/{incident_id}/feedback) */}
            <div style={{ marginTop: '0.75rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <ShieldCheck size={16} color="var(--color-accent)" />
                  <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                    Dedicated Analyst Feedback (True Positive / False Positive)
                  </span>
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  Per-incident isolation • Future model improvement • Separate from lifecycle status
                </span>
              </div>

              {feedbackSuccess && (
                <div style={{ padding: '0.5rem 0.75rem', borderRadius: '4px', backgroundColor: 'rgba(34, 197, 94, 0.1)', color: 'var(--color-success)', fontSize: '0.78rem', marginBottom: '0.6rem' }}>
                  {feedbackSuccess}
                </div>
              )}

              {feedbackError && (
                <div style={{ padding: '0.5rem 0.75rem', borderRadius: '4px', backgroundColor: 'rgba(244, 63, 94, 0.1)', color: 'var(--color-critical)', fontSize: '0.78rem', marginBottom: '0.6rem' }}>
                  {feedbackError}
                </div>
              )}

              {/* Display recorded feedback if already persisted on this incident */}
              {incidentDetail.feedback && (
                <div style={{ padding: '0.65rem 0.85rem', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--color-accent)', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.4rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: '600' }}>Active Feedback:</span>
                      <span className={`badge ${incidentDetail.feedback.label === 'True Positive' ? 'severity-critical' : 'status-success'}`} style={{ fontSize: '0.75rem' }}>
                        {incidentDetail.feedback.label}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                      Submitted: {incidentDetail.feedback.submitted_at ? String(incidentDetail.feedback.submitted_at).replace('T', ' ').slice(0, 19) : 'N/A'} by <strong>{incidentDetail.feedback.analyst || 'SOC Analyst'}</strong>
                    </span>
                  </div>
                  {incidentDetail.feedback.comment && (
                    <div style={{ marginTop: '0.4rem', fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Comment: </span>
                      {incidentDetail.feedback.comment}
                    </div>
                  )}
                </div>
              )}

              {/* Feedback Submission Form */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-secondary)' }}>
                    Assessment:
                  </span>
                  <button
                    type="button"
                    className="soc-button"
                    onClick={() => setFeedbackLabel('True Positive')}
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.7rem',
                      backgroundColor: feedbackLabel === 'True Positive' ? 'rgba(244, 63, 94, 0.2)' : 'transparent',
                      borderColor: feedbackLabel === 'True Positive' ? 'var(--color-critical)' : 'var(--border-color)',
                      color: feedbackLabel === 'True Positive' ? 'var(--color-critical)' : 'var(--text-secondary)',
                      fontWeight: feedbackLabel === 'True Positive' ? '700' : '400'
                    }}
                  >
                    ● True Positive
                  </button>
                  <button
                    type="button"
                    className="soc-button"
                    onClick={() => setFeedbackLabel('False Positive')}
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.7rem',
                      backgroundColor: feedbackLabel === 'False Positive' ? 'rgba(34, 197, 94, 0.2)' : 'transparent',
                      borderColor: feedbackLabel === 'False Positive' ? 'var(--color-success)' : 'var(--border-color)',
                      color: feedbackLabel === 'False Positive' ? 'var(--color-success)' : 'var(--text-secondary)',
                      fontWeight: feedbackLabel === 'False Positive' ? '700' : '400'
                    }}
                  >
                    ● False Positive
                  </button>
                </div>

                <div>
                  <label style={styles.formLabel}>Comment / Analyst Notes (Optional)</label>
                  <textarea
                    rows={2}
                    placeholder="Document analyst justification for this triage evaluation..."
                    className="soc-select"
                    value={feedbackComment}
                    onChange={(e) => setFeedbackComment(e.target.value)}
                    style={{ width: '100%', resize: 'vertical', fontFamily: 'inherit', fontSize: '0.8rem', padding: '0.4rem 0.6rem' }}
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                  <button
                    type="button"
                    className="soc-button"
                    onClick={() => handleSubmitFeedback()}
                    disabled={!feedbackLabel || feedbackLoading}
                    style={{
                      fontSize: '0.78rem',
                      backgroundColor: feedbackLabel ? 'var(--color-accent)' : 'var(--bg-card)',
                      color: feedbackLabel ? '#000' : 'var(--text-muted)',
                      fontWeight: '700'
                    }}
                  >
                    {feedbackLoading ? 'Submitting...' : 'Submit Feedback'}
                  </button>
                </div>
              </div>
            </div>

            {/* CONTEXTUAL RISK SCORE COMPARISON SECTION (GET /v1/risk/comparison/{event_id}) */}
            {incidentComparison && (
              <div style={{ marginTop: '0.75rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <Cpu size={16} color="var(--color-accent)" />
                    <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                      Risk Score Comparison: Before vs After Correlation
                    </span>
                  </div>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                    Primary Event: {incidentComparison.event_id}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem' }}>
                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--color-accent)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '600' }}>BEFORE CORRELATION</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--text-primary)', marginTop: '0.15rem' }}>
                      {incidentComparison.before_correlation} <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '400' }}>/ 100</span>
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>Standalone Event Score</span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: `3px solid ${incidentComparison.difference > 0 ? 'var(--color-critical)' : 'var(--color-accent)'}` }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '600' }}>AFTER CORRELATION</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: incidentComparison.after_correlation >= 81 ? 'var(--color-critical)' : 'var(--text-primary)', marginTop: '0.15rem' }}>
                      {incidentComparison.after_correlation} <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '400' }}>/ 100</span>
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>Contextual Campaign Risk</span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: `3px solid ${incidentComparison.difference > 0 ? 'var(--color-critical)' : 'var(--color-success)'}` }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '600' }}>SCORE DELTA</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: incidentComparison.difference > 0 ? 'var(--color-critical)' : 'var(--color-success)', marginTop: '0.15rem' }}>
                      {incidentComparison.difference > 0 ? `+${incidentComparison.difference}` : incidentComparison.difference}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                      {incidentComparison.correlated ? 'Multi-Stage Escalation' : 'No correlation impact'}
                    </span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '600' }}>CORRELATION STATUS</span>
                    <div style={{ marginTop: '0.25rem' }}>
                      {incidentComparison.correlated ? (
                        <span className="badge severity-critical" style={{ fontSize: '0.7rem' }}>
                          In Chain ({incidentComparison.chain_id || 'Correlated'})
                        </span>
                      ) : (
                        <span className="badge status-detected" style={{ fontSize: '0.7rem' }}>
                          No correlation impact
                        </span>
                      )}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.2rem', display: 'block' }}>
                      {incidentComparison.related_events_count} correlated alert{incidentComparison.related_events_count === 1 ? '' : 's'}
                    </span>
                  </div>
                </div>

                {incidentComparison.explanation && incidentComparison.explanation.length > 0 && (
                  <div style={{ marginTop: '0.6rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    <ul style={{ margin: 0, paddingLeft: '1.1rem', lineHeight: '1.4' }}>
                      {incidentComparison.explanation.map((e, idx) => (
                        <li key={idx}>{e}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  // =========================================================================
  // VIEW MODE B: PRIORITY INCIDENTS LIST (Default Queue Overview)
  // =========================================================================
  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED PAGE HEADER & ACTION CONTROLS */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <AlertOctagon size={20} color="var(--color-accent)" />
            <span>Priority Incidents & Investigation</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            Incident triage, multi-factor risk prioritization, analyst investigation workspace, and lifecycle state management
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button
            className="soc-button"
            onClick={() => fetchIncidentsData(true)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Refresh Incident Telemetry"
          >
            <RefreshCw size={14} className={loading ? 'spin' : ''} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 2. KPI SUMMARY METRIC CARDS */}
      <div style={styles.kpiGrid}>
        <MetricCard
          title="Total Incidents"
          value={totalCount}
          subtitle="Monitored priority security incidents"
          icon={AlertOctagon}
          variant="accent"
        />
        <MetricCard
          title="Open Incidents"
          value={openCount}
          subtitle="Awaiting analyst triage"
          icon={ShieldAlert}
          variant={openCount > 0 ? 'critical' : 'default'}
        />
        <MetricCard
          title="Investigating"
          value={investigatingCount}
          subtitle="Active containment in progress"
          icon={Clock}
          variant={investigatingCount > 0 ? 'high' : 'default'}
        />
        <MetricCard
          title="Resolved"
          value={resolvedCount}
          subtitle="Remediated & closed"
          icon={CheckCircle2}
          variant="default"
        />
        <MetricCard
          title="False Positive"
          value={fpCount}
          subtitle="Discharged benign anomalies"
          icon={ShieldCheck}
          variant="default"
        />
      </div>

      {/* 3. PRIORITY INCIDENTS DATA TABLE (GET /api/v1/incidents) */}
      <div className="panel" style={styles.tablePanel}>
        <div style={styles.tableToolbarHeader}>
          <div>
            <h3 className="section-title" style={{ margin: 0, fontSize: '0.95rem' }}>
              Priority Incidents Queue
            </h3>
            <p className="muted" style={{ margin: '0.15rem 0 0 0', fontSize: '0.75rem' }}>
              Click any incident row to open its dedicated investigation workspace
            </p>
          </div>

          {/* Filter Bar Controls */}
          <div style={styles.toolbarControls}>
            <div style={styles.searchWrapper}>
              <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
              <input
                type="text"
                placeholder="Search Incident ID, Threat, Asset..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={styles.searchInput}
              />
            </div>

            <select
              value={statusFilter}
              onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
              style={styles.selectFilter}
            >
              <option value="">Status: All</option>
              <option value="Open">Status: Open</option>
              <option value="Investigating">Status: Investigating</option>
              <option value="Resolved">Status: Resolved</option>
              <option value="False Positive">Status: False Positive</option>
            </select>

            <select
              value={riskLevelFilter}
              onChange={(e) => { setRiskLevelFilter(e.target.value); setPage(1); }}
              style={styles.selectFilter}
            >
              <option value="">Risk Level: All</option>
              <option value="Critical">Critical (81–100)</option>
              <option value="High">High (61–80)</option>
              <option value="Moderate">Moderate (41–60)</option>
              <option value="Medium">Medium (21–40)</option>
              <option value="Low">Low (0–20)</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="panel" style={styles.statePanel}>
            <p className="muted">Loading priority incidents from security backend...</p>
          </div>
        ) : error ? (
          <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
            <p style={{ color: 'var(--color-critical)' }}>{error}</p>
          </div>
        ) : filteredIncidents.length === 0 ? (
          <div className="panel" style={styles.statePanel}>
            <p className="muted">No security incidents match the selected search or filter criteria.</p>
          </div>
        ) : (
          <div>
            <div className="soc-table-fit-container">
              <table className="soc-table-fit">
                <thead>
                  <tr>
                    <th style={{ width: '10%' }}>Incident ID</th>
                    <th style={{ width: '13%' }}>Threat Category</th>
                    <th style={{ width: '8%' }}>Risk Score</th>
                    <th style={{ width: '9%' }}>Risk Level</th>
                    <th style={{ width: '6%' }}>Priority</th>
                    <th style={{ width: '9%' }}>Status</th>
                    <th style={{ width: '11%' }}>Affected Asset</th>
                    <th style={{ width: '9%' }}>User</th>
                    <th style={{ width: '7%' }}>ML Conf</th>
                    <th style={{ width: '9%' }}>MITRE Techniques</th>
                    <th style={{ width: '5%' }}>IoC</th>
                    <th style={{ width: '8%', textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedIncidents.map((inc) => (
                    <tr
                      key={inc.incident_id || Math.random()}
                      onClick={() => loadIncidentDetail(inc.incident_id)}
                      style={{
                        cursor: 'pointer',
                        backgroundColor: inc.risk_level === 'Critical' ? 'rgba(244, 63, 94, 0.04)' : undefined,
                        transition: 'background-color 0.15s ease'
                      }}
                      className="soc-clickable-row"
                      title={`Click to investigate ${inc.incident_id}`}
                    >
                      <td style={styles.monoCell}>
                        <strong style={{ color: 'var(--color-accent)' }}>
                          {inc.incident_id}
                        </strong>
                      </td>

                      <td style={{ fontWeight: '600', color: 'var(--text-primary)' }} title={inc.threat_type || inc.threat_category}>
                        {inc.threat_type || inc.threat_category}
                      </td>

                      <td style={styles.monoCell}>
                        <span style={{
                          fontWeight: '800',
                          color: inc.risk_score >= 81 ? 'var(--color-critical)' : inc.risk_score >= 61 ? 'var(--color-high)' : 'var(--color-accent)'
                        }}>
                          {inc.risk_score !== undefined ? `${inc.risk_score}/100` : '—'}
                        </span>
                      </td>

                      <td>
                        <Badge type="severity" value={inc.risk_level} />
                      </td>

                      {/* M3 Rule: Display Priority only when backend provides it, otherwise neutral '—' */}
                      <td style={styles.monoCell}>
                        {inc.priority ? (
                          <span className="badge status-detected" style={{ fontSize: '0.65rem', padding: '0.12rem 0.35rem' }}>{inc.priority}</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>

                      <td>
                        <Badge type="status" value={inc.status || 'Open'} />
                      </td>

                      <td style={{ color: 'var(--text-secondary)' }} title={inc.affected_asset || inc.asset_name || inc.asset_id || 'N/A'}>
                        {inc.affected_asset || inc.asset_name || inc.asset_id || 'N/A'}
                      </td>

                      <td title={inc.affected_user || inc.username || 'N/A'}>
                        {inc.affected_user || inc.username || 'N/A'}
                      </td>

                      <td style={styles.monoCell}>
                        {(inc.ml_confidence !== undefined && inc.ml_confidence !== null) 
                          ? `${inc.ml_confidence}%` 
                          : (inc.confidence_score !== undefined && inc.confidence_score !== null) 
                            ? `${inc.confidence_score}%` 
                            : '—'}
                      </td>

                      <td>
                        <div style={{ display: 'flex', gap: '0.2rem', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                          {(inc.mitre_techniques || inc.mitre_technique || []).length > 0 ? (
                            (inc.mitre_techniques || inc.mitre_technique).slice(0, 2).map((t, idx) => (
                              <span key={idx} className="badge severity-high" style={{ fontSize: '0.62rem', padding: '0.1rem 0.3rem' }} title={t}>
                                {t}
                              </span>
                            ))
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>—</span>
                          )}
                        </div>
                      </td>

                      <td>
                        <span className={`badge ${inc.ioc_status === 'Hit' || inc.ioc_status === true ? 'severity-critical' : 'status-success'}`} style={{ fontSize: '0.64rem', padding: '0.12rem 0.35rem' }}>
                          {inc.ioc_status === 'Hit' || inc.ioc_status === true ? 'Hit' : 'Clean'}
                        </span>
                      </td>

                      <td style={{ textAlign: 'center' }}>
                        <button
                          className="soc-button"
                          onClick={(e) => {
                            e.stopPropagation();
                            loadIncidentDetail(inc.incident_id);
                          }}
                          style={{
                            fontSize: '0.68rem',
                            padding: '0.2rem 0.45rem',
                            backgroundColor: 'rgba(6, 182, 212, 0.1)',
                            borderColor: 'var(--color-accent)',
                            color: 'var(--color-accent)',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.2rem',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          <Eye size={11} />
                          <span>Investigate</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls */}
            <div style={styles.paginationFooter}>
              <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
                <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong> ({totalCount.toLocaleString()} incidents)
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
    gap: '1.25rem',
    width: '100%',
    boxSizing: 'border-box'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem',
    marginBottom: '0.25rem'
  },
  pageHeading: {
    fontSize: '1.25rem',
    fontWeight: '700',
    margin: 0,
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '-0.01em'
  },
  pageSubtitle: {
    fontSize: '0.8rem',
    marginTop: '0.25rem',
    marginBottom: 0,
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1.25rem'
  },
  investigationWorkspace: {
    padding: '1.25rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--color-accent)',
    borderRadius: '8px',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem'
  },
  detailGridColumns: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: '1rem',
    marginTop: '0.5rem'
  },
  subCard: {
    padding: '1rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.65rem'
  },
  subCardTitle: {
    fontSize: '0.85rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0,
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem'
  },
  detailsListGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '0.6rem 1rem'
  },
  detailItem: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.15rem'
  },
  detailLabel: {
    fontSize: '0.68rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  detailValueMono: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem',
    color: 'var(--text-primary)'
  },
  formLabel: {
    fontSize: '0.72rem',
    fontWeight: '600',
    color: 'var(--text-secondary)',
    marginBottom: '0.25rem',
    display: 'block'
  },
  tablePanel: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  tableToolbarHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  toolbarControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    flexWrap: 'wrap'
  },
  searchWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  searchIcon: {
    position: 'absolute',
    left: '0.6rem',
    pointerEvents: 'none'
  },
  searchInput: {
    padding: '0.35rem 0.6rem 0.35rem 1.85rem',
    borderRadius: '6px',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    color: 'var(--text-primary)',
    fontSize: '0.78rem',
    minWidth: '220px'
  },
  selectFilter: {
    padding: '0.35rem 0.6rem',
    borderRadius: '6px',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    color: 'var(--text-primary)',
    fontSize: '0.78rem'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  paginationFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: '0.75rem',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  statePanel: {
    minHeight: '180px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  },
  successBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.65rem 0.85rem',
    backgroundColor: 'rgba(34, 197, 94, 0.1)',
    border: '1px solid rgba(34, 197, 94, 0.3)',
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
  }
};

export default IncidentResponsePage;
