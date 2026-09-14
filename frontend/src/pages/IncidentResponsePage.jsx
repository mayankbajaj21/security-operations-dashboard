import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  getIncidents, 
  getIncident, 
  updateIncidentStatus, 
  getRecommendations,
  submitIncidentFeedback,
  submitPredictionFeedback,
  getRiskComparison,
  getIncidentAttackChain,
  getIncidentFilters
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
  ArrowLeft,
  GitCommit,
  ExternalLink,
  Info,
  Filter,
  RotateCcw,
  Calendar
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
const IncidentResponsePage = ({ initialIncidentId = null, onInvestigateEvent = null }) => {
  // Incidents Data State
  const [incidentsList, setIncidentsList] = useState([]);
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Milestone 4 — Task 9: EXACT 10 FILTERS STATE
  const [severityFilter, setSeverityFilter] = useState('');
  const [riskLevelFilter, setRiskLevelFilter] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('');
  const [assetFilter, setAssetFilter] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('');
  const [mitreFilter, setMitreFilter] = useState('');
  const [cveFilter, setCveFilter] = useState('');
  const [iocStatusFilter, setIocStatusFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [startDateFilter, setStartDateFilter] = useState('');
  const [endDateFilter, setEndDateFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterOptions, setFilterOptions] = useState(null);

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

  // Milestone 4 — Task 5: Attack Chain State
  const [attackChainData, setAttackChainData] = useState(null);
  const [selectedStage, setSelectedStage] = useState(null);

  // Fetch All Incidents from GET /api/v1/incidents and dynamic filter choices
  const fetchIncidentsData = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      const [res, filterRes] = await Promise.all([
        getIncidents({ limit: 100 }, { noCache: isManual }),
        getIncidentFilters().catch(() => null)
      ]);
      const rawData = res?.data || [];
      setIncidentsList(rawData);
      if (filterRes) {
        setFilterOptions(filterRes);
      }
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

  // Load single incident details + recommendations + attack chain when an incident is clicked/selected
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
    setAttackChainData(null);
    setSelectedStage(null);
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
      const [incRes, recsRes, chainRes] = await Promise.all([
        getIncident(cleanId, { noCache: true }),
        getRecommendations(cleanId, { noCache: true }).catch(() => null),
        getIncidentAttackChain(cleanId, { noCache: true }).catch(() => null)
      ]);

      if (!incRes || !incRes.incident_id) {
        throw new Error(`Incident "${cleanId}" not found in security backend.`);
      }

      setIncidentDetail(incRes);
      setRecommendationsData(recsRes);
      setAttackChainData(chainRes);
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
    setAttackChainData(null);
    setSelectedStage(null);
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
      // Resolve authentic analyst identity from current authenticated user session if present
      let authenticatedAnalyst = null;
      try {
        const rawUser = localStorage.getItem('soc_analyst_user') || sessionStorage.getItem('soc_analyst_user');
        if (rawUser) {
          const parsed = JSON.parse(rawUser);
          authenticatedAnalyst = (parsed.full_name || parsed.name || parsed.email || '').trim() || null;
        }
      } catch (e) {}

      const analystName = authenticatedAnalyst || assigneeInput.trim() || incidentDetail.assigned_to || 'SOC Analyst';
      const payload = {
        label: targetLabel,
        comment: feedbackComment ? feedbackComment.trim() : null,
        analyst: analystName
      };

      const updated = await submitIncidentFeedback(selectedIncidentId, payload);
      
      // Also persist to MongoDB analyst_feedback collection for the correlated event (Task 13)
      const primaryEvt = incidentDetail.related_events?.[0] || incidentDetail.event_ids?.[0];
      if (primaryEvt) {
        submitPredictionFeedback(primaryEvt, {
          event_id: primaryEvt,
          actual_feedback: targetLabel,
          prediction: incidentDetail.threat_type || 'Suspicious',
          analyst: analystName,
          comment: feedbackComment ? feedbackComment.trim() : null
        }).catch(() => null);
      }

      setIncidentDetail(updated);
      setFeedbackLabel(updated.feedback?.label || targetLabel);
      setFeedbackComment(updated.feedback?.comment || '');
      setFeedbackSuccess(`Analyst feedback "${targetLabel}" recorded and persisted to database.`);
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

  // Milestone 4 — Task 9: Filter ALL incidents by the EXACT 10 filters + search query
  const filteredIncidents = useMemo(() => {
    return incidentsList.filter((inc) => {
      // 1. Severity filter
      if (severityFilter && severityFilter !== 'All') {
        const s = (inc.severity || inc.risk_level || '').toLowerCase();
        if (s !== severityFilter.toLowerCase()) return false;
      }
      // 2. Risk level filter
      if (riskLevelFilter && riskLevelFilter !== 'All') {
        if ((inc.risk_level || '').toLowerCase() !== riskLevelFilter.toLowerCase()) return false;
      }
      // 3. Threat type filter
      if (threatTypeFilter && threatTypeFilter !== 'All') {
        if ((inc.threat_type || '').toLowerCase() !== threatTypeFilter.toLowerCase()) return false;
      }
      // 4. Asset filter
      if (assetFilter && assetFilter !== 'All') {
        const aTarget = assetFilter.toLowerCase();
        const incAsset = (inc.affected_asset || inc.asset_name || inc.asset_id || '').toLowerCase();
        if (!incAsset.includes(aTarget)) return false;
      }
      // 5. Department filter
      if (departmentFilter && departmentFilter !== 'All') {
        const dTarget = departmentFilter.toLowerCase();
        if (dTarget === 'unknown' || dTarget === 'n/a' || dTarget === 'none') {
          if (inc.department && !['unknown', 'n/a', 'none'].includes(String(inc.department).toLowerCase())) {
            return false;
          }
        } else {
          if ((inc.department || '').toLowerCase() !== dTarget) return false;
        }
      }
      // 6. MITRE technique filter
      if (mitreFilter && mitreFilter !== 'All') {
        const mTarget = mitreFilter.toLowerCase();
        const incMitre = (inc.mitre_techniques || inc.mitre_technique || []).map((t) => String(t).toLowerCase());
        if (!incMitre.some((t) => t.includes(mTarget))) return false;
      }
      // 7. CVE filter
      if (cveFilter && cveFilter !== 'All') {
        const cTarget = cveFilter.toLowerCase();
        if (!(inc.cve_id || '').toLowerCase().includes(cTarget)) return false;
      }
      // 8. IOC Status filter
      if (iocStatusFilter && iocStatusFilter !== 'All') {
        if ((inc.ioc_status || '').toLowerCase() !== iocStatusFilter.toLowerCase()) return false;
      }
      // 9. Incident Status filter
      if (statusFilter && statusFilter !== 'All') {
        if ((inc.status || '').toLowerCase() !== statusFilter.toLowerCase()) return false;
      }
      // 10. Date Range filter
      if (startDateFilter && inc.created_at) {
        if (inc.created_at.slice(0, 10) < startDateFilter) return false;
      }
      if (endDateFilter && inc.created_at) {
        if (inc.created_at.slice(0, 10) > endDateFilter) return false;
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
  }, [
    incidentsList,
    severityFilter,
    riskLevelFilter,
    threatTypeFilter,
    assetFilter,
    departmentFilter,
    mitreFilter,
    cveFilter,
    iocStatusFilter,
    statusFilter,
    startDateFilter,
    endDateFilter,
    searchQuery
  ]);

  // Active filter count for badge indicator
  const activeFilterCount = useMemo(() => {
    let cnt = 0;
    if (severityFilter && severityFilter !== 'All') cnt++;
    if (riskLevelFilter && riskLevelFilter !== 'All') cnt++;
    if (threatTypeFilter && threatTypeFilter !== 'All') cnt++;
    if (assetFilter && assetFilter !== 'All') cnt++;
    if (departmentFilter && departmentFilter !== 'All') cnt++;
    if (mitreFilter && mitreFilter !== 'All') cnt++;
    if (cveFilter && cveFilter !== 'All') cnt++;
    if (iocStatusFilter && iocStatusFilter !== 'All') cnt++;
    if (statusFilter && statusFilter !== 'All') cnt++;
    if (startDateFilter || endDateFilter) cnt++;
    if (searchQuery.trim()) cnt++;
    return cnt;
  }, [
    severityFilter,
    riskLevelFilter,
    threatTypeFilter,
    assetFilter,
    departmentFilter,
    mitreFilter,
    cveFilter,
    iocStatusFilter,
    statusFilter,
    startDateFilter,
    endDateFilter,
    searchQuery
  ]);

  // Reset all 10 filters
  const handleResetAllFilters = () => {
    setSeverityFilter('');
    setRiskLevelFilter('');
    setThreatTypeFilter('');
    setAssetFilter('');
    setDepartmentFilter('');
    setMitreFilter('');
    setCveFilter('');
    setIocStatusFilter('');
    setStatusFilter('');
    setStartDateFilter('');
    setEndDateFilter('');
    setSearchQuery('');
    setPage(1);
  };

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

            {/* Task 4: Threat Investigation Core Details & Risk Factors */}
            <div style={styles.detailGridColumns}>
              {/* Card 1: Incident Details (12 exact fields) */}
              <div style={styles.subCard}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <h4 style={styles.subCardTitle}>
                    <FileText size={15} color="var(--color-accent)" />
                    <span>Incident Details</span>
                  </h4>
                  <span className="badge status-detected" style={{ fontSize: '0.7rem' }}>
                    12 Investigation Fields
                  </span>
                </div>
                <div style={styles.detailsListGrid}>
                  {/* 1. Incident ID */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Incident ID:</span>
                    <span style={styles.detailValueMono}>
                      <strong style={{ color: 'var(--color-accent)' }}>{incidentDetail.incident_id}</strong>
                    </span>
                  </div>

                  {/* 2. Threat Type */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Threat Type:</span>
                    <span style={{ fontWeight: '700', color: 'var(--text-primary)' }}>
                      {incidentDetail.threat_type || incidentDetail.threat_category || 'N/A'}
                    </span>
                  </div>

                  {/* 3. Risk Score */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Risk Score:</span>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: '800',
                      fontSize: '1rem',
                      color: incidentDetail.risk_score >= 81 ? 'var(--color-critical)' : incidentDetail.risk_score >= 61 ? 'var(--color-high)' : 'var(--color-accent)'
                    }}>
                      {incidentDetail.risk_score !== undefined && incidentDetail.risk_score !== null ? incidentDetail.risk_score : 'N/A'}{' '}
                      <span style={{ fontSize: '0.68rem', opacity: 0.7 }}>/ 100</span>
                    </span>
                  </div>

                  {/* 4. Risk Level */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Risk Level:</span>
                    <Badge type="severity" value={incidentDetail.risk_level || 'N/A'} />
                  </div>

                  {/* 5. Confidence */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Confidence:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--text-primary)' }}>
                      {(incidentDetail.confidence_score !== undefined && incidentDetail.confidence_score !== null)
                        ? `${incidentDetail.confidence_score}%`
                        : ((incidentDetail.ml_confidence !== undefined && incidentDetail.ml_confidence !== null)
                          ? `${incidentDetail.ml_confidence}%`
                          : 'N/A')}
                    </span>
                  </div>

                  {/* 6. Affected Asset */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Affected Asset:</span>
                    <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                      {incidentDetail.affected_asset || incidentDetail.asset_name || incidentDetail.asset_id || 'N/A'}
                    </span>
                  </div>

                  {/* 7. Source IP */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>Source IP:</span>
                    <span style={styles.detailValueMono}>{incidentDetail.source_ip || 'N/A'}</span>
                  </div>

                  {/* 8. User */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>User:</span>
                    <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                      {incidentDetail.affected_user || incidentDetail.username || 'N/A'}
                    </span>
                  </div>

                  {/* 9. IOC */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>IOC:</span>
                    <span className={`badge ${incidentDetail.ioc_status === 'Hit' || incidentDetail.ioc_status === 'Malicious' || incidentDetail.ioc_status === true ? 'severity-critical' : 'status-success'}`}>
                      {incidentDetail.ioc_status === true ? 'Malicious' : (incidentDetail.ioc_status || 'N/A')}
                    </span>
                  </div>

                  {/* 10. MITRE Technique */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>MITRE Technique:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                      {(incidentDetail.mitre_techniques && incidentDetail.mitre_techniques.length > 0)
                        ? incidentDetail.mitre_techniques.join(', ')
                        : ((incidentDetail.mitre_technique && incidentDetail.mitre_technique.length > 0)
                          ? incidentDetail.mitre_technique.join(', ')
                          : 'N/A')}
                    </span>
                  </div>

                  {/* 11. CVE */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>CVE:</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '600', color: incidentDetail.cve_id ? 'var(--color-accent)' : 'var(--text-muted)' }}>
                      {incidentDetail.cve_id || 'N/A'}
                    </span>
                  </div>

                  {/* 12. CVSS */}
                  <div style={styles.detailItem}>
                    <span style={styles.detailLabel}>CVSS:</span>
                    <span style={{
                      fontFamily: 'var(--font-mono)',
                      fontWeight: '700',
                      color: (incidentDetail.cvss_score !== null && incidentDetail.cvss_score !== undefined && incidentDetail.cvss_score >= 7.0)
                        ? 'var(--color-critical)'
                        : 'var(--text-primary)'
                    }}>
                      {(incidentDetail.cvss_score !== null && incidentDetail.cvss_score !== undefined)
                        ? incidentDetail.cvss_score
                        : 'N/A'}
                    </span>
                  </div>
                </div>

                {/* Additional Triage Meta Bar */}
                <div style={{ marginTop: '0.4rem', paddingTop: '0.5rem', borderTop: '1px solid var(--border-color)', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.4rem', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  <span>Priority: <strong style={{ color: 'var(--text-primary)' }}>{incidentDetail.priority || '—'}</strong></span>
                  <span>Status: <strong style={{ color: 'var(--color-accent)' }}>{incidentDetail.status || 'Open'}</strong></span>
                  <span>Assigned: <strong style={{ color: 'var(--text-primary)' }}>{incidentDetail.assigned_to || incidentDetail.assignee || 'Unassigned'}</strong></span>
                  <span>Created: <span style={{ fontFamily: 'var(--font-mono)' }}>{incidentDetail.created_at ? String(incidentDetail.created_at).replace('T', ' ').slice(0, 19) : 'N/A'}</span></span>
                </div>
              </div>

              {/* Card 2: Risk Factors (6 exact factors) */}
              <div style={styles.subCard}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <h4 style={styles.subCardTitle}>
                    <AlertTriangle size={15} color="var(--color-accent)" />
                    <span>Risk Factors</span>
                  </h4>
                  <span className="badge severity-critical" style={{ fontSize: '0.7rem' }}>
                    Authoritative M3 Factors
                  </span>
                </div>

                <div style={styles.riskFactorCard}>
                  {[
                    { key: 'critical_asset', label: 'Critical asset', desc: 'Asset criticality established as Critical in M3' },
                    { key: 'high_ml_confidence', label: 'High ML confidence', desc: 'ML threat confidence score >= 80%' },
                    { key: 'malicious_ioc', label: 'Malicious IOC', desc: 'Active threat intel Indicator of Compromise match' },
                    { key: 'high_cvss', label: 'High CVSS', desc: 'Vulnerability exposure with CVSS >= 7.0' },
                    { key: 'multiple_related_events', label: 'Multiple related events', desc: 'Attack correlation across > 1 security event' },
                    { key: 'ransomware_behavior_detected', label: 'Ransomware behavior detected', desc: 'Ransomware behavioral classification signature' }
                  ].map((rf) => {
                    const isTriggered = incidentDetail.risk_factors
                      ? Boolean(incidentDetail.risk_factors[rf.key])
                      : false;

                    return (
                      <div
                        key={rf.key}
                        style={{
                          ...styles.riskFactorItem,
                          borderColor: isTriggered ? 'rgba(244, 63, 94, 0.35)' : 'var(--border-color)',
                          backgroundColor: isTriggered ? 'rgba(244, 63, 94, 0.05)' : 'var(--bg-card)'
                        }}
                      >
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
                          <span style={{ fontSize: '0.82rem', fontWeight: '700', color: isTriggered ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                            {rf.label}
                          </span>
                          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                            {rf.desc}
                          </span>
                        </div>

                        <div>
                          {isTriggered ? (
                            <span className="badge severity-critical" style={{ fontSize: '0.72rem', display: 'inline-flex', alignItems: 'center', gap: '0.3rem', padding: '0.2rem 0.55rem' }}>
                              <Flame size={12} />
                              <span>Active</span>
                            </span>
                          ) : (
                            <span className="badge status-success" style={{ fontSize: '0.72rem', opacity: 0.7, padding: '0.2rem 0.55rem' }}>
                              ○ Inactive
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
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

            {/* Milestone 4 — Task 5: Attack Chain & Multi-Stage Kill Chain Progression */}
            <div style={{ marginTop: '0.75rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <GitCommit size={17} color="var(--color-accent)" />
                  <h4 style={{ margin: 0, fontSize: '0.9rem', fontWeight: '700', color: 'var(--color-accent)' }}>
                    Attack Chain & Kill-Chain Progression
                  </h4>
                  {attackChainData?.attack_chain_id && (
                    <span className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                      {attackChainData.attack_chain_id}
                    </span>
                  )}
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  Click any stage to reveal Event ID, Timestamp, Source, Destination, User, MITRE Technique & Risk
                </span>
              </div>

              {/* Stages List */}
              {attackChainData?.stages && attackChainData.stages.length > 0 ? (
                <div style={{ display: 'flex', gap: '0.75rem', overflowX: 'auto', paddingBottom: '0.5rem', alignItems: 'stretch' }}>
                  {attackChainData.stages.map((stg, sIdx) => {
                    const isSelected = selectedStage?.stage_number === stg.stage_number && selectedStage?.event_id === stg.event_id;
                    return (
                      <div
                        key={sIdx}
                        onClick={() => setSelectedStage(stg)}
                        style={{
                          flex: '1 1 200px',
                          minWidth: '190px',
                          padding: '0.75rem',
                          borderRadius: '6px',
                          backgroundColor: isSelected ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
                          border: isSelected ? '1.5px solid var(--color-accent)' : '1px solid var(--border-color)',
                          cursor: 'pointer',
                          display: 'flex',
                          flexDirection: 'column',
                          justifyContent: 'space-between',
                          gap: '0.4rem',
                          transition: 'all 0.15s ease'
                        }}
                        title={`Stage ${stg.stage_number}: ${stg.stage_name} — Click to inspect stage telemetry`}
                      >
                        <div>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.3rem', marginBottom: '0.2rem' }}>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--color-accent)', textTransform: 'uppercase' }}>
                              Stage {stg.stage_number}
                            </span>
                            <span className="badge severity-high" style={{ fontSize: '0.65rem' }}>
                              {stg.risk}
                            </span>
                          </div>
                          <span style={{ fontSize: '0.82rem', fontWeight: '700', color: 'var(--text-primary)', display: 'block' }}>
                            {stg.stage_name}
                          </span>
                        </div>

                        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '0.35rem', display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                          <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                            Event: <strong style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{stg.event_id}</strong>
                          </span>
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                            {stg.timestamp !== 'N/A' ? stg.timestamp : 'Timestamp: N/A'}
                          </span>
                        </div>

                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.25rem', marginTop: '0.1rem' }}>
                          <span style={{ fontSize: '0.65rem', color: 'var(--color-accent)', fontWeight: '600' }}>
                            {isSelected ? 'Viewing details ▼' : 'Click to inspect →'}
                          </span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderRadius: '4px', border: '1px solid var(--border-color)' }}>
                  <span className="muted" style={{ fontSize: '0.78rem' }}>
                    No attack chain stages available for this incident.
                  </span>
                </div>
              )}

              {/* Selected Stage Detail Drawer / Panel (Revealing all 7 required fields) */}
              {selectedStage && (
                <div style={{ marginTop: '0.75rem', padding: '0.85rem 1rem', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--color-accent)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.4rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <Info size={16} color="var(--color-accent)" />
                      <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--color-accent)' }}>
                        Stage {selectedStage.stage_number} Details: {selectedStage.stage_name}
                      </span>
                    </div>
                    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                      {onInvestigateEvent && selectedStage.event_id && selectedStage.event_id !== 'N/A' && (
                        <button
                          type="button"
                          className="soc-button"
                          onClick={() => onInvestigateEvent(selectedStage.event_id)}
                          style={{
                            fontSize: '0.75rem',
                            backgroundColor: 'var(--color-accent)',
                            color: '#000',
                            fontWeight: '700',
                            padding: '0.25rem 0.65rem'
                          }}
                          title={`Drill down to Event Investigation for ${selectedStage.event_id}`}
                        >
                          <ExternalLink size={12} style={{ marginRight: '0.25rem' }} />
                          <span>Investigate Event ({selectedStage.event_id}) →</span>
                        </button>
                      )}
                      <button
                        type="button"
                        className="soc-button"
                        onClick={() => setSelectedStage(null)}
                        style={{ fontSize: '0.72rem', padding: '0.2rem 0.5rem' }}
                      >
                        ✕ Close
                      </button>
                    </div>
                  </div>

                  {/* Exactly the 7 Required Fields per M4 Task 5 */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.6rem' }}>
                    {/* 1. Event ID */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>Event ID:</span>
                      <span style={styles.detailValueMono}>
                        <strong style={{ color: 'var(--color-accent)' }}>{selectedStage.event_id || 'N/A'}</strong>
                      </span>
                    </div>

                    {/* 2. Timestamp */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>Timestamp:</span>
                      <span style={styles.detailValueMono}>{selectedStage.timestamp || 'N/A'}</span>
                    </div>

                    {/* 3. Source */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>Source:</span>
                      <span style={styles.detailValueMono}>{selectedStage.source || 'N/A'}</span>
                    </div>

                    {/* 4. Destination */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>Destination:</span>
                      <span style={styles.detailValueMono}>{selectedStage.destination || 'N/A'}</span>
                    </div>

                    {/* 5. User */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>User:</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{selectedStage.user || 'N/A'}</span>
                    </div>

                    {/* 6. MITRE Technique */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>MITRE Technique:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-high)', fontWeight: '600' }}>
                        {selectedStage.mitre_technique || 'N/A'}
                      </span>
                    </div>

                    {/* 7. Risk */}
                    <div style={styles.detailItem}>
                      <span style={styles.detailLabel}>Risk:</span>
                      <span style={{ fontWeight: '700', color: 'var(--color-critical)' }}>
                        {selectedStage.risk || 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>
              )}
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

            {/* DEDICATED ANALYST FEEDBACK SECTION (Milestone 4 Task 13) */}
            <div style={{ marginTop: '0.75rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <ShieldCheck size={16} color="var(--color-accent)" />
                  <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                    AI Prediction &amp; Analyst Feedback (Task 13)
                  </span>
                </div>
                <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>
                  AI Prediction ≠ Analyst Feedback • Dedicated MongoDB persistence
                </span>
              </div>

              {/* Explicit AI Prediction Display */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', padding: '0.5rem 0.75rem', backgroundColor: 'var(--bg-card)', borderRadius: '6px', border: '1px solid var(--border-subtle)', marginBottom: '0.6rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: '600' }}>AI Prediction:</span>
                <span className="badge status-detected" style={{ fontWeight: '700', fontSize: '0.78rem' }}>
                  {incidentDetail.threat_type || 'Suspicious'}
                </span>
                {incidentDetail.ml_confidence !== null && (
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                    ({incidentDetail.ml_confidence}% ML Confidence)
                  </span>
                )}
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
                      <span className={`badge ${incidentDetail.feedback.label === 'True Positive' || incidentDetail.feedback.label === 'Correct' ? 'severity-critical' : 'status-success'}`} style={{ fontSize: '0.75rem' }}>
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
                    Analyst Feedback:
                  </span>
                  <button
                    type="button"
                    className="soc-button"
                    onClick={() => setFeedbackLabel('Correct')}
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.7rem',
                      backgroundColor: feedbackLabel === 'Correct' || feedbackLabel === 'True Positive' ? 'rgba(34, 197, 94, 0.2)' : 'transparent',
                      borderColor: feedbackLabel === 'Correct' || feedbackLabel === 'True Positive' ? 'var(--color-success)' : 'var(--border-color)',
                      color: feedbackLabel === 'Correct' || feedbackLabel === 'True Positive' ? 'var(--color-success)' : 'var(--text-secondary)',
                      fontWeight: feedbackLabel === 'Correct' || feedbackLabel === 'True Positive' ? '700' : '400'
                    }}
                  >
                    ✓ Correct (True Positive)
                  </button>
                  <button
                    type="button"
                    className="soc-button"
                    onClick={() => setFeedbackLabel('False Positive')}
                    style={{
                      fontSize: '0.75rem',
                      padding: '0.3rem 0.7rem',
                      backgroundColor: feedbackLabel === 'False Positive' ? 'rgba(244, 63, 94, 0.2)' : 'transparent',
                      borderColor: feedbackLabel === 'False Positive' ? 'var(--color-critical)' : 'var(--border-color)',
                      color: feedbackLabel === 'False Positive' ? 'var(--color-critical)' : 'var(--text-secondary)',
                      fontWeight: feedbackLabel === 'False Positive' ? '700' : '400'
                    }}
                  >
                    ✗ False Positive
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

          {/* Milestone 4 — Task 9: Advanced Filter Bar (Exact 10 Filters) */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem', padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Filter size={15} color="var(--color-accent)" />
                <span style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  Advanced Multi-Filter Engine (10 Filters)
                </span>
                {activeFilterCount > 0 && (
                  <span className="badge status-detected" style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem' }}>
                    {activeFilterCount} Active
                  </span>
                )}
              </div>

              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <div style={styles.searchWrapper}>
                  <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
                  <input
                    type="text"
                    placeholder="Search ID, Threat, Asset, User..."
                    value={searchQuery}
                    onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                    style={{ ...styles.searchInput, minWidth: '220px' }}
                  />
                </div>

                {activeFilterCount > 0 && (
                  <button
                    className="soc-button"
                    onClick={handleResetAllFilters}
                    style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem', display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--color-critical)' }}
                    title="Reset all 10 filters"
                  >
                    <RotateCcw size={12} />
                    <span>Reset All</span>
                  </button>
                )}
              </div>
            </div>

            {/* 10 Filters Form Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.5rem' }}>
              {/* 1. Severity */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>1. Severity</label>
                <select
                  value={severityFilter}
                  onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Severity: All</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              {/* 2. Risk Level */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>2. Risk Level</label>
                <select
                  value={riskLevelFilter}
                  onChange={(e) => { setRiskLevelFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Risk Level: All</option>
                  <option value="Critical">Critical (81–100)</option>
                  <option value="High">High (61–80)</option>
                  <option value="Moderate">Moderate (41–60)</option>
                  <option value="Medium">Medium (21–40)</option>
                  <option value="Low">Low (0–20)</option>
                </select>
              </div>

              {/* 3. Threat Type */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>3. Threat Type</label>
                <select
                  value={threatTypeFilter}
                  onChange={(e) => { setThreatTypeFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Threat: All</option>
                  {(filterOptions?.threat_types || ['Brute Force', 'DDoS', 'Malware', 'Port Scan', 'SQL Injection', 'Unauthorized Access', 'Data Exfiltration']).map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>

              {/* 4. Asset */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>4. Asset</label>
                <select
                  value={assetFilter}
                  onChange={(e) => { setAssetFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Asset: All</option>
                  {(filterOptions?.assets || ['Database-01', 'WebServer', 'Firewall', 'HR-PC-01', 'Finance-PC-02']).map((a) => (
                    <option key={a} value={a}>{a}</option>
                  ))}
                </select>
              </div>

              {/* 5. Department */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>5. Department</label>
                <select
                  value={departmentFilter}
                  onChange={(e) => { setDepartmentFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Dept: All</option>
                  {(filterOptions?.departments || ['IT', 'Finance', 'HR', 'Operations', 'Engineering']).map((d) => (
                    <option key={d} value={d}>{d}</option>
                  ))}
                </select>
              </div>

              {/* 6. MITRE Technique */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>6. MITRE Technique</label>
                <select
                  value={mitreFilter}
                  onChange={(e) => { setMitreFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">MITRE: All</option>
                  {(filterOptions?.mitre_techniques || ['T1110', 'T1078', 'T1059', 'T1498', 'T1190']).map((m) => (
                    <option key={m} value={m}>{m}</option>
                  ))}
                </select>
              </div>

              {/* 7. CVE */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>7. CVE</label>
                <select
                  value={cveFilter}
                  onChange={(e) => { setCveFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">CVE: All</option>
                  {(filterOptions?.cves || ['CVE-2023-1234', 'CVE-2024-1045', 'CVE-2024-2201']).map((c) => (
                    <option key={c} value={c}>{c}</option>
                  ))}
                </select>
              </div>

              {/* 8. IOC Status */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>8. IOC Status</label>
                <select
                  value={iocStatusFilter}
                  onChange={(e) => { setIocStatusFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">IOC: All</option>
                  <option value="Malicious">Malicious</option>
                  <option value="Suspicious">Suspicious</option>
                  <option value="Clean">Clean</option>
                  <option value="Unknown">Unknown</option>
                </select>
              </div>

              {/* 9. Incident Status */}
              <div>
                <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>9. Incident Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                  style={{ ...styles.selectFilter, width: '100%' }}
                >
                  <option value="">Status: All</option>
                  <option value="Open">Open</option>
                  <option value="Investigating">Investigating</option>
                  <option value="Resolved">Resolved</option>
                  <option value="False Positive">False Positive</option>
                </select>
              </div>

              {/* 10. Date Range (Start / End) */}
              <div style={{ display: 'flex', gap: '0.35rem' }}>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>10. Start Date</label>
                  <input
                    type="date"
                    value={startDateFilter}
                    onChange={(e) => { setStartDateFilter(e.target.value); setPage(1); }}
                    style={{ ...styles.searchInput, width: '100%', fontSize: '0.72rem', padding: '0.3rem 0.4rem' }}
                  />
                </div>
                <div style={{ flex: 1 }}>
                  <label style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', marginBottom: '0.2rem' }}>End Date</label>
                  <input
                    type="date"
                    value={endDateFilter}
                    onChange={(e) => { setEndDateFilter(e.target.value); setPage(1); }}
                    style={{ ...styles.searchInput, width: '100%', fontSize: '0.72rem', padding: '0.3rem 0.4rem' }}
                  />
                </div>
              </div>
            </div>
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
  riskFactorCard: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.45rem'
  },
  riskFactorItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.5rem 0.75rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '4px',
    border: '1px solid var(--border-color)',
    transition: 'all 0.15s ease'
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
