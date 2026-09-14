import React, { useState, useEffect, useCallback, useMemo } from 'react';
import Badge from './Badge';
import { 
  AlertTriangle, 
  ShieldAlert, 
  ArrowRight, 
  Search, 
  Target, 
  Cpu, 
  Layers, 
  Lightbulb, 
  X, 
  ExternalLink,
  Shield,
  Clock,
  Flame,
  FileText
} from 'lucide-react';
import { getIncidents } from '../services/api';

/**
 * Milestone 4 — Module 4.3, Task 3: Critical Threat Panel
 * 
 * Prominent SOC Overview dashboard component providing authoritative triage
 * of Critical Security Incidents (Risk Level = Critical, Priority = P1).
 * 
 * Required M4 Table Columns:
 * 1. Incident
 * 2. Threat
 * 3. Asset
 * 4. Risk
 * 5. Priority
 * 6. Status
 * 
 * Clicking any incident row opens comprehensive incident details with
 * direct drill-down actions leading into the Threat Investigation functionality.
 */
const CriticalThreatPanel = ({
  incidents = null,
  isLoading = false,
  error = null,
  onInvestigateIncident,
  onInvestigateEvent,
  onViewAllIncidents
}) => {
  const [internalIncidents, setInternalIncidents] = useState(null);
  const [internalLoading, setInternalLoading] = useState(false);
  const [internalError, setInternalError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);

  // Self-fetching fallback if parent does not provide incidents prop
  const fetchCriticalIncidents = useCallback(async () => {
    if (incidents !== null) return;
    setInternalLoading(true);
    setInternalError(null);
    try {
      const res = await getIncidents({ risk_level: 'Critical', limit: 20 });
      const records = res?.data || (Array.isArray(res) ? res : []);
      setInternalIncidents(records);
    } catch (err) {
      console.error('Failed to load critical incidents:', err);
      setInternalError('Unable to load authoritative critical incidents from backend API.');
      setInternalIncidents([]);
    } finally {
      setInternalLoading(false);
    }
  }, [incidents]);

  useEffect(() => {
    if (incidents === null) {
      fetchCriticalIncidents();
    }
  }, [incidents, fetchCriticalIncidents]);

  // Use parent incidents if provided; otherwise use self-fetched internal data
  const criticalList = useMemo(() => {
    const raw = incidents !== null ? (Array.isArray(incidents) ? incidents : []) : (internalIncidents || []);
    // Ensure strict Critical filtering even if parent passed an unfiltered array
    return raw.filter((inc) => (inc.risk_level || '').toLowerCase() === 'critical');
  }, [incidents, internalIncidents]);

  const loadingState = isLoading || (incidents === null && (internalLoading || internalIncidents === null));
  const errorState = error || internalError;

  const formatTimestamp = (ts) => {
    if (!ts) return '—';
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

  const handleRowClick = (inc) => {
    setSelectedIncident(inc);
  };

  const handleCloseModal = () => {
    setSelectedIncident(null);
  };

  return (
    <div className="panel" style={styles.panelRoot}>
      {/* 1. HEADER ROW */}
      <div style={styles.headerRow}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          <div style={styles.iconBadge}>
            <ShieldAlert size={18} color="var(--color-critical)" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h3 className="section-title" style={styles.title}>
                Critical Threat Panel
              </h3>
              {!loadingState && (
                <span className="badge severity-critical" style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem' }}>
                  {criticalList.length} Critical
                </span>
              )}
            </div>
            <p className="muted" style={styles.subtitle}>
              Authoritative M3 security incidents requiring immediate SOC investigation & response
            </p>
          </div>
        </div>

        {onViewAllIncidents && (
          <button
            className="soc-button"
            onClick={onViewAllIncidents}
            style={styles.navButton}
            title="Navigate to complete Priority Incidents queue in Analytics Hub"
          >
            <span>View All Incidents</span>
            <ArrowRight size={13} />
          </button>
        )}
      </div>

      {/* 2. MAIN TABLE CONTENT AREA */}
      {loadingState ? (
        <div style={styles.stateContainer}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span className="spin" style={{ display: 'inline-block' }}>⟳</span>
            <p className="muted" style={{ fontSize: '0.84rem', margin: 0 }}>
              Loading authoritative critical incidents from security backend...
            </p>
          </div>
        </div>
      ) : errorState ? (
        <div style={styles.stateContainer}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-critical)' }}>
            <AlertTriangle size={18} />
            <span style={{ fontSize: '0.84rem' }}>{errorState}</span>
          </div>
        </div>
      ) : criticalList.length === 0 ? (
        <div style={styles.stateContainer}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--color-success)' }}>
            <Shield size={18} />
            <p className="muted" style={{ fontSize: '0.84rem', margin: 0 }}>
              No active critical security incidents detected. System posture is nominal.
            </p>
          </div>
        </div>
      ) : (
        <div className="soc-table-fit-container" style={{ marginTop: '0.65rem' }}>
          <table className="soc-table-fit">
            <thead>
              <tr>
                <th style={{ width: '15%' }}>Incident</th>
                <th style={{ width: '22%' }}>Threat</th>
                <th style={{ width: '18%' }}>Asset</th>
                <th style={{ width: '15%' }}>Risk</th>
                <th style={{ width: '14%' }}>Priority</th>
                <th style={{ width: '16%' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {criticalList.slice(0, 8).map((inc) => {
                const isResolved = (inc.status || '').toLowerCase() === 'resolved';
                const isOpen = (inc.status || '').toLowerCase() === 'open';

                return (
                  <tr
                    key={inc.incident_id}
                    onClick={() => handleRowClick(inc)}
                    className="soc-clickable-row"
                    style={{
                      cursor: 'pointer',
                      backgroundColor: isResolved 
                        ? 'transparent' 
                        : isOpen 
                        ? 'rgba(244, 63, 94, 0.05)' 
                        : 'rgba(234, 179, 8, 0.04)',
                      transition: 'background-color 0.15s ease'
                    }}
                    title={`Click to investigate ${inc.incident_id}`}
                  >
                    {/* 1. Incident */}
                    <td style={styles.monoCell}>
                      <span className="badge status-detected" style={{ fontWeight: '700', letterSpacing: '0.02em' }}>
                        {inc.incident_id}
                      </span>
                    </td>

                    {/* 2. Threat */}
                    <td>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)', display: 'block' }}>
                        {inc.threat_type || inc.title}
                      </span>
                      {inc.title && inc.threat_type && inc.title !== inc.threat_type && (
                        <span className="muted" style={{ fontSize: '0.72rem', display: 'block', maxWidth: '240px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {inc.title}
                        </span>
                      )}
                    </td>

                    {/* 3. Asset */}
                    <td>
                      <span style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>
                        {inc.affected_asset || inc.asset_name || inc.asset_id || 'Infrastructure'}
                      </span>
                    </td>

                    {/* 4. Risk */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '800', color: 'var(--color-critical)', fontSize: '0.85rem' }}>
                          {inc.risk_score}
                        </span>
                        <Badge type="severity" value={inc.risk_level || 'Critical'} />
                      </div>
                    </td>

                    {/* 5. Priority */}
                    <td style={styles.monoCell}>
                      <span className="badge severity-critical" style={{ fontWeight: '800', fontSize: '0.72rem' }}>
                        {inc.priority || 'P1'}
                      </span>
                    </td>

                    {/* 6. Status */}
                    <td>
                      <Badge type="status" value={inc.status || 'Open'} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* 3. INTERACTIVE INCIDENT DETAILS MODAL / DRILL-DOWN */}
      {selectedIncident && (
        <div style={styles.modalBackdrop} onClick={handleCloseModal}>
          <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
            {/* Modal Header */}
            <div style={styles.modalHeader}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                <ShieldAlert size={22} color="var(--color-critical)" />
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                      {selectedIncident.incident_id}
                    </h3>
                    <span className="badge severity-critical" style={{ fontWeight: '800' }}>
                      {selectedIncident.priority || 'P1'}
                    </span>
                    <Badge type="status" value={selectedIncident.status || 'Open'} />
                  </div>
                  <span className="muted" style={{ fontSize: '0.78rem', display: 'block', marginTop: '0.15rem' }}>
                    {selectedIncident.title || `${selectedIncident.threat_type} Incident`}
                  </span>
                </div>
              </div>

              <button 
                onClick={handleCloseModal}
                style={styles.closeBtn}
                title="Close Details Modal"
              >
                <X size={18} />
              </button>
            </div>

            {/* Modal Body */}
            <div style={styles.modalBody}>
              {/* Summary KPIs Row */}
              <div style={styles.summaryGrid}>
                <div style={styles.summaryCard}>
                  <span style={styles.summaryLabel}>Risk Score</span>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.35rem' }}>
                    <span style={{ fontSize: '1.25rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-critical)' }}>
                      {selectedIncident.risk_score}
                    </span>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>/ 100</span>
                  </div>
                </div>

                <div style={styles.summaryCard}>
                  <span style={styles.summaryLabel}>Threat Category</span>
                  <span style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                    {selectedIncident.threat_type || 'Unknown'}
                  </span>
                </div>

                <div style={styles.summaryCard}>
                  <span style={styles.summaryLabel}>Target Asset</span>
                  <span style={{ fontSize: '0.9rem', fontWeight: '700', color: 'var(--color-accent)' }}>
                    {selectedIncident.affected_asset || selectedIncident.asset_name || 'Infrastructure'}
                  </span>
                </div>

                <div style={styles.summaryCard}>
                  <span style={styles.summaryLabel}>Detected / Created</span>
                  <span style={{ fontSize: '0.78rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                    {formatTimestamp(selectedIncident.created_at)}
                  </span>
                </div>
              </div>

              {/* Task 4: Authoritative Threat Investigation Details (12 exact fields) */}
              <div style={styles.sectionBox}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.45rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <FileText size={15} color="var(--color-accent)" />
                    <span style={styles.sectionTitle}>INCIDENT DETAILS (12 FIELDS)</span>
                  </div>
                  <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
                    Authoritative M1 + M2 + M3
                  </span>
                </div>
                <div style={styles.metaGrid}>
                  {/* 1. Incident ID */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Incident ID:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                      {selectedIncident.incident_id}
                    </span>
                  </div>
                  {/* 2. Threat Type */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Threat Type:</span>
                    <span style={styles.metaValue}>
                      {selectedIncident.threat_type || selectedIncident.title || 'N/A'}
                    </span>
                  </div>
                  {/* 3. Risk Score */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Risk Score:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)', color: 'var(--color-critical)' }}>
                      {selectedIncident.risk_score !== undefined && selectedIncident.risk_score !== null ? `${selectedIncident.risk_score} / 100` : 'N/A'}
                    </span>
                  </div>
                  {/* 4. Risk Level */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Risk Level:</span>
                    <span style={styles.metaValue}>
                      <Badge type="severity" value={selectedIncident.risk_level || 'Critical'} />
                    </span>
                  </div>
                  {/* 5. Confidence */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Confidence:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)' }}>
                      {(selectedIncident.confidence_score !== undefined && selectedIncident.confidence_score !== null)
                        ? `${selectedIncident.confidence_score}%`
                        : ((selectedIncident.ml_confidence !== undefined && selectedIncident.ml_confidence !== null)
                          ? `${selectedIncident.ml_confidence}%`
                          : 'N/A')}
                    </span>
                  </div>
                  {/* 6. Affected Asset */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Affected Asset:</span>
                    <span style={styles.metaValue}>
                      {selectedIncident.affected_asset || selectedIncident.asset_name || selectedIncident.asset_id || 'N/A'}
                    </span>
                  </div>
                  {/* 7. Source IP */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>Source IP:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)' }}>
                      {selectedIncident.source_ip || 'N/A'}
                    </span>
                  </div>
                  {/* 8. User */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>User:</span>
                    <span style={styles.metaValue}>
                      {selectedIncident.affected_user || selectedIncident.username || 'N/A'}
                    </span>
                  </div>
                  {/* 9. IOC */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>IOC:</span>
                    <span style={styles.metaValue}>
                      <span className={`badge ${selectedIncident.ioc_status === 'Hit' || selectedIncident.ioc_status === 'Malicious' || selectedIncident.ioc_status === true ? 'severity-critical' : 'status-success'}`} style={{ fontSize: '0.72rem' }}>
                        {selectedIncident.ioc_status === true ? 'Malicious' : (selectedIncident.ioc_status || 'N/A')}
                      </span>
                    </span>
                  </div>
                  {/* 10. MITRE Technique */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>MITRE Technique:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                      {(selectedIncident.mitre_techniques && selectedIncident.mitre_techniques.length > 0)
                        ? selectedIncident.mitre_techniques.join(', ')
                        : ((selectedIncident.mitre_technique && selectedIncident.mitre_technique.length > 0)
                          ? selectedIncident.mitre_technique.join(', ')
                          : 'N/A')}
                    </span>
                  </div>
                  {/* 11. CVE */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>CVE:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)', color: selectedIncident.cve_id ? 'var(--color-accent)' : 'var(--text-muted)' }}>
                      {selectedIncident.cve_id || 'N/A'}
                    </span>
                  </div>
                  {/* 12. CVSS */}
                  <div>
                    <span className="muted" style={styles.metaLabel}>CVSS:</span>
                    <span style={{ ...styles.metaValue, fontFamily: 'var(--font-mono)', color: (selectedIncident.cvss_score !== null && selectedIncident.cvss_score !== undefined && selectedIncident.cvss_score >= 7.0) ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                      {(selectedIncident.cvss_score !== null && selectedIncident.cvss_score !== undefined) ? selectedIncident.cvss_score : 'N/A'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Task 4: Authoritative Risk Factors (6 exact factors) */}
              <div style={styles.sectionBox}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.45rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <AlertTriangle size={15} color="var(--color-accent)" />
                    <span style={styles.sectionTitle}>RISK FACTORS (6 AUTHORITATIVE M3 FACTORS)</span>
                  </div>
                  <span className="badge severity-critical" style={{ fontSize: '0.68rem' }}>
                    Multi-Factor Evaluation
                  </span>
                </div>

                <div style={styles.riskFactorGrid}>
                  {[
                    { key: 'critical_asset', label: 'Critical asset', desc: 'Asset criticality established as Critical in M3' },
                    { key: 'high_ml_confidence', label: 'High ML confidence', desc: 'ML threat confidence score >= 80%' },
                    { key: 'malicious_ioc', label: 'Malicious IOC', desc: 'Confirmed Threat Intel IOC match' },
                    { key: 'high_cvss', label: 'High CVSS', desc: 'Vulnerability exposure with CVSS >= 7.0' },
                    { key: 'multiple_related_events', label: 'Multiple related events', desc: 'Attack correlation across > 1 security event' },
                    { key: 'ransomware_behavior_detected', label: 'Ransomware behavior detected', desc: 'Ransomware behavioral classification signature' }
                  ].map((rf) => {
                    const isTriggered = selectedIncident.risk_factors
                      ? Boolean(selectedIncident.risk_factors[rf.key])
                      : false;

                    return (
                      <div
                        key={rf.key}
                        style={{
                          ...styles.riskFactorModalItem,
                          borderColor: isTriggered ? 'rgba(244, 63, 94, 0.35)' : 'var(--border-color)',
                          backgroundColor: isTriggered ? 'rgba(244, 63, 94, 0.05)' : 'var(--bg-card)'
                        }}
                      >
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.1rem' }}>
                          <span style={{ fontSize: '0.8rem', fontWeight: '700', color: isTriggered ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                            {rf.label}
                          </span>
                          <span style={{ fontSize: '0.66rem', color: 'var(--text-muted)' }}>
                            {rf.desc}
                          </span>
                        </div>

                        <div>
                          {isTriggered ? (
                            <span className="badge severity-critical" style={{ fontSize: '0.7rem', display: 'inline-flex', alignItems: 'center', gap: '0.25rem', padding: '0.15rem 0.45rem' }}>
                              <Flame size={11} />
                              <span>Active</span>
                            </span>
                          ) : (
                            <span className="badge status-success" style={{ fontSize: '0.7rem', opacity: 0.7, padding: '0.15rem 0.45rem' }}>
                              ○ Inactive
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Explainable AI (XAI) Detection Reasons */}
              {(selectedIncident.reasons && selectedIncident.reasons.length > 0) && (
                <div style={styles.sectionBox}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.45rem' }}>
                    <Cpu size={15} color="var(--color-accent)" />
                    <span style={styles.sectionTitle}>DETECTION & RISK ENGINE REASONS (XAI)</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                    {selectedIncident.reasons.map((r, idx) => (
                      <span key={idx} className="badge status-detected" style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem' }}>
                        • {r}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Prescriptive Analyst Mitigation Recommendations */}
              {(selectedIncident.recommendations && selectedIncident.recommendations.length > 0) && (
                <div style={{ ...styles.sectionBox, backgroundColor: 'rgba(6, 182, 212, 0.04)', borderColor: 'rgba(6, 182, 212, 0.2)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.45rem' }}>
                    <Lightbulb size={15} color="var(--color-accent)" />
                    <span style={{ ...styles.sectionTitle, color: 'var(--color-accent)' }}>PRESCRIPTIVE MITIGATION RECOMMENDATIONS</span>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                    {selectedIncident.recommendations.map((rec, idx) => (
                      <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.45rem' }}>
                        <ArrowRight size={13} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '3px' }} />
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', lineHeight: '1.4' }}>
                          {rec}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Correlated Event IDs */}
              {(selectedIncident.related_events && selectedIncident.related_events.length > 0) && (
                <div style={styles.sectionBox}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.45rem' }}>
                    <Layers size={15} color="var(--color-accent)" />
                    <span style={styles.sectionTitle}>CORRELATED TELEMETRY EVENTS ({selectedIncident.related_events.length})</span>
                  </div>
                  <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                    {selectedIncident.related_events.map((evtId, idx) => (
                      <span key={idx} className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                        {evtId}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Actions Footer: Direct Leads into Threat Investigation */}
            <div style={styles.modalFooter}>
              <button
                className="soc-button"
                onClick={handleCloseModal}
                style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem' }}
              >
                Close
              </button>

              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                {/* Optional Telemetry Event Investigation Drill-down */}
                {selectedIncident.related_events?.[0] && onInvestigateEvent && (
                  <button
                    className="soc-button"
                    onClick={() => {
                      const evtId = selectedIncident.related_events[0];
                      handleCloseModal();
                      onInvestigateEvent(evtId);
                    }}
                    style={{ fontSize: '0.78rem', padding: '0.4rem 0.8rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                    title={`Investigate telemetry event ${selectedIncident.related_events[0]} in Event Investigation Hub`}
                  >
                    <Search size={14} />
                    <span>Investigate Telemetry ({selectedIncident.related_events[0]})</span>
                  </button>
                )}

                {/* Primary Threat Investigation Workspace Lead */}
                {onInvestigateIncident && (
                  <button
                    className="soc-button"
                    onClick={() => {
                      const incId = selectedIncident.incident_id;
                      handleCloseModal();
                      onInvestigateIncident(incId);
                    }}
                    style={{ 
                      fontSize: '0.78rem', 
                      padding: '0.4rem 0.9rem', 
                      backgroundColor: 'var(--color-accent)', 
                      color: '#000', 
                      fontWeight: '700',
                      display: 'flex', 
                      alignItems: 'center', 
                      gap: '0.4rem' 
                    }}
                    title={`Open full investigation workspace for incident ${selectedIncident.incident_id}`}
                  >
                    <span>Open Threat Investigation Workspace</span>
                    <ExternalLink size={14} />
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const styles = {
  panelRoot: {
    padding: '1.15rem 1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '8px',
    border: '1px solid var(--border-color)'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem',
    marginBottom: '0.25rem'
  },
  iconBadge: {
    width: '32px',
    height: '32px',
    borderRadius: '6px',
    backgroundColor: 'rgba(244, 63, 94, 0.12)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  title: {
    fontSize: '1rem',
    fontWeight: '700',
    margin: 0,
    color: 'var(--text-primary)'
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
    justifyContent: 'center',
    padding: '1.5rem'
  },
  modalBackdrop: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.72)',
    backdropFilter: 'blur(3px)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1000,
    padding: '1rem'
  },
  modalContent: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '10px',
    width: '100%',
    maxWidth: '680px',
    maxHeight: '90vh',
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
    boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)'
  },
  modalHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '1.1rem 1.25rem',
    borderBottom: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-secondary)'
  },
  closeBtn: {
    background: 'none',
    border: 'none',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    padding: '0.25rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px'
  },
  modalBody: {
    padding: '1.25rem',
    overflowY: 'auto',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem'
  },
  summaryGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
    gap: '0.65rem'
  },
  summaryCard: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.65rem 0.8rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.2rem'
  },
  summaryLabel: {
    fontSize: '0.68rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em'
  },
  sectionBox: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.85rem 1rem'
  },
  sectionTitle: {
    fontSize: '0.72rem',
    fontWeight: '700',
    color: 'var(--color-accent)',
    letterSpacing: '0.04em'
  },
  metaGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '0.5rem',
    marginTop: '0.35rem'
  },
  metaLabel: {
    fontSize: '0.72rem',
    display: 'block'
  },
  metaValue: {
    fontSize: '0.82rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    display: 'block'
  },
  riskFactorGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '0.45rem',
    marginTop: '0.35rem'
  },
  riskFactorModalItem: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.45rem 0.65rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '4px',
    border: '1px solid var(--border-color)',
    transition: 'all 0.15s ease'
  },
  modalFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.85rem 1.25rem',
    borderTop: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-secondary)',
    flexWrap: 'wrap',
    gap: '0.5rem'
  }
};

export default CriticalThreatPanel;
