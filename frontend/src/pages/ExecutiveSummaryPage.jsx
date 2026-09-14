// Executive Summary Page – Milestone 4, Tasks 16 & 17
// Authoritative SOC & Management Executive Security Summary Dashboard

import React, { useEffect, useState, useCallback } from 'react';
import { getExecutiveReportData, getEventTrend, downloadSecurityReport } from '../services/api';
import MetricCard from '../components/MetricCard';
import ThreatTrendChart from '../charts/ThreatTrendChart';
import { 
  BarChart2, 
  ShieldCheck, 
  AlertOctagon, 
  AlertTriangle, 
  Cpu, 
  Activity, 
  FileText, 
  Table, 
  Download, 
  Server, 
  RefreshCw,
  CheckCircle,
  AlertCircle
} from 'lucide-react';

const ExecutiveSummaryPage = () => {
  const [reportData, setReportData] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [telemetryWindow, setTelemetryWindow] = useState(null);
  const [trendRange, setTrendRange] = useState('7d');
  const [loading, setLoading] = useState(true);
  const [trendLoading, setTrendLoading] = useState(false);
  const [error, setError] = useState(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [downloadingCsv, setDownloadingCsv] = useState(false);
  const [downloadFeedback, setDownloadFeedback] = useState(null);

  const fetchExecutiveData = useCallback(async (isManualRefresh = false) => {
    if (!isManualRefresh) setLoading(true);
    setError(null);
    try {
      const [executiveRes, trendRes] = await Promise.all([
        getExecutiveReportData({ forceRefresh: true }),
        getEventTrend(trendRange, { forceRefresh: true })
      ]);
      setReportData(executiveRes);
      if (trendRes) {
        setTrendData(trendRes.trend || []);
        setTelemetryWindow(trendRes.telemetry_window || null);
      }
    } catch (e) {
      console.error('Failed to load executive summary data:', e);
      setError('Failed to load executive data. Please check backend connectivity.');
    } finally {
      setLoading(false);
      setTrendLoading(false);
    }
  }, [trendRange]);

  useEffect(() => {
    fetchExecutiveData();
  }, [fetchExecutiveData]);

  const handleTrendRangeChange = async (newRange) => {
    setTrendRange(newRange);
    setTrendLoading(true);
    try {
      const res = await getEventTrend(newRange, { forceRefresh: true });
      if (res) {
        setTrendData(res.trend || []);
        setTelemetryWindow(res.telemetry_window || null);
      }
    } catch (e) {
      console.error('Failed to update trend range:', e);
    } finally {
      setTrendLoading(false);
    }
  };

  const handleDownload = async (format) => {
    try {
      if (format === 'pdf') {
        setDownloadingPdf(true);
      } else {
        setDownloadingCsv(true);
      }
      setDownloadFeedback(null);
      await downloadSecurityReport(format);
      setDownloadFeedback({
        type: 'success',
        message: `Executive report (${format.toUpperCase()}) successfully generated and downloaded.`
      });
    } catch (err) {
      console.error(`Failed to download ${format} report:`, err);
      setDownloadFeedback({
        type: 'error',
        message: `Failed to download ${format.toUpperCase()} report. Please ensure the reporting service is active.`
      });
    } finally {
      if (format === 'pdf') {
        setDownloadingPdf(false);
      } else {
        setDownloadingCsv(false);
      }
      setTimeout(() => setDownloadFeedback(null), 6000);
    }
  };

  if (loading) {
    return (
      <div style={styles.loadingContainer}>
        <RefreshCw size={28} className="animate-spin" style={{ color: 'var(--color-accent)', marginBottom: '1rem' }} />
        <div style={{ fontSize: '1.1rem', fontWeight: '600', color: 'var(--text-primary)' }}>
          Loading Executive Security Summary...
        </div>
        <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
          Aggregating live posture score, incidents, vulnerabilities, and telemetry trends
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div style={styles.pageContainer}>
        <div className="card" style={{ borderColor: 'var(--color-critical)', padding: '2rem', textAlign: 'center' }}>
          <AlertTriangle size={36} color="var(--color-critical)" style={{ margin: '0 auto 1rem auto' }} />
          <h3 style={{ color: 'var(--color-critical)', marginBottom: '0.5rem' }}>Executive Briefing Unavailable</h3>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>{error}</p>
          <button 
            className="btn btn-primary" 
            onClick={() => fetchExecutiveData(true)}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', margin: '0 auto' }}
          >
            <RefreshCw size={16} /> Retry Connection
          </button>
        </div>
      </div>
    );
  }

  const posture = reportData?.posture || {};
  const metrics = reportData?.metrics || {};
  const conditions = posture?.conditions || {};
  const explanations = posture?.explanations || [];
  const criticalCves = reportData?.critical_cves || [];
  const affectedAssets = reportData?.affected_assets || [];
  const recentIncidents = reportData?.recent_critical_incidents || [];

  // Posture styling helpers
  const postureScore = posture.posture_score ?? 0;
  const postureStatus = posture.status || 'Unknown';
  let postureColor = 'var(--color-critical)';
  let postureBg = 'rgba(244, 63, 94, 0.08)';
  let postureBorder = 'rgba(244, 63, 94, 0.25)';

  if (postureScore >= 75) {
    postureColor = 'var(--color-success)';
    postureBg = 'rgba(34, 197, 94, 0.08)';
    postureBorder = 'rgba(34, 197, 94, 0.25)';
  } else if (postureScore >= 50) {
    postureColor = 'var(--color-warning)';
    postureBg = 'rgba(245, 158, 11, 0.08)';
    postureBorder = 'rgba(245, 158, 11, 0.25)';
  }

  return (
    <div style={styles.pageContainer}>
      {/* SECTION A: REPORT GENERATION CONTROLS */}
      <div style={styles.headerRow}>
        {/* Task 17: Generate Security Report Controls */}
        <div style={styles.reportControlsWrapper}>
          <span style={styles.reportControlLabel}>Generate Security Report:</span>
          <div style={styles.reportButtonsGroup}>
            <button
              id="download-pdf-report-btn"
              className="btn btn-outline"
              onClick={() => handleDownload('pdf')}
              disabled={downloadingPdf || downloadingCsv}
              style={styles.downloadBtn}
              title="Download Executive Security Report in PDF format"
            >
              {downloadingPdf ? (
                <RefreshCw size={15} className="animate-spin" />
              ) : (
                <FileText size={15} color="var(--color-accent)" />
              )}
              <span>{downloadingPdf ? 'Exporting PDF...' : 'Download PDF'}</span>
            </button>

            <button
              id="download-csv-report-btn"
              className="btn btn-outline"
              onClick={() => handleDownload('csv')}
              disabled={downloadingPdf || downloadingCsv}
              style={styles.downloadBtn}
              title="Download Executive Security Report metrics in CSV format"
            >
              {downloadingCsv ? (
                <RefreshCw size={15} className="animate-spin" />
              ) : (
                <Table size={15} color="var(--color-accent)" />
              )}
              <span>{downloadingCsv ? 'Exporting CSV...' : 'Download CSV'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Download Status Notification */}
      {downloadFeedback && (
        <div 
          style={{
            ...styles.feedbackBanner,
            backgroundColor: downloadFeedback.type === 'success' ? 'rgba(34, 197, 94, 0.12)' : 'rgba(244, 63, 94, 0.12)',
            borderColor: downloadFeedback.type === 'success' ? 'var(--color-success)' : 'var(--color-critical)',
            color: downloadFeedback.type === 'success' ? 'var(--color-success)' : 'var(--color-critical)'
          }}
        >
          {downloadFeedback.type === 'success' ? <CheckCircle size={16} /> : <AlertCircle size={16} />}
          <span>{downloadFeedback.message}</span>
        </div>
      )}

      {/* SECTION B: SECURITY POSTURE & EXECUTIVE OBSERVATIONS */}
      <section style={styles.postureSectionGrid}>
        {/* Posture Card */}
        <div className="card" style={{ ...styles.postureCard, backgroundColor: postureBg, borderColor: postureBorder }}>
          <div style={styles.postureCardHeader}>
            <span style={styles.sectionBadge}>OVERALL STATUS</span>
            <span style={{ ...styles.statusTag, backgroundColor: postureColor }}>{postureStatus}</span>
          </div>

          <div style={styles.postureScoreWrap}>
            <div style={{ ...styles.postureScoreNumber, color: postureColor }}>
              {postureScore}
            </div>
            <div style={styles.postureScale}>/ 100</div>
          </div>
          <div style={styles.postureScoreTitle}>Security Posture Score</div>

          <p style={styles.postureMethodologyText}>
            Deterministic health score grounded in live vulnerabilities, unresolved threats, asset exposure, and active incident volume.
          </p>

          <div style={styles.postureScaleLegend}>
            <span style={{ color: 'var(--color-critical)' }}>&lt;50 Critical</span>
            <span style={{ color: 'var(--color-warning)' }}>50–74 Warning</span>
            <span style={{ color: 'var(--color-success)' }}>&ge;75 Good</span>
          </div>
        </div>

        {/* Conditions & Key Observations Card */}
        <div className="card" style={styles.observationsCard}>
          <div style={styles.cardHeaderSmall}>
            <h3 style={styles.sectionSubtitle}>
              <Activity size={18} color="var(--color-accent)" style={{ display: 'inline', marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              Executive Risk Observations & Deduction Audit
            </h3>
            <span style={styles.generatedAtText}>
              Generated: {reportData?.generated_at || new Date().toISOString().substring(0, 19) + ' UTC'}
            </span>
          </div>

          {/* 5 Deductions Audit Chips */}
          <div style={styles.conditionsGrid}>
            <div style={styles.conditionChip}>
              <div style={styles.conditionLabel}>Critical CVEs</div>
              <div style={styles.conditionValue}>
                {conditions?.critical_vulnerabilities?.count ?? 0}
                <span style={styles.penaltyText}> (-{conditions?.critical_vulnerabilities?.penalty ?? 0} pts)</span>
              </div>
            </div>

            <div style={styles.conditionChip}>
              <div style={styles.conditionLabel}>Active Incidents</div>
              <div style={styles.conditionValue}>
                {conditions?.active_incidents?.count ?? 0}
                <span style={styles.penaltyText}> (-{conditions?.active_incidents?.penalty ?? 0} pts)</span>
              </div>
            </div>

            <div style={styles.conditionChip}>
              <div style={styles.conditionLabel}>High-Risk Assets</div>
              <div style={styles.conditionValue}>
                {conditions?.high_risk_assets?.count ?? 0}
                <span style={styles.penaltyText}> (-{conditions?.high_risk_assets?.penalty ?? 0} pts)</span>
              </div>
            </div>

            <div style={styles.conditionChip}>
              <div style={styles.conditionLabel}>Unresolved Threats</div>
              <div style={styles.conditionValue}>
                {conditions?.unresolved_threats?.count ?? 0}
                <span style={styles.penaltyText}> (-{conditions?.unresolved_threats?.penalty ?? 0} pts)</span>
              </div>
            </div>

            <div style={styles.conditionChip}>
              <div style={styles.conditionLabel}>Anomaly Volume</div>
              <div style={styles.conditionValue}>
                {conditions?.threat_volume?.count ?? 0}
                <span style={styles.penaltyText}> (-{conditions?.threat_volume?.penalty ?? 0} pts)</span>
              </div>
            </div>
          </div>

          {/* Authoritative Explanations */}
          <div style={styles.explanationsList}>
            <div style={{ fontSize: '0.8rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '0.35rem' }}>
              Posture Impact Factors:
            </div>
            {explanations.length > 0 ? (
              explanations.map((exp, idx) => (
                <div key={idx} style={styles.explanationItem}>
                  <span style={styles.bulletDot} />
                  <span>{exp}</span>
                </div>
              ))
            ) : (
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No active posture deductions recorded.</div>
            )}
          </div>
        </div>
      </section>

      {/* SECTION C: KEY SECURITY METRICS (EXACTLY 6 REQUIRED M4 METRICS) */}
      <section style={{ marginBottom: '1.75rem' }}>
        <h2 style={styles.sectionHeader}>Key Security Metrics</h2>
        <div style={styles.kpiGrid}>
          <MetricCard 
            title="Critical Threats" 
            value={metrics.critical_threats ?? 0} 
            subtitle="Immediate priority containment"
            variant="critical"
            icon={AlertOctagon} 
          />
          <MetricCard 
            title="Open Incidents" 
            value={metrics.open_incidents ?? 0} 
            subtitle="Awaiting analyst triage"
            variant="warning"
            icon={AlertTriangle} 
          />
          <MetricCard 
            title="Critical Vulnerabilities" 
            value={metrics.critical_vulnerabilities ?? 0} 
            subtitle="Cataloged active CVEs"
            variant="critical"
            icon={Cpu} 
          />
          <MetricCard 
            title="Affected Assets" 
            value={metrics.affected_assets_count ?? 0} 
            subtitle="Enterprise systems compromised"
            variant="high"
            icon={ShieldCheck} 
          />
          <MetricCard 
            title="Active Incidents" 
            value={metrics.active_incidents ?? 0} 
            subtitle="Open or Investigating status"
            variant="warning"
            icon={Activity} 
          />
          <MetricCard 
            title="Total Events" 
            value={metrics.total_security_events ?? 0} 
            subtitle="Aggregated telemetry volume"
            variant="default"
            icon={BarChart2} 
          />
        </div>
      </section>

      {/* SECTION G: THREAT TREND (LAST 7 DAYS) */}
      <section style={{ marginBottom: '1.75rem' }}>
        <ThreatTrendChart 
          trendData={trendData}
          selectedRange={trendRange}
          onRangeChange={handleTrendRangeChange}
          telemetryWindow={telemetryWindow}
          isLoading={trendLoading}
        />
      </section>

      {/* SECTION D: THREAT / INCIDENT OVERVIEW (RECENT CRITICAL INCIDENTS) */}
      <section style={{ marginBottom: '1.75rem' }}>
        <div style={styles.sectionHeaderRow}>
          <div>
            <h2 style={styles.sectionHeader}>Threat & Incident Overview</h2>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Highest risk incidents active in the enterprise environment requiring leadership visibility.
            </p>
          </div>
          <div style={styles.incidentStatusTags}>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(239, 68, 68, 0.15)', color: 'var(--color-critical)' }}>
              Open: {metrics.open_incidents ?? 0}
            </span>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(245, 158, 11, 0.15)', color: 'var(--color-warning)' }}>
              Investigating: {metrics.investigating_incidents ?? 0}
            </span>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(34, 197, 94, 0.15)', color: 'var(--color-success)' }}>
              Resolved: {metrics.resolved_incidents ?? 0}
            </span>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(100, 116, 139, 0.15)', color: 'var(--text-muted)' }}>
              FP: {metrics.false_positives ?? 0}
            </span>
          </div>
        </div>

        <div className="card" style={{ padding: '0', overflow: 'hidden' }}>
          <div style={{ overflowX: 'auto' }}>
            <table className="soc-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={styles.th}>Incident ID</th>
                  <th style={styles.th}>Threat Type</th>
                  <th style={styles.th}>Risk Score</th>
                  <th style={styles.th}>Priority</th>
                  <th style={styles.th}>Affected Asset</th>
                  <th style={styles.th}>Status</th>
                </tr>
              </thead>
              <tbody>
                {recentIncidents.length > 0 ? (
                  recentIncidents.map((inc) => (
                    <tr key={inc.incident_id} style={styles.tr}>
                      <td style={{ ...styles.td, fontFamily: 'var(--font-mono)', fontWeight: '600', color: 'var(--color-accent)' }}>
                        {inc.incident_id}
                      </td>
                      <td style={{ ...styles.td, fontWeight: '500' }}>
                        {inc.threat_type || 'Unknown Threat'}
                      </td>
                      <td style={styles.td}>
                        <span style={{
                          ...styles.scoreBadge,
                          backgroundColor: inc.risk_score >= 90 ? 'rgba(244, 63, 94, 0.15)' : 'rgba(251, 146, 60, 0.15)',
                          color: inc.risk_score >= 90 ? 'var(--color-critical)' : 'var(--color-high)',
                          borderColor: inc.risk_score >= 90 ? 'var(--color-critical)' : 'var(--color-high)'
                        }}>
                          {inc.risk_score} / 100
                        </span>
                      </td>
                      <td style={styles.td}>
                        <span style={styles.priorityBadge}>
                          {inc.priority || 'P1'}
                        </span>
                      </td>
                      <td style={{ ...styles.td, fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                        {inc.affected_asset ? (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                            <Server size={13} color="var(--text-muted)" />
                            {inc.affected_asset}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>N/A</span>
                        )}
                      </td>
                      <td style={styles.td}>
                        <span style={{
                          ...styles.statusBadge,
                          backgroundColor: 
                            inc.status === 'Open' ? 'rgba(244, 63, 94, 0.15)' :
                            inc.status === 'Investigating' ? 'rgba(245, 158, 11, 0.15)' :
                            inc.status === 'Resolved' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(100, 116, 139, 0.15)',
                          color:
                            inc.status === 'Open' ? 'var(--color-critical)' :
                            inc.status === 'Investigating' ? 'var(--color-warning)' :
                            inc.status === 'Resolved' ? 'var(--color-success)' : 'var(--text-muted)'
                        }}>
                          {inc.status || 'Open'}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} style={{ textAlign: 'center', padding: '1.5rem', color: 'var(--text-muted)' }}>
                      No recent critical incidents recorded.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* SECTION E & F: CRITICAL VULNERABILITIES & AFFECTED ASSETS */}
      <section style={styles.bottomTwoColGrid}>
        {/* SECTION E: Critical Vulnerabilities */}
        <div className="card" style={styles.bottomCard}>
          <div style={styles.cardHeaderSmall}>
            <h3 style={styles.sectionSubtitle}>
              <Cpu size={18} color="var(--color-critical)" style={{ display: 'inline', marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              Critical Vulnerabilities
            </h3>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(244, 63, 94, 0.15)', color: 'var(--color-critical)' }}>
              {metrics.critical_vulnerabilities ?? 0} Critical CVE
            </span>
          </div>

          <div style={{ marginTop: '0.75rem' }}>
            {criticalCves.length > 0 ? (
              criticalCves.map((cve, idx) => (
                <div key={idx} style={styles.cveItemCard}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', fontSize: '0.95rem', color: 'var(--color-critical)' }}>
                      {cve}
                    </span>
                    <span style={{ ...styles.miniBadge, backgroundColor: 'var(--color-critical)', color: '#fff' }}>
                      CVSS 10.0
                    </span>
                  </div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    {conditions?.critical_vulnerabilities?.impact || 'High active CVE exposure requiring remediation'}
                  </div>
                </div>
              ))
            ) : (
              <div style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No critical vulnerabilities requiring immediate remediation.
              </div>
            )}
          </div>
        </div>

        {/* SECTION F: Affected Enterprise Assets */}
        <div className="card" style={styles.bottomCard}>
          <div style={styles.cardHeaderSmall}>
            <h3 style={styles.sectionSubtitle}>
              <ShieldCheck size={18} color="var(--color-high)" style={{ display: 'inline', marginRight: '0.5rem', verticalAlign: 'text-bottom' }} />
              Affected Enterprise Assets
            </h3>
            <span style={{ ...styles.miniBadge, backgroundColor: 'rgba(251, 146, 60, 0.15)', color: 'var(--color-high)' }}>
              {metrics.affected_assets_count ?? affectedAssets.length} Assets
            </span>
          </div>

          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: '0.5rem 0 0.75rem 0' }}>
            Infrastructure nodes currently hosting critical threats, vulnerabilities, or under investigation:
          </p>

          <div style={styles.assetsGrid}>
            {affectedAssets.length > 0 ? (
              affectedAssets.map((asset, idx) => (
                <div key={idx} style={styles.assetChip}>
                  <Server size={13} color="var(--color-accent)" />
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', fontWeight: '600' }}>
                    {asset}
                  </span>
                </div>
              ))
            ) : (
              <div style={{ padding: '1rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No enterprise assets currently flagged as affected.
              </div>
            )}
          </div>
        </div>
      </section>
    </div>
  );
};

const styles = {
  pageContainer: {
    padding: '0 0 1.5rem 0',
    maxWidth: '1600px',
    margin: '0 auto'
  },
  loadingContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '400px',
    textAlign: 'center'
  },
  headerRow: {
    display: 'flex',
    justifyContent: 'flex-end',
    alignItems: 'center',
    flexWrap: 'wrap',
    gap: '1.25rem',
    marginBottom: '1.25rem'
  },
  pageTitle: {
    fontSize: '1.75rem',
    fontWeight: '800',
    color: 'var(--text-primary)',
    margin: 0,
    letterSpacing: '-0.02em'
  },
  pageSubtitle: {
    fontSize: '0.9rem',
    color: 'var(--text-secondary)',
    marginTop: '0.35rem',
    maxWidth: '650px',
    lineHeight: 1.4
  },
  reportControlsWrapper: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    flexWrap: 'wrap'
  },
  reportControlLabel: {
    fontSize: '0.8rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.05em'
  },
  reportButtonsGroup: {
    display: 'flex',
    gap: '0.6rem',
    flexWrap: 'wrap'
  },
  downloadBtn: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.85rem',
    fontWeight: '600',
    padding: '0.45rem 0.9rem',
    borderRadius: '6px',
    cursor: 'pointer',
    transition: 'all 0.15s ease'
  },
  feedbackBanner: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    padding: '0.75rem 1rem',
    borderRadius: '6px',
    border: '1px solid',
    fontSize: '0.85rem',
    fontWeight: '500',
    marginBottom: '1.5rem'
  },
  postureSectionGrid: {
    display: 'grid',
    gridTemplateColumns: '320px 1fr',
    gap: '1.25rem',
    marginBottom: '1.75rem'
  },
  postureCard: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center',
    padding: '1.75rem 1.5rem',
    borderWidth: '1px'
  },
  postureCardHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    width: '100%',
    marginBottom: '1rem'
  },
  sectionBadge: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.06em'
  },
  statusTag: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: '#fff',
    padding: '0.15rem 0.6rem',
    borderRadius: '4px',
    textTransform: 'uppercase'
  },
  postureScoreWrap: {
    display: 'flex',
    alignItems: 'baseline',
    justifyContent: 'center',
    gap: '0.35rem',
    margin: '0.5rem 0 0.25rem 0'
  },
  postureScoreNumber: {
    fontSize: '3.75rem',
    fontWeight: '900',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1
  },
  postureScale: {
    fontSize: '1.25rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  postureScoreTitle: {
    fontSize: '1rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '0.5rem'
  },
  postureMethodologyText: {
    fontSize: '0.8rem',
    color: 'var(--text-secondary)',
    lineHeight: 1.4,
    marginBottom: '1rem'
  },
  postureScaleLegend: {
    display: 'flex',
    justifyContent: 'space-between',
    width: '100%',
    fontSize: '0.75rem',
    fontWeight: '600',
    borderTop: '1px solid var(--border-color)',
    paddingTop: '0.75rem'
  },
  observationsCard: {
    padding: '1.25rem 1.5rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between'
  },
  cardHeaderSmall: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '0.85rem'
  },
  sectionSubtitle: {
    fontSize: '1.05rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0
  },
  generatedAtText: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)'
  },
  conditionsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
    gap: '0.75rem',
    marginBottom: '1rem'
  },
  conditionChip: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.6rem 0.75rem'
  },
  conditionLabel: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    fontWeight: '600',
    marginBottom: '0.2rem'
  },
  conditionValue: {
    fontSize: '1.05rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)'
  },
  penaltyText: {
    fontSize: '0.75rem',
    color: 'var(--color-critical)',
    fontWeight: '600'
  },
  explanationsList: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.75rem 1rem'
  },
  explanationItem: {
    display: 'flex',
    alignItems: 'baseline',
    gap: '0.5rem',
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    marginBottom: '0.35rem',
    lineHeight: 1.4
  },
  bulletDot: {
    width: '6px',
    height: '6px',
    borderRadius: '50%',
    backgroundColor: 'var(--color-accent)',
    flexShrink: 0
  },
  sectionHeader: {
    fontSize: '1.15rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginBottom: '0.75rem'
  },
  sectionHeaderRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-end',
    marginBottom: '0.75rem',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  incidentStatusTags: {
    display: 'flex',
    gap: '0.5rem',
    flexWrap: 'wrap'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem'
  },
  th: {
    padding: '0.75rem 1rem',
    textAlign: 'left',
    fontSize: '0.8rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    borderBottom: '1px solid var(--border-color)',
    backgroundColor: 'var(--bg-secondary)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em'
  },
  td: {
    padding: '0.75rem 1rem',
    fontSize: '0.85rem',
    borderBottom: '1px solid var(--border-color)'
  },
  tr: {
    transition: 'background-color 0.15s ease'
  },
  scoreBadge: {
    display: 'inline-block',
    fontSize: '0.75rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    padding: '0.15rem 0.5rem',
    borderRadius: '4px',
    border: '1px solid'
  },
  priorityBadge: {
    display: 'inline-block',
    fontSize: '0.75rem',
    fontWeight: '700',
    backgroundColor: 'rgba(239, 68, 68, 0.15)',
    color: 'var(--color-critical)',
    padding: '0.15rem 0.5rem',
    borderRadius: '4px'
  },
  statusBadge: {
    display: 'inline-block',
    fontSize: '0.75rem',
    fontWeight: '700',
    padding: '0.15rem 0.5rem',
    borderRadius: '4px'
  },
  miniBadge: {
    display: 'inline-block',
    fontSize: '0.75rem',
    fontWeight: '700',
    padding: '0.15rem 0.5rem',
    borderRadius: '4px'
  },
  bottomTwoColGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: '1.25rem'
  },
  bottomCard: {
    padding: '1.25rem'
  },
  cveItemCard: {
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.85rem 1rem',
    marginBottom: '0.6rem'
  },
  assetsGrid: {
    display: 'flex',
    flexWrap: 'wrap',
    gap: '0.5rem',
    maxHeight: '220px',
    overflowY: 'auto',
    paddingRight: '0.25rem'
  },
  assetChip: {
    display: 'inline-flex',
    alignItems: 'center',
    gap: '0.4rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    padding: '0.35rem 0.65rem'
  }
};

export default ExecutiveSummaryPage;
