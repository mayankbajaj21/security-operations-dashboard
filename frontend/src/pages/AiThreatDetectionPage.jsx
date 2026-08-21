import React, { useState, useEffect, useCallback } from 'react';
import { 
  getThreatSummary, 
  getModelPerformance 
} from '../services/api';
import MetricCard from '../components/MetricCard';
import { 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  Cpu, 
  CheckCircle2, 
  BarChart2, 
  PieChart as PieIcon, 
  Sparkles, 
  Info, 
  RefreshCw,
  Search,
  ArrowRight
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';

/**
 * AI Threat Detection & Model Performance Diagnostics Page
 * Consumes:
 * - GET /threat-summary (Overview KPI metrics & threat level/type breakdown)
 * - GET /model-performance (Isolation Forest model evaluation metrics)
 * 
 * Note: Prediction Event Investigation and Stored Threat Predictions have been
 * moved to the dedicated Event Investigation page.
 */
const AiThreatDetectionPage = ({ onNavigateToInvestigation = null }) => {
  // Summary & Overview State
  const [summary, setSummary] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [summaryError, setSummaryError] = useState(null);

  // Model Evaluation Diagnostic State
  const [modelPerf, setModelPerf] = useState(null);
  const [modelPerfLoading, setModelPerfLoading] = useState(true);

  // 1. Fetch Summary Data
  const fetchSummary = useCallback(async () => {
    setSummaryLoading(true);
    setSummaryError(null);
    try {
      const data = await getThreatSummary({ forceRefresh: true });
      setSummary(data);
    } catch (err) {
      console.error('Failed to fetch threat summary:', err);
      setSummaryError('Unable to load AI threat summary data.');
    } finally {
      setSummaryLoading(false);
    }
  }, []);

  // 2. Fetch Model Performance Data
  const fetchModelPerf = useCallback(async () => {
    setModelPerfLoading(true);
    try {
      const data = await getModelPerformance({ forceRefresh: true });
      setModelPerf(data);
    } catch (err) {
      console.error('Failed to fetch model performance:', err);
    } finally {
      setModelPerfLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSummary();
    fetchModelPerf();
  }, [fetchSummary, fetchModelPerf]);

  // Prepare Anomaly Distribution Chart Data
  const anomalyChartData = summary ? [
    { name: 'Normal', value: summary.normal_events, color: '#38bdf8' },
    { name: 'Suspicious (Anomaly)', value: summary.anomalies_detected, color: '#f43f5e' }
  ] : [];

  // Prepare Threat Level Breakdown Chart Data
  const threatLevelColors = {
    'Normal': '#38bdf8',
    'Low Threat': '#22c55e',
    'Medium Threat': '#facc15',
    'High Threat': '#fb923c',
    'Critical Threat': '#f43f5e'
  };

  const threatLevelChartData = summary && summary.threat_levels ? Object.entries(summary.threat_levels).map(([level, count]) => ({
    name: level,
    count: count,
    color: threatLevelColors[level] || '#94a3b8'
  })) : [];

  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED PAGE HEADER */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <Cpu size={20} color="var(--color-accent)" />
            <span>AI Threat Detection</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            Real-time threat telemetry and security risk analytics monitoring
          </p>
        </div>
        <button 
          className="soc-button" 
          onClick={() => { fetchSummary(); fetchModelPerf(); }}
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={13} />
          <span>Refresh AI Telemetry</span>
        </button>
      </div>

      {/* 1. AI DETECTION OVERVIEW KPI CARDS ROW */}
      {summaryLoading ? (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading AI threat summary metrics...</p>
        </div>
      ) : summaryError ? (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)' }}>{summaryError}</p>
        </div>
      ) : summary && (
        <div style={styles.kpiGrid}>
          <MetricCard
            title="Total Events Analyzed"
            value={summary.total_events}
            subtitle="Security events evaluated"
            icon={Activity}
            variant="accent"
          />
          <MetricCard
            title="Anomalies Detected"
            value={summary.anomalies_detected}
            subtitle={`Anomaly rate: ${((summary.anomalies_detected / (summary.total_events || 1)) * 100).toFixed(1)}%`}
            icon={AlertTriangle}
            variant="critical"
          />
          <MetricCard
            title="Normal Events"
            value={summary.normal_events}
            subtitle="Baseline operational telemetry"
            icon={CheckCircle2}
            variant="default"
          />
          <MetricCard
            title="High & Critical Threats"
            value={(summary.threat_levels?.['High Threat'] || 0) + (summary.threat_levels?.['Critical Threat'] || 0)}
            subtitle={`${summary.threat_levels?.['Critical Threat'] || 0} Critical / ${summary.threat_levels?.['High Threat'] || 0} High`}
            icon={ShieldAlert}
            variant="high"
          />
          <MetricCard
            title="Avg Confidence Score"
            value={`${summary.average_confidence_score?.toFixed(1) || 0}%`}
            subtitle="Mean threat confidence"
            icon={Sparkles}
            variant="warning"
          />
        </div>
      )}

      {/* 2. CHARTS ROW: ANOMALY DISTRIBUTION & THREAT LEVEL BREAKDOWN */}
      {summary && (
        <div style={styles.chartsGrid}>
          {/* Anomaly Distribution Donut Chart */}
          <div className="panel" style={styles.chartPanel}>
            <div style={styles.panelHeader}>
              <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <PieIcon size={15} color="var(--color-accent)" />
                <span>Anomaly Distribution</span>
              </h3>
              <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>Isolation Forest</span>
            </div>

            <div style={{ height: '200px', width: '100%', position: 'relative' }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={anomalyChartData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {anomalyChartData.map((entry, idx) => (
                      <Cell key={`cell-${idx}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '6px', fontSize: '0.8rem' }} 
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            <div style={styles.legendContainer}>
              {anomalyChartData.map((item, idx) => (
                <div key={idx} style={styles.legendItem}>
                  <span style={{ ...styles.legendDot, backgroundColor: item.color }} />
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{item.name}:</span>
                  <strong style={{ fontSize: '0.82rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                    {item.value.toLocaleString()} ({(((item.value || 0) / (summary.total_events || 1)) * 100).toFixed(1)}%)
                  </strong>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Level Distribution Bar Chart */}
          <div className="panel" style={styles.chartPanel}>
            <div style={styles.panelHeader}>
              <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <BarChart2 size={15} color="var(--color-accent)" />
                <span>Threat Level Breakdown</span>
              </h3>
              <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>Security Rules</span>
            </div>

            <div style={{ height: '200px', width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatLevelChartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" opacity={0.5} />
                  <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                  <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '6px', fontSize: '0.8rem' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {threatLevelChartData.map((entry, idx) => (
                      <Cell key={`bar-${idx}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.5rem' }}>
              {threatLevelChartData.map((item, idx) => (
                <div key={idx} style={{ fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: item.color }} />
                  <span style={{ color: 'var(--text-muted)' }}>{item.name}:</span>
                  <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{item.count}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* 3. MODEL PERFORMANCE & EVALUATION DIAGNOSTICS (GET /model-performance) */}
      {modelPerf && (
        <div className="panel" style={styles.modelPerfPanel}>
          <div style={styles.panelHeader}>
            <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <Info size={15} color="var(--color-accent)" />
              <span>Isolation Forest Model Diagnostics</span>
            </h3>
            <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
              {modelPerf.model_name} v{modelPerf.model_version}
            </span>
          </div>

          <div style={styles.modelPerfGrid}>
            <div>
              <span style={styles.detailLabel}>MODEL ALGORITHM</span>
              <span style={{ fontSize: '0.82rem', fontWeight: '600', color: 'var(--text-primary)' }}>
                {modelPerf.model_name}
              </span>
            </div>
            <div>
              <span style={styles.detailLabel}>CONTAMINATION FACTOR</span>
              <span style={styles.detailValueMono}>{modelPerf.contamination}</span>
            </div>
            <div>
              <span style={styles.detailLabel}>TOTAL EVALUATED</span>
              <span style={styles.detailValueMono}>{modelPerf.total_events_evaluated} Events</span>
            </div>
            <div>
              <span style={styles.detailLabel}>FEATURE COUNT</span>
              <span style={styles.detailValueMono}>{modelPerf.feature_count} Features</span>
            </div>
            <div>
              <span style={styles.detailLabel}>MEAN ANOMALY SCORE</span>
              <span style={styles.detailValueMono}>
                {modelPerf.score_distribution?.mean?.toFixed(6)}
              </span>
            </div>
            <div>
              <span style={styles.detailLabel}>SCORE RANGE</span>
              <span style={styles.detailValueMono}>
                [{modelPerf.score_distribution?.min?.toFixed(3)}, {modelPerf.score_distribution?.max?.toFixed(3)}]
              </span>
            </div>
          </div>

          {modelPerf.evaluation_note && (
            <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.75rem', marginBottom: 0 }}>
              Diagnostic Note: {modelPerf.evaluation_note}
            </p>
          )}
        </div>
      )}
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
    gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
    gap: '1.25rem'
  },
  chartsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
    gap: '1.25rem'
  },
  chartPanel: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    padding: '1.25rem'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.75rem'
  },
  legendContainer: {
    display: 'flex',
    justifyContent: 'space-around',
    flexWrap: 'wrap',
    gap: '0.5rem',
    marginTop: '0.5rem',
    paddingTop: '0.5rem',
    borderTop: '1px solid var(--border-subtle)'
  },
  legendItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem'
  },
  legendDot: {
    width: 8,
    height: 8,
    borderRadius: '50%'
  },
  modelPerfPanel: {
    padding: '1rem 1.25rem'
  },
  modelPerfGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: '1rem',
    marginTop: '0.5rem'
  },
  detailLabel: {
    fontSize: '0.68rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em',
    textTransform: 'uppercase',
    display: 'block'
  },
  detailValueMono: {
    fontSize: '0.85rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)'
  },
  statePanel: {
    minHeight: '160px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  }
};

export default AiThreatDetectionPage;
