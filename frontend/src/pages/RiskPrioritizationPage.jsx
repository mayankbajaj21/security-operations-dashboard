import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { 
  getRiskSummary, 
  getHighRisk, 
  calculateRisk,
  getRiskWeights,
  updateRiskWeights,
  resetRiskWeights,
  getRiskComparison
} from '../services/api';
import Badge from '../components/Badge';
import { 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  Flame, 
  ChevronLeft, 
  ChevronRight, 
  BookOpen, 
  ShieldCheck, 
  AlertOctagon,
  Search,
  Award,
  RefreshCw,
  Calculator,
  Sliders,
  CheckCircle2,
  Cpu
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

/**
 * Standard M3 5-Tier Operational Risk Levels and Score Ranges:
 * - Low: 0–20
 * - Medium: 21–40
 * - Moderate: 41–60
 * - High: 61–80
 * - Critical: 81–100
 */
export const RISK_RANGES = {
  Low: { min: 0, max: 20, color: '#38bdf8' },
  Medium: { min: 21, max: 40, color: '#facc15' },
  Moderate: { min: 41, max: 60, color: '#fbbf24' },
  High: { min: 61, max: 80, color: '#fb923c' },
  Critical: { min: 81, max: 100, color: '#f43f5e' }
};

const CompactKpiCard = ({ label, value, subtitle, color, icon: Icon }) => (
  <div className="panel" style={{ ...styles.kpiCard, borderLeft: `3px solid ${color}` }}>
    <div style={styles.kpiHeader}>
      <span style={styles.kpiLabel}>{label}</span>
      {Icon && <Icon size={14} color={color} />}
    </div>
    <div style={{ ...styles.kpiValue, color }}>
      {typeof value === 'number' ? value.toLocaleString() : value ?? '0'}
    </div>
    <div style={styles.kpiSubtitle}>{subtitle}</div>
  </div>
);

const RiskPrioritizationPage = () => {
  // Summary & High Risk Data State
  const [summaryData, setSummaryData] = useState(null);
  const [highRiskData, setHighRiskData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Table State
  const [searchQuery, setSearchQuery] = useState('');
  const [riskLevelFilter, setRiskLevelFilter] = useState('ALL');
  const [threatTypeFilter, setThreatTypeFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const [limit] = useState(10);
  const [showMethodology, setShowMethodology] = useState(true);
  const [showCalculator, setShowCalculator] = useState(false);

  // Interactive Live Risk Calculator Form State
  const [calcForm, setCalcForm] = useState({
    severity: 'High',
    ml_prediction: 'Suspicious',
    confidence_score: 85,
    asset_criticality: 'Critical',
    cvss_score: 7.5,
    threat_intel_match: true,
    threat_type: 'Brute Force'
  });
  const [calcResult, setCalcResult] = useState(null);
  const [calcLoading, setCalcLoading] = useState(false);
  const [calcError, setCalcError] = useState(null);

  // Dynamic Risk Weights State (GET /v1/risk/weights & PUT /v1/risk/weights)
  const [showWeightsPanel, setShowWeightsPanel] = useState(false);
  const [weights, setWeights] = useState({
    threat_severity: 25,
    ml_confidence: 25,
    asset_criticality: 20,
    vulnerability_risk: 20,
    threat_intelligence: 10
  });
  const [weightsMeta, setWeightsMeta] = useState({ is_custom: false, updated_at: null });
  const [weightsLoading, setWeightsLoading] = useState(false);
  const [weightsSaving, setWeightsSaving] = useState(false);
  const [weightsMsg, setWeightsMsg] = useState(null);

  // Risk Score Comparison State (GET /v1/risk/comparison/{event_id})
  const [showComparisonPanel, setShowComparisonPanel] = useState(false);
  const [comparisonEventId, setComparisonEventId] = useState('');
  const [comparisonResult, setComparisonResult] = useState(null);
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonError, setComparisonError] = useState(null);

  // Fetch active weights from backend
  const fetchActiveWeights = useCallback(async () => {
    setWeightsLoading(true);
    try {
      const data = await getRiskWeights({ noCache: true });
      if (data?.weights) {
        setWeights({
          threat_severity: Math.round(data.weights.threat_severity * 100),
          ml_confidence: Math.round(data.weights.ml_confidence * 100),
          asset_criticality: Math.round(data.weights.asset_criticality * 100),
          vulnerability_risk: Math.round(data.weights.vulnerability_risk * 100),
          threat_intelligence: Math.round(data.weights.threat_intelligence * 100)
        });
        setWeightsMeta({
          is_custom: !!data.is_custom,
          updated_at: data.updated_at
        });
      }
    } catch (err) {
      console.error('Failed to load active risk weights:', err);
    } finally {
      setWeightsLoading(false);
    }
  }, []);

  // Fetch summary and high risk data from M3 REST APIs
  const fetchRiskData = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      const [summaryRes, highRiskRes] = await Promise.all([
        getRiskSummary({ noCache: isManual }),
        getHighRisk({ page: 1, limit: 100, min_risk: 0 }, { noCache: isManual }).catch(() => null)
      ]);

      setSummaryData(summaryRes);
      const highList = highRiskRes?.data || [];
      setHighRiskData(highList);
      if (highList.length > 0) {
        setComparisonEventId((prev) => prev || highList[0]?.event_id || '');
      }
    } catch (err) {
      console.error('Failed to load M3 Risk Overview data:', err);
      setError('Unable to load risk intelligence from the security operations backend.');
      setSummaryData(null);
      setHighRiskData([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchRiskData();
    fetchActiveWeights();
  }, [fetchRiskData, fetchActiveWeights]);

  // Total weight percentage and validation
  const totalWeightsPct = useMemo(() => {
    return (
      (Number(weights.threat_severity) || 0) +
      (Number(weights.ml_confidence) || 0) +
      (Number(weights.asset_criticality) || 0) +
      (Number(weights.vulnerability_risk) || 0) +
      (Number(weights.threat_intelligence) || 0)
    );
  }, [weights]);

  const isWeightsValid = useMemo(() => {
    const hasNegative = Object.values(weights).some((v) => Number(v) < 0);
    return !hasNegative && totalWeightsPct === 100;
  }, [weights, totalWeightsPct]);

  const handleSaveWeights = async () => {
    if (!isWeightsValid) return;
    setWeightsSaving(true);
    setWeightsMsg(null);
    try {
      const payload = {
        threat_severity: Number(weights.threat_severity) / 100,
        ml_confidence: Number(weights.ml_confidence) / 100,
        asset_criticality: Number(weights.asset_criticality) / 100,
        vulnerability_risk: Number(weights.vulnerability_risk) / 100,
        threat_intelligence: Number(weights.threat_intelligence) / 100
      };
      const res = await updateRiskWeights(payload);
      setWeightsMeta({ is_custom: !!res.is_custom, updated_at: res.updated_at });
      setWeightsMsg({ type: 'success', text: 'Dynamic risk weights saved and activated successfully.' });
      fetchRiskData(true);
    } catch (err) {
      console.error('Failed to save risk weights:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Failed to update risk weights.';
      setWeightsMsg({ type: 'error', text: errMsg });
    } finally {
      setWeightsSaving(false);
    }
  };

  const handleResetWeights = async () => {
    setWeightsSaving(true);
    setWeightsMsg(null);
    try {
      const res = await resetRiskWeights();
      setWeights({
        threat_severity: 25,
        ml_confidence: 25,
        asset_criticality: 20,
        vulnerability_risk: 20,
        threat_intelligence: 10
      });
      setWeightsMeta({ is_custom: false, updated_at: res.updated_at });
      setWeightsMsg({ type: 'success', text: 'Risk weights reset to authoritative M3 defaults (25 / 25 / 20 / 20 / 10).' });
      fetchRiskData(true);
    } catch (err) {
      console.error('Failed to reset risk weights:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Failed to reset weights.';
      setWeightsMsg({ type: 'error', text: errMsg });
    } finally {
      setWeightsSaving(false);
    }
  };

  // Fetch Risk Score Comparison for an event
  const handleFetchComparison = async (targetId) => {
    const cleanId = (targetId || comparisonEventId || '').trim();
    if (!cleanId) return;
    setComparisonLoading(true);
    setComparisonError(null);
    setComparisonResult(null);
    setShowComparisonPanel(true);
    try {
      const res = await getRiskComparison(cleanId, { noCache: true });
      setComparisonResult(res);
    } catch (err) {
      console.error(`Failed to fetch comparison for ${cleanId}:`, err);
      const errMsg = err.response?.data?.detail || err.message || `Unable to fetch comparison for event ${cleanId}.`;
      setComparisonError(errMsg);
    } finally {
      setComparisonLoading(false);
    }
  };

  const handleInspectComparison = (eventId) => {
    setComparisonEventId(eventId);
    handleFetchComparison(eventId);
  };

  // Execute interactive live calculation via POST /v1/risk/calculate
  const handleCalculateSubmit = async (e) => {
    if (e) e.preventDefault();
    setCalcLoading(true);
    setCalcError(null);
    try {
      const res = await calculateRisk({
        severity: calcForm.severity,
        ml_prediction: calcForm.ml_prediction,
        confidence_score: parseFloat(calcForm.confidence_score) || 0,
        asset_criticality: calcForm.asset_criticality,
        cvss_score: parseFloat(calcForm.cvss_score) || 0,
        threat_intel_match: calcForm.threat_intel_match,
        threat_type: calcForm.threat_type,
        weights: {
          threat_severity: Number(weights.threat_severity) / 100,
          ml_confidence: Number(weights.ml_confidence) / 100,
          asset_criticality: Number(weights.asset_criticality) / 100,
          vulnerability_risk: Number(weights.vulnerability_risk) / 100,
          threat_intelligence: Number(weights.threat_intelligence) / 100
        }
      });
      setCalcResult(res);
    } catch (err) {
      console.error('Failed to calculate risk score from API:', err);
      const errMsg = err.response?.data?.detail || err.message || 'Unable to calculate risk score from backend.';
      setCalcError(errMsg);
      setCalcResult(null);
    } finally {
      setCalcLoading(false);
    }
  };

  // Derive unique threat categories for filter
  const uniqueThreatTypes = useMemo(() => {
    if (!Array.isArray(highRiskData)) return [];
    const types = new Set(highRiskData.map((e) => e.threat_type).filter(Boolean));
    return Array.from(types).sort();
  }, [highRiskData]);

  // Filtered high-risk alerts
  const filteredEvents = useMemo(() => {
    if (!Array.isArray(highRiskData)) return [];

    return highRiskData.filter((evt) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matches =
          (evt.event_id && String(evt.event_id).toLowerCase().includes(q)) ||
          (evt.threat_type && String(evt.threat_type).toLowerCase().includes(q)) ||
          (evt.asset_name && String(evt.asset_name).toLowerCase().includes(q)) ||
          (evt.username && String(evt.username).toLowerCase().includes(q));
        if (!matches) return false;
      }

      if (riskLevelFilter !== 'ALL' && evt.risk_level !== riskLevelFilter) {
        return false;
      }

      if (threatTypeFilter !== 'ALL' && evt.threat_type !== threatTypeFilter) {
        return false;
      }

      return true;
    });
  }, [highRiskData, searchQuery, riskLevelFilter, threatTypeFilter]);

  // Pagination
  const totalFiltered = filteredEvents.length;
  const totalPages = Math.ceil(totalFiltered / limit) || 1;
  const paginatedEvents = filteredEvents.slice((page - 1) * limit, page * limit);
  const startRange = totalFiltered > 0 ? (page - 1) * limit + 1 : 0;
  const endRange = Math.min(page * limit, totalFiltered);

  // Distribution Chart Data for Exact M3 5-Tier Breakdown
  const dist = summaryData?.risk_distribution || { Critical: 0, High: 0, Moderate: 0, Medium: 0, Low: 0 };
  const totalEvaluated = summaryData?.total_evaluated_events || 0;

  const getPct = (cnt) => (totalEvaluated > 0 ? ((cnt / totalEvaluated) * 100).toFixed(1) : '0.0');

  const chartData = [
    { name: 'Critical', value: dist.Critical || 0, color: RISK_RANGES.Critical.color, pct: getPct(dist.Critical || 0), range: '81–100' },
    { name: 'High', value: dist.High || 0, color: RISK_RANGES.High.color, pct: getPct(dist.High || 0), range: '61–80' },
    { name: 'Moderate', value: dist.Moderate || 0, color: RISK_RANGES.Moderate.color, pct: getPct(dist.Moderate || 0), range: '41–60' },
    { name: 'Medium', value: dist.Medium || 0, color: RISK_RANGES.Medium.color, pct: getPct(dist.Medium || 0), range: '21–40' },
    { name: 'Low', value: dist.Low || 0, color: RISK_RANGES.Low.color, pct: getPct(dist.Low || 0), range: '0–20' }
  ];

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0];
      return (
        <div style={styles.tooltipContainer}>
          <div style={{ color: item.payload.color, fontWeight: '700' }}>
            {item.name} Risk ({item.payload.range})
          </div>
          <div style={styles.tooltipValue}>
            {item.value.toLocaleString()} events ({item.payload.pct}%)
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED PAGE HEADER & ACTION CONTROLS */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <Flame size={20} color="var(--color-accent)" />
            <span>Risk Prioritization & Scoring Overview</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            M3 Deterministic Multi-Factor Risk Scoring Engine across 5 normalized operational pillars
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            className="soc-button"
            onClick={() => setShowWeightsPanel(!showWeightsPanel)}
            style={{
              fontSize: '0.78rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem',
              borderColor: weightsMeta.is_custom ? 'var(--color-warning)' : undefined,
              color: weightsMeta.is_custom ? 'var(--color-warning)' : undefined
            }}
            title="Configure 5-pillar mathematical risk scoring weights"
          >
            <Sliders size={14} />
            <span>{showWeightsPanel ? 'Close Weights' : 'Dynamic Risk Weights'}</span>
            {weightsMeta.is_custom && <span className="badge severity-moderate" style={{ fontSize: '0.62rem', padding: '0.05rem 0.25rem' }}>Custom</span>}
          </button>

          <button
            className="soc-button"
            onClick={() => setShowComparisonPanel(!showComparisonPanel)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Inspect Before vs After correlation risk comparison"
          >
            <Cpu size={14} />
            <span>{showComparisonPanel ? 'Close Comparison' : 'Score Comparison'}</span>
          </button>

          <button
            className="soc-button"
            onClick={() => setShowCalculator(!showCalculator)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <Calculator size={14} />
            <span>{showCalculator ? 'Close Calculator' : 'Live Calculator'}</span>
          </button>

          <button
            className="soc-button"
            onClick={() => setShowMethodology(!showMethodology)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          >
            <BookOpen size={14} />
            <span>{showMethodology ? 'Hide Methodology' : 'Methodology'}</span>
          </button>

          <button
            className="soc-button"
            onClick={() => fetchRiskData(true)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Refresh M3 Risk Analytics"
          >
            <RefreshCw size={14} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Evaluating multi-factor risk scores and distributions from security backend...</p>
        </div>
      )}

      {error && !loading && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && summaryData && (
        <div style={styles.contentSection}>
          {/* 2. COMPACT 6-CARD M3 RISK KPI GRID */}
          <div style={styles.kpiGrid6}>
            <CompactKpiCard
              label="EVALUATED EVENTS"
              value={totalEvaluated}
              subtitle="Scanned security telemetry"
              color="var(--color-accent)"
              icon={Activity}
            />
            <CompactKpiCard
              label="AVERAGE RISK SCORE"
              value={summaryData?.average_risk_score ?? 0}
              subtitle="Mean operational risk"
              color="var(--color-warning)"
              icon={Flame}
            />
            <CompactKpiCard
              label="CRITICAL RISK (81–100)"
              value={dist.Critical || 0}
              subtitle="Immediate action required"
              color={RISK_RANGES.Critical.color}
              icon={AlertTriangle}
            />
            <CompactKpiCard
              label="HIGH RISK (61–80)"
              value={dist.High || 0}
              subtitle="Urgent SOC prioritization"
              color={RISK_RANGES.High.color}
              icon={ShieldAlert}
            />
            <CompactKpiCard
              label="MODERATE RISK (41–60)"
              value={dist.Moderate || 0}
              subtitle="Elevated monitoring"
              color={RISK_RANGES.Moderate.color}
              icon={AlertOctagon}
            />
            <CompactKpiCard
              label="MEDIUM / LOW (0–40)"
              value={(dist.Medium || 0) + (dist.Low || 0)}
              subtitle="Standard telemetry baseline"
              color={RISK_RANGES.Low.color}
              icon={ShieldCheck}
            />
          </div>

          {/* DYNAMIC RISK WEIGHTS CONFIGURATION PANEL (PUT /v1/risk/weights) */}
          {showWeightsPanel && (
            <div className="panel" style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--color-accent)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Sliders size={18} color="var(--color-accent)" />
                  <div>
                    <h3 className="section-title" style={{ fontSize: '1rem', margin: 0 }}>
                      Dynamic Risk Weights Configuration
                    </h3>
                    <p className="muted" style={{ margin: '0.2rem 0 0 0', fontSize: '0.75rem' }}>
                      Configure the 5 operational risk-scoring pillars. Total must equal exactly 100%.
                    </p>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span className={`badge ${totalWeightsPct === 100 ? 'status-success' : 'severity-critical'}`} style={{ fontSize: '0.75rem' }}>
                    Total: {totalWeightsPct}% {totalWeightsPct === 100 ? '(Valid)' : '(Must Equal 100%)'}
                  </span>
                  {weightsMeta.is_custom && (
                    <span className="badge severity-moderate" style={{ fontSize: '0.7rem' }}>Custom Active</span>
                  )}
                </div>
              </div>

              {weightsMsg && (
                <div style={{
                  padding: '0.6rem 0.85rem',
                  borderRadius: '6px',
                  marginBottom: '1rem',
                  fontSize: '0.8rem',
                  backgroundColor: weightsMsg.type === 'success' ? 'rgba(34, 197, 94, 0.1)' : 'rgba(244, 63, 94, 0.1)',
                  border: `1px solid ${weightsMsg.type === 'success' ? 'var(--color-success)' : 'var(--color-critical)'}`,
                  color: weightsMsg.type === 'success' ? 'var(--color-success)' : 'var(--color-critical)'
                }}>
                  {weightsMsg.text}
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                <div>
                  <label style={styles.formLabel}>
                    Threat Severity: <strong>{weights.threat_severity}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={weights.threat_severity}
                    onChange={(e) => setWeights({ ...weights, threat_severity: parseInt(e.target.value) || 0 })}
                    style={{ width: '100%' }}
                  />
                  <input
                    type="number"
                    min="0"
                    max="100"
                    className="soc-select"
                    value={weights.threat_severity}
                    onChange={(e) => setWeights({ ...weights, threat_severity: parseInt(e.target.value) || 0 })}
                    style={{ marginTop: '0.35rem', width: '100%', fontSize: '0.8rem' }}
                  />
                </div>

                <div>
                  <label style={styles.formLabel}>
                    ML Confidence: <strong>{weights.ml_confidence}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={weights.ml_confidence}
                    onChange={(e) => setWeights({ ...weights, ml_confidence: parseInt(e.target.value) || 0 })}
                    style={{ width: '100%' }}
                  />
                  <input
                    type="number"
                    min="0"
                    max="100"
                    className="soc-select"
                    value={weights.ml_confidence}
                    onChange={(e) => setWeights({ ...weights, ml_confidence: parseInt(e.target.value) || 0 })}
                    style={{ marginTop: '0.35rem', width: '100%', fontSize: '0.8rem' }}
                  />
                </div>

                <div>
                  <label style={styles.formLabel}>
                    Asset Criticality: <strong>{weights.asset_criticality}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={weights.asset_criticality}
                    onChange={(e) => setWeights({ ...weights, asset_criticality: parseInt(e.target.value) || 0 })}
                    style={{ width: '100%' }}
                  />
                  <input
                    type="number"
                    min="0"
                    max="100"
                    className="soc-select"
                    value={weights.asset_criticality}
                    onChange={(e) => setWeights({ ...weights, asset_criticality: parseInt(e.target.value) || 0 })}
                    style={{ marginTop: '0.35rem', width: '100%', fontSize: '0.8rem' }}
                  />
                </div>

                <div>
                  <label style={styles.formLabel}>
                    Vulnerability Risk: <strong>{weights.vulnerability_risk}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={weights.vulnerability_risk}
                    onChange={(e) => setWeights({ ...weights, vulnerability_risk: parseInt(e.target.value) || 0 })}
                    style={{ width: '100%' }}
                  />
                  <input
                    type="number"
                    min="0"
                    max="100"
                    className="soc-select"
                    value={weights.vulnerability_risk}
                    onChange={(e) => setWeights({ ...weights, vulnerability_risk: parseInt(e.target.value) || 0 })}
                    style={{ marginTop: '0.35rem', width: '100%', fontSize: '0.8rem' }}
                  />
                </div>

                <div>
                  <label style={styles.formLabel}>
                    Threat Intelligence: <strong>{weights.threat_intelligence}%</strong>
                  </label>
                  <input
                    type="range"
                    min="0"
                    max="100"
                    step="1"
                    value={weights.threat_intelligence}
                    onChange={(e) => setWeights({ ...weights, threat_intelligence: parseInt(e.target.value) || 0 })}
                    style={{ width: '100%' }}
                  />
                  <input
                    type="number"
                    min="0"
                    max="100"
                    className="soc-select"
                    value={weights.threat_intelligence}
                    onChange={(e) => setWeights({ ...weights, threat_intelligence: parseInt(e.target.value) || 0 })}
                    style={{ marginTop: '0.35rem', width: '100%', fontSize: '0.8rem' }}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Note: Modifying weights alters analytical risk assessment scores across calculations. It does not alter underlying M2 machine learning model predictions.
                </span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    className="soc-button"
                    onClick={handleResetWeights}
                    disabled={weightsSaving}
                    style={{ fontSize: '0.78rem' }}
                  >
                    Reset to Default (25/25/20/20/10)
                  </button>
                  <button
                    className="soc-button"
                    onClick={handleSaveWeights}
                    disabled={!isWeightsValid || weightsSaving}
                    style={{
                      fontSize: '0.78rem',
                      backgroundColor: isWeightsValid ? 'var(--color-accent)' : 'var(--bg-secondary)',
                      color: isWeightsValid ? '#000' : 'var(--text-muted)',
                      fontWeight: '700'
                    }}
                  >
                    {weightsSaving ? 'Saving...' : 'Save / Apply Weights'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* RISK SCORE COMPARISON VIEWER (GET /v1/risk/comparison/{event_id}) */}
          {showComparisonPanel && (
            <div className="panel" style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid rgba(6, 182, 212, 0.4)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Cpu size={18} color="var(--color-accent)" />
                  <div>
                    <h3 className="section-title" style={{ fontSize: '1rem', margin: 0 }}>
                      Risk Score Comparison: Before vs After Correlation
                    </h3>
                    <p className="muted" style={{ margin: '0.2rem 0 0 0', fontSize: '0.75rem' }}>
                      Compares standalone event risk against contextual multi-stage attack campaign progression.
                    </p>
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <input
                    type="text"
                    value={comparisonEventId}
                    onChange={(e) => setComparisonEventId(e.target.value)}
                    placeholder="e.g. EVT00001"
                    className="soc-select"
                    style={{ width: '160px', fontSize: '0.8rem', padding: '0.25rem 0.5rem' }}
                  />
                  <button
                    className="soc-button"
                    onClick={() => handleFetchComparison(comparisonEventId)}
                    disabled={comparisonLoading}
                    style={{ fontSize: '0.78rem', backgroundColor: 'var(--color-accent)', color: '#000', fontWeight: '700' }}
                  >
                    {comparisonLoading ? 'Comparing...' : 'Compare'}
                  </button>
                </div>
              </div>

              {comparisonError && (
                <div style={{ padding: '0.6rem', borderRadius: '6px', backgroundColor: 'rgba(244, 63, 94, 0.1)', color: 'var(--color-critical)', fontSize: '0.8rem', marginBottom: '0.75rem' }}>
                  {comparisonError}
                </div>
              )}

              {comparisonResult && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {/* Compact comparison strip */}
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
                    <div className="panel" style={{ padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderLeft: '3px solid var(--color-accent)' }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '600' }}>BEFORE CORRELATION</span>
                      <div style={{ fontSize: '1.4rem', fontWeight: '800', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                        {comparisonResult.before_correlation}
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: '400' }}> / 100</span>
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Standalone 5-Pillar Score</span>
                    </div>

                    <div className="panel" style={{ padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderLeft: `3px solid ${comparisonResult.difference > 0 ? 'var(--color-critical)' : comparisonResult.difference < 0 ? 'var(--color-warning)' : 'var(--color-accent)'}` }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '600' }}>AFTER CORRELATION</span>
                      <div style={{ fontSize: '1.4rem', fontWeight: '800', color: comparisonResult.after_correlation >= 81 ? 'var(--color-critical)' : 'var(--text-primary)', marginTop: '0.2rem' }}>
                        {comparisonResult.after_correlation}
                        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: '400' }}> / 100</span>
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>Campaign Context Assessment</span>
                    </div>

                    <div className="panel" style={{ padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderLeft: `3px solid ${comparisonResult.difference > 0 ? 'var(--color-critical)' : 'var(--color-success)'}` }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '600' }}>SCORE CHANGE</span>
                      <div style={{ fontSize: '1.4rem', fontWeight: '800', color: comparisonResult.difference > 0 ? 'var(--color-critical)' : 'var(--color-success)', marginTop: '0.2rem' }}>
                        {comparisonResult.difference > 0 ? `+${comparisonResult.difference}` : comparisonResult.difference}
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)' }}>
                        {comparisonResult.correlated ? 'Multi-Stage Escalation' : 'No correlation impact'}
                      </span>
                    </div>

                    <div className="panel" style={{ padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderLeft: '3px solid var(--border-color)' }}>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '600' }}>CORRELATION STATUS</span>
                      <div style={{ marginTop: '0.35rem' }}>
                        {comparisonResult.correlated ? (
                          <span className="badge severity-critical" style={{ fontSize: '0.75rem' }}>
                            In Attack Chain ({comparisonResult.chain_id || 'Correlated'})
                          </span>
                        ) : (
                          <span className="badge status-detected" style={{ fontSize: '0.75rem' }}>
                            No correlation impact
                          </span>
                        )}
                      </div>
                      <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.25rem', display: 'block' }}>
                        {comparisonResult.related_events_count} participating alert{comparisonResult.related_events_count === 1 ? '' : 's'}
                      </span>
                    </div>
                  </div>

                  {/* Context explanation */}
                  <div style={{ padding: '0.85rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                    <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--color-accent)', display: 'block', marginBottom: '0.4rem' }}>
                      MATHEMATICAL & CONTEXTUAL EXPLANATION:
                    </span>
                    <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                      {comparisonResult.explanation?.map((pt, idx) => (
                        <li key={idx}>{pt}</li>
                      ))}
                    </ul>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.5rem', display: 'block' }}>
                      Risk Score Comparison evaluates multi-factor risk vs campaign aggregation. It is not a probability-of-compromise metric.
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 3. INTERACTIVE LIVE RISK CALCULATOR MODAL / EXPANDABLE PANEL */}
          {showCalculator && (
            <div className="panel" style={{ padding: '1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--color-accent)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Calculator size={18} color="var(--color-accent)" />
                  <h3 className="section-title" style={{ fontSize: '1rem', margin: 0 }}>
                    Interactive Multi-Factor Risk Scoring Simulator
                  </h3>
                </div>
                <span className="badge status-detected" style={{ fontSize: '0.7rem' }}>
                  POST /api/v1/risk/calculate
                </span>
              </div>

              <form onSubmit={handleCalculateSubmit} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                <div>
                  <label style={styles.formLabel}>Threat Severity (25% Weight)</label>
                  <select
                    className="soc-select"
                    value={calcForm.severity}
                    onChange={(e) => setCalcForm({ ...calcForm, severity: e.target.value })}
                  >
                    <option value="Critical">Critical (100 pts)</option>
                    <option value="High">High (75 pts)</option>
                    <option value="Medium">Medium (50 pts)</option>
                    <option value="Low">Low (25 pts)</option>
                  </select>
                </div>

                <div>
                  <label style={styles.formLabel}>ML Anomaly Confidence (25% Weight)</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <input
                      type="range"
                      min="0"
                      max="100"
                      value={calcForm.confidence_score}
                      onChange={(e) => setCalcForm({ ...calcForm, confidence_score: e.target.value })}
                      style={{ flex: 1 }}
                    />
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', minWidth: '40px' }}>
                      {calcForm.confidence_score}%
                    </span>
                  </div>
                </div>

                <div>
                  <label style={styles.formLabel}>Asset Criticality (20% Weight)</label>
                  <select
                    className="soc-select"
                    value={calcForm.asset_criticality}
                    onChange={(e) => setCalcForm({ ...calcForm, asset_criticality: e.target.value })}
                  >
                    <option value="Critical">Critical (100 pts)</option>
                    <option value="High">High (75 pts)</option>
                    <option value="Medium">Medium (50 pts)</option>
                    <option value="Low">Low (25 pts)</option>
                  </select>
                </div>

                <div>
                  <label style={styles.formLabel}>Vulnerability CVSS Score (20% Weight)</label>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <input
                      type="number"
                      step="0.1"
                      min="0"
                      max="10"
                      className="soc-select"
                      value={calcForm.cvss_score}
                      onChange={(e) => setCalcForm({ ...calcForm, cvss_score: e.target.value })}
                    />
                  </div>
                </div>

                <div>
                  <label style={styles.formLabel}>Threat Intel / IoC Match (10% Weight)</label>
                  <select
                    className="soc-select"
                    value={calcForm.threat_intel_match ? 'yes' : 'no'}
                    onChange={(e) => setCalcForm({ ...calcForm, threat_intel_match: e.target.value === 'yes' })}
                  >
                    <option value="yes">Known Malicious IoC (+10 pts)</option>
                    <option value="no">Clean / No Match (0 pts)</option>
                  </select>
                </div>

                <div>
                  <label style={styles.formLabel}>Threat Classification</label>
                  <input
                    type="text"
                    className="soc-select"
                    value={calcForm.threat_type}
                    onChange={(e) => setCalcForm({ ...calcForm, threat_type: e.target.value })}
                  />
                </div>

                <div style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'flex-end', marginTop: '0.5rem' }}>
                  <button type="submit" className="soc-button" disabled={calcLoading} style={{ padding: '0.45rem 1.25rem' }}>
                    {calcLoading ? 'Calculating Score...' : 'Calculate Risk Score →'}
                  </button>
                </div>
              </form>

              {/* Calculator Error Feedback */}
              {calcError && (
                <div style={{ marginTop: '1rem', padding: '0.75rem 1rem', backgroundColor: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', borderRadius: '6px' }}>
                  <span style={{ color: 'var(--color-critical)', fontSize: '0.8rem', fontWeight: '600' }}>{calcError}</span>
                </div>
              )}

              {/* Calculator Output Result Strip */}
              {calcResult && (
                <div style={{ marginTop: '1.25rem', padding: '1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
                    <div>
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>
                        CALCULATED MULTI-FACTOR RISK SCORE
                      </span>
                      <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem' }}>
                        <span style={{ fontSize: '1.75rem', fontWeight: '900', fontFamily: 'var(--font-mono)', color: RISK_RANGES[calcResult.risk_level]?.color || 'var(--color-accent)' }}>
                          {calcResult.risk_score}
                        </span>
                        <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>/ 100</span>
                        <Badge type="severity" value={calcResult.risk_level} />
                      </div>
                    </div>

                    {(calcResult.breakdown || calcResult.component_breakdown) && (
                      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                        <div style={styles.calcPillar}>
                          <span style={styles.calcPillarLabel}>Severity (25%)</span>
                          <span style={styles.calcPillarVal}>
                            {(calcResult.breakdown?.threat_severity?.weighted ?? calcResult.component_breakdown?.threat_severity_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                        <div style={styles.calcPillar}>
                          <span style={styles.calcPillarLabel}>ML Conf (25%)</span>
                          <span style={styles.calcPillarVal}>
                            {(calcResult.breakdown?.ml_confidence?.weighted ?? calcResult.component_breakdown?.ml_confidence_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                        <div style={styles.calcPillar}>
                          <span style={styles.calcPillarLabel}>Asset (20%)</span>
                          <span style={styles.calcPillarVal}>
                            {(calcResult.breakdown?.asset_criticality?.weighted ?? calcResult.component_breakdown?.asset_criticality_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                        <div style={styles.calcPillar}>
                          <span style={styles.calcPillarLabel}>Vuln (20%)</span>
                          <span style={styles.calcPillarVal}>
                            {(calcResult.breakdown?.vulnerability_risk?.weighted ?? calcResult.component_breakdown?.vulnerability_risk_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                        <div style={styles.calcPillar}>
                          <span style={styles.calcPillarLabel}>Intel (10%)</span>
                          <span style={styles.calcPillarVal}>
                            {(calcResult.breakdown?.threat_intelligence?.weighted ?? calcResult.component_breakdown?.threat_intel_score ?? 0).toFixed(1)}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>

                  {calcResult.reasons && (
                    <div style={{ marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                      {calcResult.reasons.map((r, idx) => (
                        <span key={idx} className="badge status-detected" style={{ fontSize: '0.72rem' }}>
                          {r}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* 4. TWO-COLUMN ROW: 5-TIER RISK DISTRIBUTION + M3 FORMULA & TOP FACTORS */}
          <div style={styles.middleRowGrid}>
            {/* Left Panel: 5-Tier Risk Distribution Donut */}
            <div className="panel" style={styles.equalPanel}>
              <div style={styles.panelHeader}>
                <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0 }}>
                  5-Tier Risk Level Distribution
                </h3>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>GET /risk/summary</span>
              </div>

              <div style={styles.donutLayout}>
                {/* Large Center-Overlay Donut Chart */}
                <div style={styles.donutChartWrapper}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={chartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={55}
                        outerRadius={80}
                        paddingAngle={3}
                        dataKey="value"
                        stroke="#0f172a"
                        strokeWidth={2}
                      >
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip content={<CustomTooltip />} />
                    </PieChart>
                  </ResponsiveContainer>

                  {/* Centered Overlay Total Count */}
                  <div style={styles.donutCenterOverlay}>
                    <span style={styles.donutCenterValue}>{totalEvaluated.toLocaleString()}</span>
                    <span style={styles.donutCenterLabel}>EVALUATED</span>
                  </div>
                </div>

                {/* Donut Legend Listing Count & Percentage */}
                <div style={styles.legendContainer}>
                  {chartData.map((item, idx) => (
                    <div key={idx} style={styles.legendRow}>
                      <div style={styles.legendLeft}>
                        <span style={{ ...styles.legendDot, backgroundColor: item.color }} />
                        <span style={styles.legendName}>{item.name}</span>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          ({item.range})
                        </span>
                      </div>
                      <div style={styles.legendRight}>
                        <span style={{ fontWeight: '700', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                          {item.value.toLocaleString()}
                        </span>
                        <span style={styles.legendPct}>
                          {item.pct}%
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Panel: M3 5-Pillar Normalized Scoring Methodology & Top Contributing Factors */}
            <div className="panel" style={styles.equalPanel}>
              <div style={styles.panelHeader}>
                <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0 }}>
                  Multi-Factor Scoring Methodology & Top Contributing Factors
                </h3>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>M3 Formula</span>
              </div>

              {showMethodology && (
                <div style={styles.scoringThreeColumns}>
                  {/* Pillar Weights */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>NORMALIZED PILLAR WEIGHTS</div>
                    <div style={styles.methodChipRow}>
                      <span>Threat Severity</span>
                      <span className="badge severity-critical" style={styles.pointChip}>25%</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>ML Confidence</span>
                      <span className="badge severity-high" style={styles.pointChip}>25%</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Asset Criticality</span>
                      <span className="badge severity-moderate" style={styles.pointChip}>20%</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Vulnerability Risk</span>
                      <span className="badge severity-medium" style={styles.pointChip}>20%</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Threat Intelligence</span>
                      <span className="badge severity-low" style={styles.pointChip}>10%</span>
                    </div>
                  </div>

                  {/* Score Ranges */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>M3 RISK LEVEL RANGES</div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-critical" style={styles.threshBadge}>81–100</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Critical</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-high" style={styles.threshBadge}>61–80</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>High</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-moderate" style={styles.threshBadge}>41–60</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Moderate</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-medium" style={styles.threshBadge}>21–40</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Medium</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-low" style={styles.threshBadge}>0–20</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Low</span>
                    </div>
                  </div>

                  {/* Top Contributing Factors from Backend */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>TOP CONTRIBUTING RISK FACTORS</div>
                    {summaryData?.top_risk_factors && summaryData.top_risk_factors.length > 0 ? (
                      summaryData.top_risk_factors.map((item, idx) => (
                        <div key={idx} style={styles.methodChipRow}>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{item.factor}</span>
                          <span className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                            {item.count}
                          </span>
                        </div>
                      ))
                    ) : (
                      <p className="muted" style={{ fontSize: '0.75rem' }}>No major factor anomalies tallied.</p>
                    )}
                  </div>
                </div>
              )}

              <div style={styles.methodFooter}>
                Deterministic Multi-Factor Score: Risk Score = (0.25 × S_sev) + (0.25 × S_ml) + (0.20 × S_asset) + (0.20 × S_vuln) + (0.10 × S_intel)
              </div>
            </div>
          </div>

          {/* 5. PRIORITIZED SECURITY ALERTS TABLE (GET /risk/high) */}
          <div style={{ marginTop: '0.25rem' }}>
            <div style={styles.tableToolbarHeader}>
              <div>
                <h3 className="section-title" style={{ margin: 0, fontSize: '0.95rem' }}>
                  Prioritized Security Risk Events
                </h3>
                <p className="muted" style={{ margin: '0.15rem 0 0 0', fontSize: '0.75rem' }}>
                  Live evaluation sorted by multi-factor operational risk score
                </p>
              </div>

              {/* Filter Controls Row */}
              <div style={styles.toolbarControls}>
                <div style={styles.searchWrapper}>
                  <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
                  <input
                    type="text"
                    placeholder="Search Event ID, Asset, Threat, User..."
                    value={searchQuery}
                    onChange={(e) => { setSearchQuery(e.target.value); setPage(1); }}
                    style={styles.searchInput}
                  />
                </div>

                <select
                  value={riskLevelFilter}
                  onChange={(e) => { setRiskLevelFilter(e.target.value); setPage(1); }}
                  style={styles.selectFilter}
                >
                  <option value="ALL">Risk Level: All</option>
                  <option value="Critical">Critical (81–100)</option>
                  <option value="High">High (61–80)</option>
                  <option value="Moderate">Moderate (41–60)</option>
                  <option value="Medium">Medium (21–40)</option>
                  <option value="Low">Low (0–20)</option>
                </select>

                <select
                  value={threatTypeFilter}
                  onChange={(e) => { setThreatTypeFilter(e.target.value); setPage(1); }}
                  style={styles.selectFilter}
                >
                  <option value="ALL">Threat Type: All</option>
                  {uniqueThreatTypes.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {totalFiltered === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No security events match the selected search or filter criteria.</p>
              </div>
            ) : (
              <div>
                <div className="soc-table-container">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th style={{ width: '60px' }}>Rank</th>
                        <th>Event ID</th>
                        <th>Timestamp</th>
                        <th>Threat Category</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>ML Confidence</th>
                        <th>Asset Name</th>
                        <th>Criticality</th>
                        <th>CVSS Score</th>
                        <th>Threat Intel</th>
                        <th>Contributing Explanations</th>
                        <th style={{ width: '80px', textAlign: 'center' }}>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedEvents.map((evt, idx) => {
                        const globalRank = (page - 1) * limit + idx + 1;
                        const isRankOne = globalRank === 1;
                        const visibleReasons = (evt.reasons || []).slice(0, 2);
                        const hiddenReasonsCount = (evt.reasons || []).length - visibleReasons.length;
                        const fullTooltip = (evt.reasons || []).join('\n• ');

                        return (
                          <tr
                            key={evt.event_id || Math.random()}
                            style={{
                              backgroundColor: evt.risk_level === 'Critical' ? 'rgba(244, 63, 94, 0.04)' : undefined
                            }}
                          >
                            <td style={styles.monoCell}>
                              {isRankOne ? (
                                <span className="badge severity-critical" style={{ fontSize: '0.72rem', fontWeight: '800' }}>
                                  #1
                                </span>
                              ) : (
                                <span style={{ fontWeight: '700', color: 'var(--color-accent)' }}>
                                  #{globalRank}
                                </span>
                              )}
                            </td>

                            <td style={styles.monoCell}>
                              <strong>{evt.event_id}</strong>
                            </td>

                            <td style={styles.monoCell}>
                              {evt.timestamp ? String(evt.timestamp).replace('T', ' ').slice(0, 19) : 'N/A'}
                            </td>

                            <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                              {evt.threat_type || evt.event_type || 'Unknown Threat'}
                            </td>

                            <td style={styles.monoCell}>
                              <span
                                className="badge"
                                style={{
                                  fontSize: '0.85rem',
                                  fontWeight: '800',
                                  padding: '0.2rem 0.55rem',
                                  color: RISK_RANGES[evt.risk_level]?.color || 'var(--color-accent)',
                                  backgroundColor: 'var(--bg-secondary)',
                                  border: `1px solid ${RISK_RANGES[evt.risk_level]?.color || 'var(--border-color)'}`
                                }}
                              >
                                {evt.risk_score} <span style={{ fontSize: '0.65rem', opacity: 0.7 }}>/ 100</span>
                              </span>
                            </td>

                            <td>
                              <Badge type="severity" value={evt.risk_level} />
                            </td>

                            <td style={styles.monoCell}>
                              <span style={{ fontWeight: '700', color: (evt.ml_confidence || 0) >= 80 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                                {evt.ml_confidence !== undefined ? `${evt.ml_confidence}%` : '—'}
                              </span>
                            </td>

                            <td style={{ color: 'var(--text-secondary)' }}>
                              {evt.asset_name || 'N/A'}
                            </td>

                            <td>
                              <Badge type="severity" value={evt.asset_criticality || 'Low'} />
                            </td>

                            <td style={styles.monoCell}>
                              <span style={{ fontWeight: '700', color: (evt.raw_cvss_score || 0) >= 7.0 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                                {evt.raw_cvss_score !== undefined ? Number(evt.raw_cvss_score).toFixed(1) : '—'}
                              </span>
                            </td>

                            <td>
                              <span className={`badge ${evt.threat_intel_match ? 'severity-critical' : 'status-success'}`} style={{ fontSize: '0.68rem' }}>
                                {evt.threat_intel_match ? 'Hit' : 'Clean'}
                              </span>
                            </td>

                            <td>
                              <div style={styles.factorsGroup} title={`Risk Explanations:\n• ${fullTooltip}`}>
                                {visibleReasons.map((reason, rIdx) => (
                                  <span key={rIdx} className="badge status-detected" style={styles.compactFactorChip}>
                                    {reason.split(' (')[0]}
                                  </span>
                                ))}
                                {hiddenReasonsCount > 0 && (
                                  <span className="badge status-detected" style={styles.moreFactorsChip}>
                                    +{hiddenReasonsCount}
                                  </span>
                                )}
                              </div>
                            </td>

                            <td style={{ textAlign: 'center' }}>
                              <button
                                className="soc-button"
                                onClick={() => handleInspectComparison(evt.event_id)}
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
                                title={`Compare Before vs After Correlation for ${evt.event_id}`}
                              >
                                <Cpu size={11} />
                                <span>Compare</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination Footer */}
                <div style={styles.paginationFooter}>
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    Showing <strong style={{ color: 'var(--text-primary)' }}>{startRange}–{endRange}</strong> of{' '}
                    <strong style={{ color: 'var(--text-primary)' }}>{totalFiltered.toLocaleString()}</strong> events
                  </span>

                  <div style={styles.paginationControls}>
                    <button
                      className="soc-button"
                      disabled={page <= 1}
                      onClick={() => setPage((prev) => Math.max(prev - 1, 1))}
                      style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                    >
                      <ChevronLeft size={14} />
                      <span>Previous</span>
                    </button>

                    <span style={{ fontSize: '0.78rem' }}>
                      Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
                      <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong>
                    </span>

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
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  kpiGrid6: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '1rem'
  },
  kpiCard: {
    padding: '0.85rem 1rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  kpiHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  kpiLabel: {
    fontSize: '0.68rem',
    fontWeight: '700',
    letterSpacing: '0.05em',
    color: 'var(--text-muted)'
  },
  kpiValue: {
    fontSize: '1.45rem',
    fontWeight: '800',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1.1
  },
  kpiSubtitle: {
    fontSize: '0.72rem',
    color: 'var(--text-secondary)'
  },
  middleRowGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
    gap: '1.25rem'
  },
  equalPanel: {
    padding: '1.15rem 1.25rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    minHeight: '340px'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.75rem',
    paddingBottom: '0.4rem',
    borderBottom: '1px solid var(--border-subtle)'
  },
  donutLayout: {
    display: 'flex',
    alignItems: 'center',
    gap: '1.25rem',
    flex: 1
  },
  donutChartWrapper: {
    position: 'relative',
    width: '180px',
    height: '180px',
    flexShrink: 0
  },
  donutCenterOverlay: {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    pointerEvents: 'none'
  },
  donutCenterValue: {
    fontSize: '1.2rem',
    fontWeight: '800',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-primary)',
    lineHeight: 1
  },
  donutCenterLabel: {
    fontSize: '0.62rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    marginTop: '0.15rem'
  },
  legendContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.45rem',
    flex: 1
  },
  legendRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '0.78rem'
  },
  legendLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem'
  },
  legendDot: {
    width: '8px',
    height: '8px',
    borderRadius: '50%',
    flexShrink: 0
  },
  legendName: {
    fontWeight: '600',
    color: 'var(--text-primary)'
  },
  legendRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  legendPct: {
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    minWidth: '42px',
    textAlign: 'right'
  },
  scoringThreeColumns: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '0.85rem',
    flex: 1
  },
  methodCol: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.45rem'
  },
  colHeader: {
    fontSize: '0.68rem',
    fontWeight: '700',
    letterSpacing: '0.04em',
    color: 'var(--color-accent)',
    paddingBottom: '0.2rem',
    borderBottom: '1px solid var(--border-subtle)'
  },
  methodChipRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '0.75rem'
  },
  pointChip: {
    fontSize: '0.68rem',
    padding: '0.15rem 0.35rem',
    fontWeight: '700'
  },
  threshBadge: {
    fontSize: '0.68rem',
    padding: '0.15rem 0.4rem',
    fontWeight: '700'
  },
  methodFooter: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    marginTop: '0.75rem',
    paddingTop: '0.5rem',
    borderTop: '1px solid var(--border-subtle)',
    fontFamily: 'var(--font-mono)'
  },
  formLabel: {
    fontSize: '0.75rem',
    fontWeight: '600',
    color: 'var(--text-secondary)',
    marginBottom: '0.3rem',
    display: 'block'
  },
  calcPillar: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    padding: '0.35rem 0.65rem',
    backgroundColor: 'var(--bg-primary)',
    borderRadius: '4px',
    border: '1px solid var(--border-subtle)'
  },
  calcPillarLabel: {
    fontSize: '0.65rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  calcPillarVal: {
    fontSize: '0.9rem',
    fontWeight: '800',
    fontFamily: 'var(--font-mono)',
    color: 'var(--color-accent)'
  },
  tableToolbarHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem',
    marginBottom: '0.75rem'
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
  factorsGroup: {
    display: 'flex',
    gap: '0.3rem',
    alignItems: 'center',
    flexWrap: 'wrap'
  },
  compactFactorChip: {
    fontSize: '0.68rem',
    padding: '0.15rem 0.35rem'
  },
  moreFactorsChip: {
    fontSize: '0.65rem',
    padding: '0.1rem 0.3rem',
    opacity: 0.8
  },
  paginationFooter: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: '0.75rem',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  paginationControls: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem'
  },
  statePanel: {
    minHeight: '180px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  },
  tooltipContainer: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.5rem 0.75rem',
    fontSize: '0.75rem',
    boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
  },
  tooltipValue: {
    fontSize: '0.8rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    marginTop: '0.15rem'
  }
};

export default RiskPrioritizationPage;
