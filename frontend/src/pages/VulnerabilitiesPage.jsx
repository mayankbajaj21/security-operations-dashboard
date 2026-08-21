import React, { useState, useEffect, useMemo } from 'react';
import { getAssets, getMetrics } from '../services/api';
import Badge from '../components/Badge';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Server, 
  Bug, 
  RefreshCw, 
  CheckCircle2, 
  Terminal,
  Radar
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell } from 'recharts';

/**
 * Vulnerabilities Page — Enterprise SOC Vulnerability Management & Assessment Center
 * Consumes:
 * - GET /assets (Monitored IT assets enriched with CVE vulnerability signatures)
 * - GET /metrics (Aggregated vulnerability indicators)
 */
const VulnerabilitiesPage = () => {
  const [assetData, setAssetData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [hoveredBlip, setHoveredBlip] = useState(null);

  // Filters & Search
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [patchFilter, setPatchFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [assetsRes] = await Promise.all([
        getAssets({ forceRefresh: true }),
        getMetrics({ forceRefresh: true }).catch(() => null)
      ]);
      setAssetData(assetsRes);
    } catch (err) {
      console.error('Failed to load vulnerability telemetry:', err);
      setError('Unable to retrieve vulnerability intelligence and asset exposure data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const rawAssets = useMemo(() => {
    if (!assetData) return [];
    if (Array.isArray(assetData.assets)) return assetData.assets;
    if (Array.isArray(assetData)) return assetData;
    return [];
  }, [assetData]);

  // Flatten and correlate all vulnerabilities across assets
  const { allVulns, kpiMetrics, severityDistribution, topAffectedAssets } = useMemo(() => {
    const flattened = [];
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let patchableCount = 0;
    const assetExposureMap = [];

    rawAssets.forEach((asset) => {
      const assetVulns = Array.isArray(asset?.vulnerabilities) ? asset.vulnerabilities : [];
      const hasVulns = assetVulns.length > 0;

      if (hasVulns) {
        const scores = assetVulns.map((v) => Number(v.vulnerability_cvss_score) || 0);
        assetExposureMap.push({
          asset_id: asset.asset_id || 'UNKNOWN',
          asset_name: asset.asset_name || 'Host Endpoint',
          asset_type: asset.asset_type || 'Server',
          criticality: asset.criticality || 'Medium',
          operating_system: asset.operating_system || 'Linux',
          vulnCount: assetVulns.length,
          criticalEventCount: asset.critical_event_count || 0,
          eventCount: asset.event_count || 0,
          maxCvss: scores.length > 0 ? Math.max(...scores) : 0
        });
      }

      assetVulns.forEach((v, vIdx) => {
        const cveKey = `${v.cve_id || 'CVE'}_${asset.asset_id || 'AST'}_${vIdx}`;
        const cvss = Number(v.vulnerability_cvss_score) || 0;
        const sev = v.vulnerability_severity || (cvss >= 9.0 ? 'Critical' : cvss >= 7.0 ? 'High' : 'Medium');

        const item = {
          ...v,
          uniqueKey: cveKey,
          cve_id: v.cve_id || 'CVE-UNKNOWN',
          vulnerability_name: v.vulnerability_name || 'Vulnerability Disclosure',
          vulnerability_severity: sev,
          vulnerability_cvss_score: cvss,
          patch_available: v.patch_available || 'Available',
          vulnerability_status: v.vulnerability_status || 'Active',
          asset_id: asset.asset_id || 'UNKNOWN',
          asset_name: asset.asset_name || 'Host Endpoint',
          asset_type: asset.asset_type || 'Server',
          asset_criticality: asset.criticality || 'Medium',
          operating_system: asset.operating_system || 'Linux',
          asset_event_count: asset.event_count || 0,
          asset_critical_events: asset.critical_event_count || 0
        };
        flattened.push(item);

        if (sev.toLowerCase() === 'critical' || cvss >= 9.0) criticalCount++;
        else if (sev.toLowerCase() === 'high' || cvss >= 7.0) highCount++;
        else if (sev.toLowerCase() === 'medium') mediumCount++;
        else lowCount++;

        const patch = (v.patch_available || '').toLowerCase();
        if (patch === 'yes' || patch === 'available' || patch === 'true') patchableCount++;
      });
    });

    // Top affected assets sorted by critical exposure
    assetExposureMap.sort((a, b) => (b.vulnCount * 10 + b.criticalEventCount) - (a.vulnCount * 10 + a.criticalEventCount));

    const totalUniqueCves = new Set(flattened.map((v) => v.cve_id)).size;
    const affectedAssetsCount = assetExposureMap.length;

    // All 4 severity bands guaranteed in distribution chart
    const sevDist = [
      { name: 'Critical', count: criticalCount, color: '#dc2626' },
      { name: 'High', count: highCount, color: '#ea580c' },
      { name: 'Medium', count: mediumCount, color: '#d97706' },
      { name: 'Low', count: lowCount, color: '#0284c7' }
    ];

    return {
      allVulns: flattened,
      kpiMetrics: {
        totalVulns: flattened.length,
        uniqueCves: totalUniqueCves,
        criticalVulns: criticalCount,
        highVulns: highCount,
        mediumVulns: mediumCount,
        lowVulns: lowCount,
        affectedAssets: affectedAssetsCount,
        patchableCount: patchableCount
      },
      severityDistribution: sevDist,
      topAffectedAssets: assetExposureMap
    };
  }, [rawAssets]);

  // Filtered vulnerabilities list
  const filteredVulns = useMemo(() => {
    return allVulns.filter((v) => {
      if (severityFilter && (v.vulnerability_severity || '').toLowerCase() !== severityFilter.toLowerCase()) {
        return false;
      }
      if (patchFilter) {
        const isYes = (v.patch_available || '').toLowerCase() === 'yes' || (v.patch_available || '').toLowerCase() === 'available';
        if (patchFilter === 'Yes' && !isYes) return false;
        if (patchFilter === 'No' && isYes) return false;
      }
      if (statusFilter && (v.vulnerability_status || '').toLowerCase() !== statusFilter.toLowerCase()) {
        return false;
      }
      if (searchTerm && searchTerm.trim()) {
        const q = searchTerm.trim().toLowerCase();
        const matchCve = (v.cve_id || '').toLowerCase().includes(q);
        const matchName = (v.vulnerability_name || '').toLowerCase().includes(q);
        const matchAsset = (v.asset_name || '').toLowerCase().includes(q) || (v.asset_id || '').toLowerCase().includes(q);
        if (!matchCve && !matchName && !matchAsset) return false;
      }
      return true;
    });
  }, [allVulns, severityFilter, patchFilter, statusFilter, searchTerm]);

  // Generate radar coordinate blips from live vulnerability data
  const radarBlips = useMemo(() => {
    if (!allVulns || allVulns.length === 0) return [];
    
    return allVulns.map((v, idx) => {
      const angle = (idx * (360 / Math.max(allVulns.length, 1)) + 45) * (Math.PI / 180);
      const cvss = Number(v.vulnerability_cvss_score) || 7.0;
      const distance = 40 + (cvss / 10) * 65; 
      const cx = 150 + distance * Math.cos(angle);
      const cy = 150 + distance * Math.sin(angle);
      const isCritical = (v.vulnerability_severity || '').toLowerCase() === 'critical' || cvss >= 9.0;
      const isHigh = (v.vulnerability_severity || '').toLowerCase() === 'high' || (cvss >= 7.0 && cvss < 9.0);

      return {
        id: v.uniqueKey || `blip-${idx}`,
        cx,
        cy,
        cve: v.cve_id,
        name: v.vulnerability_name,
        asset: v.asset_name,
        cvss: v.vulnerability_cvss_score,
        severity: v.vulnerability_severity,
        patch: v.patch_available,
        color: isCritical ? '#dc2626' : isHigh ? '#ea580c' : '#0284c7'
      };
    });
  }, [allVulns]);

  return (
    <div style={styles.container}>
      {/* 1. TOP ACTION TOOLBAR */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', width: '100%', marginBottom: '-0.25rem' }}>
        <button 
          className="soc-button" 
          onClick={fetchData}
          disabled={loading}
          style={{ fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '0.4rem', padding: '0.45rem 0.85rem' }}
        >
          <RefreshCw size={13} className={loading ? 'spin-icon' : ''} />
          <span>{loading ? 'Refreshing...' : 'Refresh Vulnerability Data'}</span>
        </button>
      </div>

      {loading && !assetData ? (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading enterprise vulnerability telemetry and asset risk profiles...</p>
        </div>
      ) : error ? (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      ) : (
        <div style={styles.contentSection}>
          
          {/* ==========================================================================
              2. VULNERABILITY ASSESSMENT CENTER (INTERACTIVE 2-COLUMN SECTION)
              ========================================================================== */}
          <div className="soc-vuln-assessment-grid">
            
            {/* LEFT: VULNERABILITY EXPOSURE RADAR */}
            <div className="panel" style={styles.radarCard}>
              <div style={styles.cardHeader}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Radar size={16} color="var(--color-accent)" />
                  <h3 style={styles.cardHeading}>Vulnerability Exposure Radar</h3>
                </div>
                <span className="badge status-detected" style={{ fontSize: '0.68rem', fontFamily: 'var(--font-mono)' }}>
                  LIVE TELEMETRY
                </span>
              </div>

              {/* Radar Graphic Canvas */}
              <div style={styles.radarCanvasWrapper}>
                <svg width="300" height="300" viewBox="0 0 300 300" style={{ overflow: 'visible' }}>
                  <defs>
                    <radialGradient id="radarGlow" cx="50%" cy="50%" r="50%">
                      <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.12" />
                      <stop offset="70%" stopColor="var(--color-accent)" stopOpacity="0.04" />
                      <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                    </radialGradient>
                    <linearGradient id="sweepGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                      <stop offset="0%" stopColor="var(--color-accent)" stopOpacity="0.45" />
                      <stop offset="100%" stopColor="transparent" stopOpacity="0" />
                    </linearGradient>
                  </defs>

                  {/* Concentric Radar Rings */}
                  <circle cx="150" cy="150" r="125" fill="url(#radarGlow)" stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="3 3" opacity="0.6" />
                  <circle cx="150" cy="150" r="95" fill="none" stroke="var(--border-subtle)" strokeWidth="1" opacity="0.7" />
                  <circle cx="150" cy="150" r="65" fill="none" stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="2 2" opacity="0.7" />
                  <circle cx="150" cy="150" r="35" fill="none" stroke="var(--border-subtle)" strokeWidth="1" opacity="0.8" />

                  {/* Radar Crosshairs */}
                  <line x1="25" y1="150" x2="275" y2="150" stroke="var(--border-subtle)" strokeWidth="1" opacity="0.4" />
                  <line x1="150" y1="25" x2="150" y2="275" stroke="var(--border-subtle)" strokeWidth="1" opacity="0.4" />
                  <line x1="60" y1="60" x2="240" y2="240" stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="2 4" opacity="0.3" />
                  <line x1="240" y1="60" x2="60" y2="240" stroke="var(--border-subtle)" strokeWidth="1" strokeDasharray="2 4" opacity="0.3" />

                  {/* Rotating Scanner Sweep */}
                  <g className="soc-radar-sweep-hand">
                    <line x1="150" y1="150" x2="150" y2="25" stroke="var(--color-accent)" strokeWidth="1.5" opacity="0.8" />
                    <polygon points="150,150 150,25 210,50" fill="url(#sweepGradient)" />
                  </g>

                  {/* Interactive Plotted Blips for Real Vulnerabilities */}
                  {radarBlips.map((blip) => (
                    <g 
                      key={blip.id} 
                      style={{ cursor: 'pointer' }}
                      onMouseEnter={() => setHoveredBlip(blip)}
                      onMouseLeave={() => setHoveredBlip(null)}
                    >
                      <circle cx={blip.cx} cy={blip.cy} r="14" fill={blip.color} opacity="0.2" className="soc-radar-blip-pulse" />
                      <circle cx={blip.cx} cy={blip.cy} r="6" fill={blip.color} stroke="#ffffff" strokeWidth="1.5" />
                    </g>
                  ))}

                  {/* Center Hub Indicator */}
                  <circle cx="150" cy="150" r="4" fill="var(--color-accent)" />
                </svg>

                {/* Central Exposure Analysis Badge */}
                <div style={styles.radarCenterInfo}>
                  <span style={styles.radarCenterTitle}>EXPOSURE ANALYSIS</span>
                  <span style={styles.radarCenterSub}>
                    {kpiMetrics.affectedAssets} affected asset · {kpiMetrics.criticalVulns} critical vulnerability
                  </span>
                </div>

                {/* Interactive Blip Hover Tooltip */}
                {hoveredBlip && (
                  <div style={styles.radarTooltip}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.2rem' }}>
                      <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                        {hoveredBlip.cve}
                      </strong>
                      <span className="badge" style={{ backgroundColor: `${hoveredBlip.color}22`, color: hoveredBlip.color, fontSize: '0.68rem' }}>
                        CVSS {Number(hoveredBlip.cvss).toFixed(1)}
                      </span>
                    </div>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', display: 'block' }}>
                      {hoveredBlip.name}
                    </span>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.2rem' }}>
                      Asset: <strong style={{ color: 'var(--text-primary)' }}>{hoveredBlip.asset}</strong>
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* RIGHT: VULNERABILITY ASSESSMENT CENTER */}
            <div className="panel" style={styles.assessmentCenterCard}>
              <div style={styles.cardHeader}>
                <div>
                  <h3 style={styles.cardHeading}>Vulnerability Assessment Center</h3>
                  <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem' }}>
                    Assess current asset exposure and vulnerability severity
                  </p>
                </div>
                <span className="badge status-success" style={{ fontSize: '0.7rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: 'var(--color-success)' }} />
                  <span>Assessment Complete</span>
                </span>
              </div>

              {/* Assessment Progress Bar */}
              <div style={styles.assessmentProgressBarRow}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '0.35rem' }}>
                  <span style={{ color: 'var(--text-secondary)', fontWeight: '600' }}>Asset Assessment Coverage</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '700', color: 'var(--color-accent)' }}>
                    100% ({rawAssets.length}/{rawAssets.length} Monitored Hosts)
                  </span>
                </div>
                <div style={styles.progressTrack}>
                  <div style={{ ...styles.progressFill, width: '100%' }} />
                </div>
              </div>

              {/* 4 Summary Metric Tiles */}
              <div style={styles.assessmentMetricsGrid}>
                <div style={styles.assessmentMetricTile}>
                  <span style={styles.tileLabel}>Assets Analyzed</span>
                  <strong style={styles.tileValue}>{rawAssets.length}</strong>
                </div>
                <div style={styles.assessmentMetricTile}>
                  <span style={styles.tileLabel}>Vulnerabilities Detected</span>
                  <strong style={{ ...styles.tileValue, color: allVulns.length > 0 ? 'var(--color-high)' : 'var(--text-primary)' }}>
                    {allVulns.length}
                  </strong>
                </div>
                <div style={styles.assessmentMetricTile}>
                  <span style={styles.tileLabel}>Critical Findings</span>
                  <strong style={{ ...styles.tileValue, color: kpiMetrics.criticalVulns > 0 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                    {kpiMetrics.criticalVulns}
                  </strong>
                </div>
                <div style={styles.assessmentMetricTile}>
                  <span style={styles.tileLabel}>Patchable Findings</span>
                  <strong style={{ ...styles.tileValue, color: 'var(--color-accent)' }}>
                    {kpiMetrics.patchableCount}
                  </strong>
                </div>
              </div>

              {/* Terminal Console Output */}
              <div style={{ marginTop: '0.85rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.35rem' }}>
                  <Terminal size={13} color="var(--color-accent)" />
                  <span style={{ fontSize: '0.7rem', fontWeight: '700', letterSpacing: '0.06em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Assessment Output
                  </span>
                </div>

                <div className="soc-assessment-terminal">
                  <div>&gt; [SYSTEM] Initializing SOC vulnerability exposure analysis...</div>
                  <div>&gt; [TELEMETRY] Monitored IT assets scanned: {rawAssets.length} host(s)</div>
                  <div>&gt; [TELEMETRY] Total CVE disclosures correlated: {allVulns.length} signature(s)</div>
                  {allVulns.map((v, i) => (
                    <div key={i} style={{ color: (v.vulnerability_severity || '').toLowerCase() === 'critical' ? '#f87171' : '#fdba74' }}>
                      &gt; [{(v.vulnerability_severity || 'HIGH').toUpperCase()}] {v.cve_id} | {v.vulnerability_name || 'Vulnerability'} | Target: {v.asset_name} | CVSS {Number(v.vulnerability_cvss_score).toFixed(1)} | Patch: {v.patch_available || 'Available'}
                    </div>
                  ))}
                  <div style={{ color: 'var(--color-success)' }}>
                    &gt; [STATUS] Vulnerability posture assessment complete. Monitored environment synchronized.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ==========================================================================
              3. VULNERABILITY OVERVIEW (COMPACT KPI STRIP)
              ========================================================================== */}
          <div style={styles.kpiOverviewGrid}>
            <div className="panel" style={styles.kpiMiniCard}>
              <div style={styles.kpiHeader}>
                <span style={styles.kpiTitle}>Total Vulnerabilities</span>
                <div style={{ ...styles.kpiIconBox, backgroundColor: 'rgba(6, 182, 212, 0.12)', color: 'var(--color-accent)' }}>
                  <Bug size={16} />
                </div>
              </div>
              <div style={styles.kpiBody}>
                <strong style={styles.kpiValueMono}>{kpiMetrics.totalVulns}</strong>
                <span style={styles.kpiSub}>{kpiMetrics.uniqueCves} unique CVE signature(s)</span>
              </div>
            </div>

            <div className="panel" style={styles.kpiMiniCard}>
              <div style={styles.kpiHeader}>
                <span style={styles.kpiTitle}>Critical Vulnerabilities</span>
                <div style={{ ...styles.kpiIconBox, backgroundColor: 'rgba(244, 63, 94, 0.12)', color: 'var(--color-critical)' }}>
                  <AlertTriangle size={16} />
                </div>
              </div>
              <div style={styles.kpiBody}>
                <strong style={{ ...styles.kpiValueMono, color: 'var(--color-critical)' }}>{kpiMetrics.criticalVulns}</strong>
                <span style={styles.kpiSub}>CVSS &gt;= 9.0 critical exposure</span>
              </div>
            </div>

            <div className="panel" style={styles.kpiMiniCard}>
              <div style={styles.kpiHeader}>
                <span style={styles.kpiTitle}>High Vulnerabilities</span>
                <div style={{ ...styles.kpiIconBox, backgroundColor: 'rgba(251, 146, 60, 0.12)', color: 'var(--color-high)' }}>
                  <ShieldAlert size={16} />
                </div>
              </div>
              <div style={styles.kpiBody}>
                <strong style={{ ...styles.kpiValueMono, color: 'var(--color-high)' }}>{kpiMetrics.highVulns}</strong>
                <span style={styles.kpiSub}>CVSS 7.0 - 8.9 elevated impact</span>
              </div>
            </div>

            <div className="panel" style={styles.kpiMiniCard}>
              <div style={styles.kpiHeader}>
                <span style={styles.kpiTitle}>Affected Assets</span>
                <div style={{ ...styles.kpiIconBox, backgroundColor: 'rgba(245, 158, 11, 0.12)', color: 'var(--color-warning)' }}>
                  <Server size={16} />
                </div>
              </div>
              <div style={styles.kpiBody}>
                <strong style={styles.kpiValueMono}>{kpiMetrics.affectedAssets}</strong>
                <span style={styles.kpiSub}>Out of {rawAssets.length} monitored host(s)</span>
              </div>
            </div>
          </div>

          {/* ==========================================================================
              4. MAIN ANALYTICS ROW (2 EQUAL COLUMNS)
              ========================================================================== */}
          <div className="soc-vuln-analytics-grid">
            
            {/* LEFT: VULNERABILITY RISK DISTRIBUTION */}
            <div className="panel" style={styles.analyticsPanel}>
              <div style={styles.panelHeader}>
                <div>
                  <h3 style={styles.cardHeading}>Vulnerability Risk Distribution</h3>
                  <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem' }}>
                    Active vulnerabilities categorized by CVSS severity levels
                  </p>
                </div>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>CVSS Severity</span>
              </div>

              <div style={{ height: '220px', width: '100%', marginTop: '0.5rem' }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={severityDistribution} margin={{ top: 15, right: 20, left: -20, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" opacity={0.5} />
                    <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                    <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} allowDecimals={false} />
                    <Tooltip 
                      contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '6px', fontSize: '0.8rem' }}
                      formatter={(value) => [`${value} Vulnerability(ies)`, 'Count']}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {severityDistribution.map((entry, idx) => (
                        <Cell key={`bar-${idx}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-around', marginTop: '0.75rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
                {severityDistribution.map((item, idx) => (
                  <div key={idx} style={{ fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: item.color }} />
                    <span style={{ color: 'var(--text-muted)' }}>{item.name}:</span>
                    <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{item.count}</strong>
                  </div>
                ))}
              </div>
            </div>

            {/* RIGHT: VULNERABLE ASSET EXPOSURE */}
            <div className="panel" style={styles.analyticsPanel}>
              <div style={styles.panelHeader}>
                <div>
                  <h3 style={styles.cardHeading}>Vulnerable Asset Exposure</h3>
                  <p className="muted" style={{ fontSize: '0.75rem', marginTop: '0.15rem' }}>
                    Ranked IT assets categorized by vulnerability density &amp; CVSS severity
                  </p>
                </div>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>Exposure Ranking</span>
              </div>

              {topAffectedAssets.length === 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '220px' }}>
                  <CheckCircle2 size={32} color="var(--color-success)" style={{ marginBottom: '0.5rem' }} />
                  <p style={{ color: 'var(--text-primary)', fontWeight: '600', fontSize: '0.85rem' }}>
                    Zero Vulnerable Assets Detected
                  </p>
                  <p className="muted" style={{ fontSize: '0.75rem' }}>
                    All monitored endpoints currently report zero active CVE exposures.
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', marginTop: '0.5rem' }}>
                  {topAffectedAssets.map((asset) => (
                    <div 
                      key={asset.asset_id}
                      style={styles.assetExposureCard}
                    >
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.15rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                          <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                            {asset.asset_name}
                          </span>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            · {asset.asset_id}
                          </span>
                        </div>
                        <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                          {asset.asset_type} • {asset.operating_system}
                        </span>
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                        <div style={{ textAlign: 'right' }}>
                          <span className="badge severity-critical" style={{ fontSize: '0.72rem' }}>
                            {asset.vulnCount} {asset.vulnCount === 1 ? 'vulnerability' : 'vulnerabilities'}
                          </span>
                        </div>
                        <div style={{ textAlign: 'right', minWidth: '60px' }}>
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', display: 'block' }}>MAX CVSS</span>
                          <strong style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', color: asset.maxCvss >= 9 ? 'var(--color-critical)' : 'var(--color-warning)' }}>
                            {Number(asset.maxCvss).toFixed(1)}
                          </strong>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* ==========================================================================
              5. FULL-WIDTH VULNERABILITY INVENTORY TABLE
              ========================================================================== */}
          <div className="panel" style={styles.tablePanel}>
            <div style={styles.tableToolbar}>
              <div>
                <h3 style={styles.cardHeading}>Vulnerability &amp; CVE Inventory</h3>
                <p className="muted" style={{ fontSize: '0.75rem', margin: '0.15rem 0 0 0' }}>
                  Enterprise Common Vulnerabilities and Exposures (CVE) repository and patch status
                </p>
              </div>

              {/* Table Search & Dropdown Filters */}
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
                <div style={{ position: 'relative' }}>
                  <input
                    type="text"
                    className="soc-select"
                    placeholder="Search CVE ID, Name, Asset..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    style={{ fontSize: '0.75rem', padding: '0.35rem 0.65rem', minWidth: '220px' }}
                  />
                </div>

                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="">Severity: All</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>

                <select
                  value={patchFilter}
                  onChange={(e) => setPatchFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="">Patch: All</option>
                  <option value="Yes">Patch Available</option>
                  <option value="No">No Patch</option>
                </select>

                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="">Status: All</option>
                  <option value="Open">Open</option>
                  <option value="Active">Active</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Resolved">Resolved</option>
                </select>
              </div>
            </div>

            {filteredVulns.length === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No vulnerabilities match the current filter criteria.</p>
              </div>
            ) : (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>CVE ID</th>
                      <th>Vulnerability Name</th>
                      <th>Target Asset</th>
                      <th>Severity</th>
                      <th>CVSS</th>
                      <th>Patch Available</th>
                      <th>Status</th>
                      <th>Telemetry Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredVulns.map((vuln) => (
                      <tr key={vuln.uniqueKey || Math.random()}>
                        <td style={styles.monoCell}>
                          <span className="badge status-detected" style={{ fontWeight: '700' }}>
                            {vuln.cve_id}
                          </span>
                        </td>
                        <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                          {vuln.vulnerability_name}
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column' }}>
                            <span style={{ fontWeight: '600', fontSize: '0.78rem', color: 'var(--text-primary)' }}>
                              {vuln.asset_name}
                            </span>
                            <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                              {vuln.asset_id} • {vuln.asset_type}
                            </span>
                          </div>
                        </td>
                        <td>
                          <Badge type="severity" value={vuln.vulnerability_severity} />
                        </td>
                        <td style={styles.monoCell}>
                          <strong style={{
                            color: vuln.vulnerability_cvss_score >= 9.0 ? 'var(--color-critical)' : vuln.vulnerability_cvss_score >= 7.0 ? 'var(--color-high)' : 'var(--text-primary)'
                          }}>
                            {Number(vuln.vulnerability_cvss_score).toFixed(1)}
                          </strong>
                        </td>
                        <td>
                          {(vuln.patch_available || '').toLowerCase() === 'yes' || (vuln.patch_available || '').toLowerCase() === 'available' ? (
                            <span className="badge status-success">Patch Available</span>
                          ) : (
                            <span className="badge status-blocked">No Patch</span>
                          )}
                        </td>
                        <td>
                          <Badge type="status" value={vuln.vulnerability_status} />
                        </td>
                        <td style={styles.monoCell}>
                          {vuln.asset_critical_events > 0 ? (
                            <span className="badge severity-critical">
                              {vuln.asset_critical_events} Critical
                            </span>
                          ) : (
                            <span className="muted" style={{ fontSize: '0.75rem' }}>
                              {vuln.asset_event_count || 0} Events
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
    gap: '1.25rem'
  },
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.75rem'
  },
  cardHeading: {
    fontSize: '0.95rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0
  },
  radarCard: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    position: 'relative'
  },
  radarCanvasWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: '300px',
    marginTop: '0.5rem'
  },
  radarCenterInfo: {
    position: 'absolute',
    textAlign: 'center',
    pointerEvents: 'none',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    gap: '0.2rem'
  },
  radarCenterTitle: {
    fontSize: '0.68rem',
    fontWeight: '800',
    letterSpacing: '0.08em',
    color: 'var(--color-accent)',
    textTransform: 'uppercase'
  },
  radarCenterSub: {
    fontSize: '0.72rem',
    fontWeight: '600',
    color: 'var(--text-primary)'
  },
  radarTooltip: {
    position: 'absolute',
    bottom: '10px',
    left: '50%',
    transform: 'translateX(-50%)',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--color-accent)',
    borderRadius: '6px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 14px rgba(0,0,0,0.35)',
    zIndex: 20,
    minWidth: '200px'
  },
  assessmentCenterCard: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between'
  },
  assessmentProgressBarRow: {
    margin: '0.5rem 0 0.85rem 0'
  },
  progressTrack: {
    width: '100%',
    height: '6px',
    backgroundColor: 'var(--border-color)',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  progressFill: {
    height: '100%',
    backgroundColor: 'var(--color-accent)',
    borderRadius: '3px',
    transition: 'width 0.4s ease'
  },
  assessmentMetricsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(4, 1fr)',
    gap: '0.65rem'
  },
  assessmentMetricTile: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.55rem 0.65rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.2rem'
  },
  tileLabel: {
    fontSize: '0.68rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  tileValue: {
    fontSize: '1.15rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  kpiOverviewGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
    gap: '1.25rem'
  },
  kpiMiniCard: {
    padding: '1rem 1.15rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    minHeight: '95px'
  },
  kpiHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  kpiTitle: {
    fontSize: '0.74rem',
    fontWeight: '600',
    color: 'var(--text-muted)',
    textTransform: 'uppercase',
    letterSpacing: '0.04em'
  },
  kpiIconBox: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '28px',
    height: '28px',
    borderRadius: '6px'
  },
  kpiBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.15rem',
    marginTop: '0.4rem'
  },
  kpiValueMono: {
    fontSize: '1.5rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '700',
    lineHeight: '1.1',
    color: 'var(--text-primary)'
  },
  kpiSub: {
    fontSize: '0.72rem',
    color: 'var(--text-secondary)'
  },
  analyticsPanel: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.5rem'
  },
  assetExposureCard: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0.65rem 0.85rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)'
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
    padding: '0.35rem 0.6rem',
    fontSize: '0.75rem',
    outline: 'none',
    fontFamily: 'var(--font-sans)',
    cursor: 'pointer'
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
  }
};

export default VulnerabilitiesPage;
