import React, { useState, useEffect, useMemo } from 'react';
import { getEvents } from '../services/api';
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
  Award
} from 'lucide-react';
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts';

/**
 * Deterministic Rule-Based Risk Scoring Function
 * Calculates a transparent risk score (0-100) and extracts contributing factors.
 */
export const calculateEventRisk = (evt) => {
  let score = 0;
  const factors = [];

  // Base Event Severity
  const severity = evt.event_severity || 'Low';
  if (severity === 'Critical') {
    score += 40;
    factors.push('Critical Severity (+40)');
  } else if (severity === 'High') {
    score += 30;
    factors.push('High Severity (+30)');
  } else if (severity === 'Medium') {
    score += 20;
    factors.push('Medium Severity (+20)');
  } else {
    score += 10;
    factors.push('Low Severity (+10)');
  }

  // Malware Signal
  const isMalware = evt.malware_detected === true || String(evt.malware_detected).toLowerCase() === 'yes';
  if (isMalware) {
    score += 20;
    factors.push('Malware Flagged (+20)');
  }

  // Threat Intelligence Match
  const isThreatMatch = evt.threat_intel_match === true || evt.threat_intel_matches > 0;
  if (isThreatMatch) {
    score += 25;
    factors.push('Threat Intel Match (+25)');
  }

  // Vulnerability Record Enrichment (Awarded ONLY when vulnerability_record_id exists)
  const hasVulnRecord = Boolean(
    evt.vulnerability_record_id &&
    String(evt.vulnerability_record_id).trim() !== '' &&
    evt.vulnerability_record_id !== 'null'
  );
  if (hasVulnRecord) {
    score += 15;
    factors.push('Vulnerability Enriched (+15)');
  }

  // Critical Vulnerability Severity
  const vulnSev = evt.vulnerability_severity;
  if (vulnSev === 'Critical') {
    score += 15;
    factors.push('Critical Vulnerability (+15)');
  }

  // Asset Criticality
  const assetCrit = evt.asset_criticality;
  if (assetCrit === 'Critical') {
    score += 15;
    factors.push('Critical Asset (+15)');
  } else if (assetCrit === 'High') {
    score += 10;
    factors.push('High Criticality Asset (+10)');
  }

  // MITRE Mapping
  const isMitreMapped = evt.mitre_mapping_status === 'Mapped' || Boolean(evt.mitre_id);
  if (isMitreMapped) {
    score += 5;
    factors.push('MITRE Mapped (+5)');
  }

  // Historical Incident Linkage
  const hasIncident = Boolean(evt.incident_id && String(evt.incident_id).trim() !== '' && evt.incident_id !== 'null');
  if (hasIncident) {
    score += 10;
    factors.push('Incident Linked (+10)');
  }

  // Cap final risk score at 100
  const finalScore = Math.min(100, score);

  // Assign Risk Levels
  let riskLevel = 'Low';
  if (finalScore >= 80) {
    riskLevel = 'Critical';
  } else if (finalScore >= 60) {
    riskLevel = 'High';
  } else if (finalScore >= 40) {
    riskLevel = 'Medium';
  }

  return {
    ...evt,
    riskScore: finalScore,
    riskLevel,
    riskFactors: factors
  };
};

/**
 * Compact Enterprise SOC KPI Card Component
 */
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

const RiskPrioritizationPage = ({ allEvents = null }) => {
  // Filters & Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [riskLevelFilter, setRiskLevelFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');

  // Table pagination state
  const [page, setPage] = useState(1);
  const [limit] = useState(15);
  const [showMethodology, setShowMethodology] = useState(true);

  // Calculate and rank events using useMemo when allEvents prop is present
  const derivedRankedEvents = useMemo(() => {
    if (!Array.isArray(allEvents)) return null;
    const scored = allEvents.map(calculateEventRisk);
    scored.sort((a, b) => b.riskScore - a.riskScore);
    return scored;
  }, [allEvents]);

  // Fallback standalone state if allEvents prop is not provided (standalone usage)
  const [standaloneRankedEvents, setStandaloneRankedEvents] = useState([]);
  const [standaloneLoading, setStandaloneLoading] = useState(false);
  const [standaloneError, setStandaloneError] = useState(null);

  useEffect(() => {
    // Only execute standalone API fetching if allEvents prop was NOT supplied at all
    if (allEvents !== undefined) return;

    let isMounted = true;
    setStandaloneLoading(true);
    setStandaloneError(null);

    const fetchAndRankAllEvents = async () => {
      try {
        const firstPage = await getEvents({ page: 1, limit: 100 });
        const totalPages = firstPage?.pagination?.total_pages || 1;
        let allRecords = [...(firstPage?.data || [])];

        if (totalPages > 1) {
          const batchSize = 4;
          for (let p = 2; p <= totalPages; p += batchSize) {
            const batchPromises = [];
            for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
              batchPromises.push(getEvents({ page: b, limit: 100 }));
            }
            const batchResults = await Promise.all(batchPromises);
            batchResults.forEach((res) => {
              if (res?.data) {
                allRecords = allRecords.concat(res.data);
              }
            });
          }
        }

        if (isMounted) {
          const scored = allRecords.map(calculateEventRisk);
          scored.sort((a, b) => b.riskScore - a.riskScore);
          setStandaloneRankedEvents(scored);
          setStandaloneLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to fetch and rank events:', err);
          setStandaloneError('Unable to load security risk telemetry.');
          setStandaloneLoading(false);
        }
      }
    };

    fetchAndRankAllEvents();

    return () => {
      isMounted = false;
    };
  }, [allEvents]);

  const rankedEvents = allEvents !== undefined ? (derivedRankedEvents || []) : standaloneRankedEvents;
  const loading = allEvents !== undefined ? (derivedRankedEvents === null) : standaloneLoading;
  const error = allEvents !== undefined ? null : standaloneError;

  // Reset pagination to page 1 whenever filters or search query changes
  useEffect(() => {
    setPage(1);
  }, [searchQuery, riskLevelFilter, severityFilter, eventTypeFilter]);

  // Derive unique event types for filter dropdown
  const uniqueEventTypes = useMemo(() => {
    const types = new Set(rankedEvents.map((e) => e.event_type).filter(Boolean));
    return Array.from(types).sort();
  }, [rankedEvents]);

  // Client-side Filtered Events
  const filteredEvents = useMemo(() => {
    return rankedEvents.filter((evt) => {
      // 1. Search Query Filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase().trim();
        const matchesSearch =
          (evt.event_id && String(evt.event_id).toLowerCase().includes(query)) ||
          (evt.event_type && String(evt.event_type).toLowerCase().includes(query)) ||
          (evt.source_ip && String(evt.source_ip).toLowerCase().includes(query)) ||
          (evt.destination_ip && String(evt.destination_ip).toLowerCase().includes(query)) ||
          (evt.username && String(evt.username).toLowerCase().includes(query));

        if (!matchesSearch) return false;
      }

      // 2. Risk Level Filter
      if (riskLevelFilter !== 'ALL' && evt.riskLevel !== riskLevelFilter) {
        return false;
      }

      // 3. Base Severity Filter
      if (severityFilter !== 'ALL' && evt.event_severity !== severityFilter) {
        return false;
      }

      // 4. Event Type Filter
      if (eventTypeFilter !== 'ALL' && evt.event_type !== eventTypeFilter) {
        return false;
      }

      return true;
    });
  }, [rankedEvents, searchQuery, riskLevelFilter, severityFilter, eventTypeFilter]);

  // Aggregated Summary Statistics
  const totalAnalyzed = rankedEvents.length;
  const criticalCount = rankedEvents.filter((e) => e.riskLevel === 'Critical').length;
  const highCount = rankedEvents.filter((e) => e.riskLevel === 'High').length;
  const mediumCount = rankedEvents.filter((e) => e.riskLevel === 'Medium').length;
  const lowCount = rankedEvents.filter((e) => e.riskLevel === 'Low').length;

  const avgScore = totalAnalyzed > 0
    ? (rankedEvents.reduce((acc, e) => acc + e.riskScore, 0) / totalAnalyzed).toFixed(1)
    : 0;

  // Percentages for Donut Legend
  const getPct = (cnt) => (totalAnalyzed > 0 ? ((cnt / totalAnalyzed) * 100).toFixed(1) : '0.0');

  // Chart Data for Risk Distribution
  const chartData = [
    { name: 'Critical', value: criticalCount, color: '#f43f5e', pct: getPct(criticalCount) },
    { name: 'High', value: highCount, color: '#fb923c', pct: getPct(highCount) },
    { name: 'Medium', value: mediumCount, color: '#facc15', pct: getPct(mediumCount) },
    { name: 'Low', value: lowCount, color: '#38bdf8', pct: getPct(lowCount) }
  ];

  // Pagination for prioritized table view
  const totalFiltered = filteredEvents.length;
  const totalPages = Math.ceil(totalFiltered / limit) || 1;
  const paginatedEvents = filteredEvents.slice((page - 1) * limit, page * limit);
  const startRange = totalFiltered > 0 ? (page - 1) * limit + 1 : 0;
  const endRange = Math.min(page * limit, totalFiltered);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const item = payload[0];
      return (
        <div style={styles.tooltipContainer}>
          <div style={{ color: item.payload.color, fontWeight: '700' }}>{item.name} Risk</div>
          <div style={styles.tooltipValue}>{item.value.toLocaleString()} events ({item.payload.pct}%)</div>
        </div>
      );
    }
    return null;
  };

  return (
    <div style={styles.container}>
      {/* 1. COMPACT PAGE HEADER */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={{ fontSize: '1.2rem', margin: 0 }}>
            Security Risk & Alert Prioritization
          </h2>
          <p className="muted" style={{ fontSize: '0.78rem', margin: '0.2rem 0 0 0' }}>
            Alerts ranked via transparent enrichment-based scoring rules
          </p>
        </div>
        <button
          className="soc-button"
          onClick={() => setShowMethodology(!showMethodology)}
          style={styles.methodologyToggleBtn}
        >
          <BookOpen size={13} />
          <span>{showMethodology ? 'Hide Rules' : 'Scoring Methodology'}</span>
        </button>
      </div>

      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Retrieving all 1,800 events from MongoDB & computing deterministic risk rankings...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && (
        <div style={styles.contentSection}>
          {/* 2. COMPACT 6-CARD KPI GRID */}
          <div style={styles.kpiGrid6}>
            <CompactKpiCard
              label="TOTAL EVENTS"
              value={totalAnalyzed}
              subtitle="Scanned logs"
              color="var(--color-accent)"
              icon={Activity}
            />
            <CompactKpiCard
              label="CRITICAL RISK ALERTS"
              value={criticalCount}
              subtitle="Score 80-100"
              color="var(--color-critical)"
              icon={AlertTriangle}
            />
            <CompactKpiCard
              label="HIGH RISK ALERTS"
              value={highCount}
              subtitle="Score 60-79"
              color="var(--color-high)"
              icon={ShieldAlert}
            />
            <CompactKpiCard
              label="MEDIUM RISK ALERTS"
              value={mediumCount}
              subtitle="Score 40-59"
              color="var(--color-warning)"
              icon={AlertOctagon}
            />
            <CompactKpiCard
              label="LOW RISK ALERTS"
              value={lowCount}
              subtitle="Score 0-39"
              color="#38bdf8"
              icon={ShieldCheck}
            />
            <CompactKpiCard
              label="AVERAGE RISK SCORE"
              value={avgScore}
              subtitle="Mean severity"
              color="var(--color-warning)"
              icon={Flame}
            />
          </div>

          {/* 3. TWO-COLUMN EQUAL-HEIGHT ROW (DONUT + METHODOLOGY) */}
          <div style={styles.middleRowGrid}>
            {/* Left Panel: Risk Level Distribution Donut */}
            <div className="panel" style={styles.equalPanel}>
              <div style={styles.panelHeader}>
                <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0 }}>
                  Risk Level Distribution
                </h3>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>Live Telemetry</span>
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
                    <span style={styles.donutCenterValue}>{totalAnalyzed.toLocaleString()}</span>
                    <span style={styles.donutCenterLabel}>EVENTS</span>
                  </div>
                </div>

                {/* Donut Legend Listing Count & Percentage */}
                <div style={styles.legendContainer}>
                  {chartData.map((item, idx) => (
                    <div key={idx} style={styles.legendRow}>
                      <div style={styles.legendLeft}>
                        <span style={{ ...styles.legendDot, backgroundColor: item.color }} />
                        <span style={styles.legendName}>{item.name}</span>
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

            {/* Right Panel: Transparent Rule-Based Risk Scoring Methodology */}
            <div className="panel" style={styles.equalPanel}>
              <div style={styles.panelHeader}>
                <h3 className="section-title" style={{ fontSize: '0.9rem', margin: 0 }}>
                  Transparent Rule-Based Risk Scoring Methodology
                </h3>
                <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>Deterministic</span>
              </div>

              {showMethodology && (
                <div style={styles.scoringThreeColumns}>
                  {/* Column 1: Base Event Severity */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>BASE EVENT SEVERITY</div>
                    <div style={styles.methodChipRow}>
                      <span>Critical</span>
                      <span className="badge severity-critical" style={styles.pointChip}>+40</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>High</span>
                      <span className="badge severity-high" style={styles.pointChip}>+30</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Medium</span>
                      <span className="badge severity-medium" style={styles.pointChip}>+20</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Low</span>
                      <span className="badge severity-low" style={styles.pointChip}>+10</span>
                    </div>
                  </div>

                  {/* Column 2: Enrichment & Threat Signals */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>ENRICHMENT & SIGNALS</div>
                    <div style={styles.methodChipRow}>
                      <span>Threat Intel Match</span>
                      <span className="badge status-detected" style={styles.pointChip}>+25</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Malware Detected</span>
                      <span className="badge severity-critical" style={styles.pointChip}>+20</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Critical Vuln</span>
                      <span className="badge severity-critical" style={styles.pointChip}>+15</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Vuln Enriched</span>
                      <span className="badge status-detected" style={styles.pointChip}>+15</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Critical Asset</span>
                      <span className="badge severity-critical" style={styles.pointChip}>+15</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>High Asset</span>
                      <span className="badge severity-high" style={styles.pointChip}>+10</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>MITRE Mapped</span>
                      <span className="badge status-detected" style={styles.pointChip}>+5</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span>Historical Incident</span>
                      <span className="badge status-blocked" style={styles.pointChip}>+10</span>
                    </div>
                  </div>

                  {/* Column 3: Score Thresholds */}
                  <div style={styles.methodCol}>
                    <div style={styles.colHeader}>SCORE THRESHOLDS</div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-critical" style={styles.threshBadge}>80–100</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Critical</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-high" style={styles.threshBadge}>60–79</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>High</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-medium" style={styles.threshBadge}>40–59</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Medium</span>
                    </div>
                    <div style={styles.methodChipRow}>
                      <span className="badge severity-low" style={styles.threshBadge}>0–39</span>
                      <span style={{ fontWeight: '600', color: 'var(--text-primary)' }}>Low</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Subtle Methodology Footer */}
              <div style={styles.methodFooter}>
                Maximum Score: 100 points • Higher score = higher investigation priority
              </div>
            </div>
          </div>

          {/* 4. REDESIGNED FULL-WIDTH ENTERPRISE SOC ALERT TABLE */}
          <div style={{ marginTop: '0.25rem' }}>
            {/* Table Control Toolbar Header */}
            <div style={styles.tableToolbarHeader}>
              <div>
                <h3 className="section-title" style={{ margin: 0, fontSize: '0.95rem' }}>
                  Prioritized Security Alerts
                </h3>
                <p className="muted" style={{ margin: '0.15rem 0 0 0', fontSize: '0.75rem' }}>
                  Ranked by deterministic risk score
                </p>
              </div>

              {/* Filter Controls Row */}
              <div style={styles.toolbarControls}>
                {/* Search Input */}
                <div style={styles.searchWrapper}>
                  <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
                  <input
                    type="text"
                    placeholder="Search Event ID, IP, User, Type..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={styles.searchInput}
                  />
                </div>

                {/* Risk Level Filter */}
                <select
                  value={riskLevelFilter}
                  onChange={(e) => setRiskLevelFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="ALL">Risk Level: All</option>
                  <option value="Critical">Risk Level: Critical</option>
                  <option value="High">Risk Level: High</option>
                  <option value="Medium">Risk Level: Medium</option>
                  <option value="Low">Risk Level: Low</option>
                </select>

                {/* Base Severity Filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="ALL">Severity: All</option>
                  <option value="Critical">Severity: Critical</option>
                  <option value="High">Severity: High</option>
                  <option value="Medium">Severity: Medium</option>
                  <option value="Low">Severity: Low</option>
                </select>

                {/* Event Type Filter */}
                <select
                  value={eventTypeFilter}
                  onChange={(e) => setEventTypeFilter(e.target.value)}
                  style={styles.selectFilter}
                >
                  <option value="ALL">Event Type: All</option>
                  {uniqueEventTypes.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {totalFiltered === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No security alerts match the selected search or filter criteria.</p>
              </div>
            ) : (
              <div>
                <div className="soc-table-container">
                  <table className="soc-table">
                    <thead>
                      <tr>
                        <th style={{ width: '65px' }}>Rank</th>
                        <th>Event ID</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Base Severity</th>
                        <th>Risk Score</th>
                        <th>Risk Level</th>
                        <th>Source IP</th>
                        <th>Destination IP</th>
                        <th>Username</th>
                        <th>Risk Factors</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedEvents.map((evt) => {
                        const isRankOne = evt.event_id === rankedEvents[0]?.event_id;
                        const visibleFactors = evt.riskFactors.slice(0, 2);
                        const hiddenCount = evt.riskFactors.length - visibleFactors.length;
                        const fullFactorTooltip = evt.riskFactors.join('\n• ');

                        return (
                          <tr 
                            key={evt.event_id || Math.random()}
                            style={{
                              backgroundColor: evt.riskLevel === 'Critical'
                                ? 'rgba(244, 63, 94, 0.04)'
                                : undefined,
                              height: '52px'
                            }}
                          >
                            {/* Rank Column */}
                            <td style={styles.monoCell}>
                              {isRankOne ? (
                                <span 
                                  className="badge" 
                                  style={styles.rankOneBadge}
                                  title="Top Prioritized Risk Alert #1"
                                >
                                  <Award size={11} style={{ marginRight: '0.2rem' }} />
                                  #1
                                </span>
                              ) : (
                                <span style={{ fontWeight: '700', color: 'var(--color-accent)' }}>
                                  #{evt.globalRank || rankedEvents.findIndex((r) => r.event_id === evt.event_id) + 1}
                                </span>
                              )}
                            </td>

                            {/* Event ID */}
                            <td style={styles.monoCell}>{evt.event_id}</td>

                            {/* Timestamp */}
                            <td style={styles.monoCell}>
                              {evt.timestamp ? String(evt.timestamp).replace('T', ' ') : 'N/A'}
                            </td>

                            {/* Event Type */}
                            <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{evt.event_type}</td>

                            {/* Base Severity */}
                            <td>
                              <Badge type="severity" value={evt.event_severity} />
                            </td>

                            {/* Prominent Risk Score */}
                            <td style={styles.monoCell}>
                              <span 
                                className="badge" 
                                style={{
                                  fontSize: '0.85rem',
                                  fontWeight: '800',
                                  padding: '0.25rem 0.6rem',
                                  backgroundColor: evt.riskScore >= 80 ? 'rgba(244, 63, 94, 0.18)' : evt.riskScore >= 60 ? 'rgba(251, 146, 60, 0.15)' : 'var(--bg-primary)',
                                  color: evt.riskScore >= 80 ? 'var(--color-critical)' : evt.riskScore >= 60 ? 'var(--color-high)' : 'var(--color-accent)',
                                  border: `1px solid ${evt.riskScore >= 80 ? 'var(--color-critical)' : 'var(--border-color)'}`
                                }}
                              >
                                {evt.riskScore} <span style={{ fontSize: '0.65rem', opacity: 0.7, fontWeight: '400' }}>/ 100</span>
                              </span>
                            </td>

                            {/* Risk Level */}
                            <td>
                              <Badge type="severity" value={evt.riskLevel} />
                            </td>

                            {/* Source IP */}
                            <td style={styles.monoCell}>{evt.source_ip || 'N/A'}</td>

                            {/* Destination IP */}
                            <td style={styles.monoCell}>{evt.destination_ip || 'N/A'}</td>

                            {/* Username */}
                            <td>{evt.username || 'N/A'}</td>

                            {/* Compact Risk Factors */}
                            <td>
                              <div style={styles.factorsGroup} title={`Contributing Risk Factors:\n• ${fullFactorTooltip}`}>
                                {visibleFactors.map((factor, fIdx) => (
                                  <span key={fIdx} className="badge status-detected" style={styles.compactFactorChip}>
                                    {factor.split(' (')[0]}
                                  </span>
                                ))}
                                {hiddenCount > 0 && (
                                  <span className="badge status-detected" style={styles.moreFactorsChip}>
                                    +{hiddenCount}
                                  </span>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination Footer */}
                <div style={styles.paginationFooter}>
                  <div style={styles.paginationInfo}>
                    <span>
                      Showing <strong style={{ color: 'var(--text-primary)' }}>{startRange}–{endRange}</strong> of{' '}
                      <strong style={{ color: 'var(--text-primary)' }}>{totalFiltered.toLocaleString()}</strong> results
                      {totalFiltered !== totalAnalyzed && ` (filtered from ${totalAnalyzed.toLocaleString()})`}
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

                    <span style={{ fontSize: '0.78rem' }}>
                      Page <strong style={{ color: 'var(--text-primary)' }}>{page}</strong> of{' '}
                      <strong style={{ color: 'var(--text-primary)' }}>{totalPages}</strong>
                    </span>

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
    marginBottom: '0.15rem'
  },
  methodologyToggleBtn: {
    fontSize: '0.75rem',
    padding: '0.35rem 0.65rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem'
  },
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  kpiCard: {
    padding: '0.65rem 0.85rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'center'
  },
  kpiHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.2rem'
  },
  kpiLabel: {
    fontSize: '0.65rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em'
  },
  kpiValue: {
    fontSize: '1.25rem',
    fontWeight: '800',
    fontFamily: 'var(--font-mono)',
    lineHeight: '1.2'
  },
  kpiSubtitle: {
    fontSize: '0.68rem',
    color: 'var(--text-secondary)',
    marginTop: '0.15rem'
  },
  kpiGrid6: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
    gap: '0.85rem'
  },
  middleRowGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))',
    gap: '1.25rem'
  },
  equalPanel: {
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    padding: '1rem 1.15rem',
    minHeight: '260px'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.75rem'
  },
  donutLayout: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-around',
    gap: '1rem',
    flex: 1
  },
  donutChartWrapper: {
    position: 'relative',
    width: '160px',
    height: '160px'
  },
  donutCenterOverlay: {
    position: 'absolute',
    top: '50%',
    left: '50%',
    transform: 'translate(-50%, -50%)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    pointerEvents: 'none'
  },
  donutCenterValue: {
    fontSize: '1.1rem',
    fontWeight: '800',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1
  },
  donutCenterLabel: {
    fontSize: '0.6rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em',
    marginTop: '0.2rem'
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
    borderRadius: '50%'
  },
  legendName: {
    color: 'var(--text-secondary)',
    fontWeight: '500'
  },
  legendRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  legendPct: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    minWidth: '42px',
    textAlign: 'right'
  },
  scoringThreeColumns: {
    display: 'grid',
    gridTemplateColumns: 'repeat(3, 1fr)',
    gap: '0.75rem',
    flex: 1
  },
  methodCol: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem',
    backgroundColor: 'var(--bg-primary)',
    padding: '0.65rem 0.75rem',
    borderRadius: '4px',
    border: '1px solid var(--border-color)'
  },
  colHeader: {
    fontSize: '0.62rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.05em',
    marginBottom: '0.2rem'
  },
  methodChipRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    fontSize: '0.73rem',
    color: 'var(--text-secondary)'
  },
  pointChip: {
    fontSize: '0.65rem',
    padding: '0.1rem 0.35rem',
    fontWeight: '700'
  },
  threshBadge: {
    fontSize: '0.68rem',
    padding: '0.12rem 0.4rem',
    fontFamily: 'var(--font-mono)'
  },
  methodFooter: {
    fontSize: '0.68rem',
    color: 'var(--text-muted)',
    marginTop: '0.6rem',
    textAlign: 'center'
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
    gap: '0.6rem',
    flexWrap: 'wrap'
  },
  searchWrapper: {
    position: 'relative',
    display: 'flex',
    alignItems: 'center'
  },
  searchIcon: {
    position: 'absolute',
    left: '0.6rem'
  },
  searchInput: {
    padding: '0.35rem 0.6rem 0.35rem 1.8rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    color: 'var(--text-primary)',
    fontSize: '0.78rem',
    width: '200px',
    outline: 'none'
  },
  selectFilter: {
    padding: '0.35rem 0.6rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    color: 'var(--text-primary)',
    fontSize: '0.78rem',
    outline: 'none',
    cursor: 'pointer'
  },
  rankOneBadge: {
    backgroundColor: 'rgba(244, 63, 94, 0.2)',
    color: 'var(--color-critical)',
    border: '1px solid var(--color-critical)',
    fontWeight: '800',
    padding: '0.2rem 0.45rem',
    fontSize: '0.75rem'
  },
  factorsGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    flexWrap: 'wrap'
  },
  compactFactorChip: {
    fontSize: '0.65rem',
    padding: '0.12rem 0.35rem',
    fontWeight: '500'
  },
  moreFactorsChip: {
    fontSize: '0.65rem',
    padding: '0.12rem 0.35rem',
    backgroundColor: 'var(--bg-primary)',
    color: 'var(--color-accent)',
    border: '1px solid var(--border-color)'
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
    gap: '0.75rem'
  },
  tooltipContainer: {
    backgroundColor: '#131c2e',
    border: '1px solid #334155',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem',
    boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
    fontSize: '0.75rem'
  },
  tooltipValue: {
    color: '#f8fafc',
    marginTop: '0.2rem',
    fontFamily: 'var(--font-mono)'
  }
};

export default RiskPrioritizationPage;
