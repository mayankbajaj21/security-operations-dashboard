import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  getThreatIntel, 
  getMitre, 
  getAssets, 
  getAttackChains,
  getIncidents,
  getVulnerabilities
} from '../services/api';
import Badge from '../components/Badge';
import MetricCard from '../components/MetricCard';
import { 
  Radar, 
  Target, 
  ShieldAlert, 
  GitCommit, 
  Flame, 
  RefreshCw, 
  Search, 
  CheckCircle2, 
  AlertTriangle,
  Globe,
  Server,
  Layers,
  ShieldCheck,
  Cpu,
  ArrowRight,
  AlertOctagon,
  FileText,
  ExternalLink,
  Info
} from 'lucide-react';
import { 
  ResponsiveContainer, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip as RechartsTooltip, 
  Cell 
} from 'recharts';

/**
 * Security Intelligence & Threat Enrichment Hub
 * Milestone 4: Final Integration Layer
 * - Task 6: MITRE Technique Analysis (Table: Technique, Name, Events, Risk & Synchronized Distribution Chart)
 * - Task 7: Vulnerability Panel (Critical, High, Medium CVE summaries, Table: CVE, Asset, CVSS, Severity, Status)
 * - Task 8: IOC Intelligence Panel (IP, Domain, URL, File Hash, Email, Table: IOC, Type, Status, Threat Count, Affected Assets, First Seen, Last Seen)
 */
const SecurityIntelligencePage = ({ onInvestigateEvent = null }) => {
  const [intelSummary, setIntelSummary] = useState(null);
  const [threatIntelData, setThreatIntelData] = useState([]);
  const [mitreData, setMitreData] = useState(null);
  const [assetsData, setAssetsData] = useState([]);
  const [attackChainsData, setAttackChainsData] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [incidentsData, setIncidentsData] = useState([]);
  const [vulnerabilitiesData, setVulnerabilitiesData] = useState([]);
  const [vulnerabilitySummary, setVulnerabilitySummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filter and Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTab, setSelectedTab] = useState('iocs'); // 'iocs' | 'vulnerabilities' | 'mitre' | 'chains'

  // Task 8: IOC Type Filter (IP, Domain, URL, File Hash, Email)
  const [iocTypeFilter, setIocTypeFilter] = useState('All');

  // Task 7: Vulnerability Severity Filter (Critical, High, Medium, Low)
  const [vulnSeverityFilter, setVulnSeverityFilter] = useState('All');

  const fetchSecurityIntelligence = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      const [intelRes, mitreRes, assetsRes, chainsRes, incRes, vulnsRes] = await Promise.all([
        getThreatIntel({ noCache: isManual }).catch(() => null),
        getMitre({ noCache: isManual }).catch(() => null),
        getAssets({ noCache: isManual }).catch(() => null),
        getAttackChains({ window_minutes: 15 }, { noCache: isManual }).catch(() => null),
        getIncidents({ page: 1, limit: 100 }, { noCache: isManual }).catch(() => null),
        getVulnerabilities({}, { noCache: isManual }).catch(() => null)
      ]);

      // 1. Task 8: Threat Intel IoCs (GET /threat-intel -> indicators array)
      const rawIndicators = intelRes?.indicators || (Array.isArray(intelRes) ? intelRes : intelRes?.data || []);
      setThreatIntelData(rawIndicators);
      setIntelSummary(intelRes?.summary || null);

      // 2. Task 6: MITRE Mappings & Techniques (GET /mitre)
      setMitreData(mitreRes);

      // 3. Asset Inventory
      const rawAssets = assetsRes?.assets || (Array.isArray(assetsRes) ? assetsRes : assetsRes?.data || []);
      setAssetsData(rawAssets);

      // 4. Attack Chains
      const rawChains = Array.isArray(chainsRes?.data) ? chainsRes.data : Array.isArray(chainsRes) ? chainsRes : [];
      setAttackChainsData(rawChains);

      // 6. Linked Incidents
      const rawIncidents = Array.isArray(incRes?.data) ? incRes.data : Array.isArray(incRes) ? incRes : [];
      setIncidentsData(rawIncidents);

      // 7. Task 7: Authoritative Vulnerabilities (GET /v1/vulnerabilities)
      if (vulnsRes?.data) {
        setVulnerabilitiesData(vulnsRes.data);
        setVulnerabilitySummary(vulnsRes.summary);
      }
    } catch (err) {
      console.error('Failed to load security intelligence records:', err);
      setError('Unable to load security intelligence analytics from the backend.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSecurityIntelligence();
  }, [fetchSecurityIntelligence]);

  // =========================================================================
  // TASK 8: Filtered IOCs with Type Support (IP, Domain, URL, File Hash, Email)
  // =========================================================================
  const iocTypesList = ['All', 'IP', 'Domain', 'URL', 'File Hash', 'Email'];

  const filteredIocs = useMemo(() => {
    if (!Array.isArray(threatIntelData)) return [];
    return threatIntelData.filter((item) => {
      // IOC Type filter
      if (iocTypeFilter !== 'All') {
        const itemType = (item.type || item.indicator_type || '').toLowerCase();
        const targetType = iocTypeFilter.toLowerCase();
        if (targetType === 'ip' && !itemType.includes('ip')) return false;
        if (targetType === 'domain' && !itemType.includes('domain')) return false;
        if (targetType === 'url' && !itemType.includes('url')) return false;
        if (targetType === 'file hash' && !itemType.includes('hash')) return false;
        if (targetType === 'email' && !itemType.includes('mail')) return false;
      }
      // Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const iocVal = (item.ioc || item.indicator_value || item.indicator || '').toLowerCase();
        const typeVal = (item.type || item.indicator_type || '').toLowerCase();
        const statusVal = (item.status || item.severity || '').toLowerCase();
        const assetVal = (item.affected_assets || '').toLowerCase();
        if (!iocVal.includes(q) && !typeVal.includes(q) && !statusVal.includes(q) && !assetVal.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [threatIntelData, iocTypeFilter, searchQuery]);

  // =========================================================================
  // TASK 7: Filtered Vulnerabilities (Critical, High, Medium, Low)
  // =========================================================================
  const vulnSeveritiesList = ['All', 'Critical', 'High', 'Medium', 'Low'];

  const filteredVulnerabilities = useMemo(() => {
    if (!Array.isArray(vulnerabilitiesData)) return [];
    return vulnerabilitiesData.filter((item) => {
      if (vulnSeverityFilter !== 'All') {
        if ((item.severity || '').toLowerCase() !== vulnSeverityFilter.toLowerCase()) return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const cve = (item.cve || item.cve_id || '').toLowerCase();
        const ast = (item.asset || item.asset_name || '').toLowerCase();
        const sev = (item.severity || '').toLowerCase();
        const stat = (item.status || '').toLowerCase();
        if (!cve.includes(q) && !ast.includes(q) && !sev.includes(q) && !stat.includes(q)) {
          return false;
        }
      }
      return true;
    });
  }, [vulnerabilitiesData, vulnSeverityFilter, searchQuery]);

  // =========================================================================
  // TASK 6: Dynamic MITRE Technique Analysis Data
  // =========================================================================
  const mitreTechniques = useMemo(() => {
    if (mitreData?.techniques && Array.isArray(mitreData.techniques) && mitreData.techniques.length > 0) {
      return mitreData.techniques;
    }
    // Fallback from mappings if techniques key not yet present
    if (mitreData?.mappings && Array.isArray(mitreData.mappings)) {
      return mitreData.mappings.map((m) => ({
        technique: m.mitre_id || 'T1110',
        name: m.technique_name || m.event_type || 'Brute Force',
        events: m.event_count || 0,
        risk: 'High'
      }));
    }
    return [];
  }, [mitreData]);

  const filteredMitreTechniques = useMemo(() => {
    if (!searchQuery.trim()) return mitreTechniques;
    const q = searchQuery.toLowerCase().trim();
    return mitreTechniques.filter((t) => {
      return (
        t.technique.toLowerCase().includes(q) ||
        t.name.toLowerCase().includes(q) ||
        String(t.risk).toLowerCase().includes(q)
      );
    });
  }, [mitreTechniques, searchQuery]);

  // Derived Top KPI counts
  const totalIocs = threatIntelData.length;
  const activeChainsCount = attackChainsData.length;
  const mitreMappedCount = mitreData?.summary?.mapped_events ?? 0;
  const totalIncidentsCount = incidentsData.length;

  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED PAGE HEADER & REFRESH */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <Radar size={20} color="var(--color-accent)" />
            <span>Security Intelligence & Threat Enrichment</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            Milestone 4 Integration: Authoritative IOC intelligence, MITRE ATT&amp;CK analysis, vulnerability exposure, and attack chain correlation
          </p>
        </div>

        <button
          className="soc-button"
          onClick={() => fetchSecurityIntelligence(true)}
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          title="Refresh Security Intelligence"
        >
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>Refresh Intelligence</span>
        </button>
      </div>

      {/* 2. KPI SUMMARY METRIC CARDS */}
      <div style={styles.kpiGrid}>
        <MetricCard
          title="Monitored IoC Indicators"
          value={totalIocs}
          subtitle="Threat intelligence catalog"
          icon={Radar}
          variant="accent"
        />
        <MetricCard
          title="MITRE Mapped Events"
          value={mitreMappedCount.toLocaleString()}
          subtitle={`${mitreData?.summary?.mapping_percentage ?? 0}% mapped telemetry`}
          icon={Target}
          variant="high"
        />
        <MetricCard
          title="Active Attack Chains"
          value={activeChainsCount}
          subtitle="Correlated multi-stage pathways"
          icon={GitCommit}
          variant={activeChainsCount > 0 ? 'critical' : 'default'}
        />
        <MetricCard
          title="Linked Priority Incidents"
          value={totalIncidentsCount}
          subtitle="Enriched triage incidents"
          icon={AlertOctagon}
          variant="warning"
        />
      </div>

      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Correlating threat intelligence, MITRE mappings, and vulnerability telemetry...</p>
        </div>
      )}

      {error && !loading && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && (
        <div style={styles.contentSection}>
          {/* 3. MULTI-FACTOR RISK CONTRIBUTION HIGHLIGHT BANNER */}
          <div className="panel" style={{ padding: '1rem 1.25rem', backgroundColor: 'var(--bg-secondary)', border: '1px solid var(--border-color)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Flame size={18} color="var(--color-accent)" />
                <h3 className="section-title" style={{ fontSize: '0.92rem', margin: 0 }}>
                  Security Intelligence Multi-Factor Risk Scoring Contribution
                </h3>
              </div>
              <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
                M3 5-Pillar Normalized Weights
              </span>
            </div>

            <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0 0 0.75rem 0', lineHeight: '1.45' }}>
              Security Intelligence directly feeds the operational risk scoring engine. When an observed telemetry event matches a verified IoC (+10%), references a severe CVE (+20%), or targets a critical IT asset (+20%), the deterministic risk score elevates accordingly.
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem' }}>
              <div style={styles.intelPillarCard}>
                <span style={styles.intelPillarTitle}>Threat Intel IoC Hit</span>
                <span style={styles.intelPillarWeight}>+10% Max Weight</span>
                <span style={styles.intelPillarDesc}>Exact IP / Domain / Hash match from verified feeds</span>
              </div>
              <div style={styles.intelPillarCard}>
                <span style={styles.intelPillarTitle}>Vulnerability Risk (CVSS)</span>
                <span style={styles.intelPillarWeight}>+20% Max Weight</span>
                <span style={styles.intelPillarDesc}>CVSS score normalized (CVSS 10.0 = 20 pts)</span>
              </div>
              <div style={styles.intelPillarCard}>
                <span style={styles.intelPillarTitle}>Asset Criticality</span>
                <span style={styles.intelPillarWeight}>+20% Max Weight</span>
                <span style={styles.intelPillarDesc}>Critical (20 pts), High (15 pts), Medium (10 pts)</span>
              </div>
              <div style={styles.intelPillarCard}>
                <span style={styles.intelPillarTitle}>ML Threat Confidence</span>
                <span style={styles.intelPillarWeight}>+25% Max Weight</span>
                <span style={styles.intelPillarDesc}>Isolation Forest anomaly confidence scaling</span>
              </div>
            </div>
          </div>

          {/* 4. INTEL SUB-TABS & DATA SECTION */}
          <div className="panel" style={{ padding: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.75rem' }}>
              {/* Tab Selector Buttons */}
              <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                <button
                  className={`soc-button ${selectedTab === 'iocs' ? 'active' : ''}`}
                  onClick={() => setSelectedTab('iocs')}
                  style={{
                    fontSize: '0.78rem',
                    backgroundColor: selectedTab === 'iocs' ? 'var(--color-accent)' : undefined,
                    color: selectedTab === 'iocs' ? '#000' : undefined
                  }}
                >
                  <Radar size={13} style={{ marginRight: '0.25rem' }} />
                  <span>IOC Intelligence ({threatIntelData.length})</span>
                </button>

                <button
                  className={`soc-button ${selectedTab === 'vulnerabilities' ? 'active' : ''}`}
                  onClick={() => setSelectedTab('vulnerabilities')}
                  style={{
                    fontSize: '0.78rem',
                    backgroundColor: selectedTab === 'vulnerabilities' ? 'var(--color-accent)' : undefined,
                    color: selectedTab === 'vulnerabilities' ? '#000' : undefined
                  }}
                >
                  <Server size={13} style={{ marginRight: '0.25rem' }} />
                  <span>Vulnerability &amp; CVEs ({vulnerabilitiesData.length})</span>
                </button>

                <button
                  className={`soc-button ${selectedTab === 'mitre' ? 'active' : ''}`}
                  onClick={() => setSelectedTab('mitre')}
                  style={{
                    fontSize: '0.78rem',
                    backgroundColor: selectedTab === 'mitre' ? 'var(--color-accent)' : undefined,
                    color: selectedTab === 'mitre' ? '#000' : undefined
                  }}
                >
                  <Target size={13} style={{ marginRight: '0.25rem' }} />
                  <span>MITRE Technique Analysis ({mitreTechniques.length})</span>
                </button>

                <button
                  className={`soc-button ${selectedTab === 'chains' ? 'active' : ''}`}
                  onClick={() => setSelectedTab('chains')}
                  style={{
                    fontSize: '0.78rem',
                    backgroundColor: selectedTab === 'chains' ? 'var(--color-accent)' : undefined,
                    color: selectedTab === 'chains' ? '#000' : undefined
                  }}
                >
                  <GitCommit size={13} style={{ marginRight: '0.25rem' }} />
                  <span>Attack Chains ({attackChainsData.length})</span>
                </button>
              </div>

              {/* Search Box */}
              <div style={styles.searchWrapper}>
                <Search size={14} color="var(--text-muted)" style={styles.searchIcon} />
                <input
                  type="text"
                  placeholder="Search intelligence..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={styles.searchInput}
                />
              </div>
            </div>

            {/* =========================================================================
                TAB 1: TASK 8 — IOC INTELLIGENCE PANEL
                Required: IOC, Type (IP, Domain, URL, File Hash, Email), Status, 
                          Threat Count, Affected Assets, First Seen, Last Seen
               ========================================================================= */}
            {selectedTab === 'iocs' && (
              <div>
                {/* IOC Type Filter Buttons */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-secondary)' }}>
                    Filter by IOC Type:
                  </span>
                  {iocTypesList.map((t) => (
                    <button
                      key={t}
                      type="button"
                      className="soc-button"
                      onClick={() => setIocTypeFilter(t)}
                      style={{
                        fontSize: '0.72rem',
                        padding: '0.25rem 0.6rem',
                        backgroundColor: iocTypeFilter === t ? 'var(--color-accent)' : 'var(--bg-card)',
                        color: iocTypeFilter === t ? '#000' : 'var(--text-secondary)',
                        fontWeight: iocTypeFilter === t ? '700' : '400'
                      }}
                    >
                      {t}
                    </button>
                  ))}
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    Showing {filteredIocs.length} indicator{filteredIocs.length === 1 ? '' : 's'}
                  </span>
                </div>

                {filteredIocs.length === 0 ? (
                  <div style={styles.emptyState}>
                    <p className="muted">
                      {iocTypeFilter === 'All' 
                        ? 'No threat intelligence IOC records match search criteria.' 
                        : `No ${iocTypeFilter} indicators recorded in authoritative threat intelligence catalog.`}
                    </p>
                  </div>
                ) : (
                  <div className="soc-table-container">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>IOC</th>
                          <th>Type</th>
                          <th>Status</th>
                          <th>Threat Count</th>
                          <th>Affected Assets</th>
                          <th>First Seen</th>
                          <th>Last Seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIocs.map((item, idx) => {
                          const iocVal = item.ioc || item.indicator_value || item.indicator || 'N/A';
                          const iocType = item.type || item.indicator_type || 'IP';
                          const statusVal = item.status || item.severity || 'Active';
                          const threatCount = item.threat_count ?? item.event_match_count ?? 0;
                          const assetsVal = item.affected_assets || 'N/A';
                          const firstSeen = item.first_seen || 'N/A';
                          const lastSeen = item.last_seen || 'N/A';

                          return (
                            <tr key={idx}>
                              <td style={styles.monoCell}>
                                <strong style={{ color: 'var(--color-accent)' }}>{iocVal}</strong>
                              </td>
                              <td>
                                <span className="badge status-detected">{iocType}</span>
                              </td>
                              <td>
                                <span className={`badge ${statusVal === 'High' || statusVal === 'Critical' || statusVal === 'Malicious' ? 'severity-critical' : 'status-success'}`}>
                                  {statusVal}
                                </span>
                              </td>
                              <td style={styles.monoCell}>
                                <span style={{ fontWeight: '700', color: threatCount > 0 ? 'var(--color-critical)' : 'var(--text-muted)' }}>
                                  {threatCount}
                                </span>
                              </td>
                              <td>
                                <span style={{ color: assetsVal !== 'N/A' ? 'var(--text-primary)' : 'var(--text-muted)', fontWeight: assetsVal !== 'N/A' ? '600' : '400' }}>
                                  {assetsVal}
                                </span>
                              </td>
                              <td style={styles.monoCell}>
                                <span style={{ fontSize: '0.72rem', color: firstSeen !== 'N/A' ? 'var(--text-secondary)' : 'var(--text-muted)' }}>
                                  {firstSeen}
                                </span>
                              </td>
                              <td style={styles.monoCell}>
                                <span style={{ fontSize: '0.72rem', color: lastSeen !== 'N/A' ? 'var(--text-secondary)' : 'var(--text-muted)' }}>
                                  {lastSeen}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* =========================================================================
                TAB 2: TASK 7 — VULNERABILITY PANEL
                Required: Critical CVEs, High CVEs, Medium CVEs summaries & affected assets
                          Table: CVE, Asset, CVSS, Severity, Status
               ========================================================================= */}
            {selectedTab === 'vulnerabilities' && (
              <div>
                {/* Critical / High / Medium Summaries per M4 Task 7 */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--color-critical)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase' }}>CRITICAL CVES</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--color-critical)', marginTop: '0.15rem' }}>
                      {vulnerabilitySummary?.critical_count ?? 0}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>CVSS 9.0 – 10.0</span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--color-high)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase' }}>HIGH CVES</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--color-high)', marginTop: '0.15rem' }}>
                      {vulnerabilitySummary?.high_count ?? 0}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>CVSS 7.0 – 8.9</span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--color-warning)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase' }}>MEDIUM CVES</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--color-warning)', marginTop: '0.15rem' }}>
                      {vulnerabilitySummary?.medium_count ?? 0}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>CVSS 4.0 – 6.9</span>
                  </div>

                  <div className="panel" style={{ padding: '0.75rem', backgroundColor: 'var(--bg-card)', borderLeft: '3px solid var(--color-accent)' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: '700', textTransform: 'uppercase' }}>AFFECTED ASSETS</span>
                    <div style={{ fontSize: '1.25rem', fontWeight: '800', color: 'var(--color-accent)', marginTop: '0.15rem' }}>
                      {vulnerabilitySummary?.affected_assets_count ?? 0}
                    </div>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>Target infrastructure</span>
                  </div>
                </div>

                {/* Severity Filter Controls */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-secondary)' }}>
                    Filter Severity:
                  </span>
                  {vulnSeveritiesList.map((s) => (
                    <button
                      key={s}
                      type="button"
                      className="soc-button"
                      onClick={() => setVulnSeverityFilter(s)}
                      style={{
                        fontSize: '0.72rem',
                        padding: '0.25rem 0.6rem',
                        backgroundColor: vulnSeverityFilter === s ? 'var(--color-accent)' : 'var(--bg-card)',
                        color: vulnSeverityFilter === s ? '#000' : 'var(--text-secondary)',
                        fontWeight: vulnSeverityFilter === s ? '700' : '400'
                      }}
                    >
                      {s}
                    </button>
                  ))}
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
                    Showing {filteredVulnerabilities.length} record{filteredVulnerabilities.length === 1 ? '' : 's'}
                  </span>
                </div>

                {filteredVulnerabilities.length === 0 ? (
                  <div style={styles.emptyState}>
                    <p className="muted">No vulnerability records match current filter criteria.</p>
                  </div>
                ) : (
                  <div className="soc-table-container">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>CVE</th>
                          <th>Asset</th>
                          <th>CVSS</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredVulnerabilities.map((v, idx) => {
                          const cveVal = v.cve || v.cve_id || 'N/A';
                          const assetVal = v.asset || v.asset_name || 'N/A';
                          const cvssVal = v.cvss !== null && v.cvss !== undefined ? Number(v.cvss).toFixed(1) : 'N/A';
                          const sevVal = v.severity || 'Unknown';
                          const statusVal = v.status || 'Open';

                          return (
                            <tr key={idx}>
                              <td style={styles.monoCell}>
                                <strong style={{ color: 'var(--color-accent)' }}>{cveVal}</strong>
                              </td>
                              <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                                {assetVal}
                              </td>
                              <td style={styles.monoCell}>
                                <span style={{
                                  fontWeight: '800',
                                  color: Number(cvssVal) >= 9.0 ? 'var(--color-critical)' : Number(cvssVal) >= 7.0 ? 'var(--color-high)' : 'var(--text-primary)'
                                }}>
                                  {cvssVal}
                                </span>
                              </td>
                              <td>
                                <Badge type="severity" value={sevVal} />
                              </td>
                              <td>
                                <span className={`badge ${statusVal.toLowerCase() === 'open' ? 'severity-critical' : 'status-success'}`}>
                                  {statusVal}
                                </span>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* =========================================================================
                TAB 3: TASK 6 — MITRE TECHNIQUE ANALYSIS
                Required: TABLE (Technique, Name, Events, Risk)
                          CHART: MITRE technique distribution chart (synchronized)
               ========================================================================= */}
            {selectedTab === 'mitre' && (
              <div>
                {/* Synchronized MITRE Technique Distribution Chart */}
                <div className="panel" style={{ padding: '1rem', backgroundColor: 'var(--bg-secondary)', marginBottom: '1.25rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <div>
                      <h4 style={{ margin: 0, fontSize: '0.88rem', fontWeight: '700', color: 'var(--color-accent)' }}>
                        MITRE ATT&amp;CK Technique Distribution
                      </h4>
                      <p className="muted" style={{ margin: '0.15rem 0 0 0', fontSize: '0.72rem' }}>
                        Dynamic event frequency across observed ATT&amp;CK technique identifiers
                      </p>
                    </div>
                    <span className="badge status-detected" style={{ fontSize: '0.68rem' }}>
                      Synchronized Telemetry Data
                    </span>
                  </div>

                  {mitreTechniques.length === 0 ? (
                    <div style={{ height: '140px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <p className="muted" style={{ fontSize: '0.8rem' }}>No MITRE technique distribution data available.</p>
                    </div>
                  ) : (
                    <div style={{ width: '100%', height: 180 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={mitreTechniques} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.07)" />
                          <XAxis 
                            dataKey="technique" 
                            stroke="var(--text-muted)" 
                            tick={{ fill: 'var(--text-muted)', fontSize: 11, fontFamily: 'var(--font-mono)' }}
                          />
                          <YAxis 
                            stroke="var(--text-muted)" 
                            tick={{ fill: 'var(--text-muted)', fontSize: 11 }}
                            allowDecimals={false}
                          />
                          <RechartsTooltip 
                            formatter={(value, name, props) => [`${value} events (${props.payload.name})`, 'Observed Events']}
                            contentStyle={{ backgroundColor: 'var(--bg-card)', borderColor: 'var(--border-color)', borderRadius: '6px', fontSize: '0.78rem' }}
                          />
                          <Bar dataKey="events" fill="#06b6d4" radius={[4, 4, 0, 0]}>
                            {mitreTechniques.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.risk === 'Critical' ? '#f43f5e' : entry.risk === 'High' ? '#fb923c' : '#06b6d4'} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  )}
                </div>

                {/* MITRE Technique Analysis Table */}
                <div style={{ marginBottom: '0.5rem' }}>
                  <h4 style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
                    MITRE ATT&amp;CK Technique Table
                  </h4>
                </div>

                {filteredMitreTechniques.length === 0 ? (
                  <div style={styles.emptyState}>
                    <p className="muted">No MITRE techniques recorded in security events.</p>
                  </div>
                ) : (
                  <div className="soc-table-container">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>Technique</th>
                          <th>Name</th>
                          <th>Events</th>
                          <th>Risk</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredMitreTechniques.map((item, idx) => (
                          <tr key={idx}>
                            <td style={styles.monoCell}>
                              <span className="badge status-detected" style={{ fontWeight: '700' }}>
                                {item.technique}
                              </span>
                            </td>
                            <td style={{ fontWeight: '600', color: 'var(--color-accent)' }}>
                              {item.name}
                            </td>
                            <td style={styles.monoCell}>
                              <strong style={{ color: 'var(--text-primary)' }}>
                                {item.events?.toLocaleString()}
                              </strong>
                            </td>
                            <td>
                              <Badge type="severity" value={item.risk} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )}

            {/* TAB 4: CORRELATED ATTACK CHAINS SUMMARY */}
            {selectedTab === 'chains' && (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Attack Chain ID</th>
                      <th>Campaign Title</th>
                      <th>Current Stage</th>
                      <th>Risk Score</th>
                      <th>Confidence</th>
                      <th>Target Host</th>
                      <th>Target User</th>
                      <th>Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {attackChainsData.slice(0, 15).map((chain, idx) => (
                      <tr key={idx}>
                        <td style={styles.monoCell}>
                          <span className="badge status-detected">{chain.attack_chain_id}</span>
                        </td>
                        <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                          {chain.name || `Attack Campaign (${chain.stage})`}
                        </td>
                        <td>
                          <span className="badge severity-high">{chain.stage}</span>
                        </td>
                        <td style={styles.monoCell}>
                          <strong style={{ color: chain.risk_score >= 81 ? 'var(--color-critical)' : 'var(--color-high)' }}>
                            {chain.risk_score || 85} / 100
                          </strong>
                        </td>
                        <td style={styles.monoCell}>
                          <span style={{ color: 'var(--text-primary)', fontWeight: '600' }}>
                            {chain.confidence || 80}%
                          </span>
                        </td>
                        <td>{chain.affected_asset || '—'}</td>
                        <td>{chain.target_user || '—'}</td>
                        <td style={styles.monoCell}>
                          <span className="badge status-detected">
                            {(chain.events || []).length} events
                          </span>
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
    color: 'var(--text-primary)'
  },
  pageSubtitle: {
    fontSize: '0.8rem',
    margin: '0.2rem 0 0 0',
    color: 'var(--text-muted)'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '1rem'
  },
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  statePanel: {
    minHeight: '140px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center'
  },
  emptyState: {
    padding: '2rem',
    textAlign: 'center',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.8rem'
  },
  searchWrapper: {
    position: 'relative',
    minWidth: '220px'
  },
  searchIcon: {
    position: 'absolute',
    left: '0.65rem',
    top: '50%',
    transform: 'translateY(-50%)'
  },
  searchInput: {
    width: '100%',
    padding: '0.35rem 0.65rem 0.35rem 2rem',
    fontSize: '0.78rem',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    color: 'var(--text-primary)',
    outline: 'none'
  },
  intelPillarCard: {
    padding: '0.65rem 0.85rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '4px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.2rem'
  },
  intelPillarTitle: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  intelPillarWeight: {
    fontSize: '0.85rem',
    fontWeight: '800',
    color: 'var(--color-accent)',
    fontFamily: 'var(--font-mono)'
  },
  intelPillarDesc: {
    fontSize: '0.68rem',
    color: 'var(--text-muted)'
  }
};

export default SecurityIntelligencePage;
