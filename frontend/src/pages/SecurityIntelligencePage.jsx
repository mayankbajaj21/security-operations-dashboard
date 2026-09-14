import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { 
  getThreatIntel, 
  getMitre, 
  getAssets, 
  getAttackChains, 
  getRiskSummary,
  getIncidents 
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
  FileText
} from 'lucide-react';

const SecurityIntelligencePage = () => {
  const [intelSummary, setIntelSummary] = useState(null);
  const [threatIntelData, setThreatIntelData] = useState([]);
  const [mitreData, setMitreData] = useState(null);
  const [assetsData, setAssetsData] = useState([]);
  const [attackChainsData, setAttackChainsData] = useState([]);
  const [riskSummary, setRiskSummary] = useState(null);
  const [incidentsData, setIncidentsData] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filter and Search State
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTab, setSelectedTab] = useState('iocs'); // 'iocs' | 'assets' | 'mitre' | 'chains'

  const fetchSecurityIntelligence = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      const [intelRes, mitreRes, assetsRes, chainsRes, riskRes, incRes] = await Promise.all([
        getThreatIntel({ noCache: isManual }).catch(() => null),
        getMitre({ noCache: isManual }).catch(() => null),
        getAssets({ noCache: isManual }).catch(() => null),
        getAttackChains({ window_minutes: 15 }, { noCache: isManual }).catch(() => null),
        getRiskSummary({ noCache: isManual }).catch(() => null),
        getIncidents({ page: 1, limit: 100 }, { noCache: isManual }).catch(() => null)
      ]);

      // 1. Threat Intel IoCs (GET /threat-intel -> indicators array)
      const rawIndicators = intelRes?.indicators || (Array.isArray(intelRes) ? intelRes : intelRes?.data || []);
      setThreatIntelData(rawIndicators);
      setIntelSummary(intelRes?.summary || null);

      // 2. MITRE Mappings (GET /mitre -> mappings array & summary)
      setMitreData(mitreRes);

      // 3. Asset Inventory & Vulnerabilities (GET /assets -> assets array)
      const rawAssets = assetsRes?.assets || (Array.isArray(assetsRes) ? assetsRes : assetsRes?.data || []);
      setAssetsData(rawAssets);

      // 4. Attack Chains (GET /api/v1/attack-chains -> data array)
      const rawChains = Array.isArray(chainsRes?.data) ? chainsRes.data : Array.isArray(chainsRes) ? chainsRes : [];
      setAttackChainsData(rawChains);

      // 5. Risk Summary (GET /api/v1/risk/summary)
      setRiskSummary(riskRes);

      // 6. Linked Incidents (GET /api/v1/incidents -> data array)
      const rawIncidents = Array.isArray(incRes?.data) ? incRes.data : Array.isArray(incRes) ? incRes : [];
      setIncidentsData(rawIncidents);
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

  // Filtered IoCs
  const filteredIocs = useMemo(() => {
    if (!Array.isArray(threatIntelData)) return [];
    if (!searchQuery.trim()) return threatIntelData;
    const q = searchQuery.toLowerCase().trim();
    return threatIntelData.filter((item) => {
      const val = item.indicator_value || item.indicator || item.ioc_value || '';
      const type = item.indicator_type || item.type || '';
      const name = item.threat_name || item.threat_type || '';
      const actor = item.threat_actor || item.source || '';
      return (
        val.toLowerCase().includes(q) ||
        type.toLowerCase().includes(q) ||
        name.toLowerCase().includes(q) ||
        actor.toLowerCase().includes(q)
      );
    });
  }, [threatIntelData, searchQuery]);

  // Flatten Asset Vulnerabilities for Tab 2
  const assetVulnRows = useMemo(() => {
    const rows = [];
    assetsData.forEach((asset) => {
      const vulns = asset.vulnerabilities || [];
      if (vulns.length > 0) {
        vulns.forEach((v) => {
          rows.push({
            asset_id: asset.asset_id,
            asset_name: asset.asset_name,
            criticality: asset.criticality || 'Medium',
            owner: asset.owner || 'SOC IT',
            department: asset.department || 'Operations',
            operating_system: asset.operating_system || 'Windows',
            cve_id: v.cve_id,
            vulnerability_name: v.vulnerability_name,
            vulnerability_severity: v.vulnerability_severity || v.severity || 'Critical',
            cvss_score: v.vulnerability_cvss_score ?? v.cvss_score ?? 9.5,
            patch_available: v.patch_available || 'Yes',
            status: v.vulnerability_status || v.status || 'Open'
          });
        });
      } else {
        rows.push({
          asset_id: asset.asset_id,
          asset_name: asset.asset_name,
          criticality: asset.criticality || 'Medium',
          owner: asset.owner || 'SOC IT',
          department: asset.department || 'Operations',
          operating_system: asset.operating_system || 'Windows',
          cve_id: 'None',
          vulnerability_name: 'No Known CVE Records',
          vulnerability_severity: 'Low',
          cvss_score: 0.0,
          patch_available: 'N/A',
          status: 'Secure'
        });
      }
    });
    return rows;
  }, [assetsData]);

  // Derived Summary Counts
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
            M3 Integrated Threat Intelligence: IoCs, MITRE ATT&CK techniques, vulnerability exposure, attack chain linkage, and risk contribution
          </p>
        </div>

        <button
          className="soc-button"
          onClick={() => fetchSecurityIntelligence(true)}
          style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
          title="Refresh Security Intelligence"
        >
          <RefreshCw size={14} />
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
          <p className="muted">Correlating threat intelligence, MITRE mappings, and asset vulnerabilities...</p>
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
                  <span>Threat Intelligence IoCs ({threatIntelData.length})</span>
                </button>

                <button
                  className={`soc-button ${selectedTab === 'assets' ? 'active' : ''}`}
                  onClick={() => setSelectedTab('assets')}
                  style={{
                    fontSize: '0.78rem',
                    backgroundColor: selectedTab === 'assets' ? 'var(--color-accent)' : undefined,
                    color: selectedTab === 'assets' ? '#000' : undefined
                  }}
                >
                  <Server size={13} style={{ marginRight: '0.25rem' }} />
                  <span>Asset CVE Exposure ({assetVulnRows.length})</span>
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
                  <span>MITRE Technique Matrix ({(mitreData?.mappings || []).length})</span>
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
                  <span>Correlated Attack Chains ({attackChainsData.length})</span>
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

            {/* TAB 1: IOCS TABLE */}
            {selectedTab === 'iocs' && (
              <div>
                {filteredIocs.length === 0 ? (
                  <div style={styles.emptyState}>
                    <p className="muted">No threat intelligence IoC records match criteria.</p>
                  </div>
                ) : (
                  <div className="soc-table-container">
                    <table className="soc-table">
                      <thead>
                        <tr>
                          <th>Indicator ID</th>
                          <th>Indicator Value (IoC)</th>
                          <th>Type</th>
                          <th>Threat Classification</th>
                          <th>Threat Actor</th>
                          <th>Confidence</th>
                          <th>Severity</th>
                          <th>Event Matches</th>
                          <th>Risk Weight</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredIocs.map((ioc, idx) => {
                          const val = ioc.indicator_value || ioc.indicator || ioc.ioc_value || '185.91.22.14';
                          const type = ioc.indicator_type || ioc.type || 'IP Address';
                          const id = ioc.indicator_id || `IOC00${idx + 1}`;
                          const threat = ioc.threat_name || ioc.threat_type || 'Brute Force';
                          const actor = ioc.threat_actor || ioc.source || 'Unknown';
                          const conf = ioc.confidence || 'High';
                          const sev = ioc.severity || 'High';
                          const matchCount = ioc.event_match_count ?? 0;

                          return (
                            <tr key={idx}>
                              <td style={styles.monoCell}>
                                <span className="badge status-detected">{id}</span>
                              </td>
                              <td style={styles.monoCell}>
                                <strong style={{ color: 'var(--color-accent)' }}>{val}</strong>
                              </td>
                              <td>
                                <span className="badge status-detected">{type}</span>
                              </td>
                              <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>{threat}</td>
                              <td style={{ color: 'var(--text-secondary)' }}>{actor}</td>
                              <td>
                                <span className="badge severity-high">{conf}</span>
                              </td>
                              <td>
                                <Badge type="severity" value={sev} />
                              </td>
                              <td style={styles.monoCell}>
                                <span style={{ fontWeight: '700', color: matchCount > 0 ? 'var(--color-critical)' : 'var(--text-muted)' }}>
                                  {matchCount} matches
                                </span>
                              </td>
                              <td style={styles.monoCell}>
                                <span className="badge severity-critical">+10 pts</span>
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

            {/* TAB 2: ASSET CVE EXPOSURE TABLE */}
            {selectedTab === 'assets' && (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Asset ID</th>
                      <th>Asset Hostname</th>
                      <th>Criticality</th>
                      <th>Owner / Dept</th>
                      <th>Linked CVE</th>
                      <th>Vulnerability Name</th>
                      <th>Base CVSS</th>
                      <th>Severity</th>
                      <th>Patch Available</th>
                      <th>Risk Engine Contribution</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assetVulnRows.map((row, idx) => {
                      const cvss = Number(row.cvss_score || 0);
                      const isHighCvss = cvss >= 7.0;

                      return (
                        <tr key={idx}>
                          <td style={styles.monoCell}>
                            <span className="badge status-detected">{row.asset_id || `AST00${idx + 1}`}</span>
                          </td>
                          <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                            {row.asset_name}
                          </td>
                          <td>
                            <Badge type="severity" value={row.criticality} />
                          </td>
                          <td style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>
                            {row.owner} ({row.department})
                          </td>
                          <td style={styles.monoCell}>
                            <span className="badge status-detected">
                              {row.cve_id}
                            </span>
                          </td>
                          <td style={{ color: 'var(--text-primary)' }}>{row.vulnerability_name}</td>
                          <td style={styles.monoCell}>
                            <span style={{ fontWeight: '800', color: isHighCvss ? 'var(--color-critical)' : cvss > 0 ? 'var(--color-warning)' : 'var(--text-muted)' }}>
                              {cvss > 0 ? cvss.toFixed(1) : '—'}
                            </span>
                          </td>
                          <td>
                            <Badge type="severity" value={row.vulnerability_severity} />
                          </td>
                          <td>
                            <span className={`badge ${row.patch_available === 'Yes' ? 'status-success' : 'status-failed'}`}>
                              {row.patch_available}
                            </span>
                          </td>
                          <td style={styles.monoCell}>
                            <span className="badge severity-high">
                              +{((cvss / 10) * 20).toFixed(1)} / 20 pts
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 3: MITRE ATT&CK TECHNIQUE MATRIX */}
            {selectedTab === 'mitre' && (
              <div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
                  {(mitreData?.mappings || []).map((m, idx) => (
                    <div key={idx} style={styles.mitreCard}>
                      <div style={styles.mitreCardHeader}>
                        <span style={styles.mitreTactic}>{m.tactic || 'CREDENTIAL ACCESS'}</span>
                        <span className="badge status-detected">{m.mitre_id || 'T1110'}</span>
                      </div>
                      <strong style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
                        {m.technique_name || m.event_type}
                      </strong>
                      <p className="muted" style={{ fontSize: '0.75rem', margin: '0 0 0.5rem 0' }}>
                        Associated with event type "{m.event_type}" across security telemetry.
                      </p>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)', fontSize: '0.72rem' }}>
                        <span style={{ color: 'var(--text-muted)' }}>Mapped Telemetry Logs:</span>
                        <strong style={{ color: 'var(--color-accent)', fontFamily: 'var(--font-mono)' }}>
                          {(m.event_count || 0).toLocaleString()} events
                        </strong>
                      </div>
                    </div>
                  ))}
                </div>

                <div style={{ padding: '0.75rem 1rem', backgroundColor: 'var(--bg-secondary)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                  Total Evaluated Telemetry: <strong style={{ color: 'var(--text-primary)' }}>{mitreData?.summary?.total_events?.toLocaleString() ?? '0'}</strong> events • Mapped: <strong style={{ color: 'var(--color-accent)' }}>{mitreData?.summary?.mapped_events?.toLocaleString() ?? '0'}</strong> ({mitreData?.summary?.mapping_percentage ?? '0'}%)
                </div>
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
                          <span style={{ fontWeight: '700', color: 'var(--color-accent)' }}>
                            {chain.confidence || chain.ml_confidence || 80}%
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>
                          {chain.affected_asset || chain.participating_entities?.asset_name || 'Production Host'}
                        </td>
                        <td>
                          {chain.target_user || chain.username || chain.participating_entities?.username || 'analyst'}
                        </td>
                        <td style={styles.monoCell}>
                          {(chain.events || chain.related_events || []).length} logs
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
  contentSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  intelPillarCard: {
    padding: '0.75rem',
    backgroundColor: 'var(--bg-card)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  intelPillarTitle: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  intelPillarWeight: {
    fontSize: '0.7rem',
    fontWeight: '700',
    color: 'var(--color-accent)',
    fontFamily: 'var(--font-mono)'
  },
  intelPillarDesc: {
    fontSize: '0.68rem',
    color: 'var(--text-muted)',
    lineHeight: '1.3'
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
    minWidth: '200px'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  mitreCard: {
    padding: '1rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column'
  },
  mitreCardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.4rem'
  },
  mitreTactic: {
    fontSize: '0.68rem',
    fontWeight: '700',
    color: 'var(--color-accent)',
    letterSpacing: '0.04em'
  },
  statePanel: {
    minHeight: '180px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  },
  emptyState: {
    padding: '2rem',
    textAlign: 'center'
  }
};

export default SecurityIntelligencePage;
