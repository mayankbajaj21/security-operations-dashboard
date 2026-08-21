import React, { useState, useEffect, useMemo } from 'react';
import { getEvents } from '../services/api';
import Badge from '../components/Badge';
import { 
  Server, 
  ShieldAlert, 
  ChevronDown, 
  ChevronRight, 
  AlertTriangle 
} from 'lucide-react';

import { aggregateAssetRisk } from '../utils/assetRiskAggregator';

const getRiskColor = (level) => {
  switch (level?.toLowerCase()) {
    case 'critical':
      return 'var(--color-critical)';
    case 'high':
      return 'var(--color-high)';
    case 'medium':
      return 'var(--color-medium)';
    case 'low':
      return 'var(--color-low)';
    default:
      return 'var(--color-accent)';
  }
};

/**
 * Asset Risk Page — Analytics Subpage
 * 
 * Single Unified Master Table for Asset Risk & Exposure:
 * - Authoritative Source: Security Events Dataset (GET /events)
 * - 5 Compact Asset Telemetry KPI Cards
 * - Master Asset Risk & Exposure Table with Expand/Collapse Vulnerability Details
 */
const AssetRiskPage = ({ allEvents = null }) => {
  const [standaloneEvents, setStandaloneEvents] = useState(allEvents);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedAsset, setExpandedAsset] = useState(null);

  // Fetch all events if parent prop was not supplied
  useEffect(() => {
    if (allEvents !== undefined && allEvents !== null) {
      setStandaloneEvents(allEvents);
      return;
    }

    let isMounted = true;
    setLoading(true);
    setError(null);

    const fetchAllEvents = async () => {
      try {
        const firstPage = await getEvents({ page: 1, limit: 100 }, { forceRefresh: true });
        const totalPages = firstPage?.pagination?.total_pages || 1;
        let records = [...(firstPage?.data || [])];

        if (totalPages > 1) {
          const batchSize = 4;
          for (let p = 2; p <= totalPages; p += batchSize) {
            const batchPromises = [];
            for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
              batchPromises.push(getEvents({ page: b, limit: 100 }, { forceRefresh: true }));
            }
            const batchResults = await Promise.all(batchPromises);
            batchResults.forEach((res) => {
              if (res?.data) {
                records = records.concat(res.data);
              }
            });
          }
        }

        if (isMounted) {
          setStandaloneEvents(records);
          setLoading(false);
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to fetch event telemetry for asset risk analysis:', err);
          setError('Unable to load asset risk telemetry.');
          setLoading(false);
        }
      }
    };

    fetchAllEvents();

    return () => {
      isMounted = false;
    };
  }, [allEvents]);

  // Keep events in sync if parent prop updates
  useEffect(() => {
    if (allEvents) {
      setStandaloneEvents(allEvents);
    }
  }, [allEvents]);

  const activeEvents = allEvents || standaloneEvents;

  // Derive unified asset population, risk metrics, and vulnerability details from security events
  const assetsList = useMemo(() => {
    return aggregateAssetRisk(activeEvents);
  }, [activeEvents]);

  // Clean toggle expand function (expands if different, collapses if same)
  const toggleExpand = (assetName) => {
    setExpandedAsset((prev) => (prev === assetName ? null : assetName));
  };

  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED ANALYTICS SUB-PAGE HEADER */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <Server size={20} color="var(--color-accent)" />
            <span>Asset Risk</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            Real-time threat telemetry and security risk analytics monitoring
          </p>
        </div>
      </div>

      {/* 2. FIVE ASSET TELEMETRY CARDS (DYNAMICALLY GENERATED FROM GET /events) */}
      <div style={styles.assetCardsGrid}>
        {assetsList.map((asset) => (
          <div key={asset.asset_name} className="panel" style={styles.assetCard}>
            <div style={styles.assetCardHeader}>
              <span style={styles.assetCardName}>{asset.asset_name}</span>
            </div>
            <div style={styles.assetCardBody}>
              <strong style={styles.assetCardCount}>
                {asset.totalEvents?.toLocaleString()}
              </strong>
              <span style={styles.assetCardLabel}>Total Events</span>
            </div>
          </div>
        ))}
      </div>

      {loading && !activeEvents && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Analyzing security event telemetry for asset risk profiles...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {/* 3. SINGLE UNIFIED MASTER TABLE: ASSET RISK & EXPOSURE */}
      {(!loading || activeEvents) && !error && (
        <div className="panel" style={styles.tablePanel}>
          <div style={styles.panelHeader}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ShieldAlert size={18} color="var(--color-accent)" />
              <div>
                <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
                  Asset Risk &amp; Exposure
                </h3>
                <p className="muted" style={{ fontSize: '0.73rem', margin: '0.15rem 0 0 0' }}>
                  Assets requiring analyst attention
                </p>
              </div>
            </div>
          </div>

          {assetsList.length === 0 ? (
            <div style={styles.statePanel}>
              <p className="muted">No assets found in the security events dataset.</p>
            </div>
          ) : (
            <div className="soc-table-container">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th style={{ width: '36px' }}></th>
                    <th style={{ width: '50px' }}>Rank</th>
                    <th>Asset</th>
                    <th style={{ minWidth: '130px' }}>Risk Score</th>
                    <th>Risk Level</th>
                    <th>Total Events</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Malware</th>
                    <th>Vulnerabilities</th>
                    <th>Max CVSS</th>
                    <th>Incidents</th>
                  </tr>
                </thead>
                <tbody>
                  {assetsList.map((asset, idx) => {
                    const isExpanded = expandedAsset === asset.asset_name;
                    const riskColor = getRiskColor(asset.risk_level);
                    const hasCriticalEvents = asset.criticalEvents > 0;

                    return (
                      <React.Fragment key={asset.asset_name}>
                        <tr
                          onClick={() => toggleExpand(asset.asset_name)}
                          style={{
                            cursor: 'pointer',
                            backgroundColor: isExpanded
                              ? 'var(--bg-card-hover)'
                              : hasCriticalEvents
                              ? 'rgba(244, 63, 94, 0.04)'
                              : undefined
                          }}
                        >
                          <td style={{ textAlign: 'center' }}>
                            {isExpanded ? (
                              <ChevronDown size={15} color="var(--color-accent)" />
                            ) : (
                              <ChevronRight size={15} color="var(--text-muted)" />
                            )}
                          </td>
                          <td style={styles.rankCell}>
                            #{idx + 1}
                          </td>
                          <td>
                            <strong style={{ fontSize: '0.84rem', color: 'var(--text-primary)' }}>
                              {asset.asset_name}
                            </strong>
                          </td>
                          <td>
                            {/* Score Bar & Number */}
                            <div style={styles.scoreCell}>
                              <div style={styles.scoreBarTrack}>
                                <div
                                  style={{
                                    ...styles.scoreBarFill,
                                    width: `${asset.normalizedScore}%`,
                                    backgroundColor: riskColor
                                  }}
                                />
                              </div>
                              <span style={{ ...styles.scoreNum, color: riskColor }}>
                                {asset.normalizedScore}
                              </span>
                            </div>
                          </td>
                          <td>
                            <Badge type="severity" value={asset.risk_level} />
                          </td>
                          <td style={styles.monoCell}>
                            {asset.totalEvents?.toLocaleString()}
                          </td>
                          <td>
                            {asset.criticalEvents > 0 ? (
                              <span className="badge severity-critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                                <AlertTriangle size={11} />
                                {asset.criticalEvents}
                              </span>
                            ) : (
                              <span className="muted" style={{ fontSize: '0.75rem' }}>0</span>
                            )}
                          </td>
                          <td>
                            {asset.highEvents > 0 ? (
                              <span className="badge severity-high">
                                {asset.highEvents}
                              </span>
                            ) : (
                              <span className="muted" style={{ fontSize: '0.75rem' }}>0</span>
                            )}
                          </td>
                          <td>
                            {asset.malwareEvents > 0 ? (
                              <span className="badge status-detected">
                                {asset.malwareEvents}
                              </span>
                            ) : (
                              <span className="muted" style={{ fontSize: '0.75rem' }}>0</span>
                            )}
                          </td>
                          <td style={styles.monoCell}>
                            {asset.vulnerabilityEvents > 0 ? (
                              <span style={{ fontWeight: '600' }}>
                                {asset.vulnerabilityEvents.toLocaleString()}
                              </span>
                            ) : (
                              <span className="muted">0</span>
                            )}
                          </td>
                          <td style={styles.monoCell}>
                            {asset.maxCvss > 0 ? (
                              <strong style={{ color: asset.maxCvss >= 9.0 ? 'var(--color-critical)' : 'var(--color-warning)' }}>
                                {asset.maxCvss.toFixed(1)}
                              </strong>
                            ) : (
                              <span className="muted">N/A</span>
                            )}
                          </td>
                          <td style={styles.monoCell}>
                            {asset.incidentEvents > 0 ? (
                              <span className="badge status-failed">
                                {asset.incidentEvents}
                              </span>
                            ) : (
                              <span className="muted" style={{ fontSize: '0.75rem' }}>0</span>
                            )}
                          </td>
                        </tr>

                        {/* Expandable Vulnerability Details Row */}
                        {isExpanded && (
                          <tr>
                            <td colSpan={12} style={styles.expandedContainerCell}>
                              <div style={styles.vulnDetailPanel}>
                                <div style={styles.vulnHeader}>
                                  <h4 style={styles.vulnTitle}>
                                    Vulnerability Details for {asset.asset_name}
                                  </h4>
                                  <span className="muted" style={{ fontSize: '0.73rem' }}>
                                    {asset.vulnerabilities.length} distinct CVE exposure{asset.vulnerabilities.length === 1 ? '' : 's'} linked in event telemetry
                                  </span>
                                </div>

                                {asset.vulnerabilities.length === 0 ? (
                                  <p className="muted" style={{ fontSize: '0.78rem', margin: '0.25rem 0 0 0' }}>
                                    No specific CVE vulnerabilities identified for this asset in event telemetry.
                                  </p>
                                ) : (
                                  <div className="soc-table-container" style={{ marginTop: '0.4rem' }}>
                                    <table className="soc-table">
                                      <thead>
                                        <tr style={{ backgroundColor: 'var(--bg-primary)' }}>
                                          <th>CVE ID</th>
                                          <th>Severity</th>
                                          <th>CVSS Score</th>
                                          <th>Event Occurrences</th>
                                        </tr>
                                      </thead>
                                      <tbody>
                                        {asset.vulnerabilities.map((vuln) => (
                                          <tr key={vuln.cve_id}>
                                            <td style={styles.monoCell}>
                                              <span className="badge status-detected" style={{ fontWeight: '600' }}>
                                                {vuln.cve_id}
                                              </span>
                                            </td>
                                            <td>
                                              <Badge type="severity" value={vuln.severity} />
                                            </td>
                                            <td style={styles.monoCell}>
                                              {vuln.maxCvss > 0 ? (
                                                <strong style={{ color: vuln.maxCvss >= 9.0 ? 'var(--color-critical)' : 'var(--color-warning)' }}>
                                                  {vuln.maxCvss.toFixed(1)}
                                                </strong>
                                              ) : (
                                                <span className="muted">N/A</span>
                                              )}
                                            </td>
                                            <td style={styles.monoCell}>
                                              <strong>{vuln.count}</strong> events
                                            </td>
                                          </tr>
                                        ))}
                                      </tbody>
                                    </table>
                                  </div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
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
    marginBottom: '0.15rem'
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
  assetCardsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '1rem',
    width: '100%'
  },
  assetCard: {
    padding: '0.85rem 1rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    borderRadius: '6px',
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    gap: '0.5rem'
  },
  assetCardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  assetCardName: {
    fontSize: '0.84rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '-0.01em'
  },
  assetCardBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.15rem'
  },
  assetCardCount: {
    fontSize: '1.6rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '800',
    color: 'var(--color-accent)',
    lineHeight: '1.1'
  },
  assetCardLabel: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    fontWeight: '500'
  },
  tablePanel: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem'
  },
  panelHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  rankCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    textAlign: 'center'
  },
  scoreCell: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  scoreBarTrack: {
    width: '50px',
    height: '6px',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-subtle)',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  scoreBarFill: {
    height: '100%',
    borderRadius: '3px',
    transition: 'width 0.3s ease'
  },
  scoreNum: {
    fontSize: '0.82rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    minWidth: '24px'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  expandedContainerCell: {
    backgroundColor: 'var(--bg-secondary)',
    padding: '1rem 1.25rem',
    borderTop: '1px solid var(--border-color)',
    borderBottom: '1px solid var(--border-color)'
  },
  vulnDetailPanel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  vulnHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem',
    marginBottom: '0.2rem'
  },
  vulnTitle: {
    fontSize: '0.84rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0
  },
  statePanel: {
    minHeight: '180px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  }
};

export default AssetRiskPage;
