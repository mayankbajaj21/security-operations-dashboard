import React, { useState, useMemo } from 'react';
import Badge from '../components/Badge';
import { ShieldAlert, ChevronDown, ChevronRight, AlertTriangle, AlertCircle, Shield } from 'lucide-react';

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

const getRecommendation = (item) => {
  if (item.malwareEvents > 0) return 'Investigate malware activity';
  if (item.criticalEvents > 0) return 'Investigate critical events';
  if (item.incidentEvents > 0) return 'Review linked incidents';
  if (item.threatIntelMatches > 0) return 'Validate threat intel matches';
  if (item.vulnerabilityEvents > 0) return 'Review vulnerable services';
  if (item.highEvents > 0) return 'Review high severity alerts';
  return 'Monitor asset telemetry';
};

/**
 * Compact & Actionable SOC Asset Risk & Exposure Widget
 * Always analyzes security-relevant event telemetry.
 * Consumes global `allEvents` array passed from App.jsx parent.
 * Performs zero backend API calls.
 */
const TopAffectedAssetsChart = ({ allEvents = null }) => {
  const [expandedAsset, setExpandedAsset] = useState(null);

  // Compute normalized relative risk score, risk factors, recommendations, and summary KPI metrics
  const { topAssets, summaryStats } = useMemo(() => {
    if (!allEvents || !Array.isArray(allEvents)) {
      return { topAssets: [], summaryStats: { criticalCount: 0, highCount: 0, vulnAssetCount: 0 } };
    }

    const assetMap = {};

    allEvents.forEach((evt) => {
      const rawAsset = evt.asset_name;
      if (!rawAsset || typeof rawAsset !== 'string' || !rawAsset.trim() || rawAsset.trim().toLowerCase() === 'null') {
        return;
      }

      const assetName = rawAsset.trim();
      const severityStr = evt.event_severity?.toLowerCase() || '';
      const isCritical = severityStr === 'critical';
      const isHigh = severityStr === 'high';
      const isMedium = severityStr === 'medium';
      const isLow = severityStr === 'low';
      const isMalware = Boolean(evt.malware_detected);
      const isThreatIntel = Boolean(evt.threat_intel_match);
      const hasVuln = Boolean(evt.vulnerability_id || evt.vulnerability_record_id);
      const hasIncident = Boolean(evt.incident_id && String(evt.incident_id).trim() !== '');

      if (!assetMap[assetName]) {
        assetMap[assetName] = {
          asset_name: assetName,
          totalEvents: 0,
          criticalEvents: 0,
          highEvents: 0,
          mediumEvents: 0,
          lowEvents: 0,
          malwareEvents: 0,
          vulnerabilityEvents: 0,
          threatIntelMatches: 0,
          incidentEvents: 0
        };
      }

      const item = assetMap[assetName];
      item.totalEvents += 1;
      if (isCritical) item.criticalEvents += 1;
      if (isHigh) item.highEvents += 1;
      if (isMedium) item.mediumEvents += 1;
      if (isLow) item.lowEvents += 1;
      if (isMalware) item.malwareEvents += 1;
      if (hasVuln) item.vulnerabilityEvents += 1;
      if (isThreatIntel) item.threatIntelMatches += 1;
      if (hasIncident) item.incidentEvents += 1;
    });

    const assetList = Object.values(assetMap);
    if (assetList.length === 0) {
      return { topAssets: [], summaryStats: { criticalCount: 0, highCount: 0, vulnAssetCount: 0 } };
    }

    // 1. Calculate raw exposure score per asset
    assetList.forEach((item) => {
      item.rawScore =
        item.criticalEvents * 5 +
        item.highEvents * 3 +
        item.malwareEvents * 4 +
        item.vulnerabilityEvents * 2 +
        item.threatIntelMatches * 3 +
        item.incidentEvents * 4 +
        item.totalEvents * 0.1;
    });

    // 2. Determine maxRawScore for relative normalization
    const maxRawScore = Math.max(...assetList.map((a) => a.rawScore), 0);

    // 3. Normalize score (0-100) and assign risk level
    let critCount = 0;
    let highCount = 0;
    let vulnAssets = 0;

    assetList.forEach((item) => {
      item.normalizedScore = maxRawScore > 0 ? Math.round((item.rawScore / maxRawScore) * 100) : 0;

      if (item.normalizedScore >= 80) {
        item.risk_level = 'Critical';
        critCount += 1;
      } else if (item.normalizedScore >= 60) {
        item.risk_level = 'High';
        highCount += 1;
      } else if (item.normalizedScore >= 40) {
        item.risk_level = 'Medium';
      } else {
        item.risk_level = 'Low';
      }

      if (item.vulnerabilityEvents > 0) {
        vulnAssets += 1;
      }

      item.recommendation = getRecommendation(item);
    });

    // 4. Sort by normalizedScore desc, criticalEvents desc, highEvents desc, totalEvents desc
    assetList.sort((a, b) => {
      if (b.normalizedScore !== a.normalizedScore) return b.normalizedScore - a.normalizedScore;
      if (b.criticalEvents !== a.criticalEvents) return b.criticalEvents - a.criticalEvents;
      if (b.highEvents !== a.highEvents) return b.highEvents - a.highEvents;
      return b.totalEvents - a.totalEvents;
    });

    return {
      topAssets: assetList.slice(0, 5),
      summaryStats: {
        criticalCount: critCount,
        highCount: highCount,
        vulnAssetCount: vulnAssets
      }
    };
  }, [allEvents]);

  const isLoading = allEvents === null;

  const toggleExpand = (name) => {
    setExpandedAsset((prev) => (prev === name ? null : name));
  };

  return (
    <div className="panel" style={styles.panel}>
      {/* Panel Header */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <ShieldAlert size={18} color="var(--color-accent)" />
          <div>
            <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0 }}>
              Asset Risk & Exposure
            </h3>
            <p className="muted" style={{ fontSize: '0.73rem', margin: '0.15rem 0 0 0' }}>
              Assets requiring analyst attention
            </p>
          </div>
        </div>
      </div>

      {/* Summary KPI Pills */}
      {!isLoading && (
        <div style={styles.summaryPillRow}>
          <div style={styles.pillItem}>
            <AlertCircle size={13} color="var(--color-critical)" />
            <span style={styles.pillLabel}>Critical Assets:</span>
            <strong style={{ color: 'var(--color-critical)' }}>{summaryStats.criticalCount}</strong>
          </div>
          <div style={styles.pillItem}>
            <AlertTriangle size={13} color="var(--color-high)" />
            <span style={styles.pillLabel}>High-Risk Assets:</span>
            <strong style={{ color: 'var(--color-high)' }}>{summaryStats.highCount}</strong>
          </div>
          <div style={styles.pillItem}>
            <Shield size={13} color="var(--color-warning)" />
            <span style={styles.pillLabel}>Vulnerable Assets:</span>
            <strong style={{ color: 'var(--color-warning)' }}>{summaryStats.vulnAssetCount}</strong>
          </div>
        </div>
      )}

      {/* Loading / Empty / Top 5 Asset List */}
      {isLoading ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>Loading asset risk & exposure analysis...</p>
        </div>
      ) : topAssets.length === 0 ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No asset telemetry available.</p>
        </div>
      ) : (
        <div style={styles.assetList}>
          {topAssets.map((asset, idx) => {
            const isExpanded = expandedAsset === asset.asset_name;
            const riskColor = getRiskColor(asset.risk_level);

            return (
              <div key={asset.asset_name} style={styles.assetCard}>
                {/* Main Action Row */}
                <div style={styles.cardHeader} onClick={() => toggleExpand(asset.asset_name)}>
                  <div style={styles.rowLeft}>
                    <span style={styles.rankNum}>#{idx + 1}</span>
                    {isExpanded ? (
                      <ChevronDown size={14} color="var(--text-muted)" />
                    ) : (
                      <ChevronRight size={14} color="var(--text-muted)" />
                    )}
                    <span style={styles.assetName}>{asset.asset_name}</span>
                  </div>

                  <div style={styles.rowRight}>
                    {/* Score Bar & Numeric Display */}
                    <div style={styles.scoreBox}>
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

                    <Badge type="severity" value={asset.risk_level} />
                  </div>
                </div>

                {/* Factors & Action Line */}
                <div style={styles.factorRow}>
                  <div style={styles.factorBadges}>
                    {asset.criticalEvents > 0 && (
                      <span className="badge severity-critical" style={styles.miniBadge}>
                        Critical {asset.criticalEvents}
                      </span>
                    )}
                    {asset.highEvents > 0 && (
                      <span className="badge severity-high" style={styles.miniBadge}>
                        High {asset.highEvents}
                      </span>
                    )}
                    {asset.malwareEvents > 0 && (
                      <span className="badge status-detected" style={styles.miniBadge}>
                        Malware {asset.malwareEvents}
                      </span>
                    )}
                    {asset.vulnerabilityEvents > 0 && (
                      <span className="badge severity-medium" style={styles.miniBadge}>
                        Vuln {asset.vulnerabilityEvents}
                      </span>
                    )}
                    {asset.threatIntelMatches > 0 && (
                      <span className="badge status-blocked" style={styles.miniBadge}>
                        Threat Intel {asset.threatIntelMatches}
                      </span>
                    )}
                    {asset.incidentEvents > 0 && (
                      <span className="badge status-failed" style={styles.miniBadge}>
                        Incidents {asset.incidentEvents}
                      </span>
                    )}
                  </div>

                  <div style={styles.recText}>
                    <span style={{ color: 'var(--text-muted)' }}>Action:</span>{' '}
                    <span style={{ color: 'var(--color-accent)', fontWeight: '600' }}>
                      {asset.recommendation}
                    </span>
                  </div>
                </div>

                {/* Expanded Inline Detail Drawer */}
                {isExpanded && (
                  <div style={styles.detailDrawer}>
                    <div style={styles.detailGrid}>
                      <div>
                        Total Telemetry Events: <strong>{asset.totalEvents}</strong>
                      </div>
                      <div>
                        Critical Severity: <strong style={{ color: 'var(--color-critical)' }}>{asset.criticalEvents}</strong>
                      </div>
                      <div>
                        High Severity: <strong style={{ color: 'var(--color-high)' }}>{asset.highEvents}</strong>
                      </div>
                      <div>
                        Medium Severity: <strong>{asset.mediumEvents}</strong>
                      </div>
                      <div>
                        Low Severity: <strong>{asset.lowEvents}</strong>
                      </div>
                      <div>
                        Malware Detections: <strong>{asset.malwareEvents}</strong>
                      </div>
                      <div>
                        Vulnerabilities Linked: <strong>{asset.vulnerabilityEvents}</strong>
                      </div>
                      <div>
                        Threat Intel Matches: <strong>{asset.threatIntelMatches}</strong>
                      </div>
                      <div>
                        Incident Records: <strong>{asset.incidentEvents}</strong>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const styles = {
  panel: {
    padding: '1rem 1.25rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
    minWidth: 0,
    width: '100%'
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  summaryPillRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem',
    backgroundColor: 'rgba(15, 23, 42, 0.5)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.4rem 0.75rem',
    flexWrap: 'wrap'
  },
  pillItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem',
    fontSize: '0.75rem'
  },
  pillLabel: {
    color: 'var(--text-muted)',
    fontWeight: '500'
  },
  assetList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  assetCard: {
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.55rem 0.75rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.4rem'
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    cursor: 'pointer',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  rowLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  rankNum: {
    fontSize: '0.75rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    width: '20px'
  },
  assetName: {
    fontSize: '0.85rem',
    fontWeight: '600',
    color: 'var(--text-primary)'
  },
  rowRight: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
  scoreBox: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem'
  },
  scoreBarTrack: {
    width: '60px',
    height: '6px',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '3px',
    overflow: 'hidden'
  },
  scoreBarFill: {
    height: '100%',
    borderRadius: '3px',
    transition: 'width 0.3s ease'
  },
  scoreNum: {
    fontSize: '0.8rem',
    fontWeight: '700',
    fontFamily: 'var(--font-mono)',
    minWidth: '22px',
    textAlign: 'right'
  },
  factorRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.5rem',
    paddingTop: '0.2rem',
    borderTop: '1px solid rgba(255, 255, 255, 0.03)'
  },
  factorBadges: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    flexWrap: 'wrap'
  },
  miniBadge: {
    fontSize: '0.66rem',
    padding: '0.1rem 0.35rem'
  },
  recText: {
    fontSize: '0.73rem'
  },
  detailDrawer: {
    marginTop: '0.3rem',
    backgroundColor: 'rgba(15, 23, 42, 0.7)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    padding: '0.5rem 0.75rem'
  },
  detailGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '0.4rem',
    fontSize: '0.73rem',
    color: 'var(--text-secondary)'
  },
  stateContainer: {
    height: '140px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    textAlign: 'center'
  }
};

export default TopAffectedAssetsChart;
