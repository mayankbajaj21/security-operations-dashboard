import React, { useState, useEffect } from 'react';
import { getAssets } from '../services/api';
import MetricCard from '../components/MetricCard';
import Badge from '../components/Badge';
import { Server, ShieldAlert, ShieldCheck, ChevronDown, ChevronRight, AlertTriangle } from 'lucide-react';

const AssetRiskPage = () => {
  const [assetData, setAssetData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [expandedAssetId, setExpandedAssetId] = useState(null);

  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    getAssets()
      .then((data) => {
        if (isMounted) {
          setAssetData(data);
          setLoading(false);
          // Auto-expand first asset if available
          if (data?.assets && data.assets.length > 0) {
            setExpandedAssetId(data.assets[0].asset_id);
          }
        }
      })
      .catch((err) => {
        if (isMounted) {
          console.error('Failed to fetch asset inventory data:', err);
          setError('Unable to load asset risk telemetry.');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const toggleExpand = (assetId) => {
    setExpandedAssetId((prev) => (prev === assetId ? null : assetId));
  };

  const summary = assetData?.summary;
  const assetsList = assetData?.assets || [];

  return (
    <div style={styles.container}>
      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Loading asset inventory & vulnerability risk telemetry...</p>
        </div>
      )}

      {error && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && assetData && (
        <div style={styles.contentSection}>
          {/* Summary KPI Cards */}
          <div style={styles.kpiGrid}>
            <MetricCard
              title="Total Assets"
              value={summary?.total_assets}
              subtitle="Monitored IT inventory"
              icon={Server}
              variant="accent"
            />
            <MetricCard
              title="Assets With Events"
              value={summary?.assets_with_events}
              subtitle="Assets linked to telemetry"
              icon={ShieldAlert}
              variant="high"
            />
            <MetricCard
              title="Assets Without Events"
              value={summary?.assets_without_events}
              subtitle="Zero security event logs"
              icon={ShieldCheck}
              variant="default"
            />
          </div>

          {/* Asset Inventory Table */}
          <div style={{ marginTop: '0.5rem' }}>
            <h3 className="section-title" style={{ marginBottom: '0.75rem' }}>
              IT Assets & Vulnerability Risk Inventory
            </h3>

            {assetsList.length === 0 ? (
              <div className="panel" style={styles.statePanel}>
                <p className="muted">No assets found in database.</p>
              </div>
            ) : (
              <div className="soc-table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th style={{ width: '40px' }}></th>
                      <th>Asset ID</th>
                      <th>Asset Name</th>
                      <th>Type</th>
                      <th>Owner</th>
                      <th>Department</th>
                      <th>Criticality</th>
                      <th>OS</th>
                      <th>Total Events</th>
                      <th>Vuln Events</th>
                      <th>Critical Events</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assetsList.map((asset) => {
                      const isExpanded = expandedAssetId === asset.asset_id;
                      const hasCriticalEvents = asset.critical_event_count > 0;
                      const hasCriticalVulns = asset.vulnerabilities?.some(
                        (v) => v.vulnerability_severity === 'Critical'
                      );

                      return (
                        <React.Fragment key={asset.asset_id || Math.random()}>
                          <tr
                            onClick={() => toggleExpand(asset.asset_id)}
                            style={{
                              cursor: 'pointer',
                              backgroundColor: isExpanded
                                ? 'var(--bg-card-hover)'
                                : hasCriticalEvents || hasCriticalVulns
                                ? 'rgba(244, 63, 94, 0.04)'
                                : undefined
                            }}
                          >
                            <td style={{ textAlign: 'center' }}>
                              {isExpanded ? (
                                <ChevronDown size={16} color="var(--color-accent)" />
                              ) : (
                                <ChevronRight size={16} color="var(--text-muted)" />
                              )}
                            </td>
                            <td style={styles.monoCell}>{asset.asset_id}</td>
                            <td style={{ fontWeight: '600', color: 'var(--text-primary)' }}>
                              {asset.asset_name}
                            </td>
                            <td>{asset.asset_type}</td>
                            <td>{asset.owner || 'N/A'}</td>
                            <td>{asset.department || 'N/A'}</td>
                            <td>
                              <Badge type="severity" value={asset.criticality} />
                            </td>
                            <td style={{ color: 'var(--text-secondary)' }}>{asset.operating_system}</td>
                            <td style={styles.monoCell}>{asset.event_count?.toLocaleString()}</td>
                            <td style={styles.monoCell}>{asset.vulnerability_event_count?.toLocaleString()}</td>
                            <td>
                              {asset.critical_event_count > 0 ? (
                                <span className="badge severity-critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
                                  <AlertTriangle size={12} />
                                  {asset.critical_event_count}
                                </span>
                              ) : (
                                <span className="muted" style={{ fontSize: '0.75rem' }}>0</span>
                              )}
                            </td>
                          </tr>

                          {/* Expanded Vulnerability Detail Row */}
                          {isExpanded && (
                            <tr>
                              <td colSpan={11} style={{ backgroundColor: 'var(--bg-secondary)', padding: '1rem 1.5rem' }}>
                                <div style={styles.vulnDetailPanel}>
                                  <h4 style={styles.vulnTitle}>
                                    Vulnerabilities Linked to {asset.asset_name} ({asset.asset_id})
                                  </h4>

                                  {!asset.vulnerabilities || asset.vulnerabilities.length === 0 ? (
                                    <p className="muted" style={{ fontSize: '0.8rem' }}>
                                      No specific CVE vulnerabilities identified for this asset.
                                    </p>
                                  ) : (
                                    <div className="soc-table-container" style={{ marginTop: '0.5rem' }}>
                                      <table className="soc-table">
                                        <thead>
                                          <tr style={{ backgroundColor: 'var(--bg-primary)' }}>
                                            <th>CVE ID</th>
                                            <th>Vulnerability Name</th>
                                            <th>Severity</th>
                                            <th>CVSS Score</th>
                                            <th>Patch Available</th>
                                            <th>Status</th>
                                          </tr>
                                        </thead>
                                        <tbody>
                                          {asset.vulnerabilities.map((vuln) => (
                                            <tr key={vuln.cve_id || Math.random()}>
                                              <td style={styles.monoCell}>
                                                <span className="badge status-detected">{vuln.cve_id}</span>
                                              </td>
                                              <td style={{ fontWeight: '500' }}>{vuln.vulnerability_name}</td>
                                              <td>
                                                <Badge type="severity" value={vuln.vulnerability_severity} />
                                              </td>
                                              <td style={styles.monoCell}>
                                                <strong style={{ color: vuln.vulnerability_cvss_score >= 9.0 ? 'var(--color-critical)' : 'var(--text-primary)' }}>
                                                  {vuln.vulnerability_cvss_score}
                                                </strong>
                                              </td>
                                              <td>
                                                {vuln.patch_available === 'Yes' ? (
                                                  <span className="badge status-success">Patch Available</span>
                                                ) : (
                                                  <span className="badge status-blocked">No Patch</span>
                                                )}
                                              </td>
                                              <td>
                                                <Badge type="status" value={vuln.vulnerability_status} />
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
    gap: '1.5rem'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
    gap: '1.25rem'
  },
  monoCell: {
    fontFamily: 'var(--font-mono)',
    fontSize: '0.78rem'
  },
  vulnDetailPanel: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  vulnTitle: {
    fontSize: '0.85rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    letterSpacing: '-0.01em'
  },
  statePanel: {
    minHeight: '200px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  }
};

export default AssetRiskPage;
