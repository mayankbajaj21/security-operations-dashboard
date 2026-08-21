import React, { useMemo } from 'react';
import { Server, ArrowRight } from 'lucide-react';
import { aggregateAssetRisk } from '../utils/assetRiskAggregator';

/**
 * AssetRiskOverviewCard — Compact Overview Widget for Asset Risk & Exposure
 * 
 * Displays a concise row of 5 compact asset KPI cards (Database-01, Finance-PC-02, Firewall, WebServer, HR-PC-01)
 * with direct navigation to Analytics -> Asset Risk.
 * Authoritative Source: Security Events Dataset (GET /events)
 */
const AssetRiskOverviewCard = ({ allEvents = null, onNavigateToAssetRisk }) => {
  // Aggregate asset telemetry dynamically from security events
  const assets = useMemo(() => {
    return aggregateAssetRisk(allEvents);
  }, [allEvents]);

  const isLoading = allEvents === null;

  return (
    <div className="panel" style={styles.panel}>
      {/* Header */}
      <div style={styles.headerRow}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={styles.iconContainer}>
            <Server size={18} color="var(--color-accent)" />
          </div>
          <div>
            <h3 className="section-title" style={styles.title}>
              Asset Risk &amp; Exposure
            </h3>
            <p className="muted" style={styles.subtitle}>
              Assets requiring analyst attention
            </p>
          </div>
        </div>

        {onNavigateToAssetRisk && (
          <button
            className="soc-button"
            onClick={onNavigateToAssetRisk}
            style={styles.actionButton}
            title="Navigate to Analytics -> Asset Risk"
          >
            <span>View Asset Risk</span>
            <ArrowRight size={14} />
          </button>
        )}
      </div>

      {/* 5 Compact Asset KPI Cards */}
      {isLoading ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>Loading asset risk telemetry...</p>
        </div>
      ) : assets.length === 0 ? (
        <div style={styles.stateContainer}>
          <p className="muted" style={{ fontSize: '0.8rem' }}>No asset telemetry available.</p>
        </div>
      ) : (
        <div style={styles.cardsGrid}>
          {assets.map((asset) => (
            <div
              key={asset.asset_name}
              style={styles.cardItem}
              onClick={onNavigateToAssetRisk}
              title={`View ${asset.asset_name} in Asset Risk`}
            >
              <span style={styles.cardAssetName}>{asset.asset_name}</span>
              <div style={styles.cardBody}>
                <strong style={styles.cardCount}>
                  {asset.totalEvents?.toLocaleString()}
                </strong>
                <span style={styles.cardLabel}>Total Events</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const styles = {
  panel: {
    padding: '1rem 1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem',
    borderRadius: '8px'
  },
  headerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  iconContainer: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '32px',
    height: '32px',
    borderRadius: '6px',
    backgroundColor: 'rgba(6, 182, 212, 0.12)'
  },
  title: {
    fontSize: '0.92rem',
    fontWeight: '700',
    margin: 0,
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '-0.01em'
  },
  subtitle: {
    fontSize: '0.74rem',
    margin: '0.15rem 0 0 0',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)'
  },
  actionButton: {
    fontSize: '0.76rem',
    padding: '0.35rem 0.75rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    cursor: 'pointer'
  },
  stateContainer: {
    padding: '1rem',
    textAlign: 'center'
  },
  cardsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))',
    gap: '0.75rem',
    width: '100%'
  },
  cardItem: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.75rem 0.85rem',
    display: 'flex',
    flexDirection: 'column',
    justifyContent: 'space-between',
    gap: '0.35rem',
    cursor: 'pointer',
    transition: 'border-color 0.15s ease, background-color 0.15s ease'
  },
  cardAssetName: {
    fontSize: '0.8rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-sans)',
    letterSpacing: '-0.01em',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis'
  },
  cardBody: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.1rem'
  },
  cardCount: {
    fontSize: '1.45rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '800',
    color: 'var(--color-accent)',
    lineHeight: '1.1'
  },
  cardLabel: {
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-sans)',
    fontWeight: '500'
  }
};

export default AssetRiskOverviewCard;
