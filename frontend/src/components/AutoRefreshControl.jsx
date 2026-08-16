import React from 'react';
import { RefreshCw, Clock, AlertCircle } from 'lucide-react';

/**
 * Presentational Auto-Refresh Control Component
 */
const AutoRefreshControl = ({
  isRefreshing = false,
  lastUpdated = null,
  autoRefreshEnabled = true,
  onRefresh,
  onToggle,
  refreshError = null
}) => {
  const formatTime = (dateObj) => {
    if (!dateObj) return 'Just now';
    try {
      return dateObj.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
      });
    } catch (e) {
      return 'Just now';
    }
  };

  return (
    <div style={styles.container}>
      {refreshError && (
        <div style={styles.errorContainer}>
          <AlertCircle size={13} color="var(--color-critical)" />
          <span style={styles.errorText}>{refreshError}</span>
        </div>
      )}

      <div style={styles.controlsRow}>
        {/* Status indicator badge */}
        <div style={styles.statusBadge}>
          <span
            style={{
              ...styles.statusDot,
              backgroundColor: isRefreshing
                ? 'var(--color-warning)'
                : autoRefreshEnabled
                ? 'var(--color-success)'
                : 'var(--text-muted)'
            }}
          />
          <span style={styles.statusText}>
            {isRefreshing ? 'Refreshing...' : autoRefreshEnabled ? 'Live (60s)' : 'Auto-refresh OFF'}
          </span>
        </div>

        {/* Last updated timestamp */}
        <div style={styles.timestampContainer}>
          <Clock size={12} color="var(--text-muted)" />
          <span style={styles.timestampText}>
            Updated: <strong style={{ color: 'var(--text-primary)' }}>{formatTime(lastUpdated)}</strong>
          </span>
        </div>

        {/* Manual refresh button */}
        <button
          className="soc-button"
          onClick={onRefresh}
          disabled={isRefreshing}
          style={styles.refreshButton}
          title="Trigger immediate telemetry refresh"
        >
          <RefreshCw size={12} className={isRefreshing ? 'spin-icon' : ''} />
          <span>Refresh</span>
        </button>

        {/* Auto Refresh toggle button */}
        <button
          className="soc-button"
          onClick={onToggle}
          style={{
            ...styles.toggleButton,
            borderColor: autoRefreshEnabled ? 'var(--color-accent)' : 'var(--border-color)',
            backgroundColor: autoRefreshEnabled ? 'rgba(6, 182, 212, 0.08)' : 'transparent'
          }}
        >
          <span>Auto Refresh:</span>
          <strong style={{ color: autoRefreshEnabled ? 'var(--color-accent)' : 'var(--text-muted)' }}>
            {autoRefreshEnabled ? 'ON' : 'OFF'}
          </strong>
        </button>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-end',
    gap: '0.35rem'
  },
  controlsRow: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.35rem 0.65rem'
  },
  statusBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem'
  },
  statusDot: {
    width: '7px',
    height: '7px',
    borderRadius: '50%',
    display: 'inline-block'
  },
  statusText: {
    fontSize: '0.73rem',
    fontWeight: '600',
    color: 'var(--text-primary)'
  },
  timestampContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    paddingLeft: '0.4rem',
    borderLeft: '1px solid var(--border-color)'
  },
  timestampText: {
    fontSize: '0.72rem',
    color: 'var(--text-secondary)'
  },
  refreshButton: {
    fontSize: '0.72rem',
    padding: '0.25rem 0.55rem',
    height: '26px'
  },
  toggleButton: {
    fontSize: '0.72rem',
    padding: '0.25rem 0.55rem',
    height: '26px',
    display: 'flex',
    gap: '0.3rem'
  },
  errorContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem',
    backgroundColor: 'rgba(244, 63, 94, 0.08)',
    border: '1px solid rgba(244, 63, 94, 0.2)',
    borderRadius: '4px',
    padding: '0.2rem 0.5rem'
  },
  errorText: {
    fontSize: '0.7rem',
    color: 'var(--color-critical)',
    fontWeight: '500'
  }
};

export default AutoRefreshControl;
