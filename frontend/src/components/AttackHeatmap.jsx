import React, { useState, useMemo } from 'react';
import { Grid, Flame, Info } from 'lucide-react';

const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, '0'));

const RELEVANT_TYPES = [
  'brute force',
  'malware',
  'malware infection',
  'failed login',
  'privilege escalation',
  'port scan',
  'phishing',
  'phishing attempt',
  'sql injection',
  'unauthorized access',
  'unauthorized file access',
  'data exfiltration',
  'ransomware execution',
  'ddos attack'
];

const FILTERS = [
  { id: 'all', label: 'All Events' },
  { id: 'suspicious', label: 'Suspicious' },
  { id: 'low', label: 'Low Threat' },
  { id: 'medium', label: 'Medium Threat' },
  { id: 'high', label: 'High Threat' },
  { id: 'critical', label: 'Critical Threat' }
];

/**
 * Presentational Attack Activity Heatmap Component (7 Days x 24 Hours)
 * Occupies 100% full available content width.
 * Features 6 exact filters: All Events, Suspicious, Low Threat, Medium Threat, High Threat, Critical Threat.
 */
const AttackHeatmap = ({ allEvents = null, onSelectTimeSlot }) => {
  const [filterOption, setFilterOption] = useState('all');
  const [hoveredCell, setHoveredCell] = useState(null);

  // Compute 7x24 matrix and peak statistics using useMemo
  const { matrix, maxCount, peakCell, totalMatchingEvents } = useMemo(() => {
    // Initialize empty 7x24 grid structure
    const grid = {};
    DAYS.forEach((day) => {
      grid[day] = {};
      HOURS.forEach((hour) => {
        grid[day][hour] = {
          count: 0,
          critical: 0,
          high: 0,
          medium: 0,
          low: 0
        };
      });
    });

    if (!Array.isArray(allEvents) || allEvents.length === 0) {
      return { matrix: grid, maxCount: 0, peakCell: null, totalMatchingEvents: 0 };
    }

    let calculatedMax = 0;
    let peak = null;
    let matchCount = 0;

    allEvents.forEach((evt) => {
      if (!evt.timestamp) return;

      const dateObj = new Date(evt.timestamp);
      if (isNaN(dateObj.getTime())) return;

      const severityStr = (evt.event_severity || evt.severity || '').toLowerCase();
      const typeStr = (evt.event_type || evt.threat_type || '').toLowerCase();
      const isSuspicious = 
        evt.prediction === 'Suspicious' || 
        evt.threat_intel_match === true || 
        severityStr === 'critical' || 
        severityStr === 'high' || 
        RELEVANT_TYPES.some(t => typeStr.includes(t));

      // Filter handling in exact order
      if (filterOption === 'suspicious') {
        if (!isSuspicious) return;
      } else if (filterOption === 'low') {
        if (severityStr !== 'low') return;
      } else if (filterOption === 'medium') {
        if (severityStr !== 'medium') return;
      } else if (filterOption === 'high') {
        if (severityStr !== 'high') return;
      } else if (filterOption === 'critical') {
        if (severityStr !== 'critical') return;
      }

      // Convert JS getDay() (0=Sun, 1=Mon..6=Sat) to Mon=0..Sun=6 index
      const dayIdx = (dateObj.getDay() + 6) % 7;
      const dayName = DAYS[dayIdx];
      const hourStr = String(dateObj.getHours()).padStart(2, '0');

      if (grid[dayName] && grid[dayName][hourStr]) {
        grid[dayName][hourStr].count += 1;
        matchCount += 1;

        if (severityStr === 'critical') grid[dayName][hourStr].critical += 1;
        else if (severityStr === 'high') grid[dayName][hourStr].high += 1;
        else if (severityStr === 'medium') grid[dayName][hourStr].medium += 1;
        else if (severityStr === 'low') grid[dayName][hourStr].low += 1;

        const currentCount = grid[dayName][hourStr].count;
        if (currentCount > calculatedMax) {
          calculatedMax = currentCount;
          peak = { day: dayName, hour: hourStr, count: currentCount };
        }
      }
    });

    return {
      matrix: grid,
      maxCount: calculatedMax,
      peakCell: peak,
      totalMatchingEvents: matchCount
    };
  }, [allEvents, filterOption]);

  // Compute dynamic cell background & text color relative to maxCount
  const getCellStyles = (count) => {
    if (count === 0 || maxCount === 0) {
      return {
        backgroundColor: 'var(--bg-card)',
        color: 'var(--text-muted)',
        border: '1px solid var(--border-subtle)'
      };
    }

    const ratio = count / maxCount;

    if (ratio > 0.75) {
      return {
        backgroundColor: 'rgba(244, 63, 94, 0.9)',
        color: '#ffffff',
        boxShadow: '0 0 8px rgba(244, 63, 94, 0.45)'
      };
    } else if (ratio > 0.45) {
      return {
        backgroundColor: 'rgba(245, 158, 11, 0.85)',
        color: '#ffffff'
      };
    } else if (ratio > 0.2) {
      return {
        backgroundColor: 'rgba(6, 182, 212, 0.75)',
        color: '#ffffff'
      };
    } else {
      return {
        backgroundColor: 'rgba(6, 182, 212, 0.25)',
        color: 'var(--text-primary)'
      };
    }
  };

  const getFilterActiveColor = (filterId) => {
    switch (filterId) {
      case 'critical':
        return 'var(--color-critical)';
      case 'high':
        return 'var(--color-high)';
      case 'medium':
        return 'var(--color-warning)';
      case 'low':
        return 'var(--color-low)';
      case 'suspicious':
        return 'var(--color-critical)';
      default:
        return 'var(--color-accent)';
    }
  };

  if (allEvents === null) {
    return (
      <div className="panel" style={styles.statePanel}>
        <p className="muted">Loading attack activity heatmap...</p>
      </div>
    );
  }

  return (
    <div className="panel" style={styles.container}>
      {/* Header Bar */}
      <div style={styles.header}>
        <div style={styles.titleGroup}>
          <Grid size={18} color="var(--color-accent)" />
          <div>
            <h3 style={styles.title}>Attack Activity Heatmap</h3>
            <p className="muted" style={styles.subtitle}>
              Temporal distribution of security events by day of week and hour of day
            </p>
          </div>
        </div>

        {/* 6 Exact Heatmap Filter Controls */}
        <div style={styles.toolbar}>
          <div style={styles.toggleGroup}>
            {FILTERS.map((f) => {
              const isActive = filterOption === f.id;
              const activeColor = getFilterActiveColor(f.id);
              return (
                <button
                  key={f.id}
                  className="soc-button"
                  onClick={() => setFilterOption(f.id)}
                  style={{
                    ...styles.toggleBtn,
                    backgroundColor: isActive ? activeColor : 'transparent',
                    color: isActive ? '#ffffff' : 'var(--text-secondary)',
                    fontWeight: isActive ? '700' : '600',
                    boxShadow: isActive ? `0 2px 6px ${activeColor}44` : 'none'
                  }}
                >
                  {f.label}
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* Dynamic Summary Insight Banner */}
      <div style={styles.insightBanner}>
        <div style={styles.insightLeft}>
          <Flame size={15} color={maxCount > 0 ? 'var(--color-warning)' : 'var(--text-muted)'} />
          {peakCell ? (
            <span style={styles.insightText}>
              Peak Activity Window:{' '}
              <strong style={{ color: 'var(--color-accent)' }}>
                {peakCell.day}, {peakCell.hour}:00–{String(Number(peakCell.hour) + 1).padStart(2, '0')}:00
              </strong>{' '}
              with <strong style={{ color: 'var(--color-warning)' }}>{peakCell.count} events</strong>.
            </span>
          ) : (
            <span style={styles.insightText}>No event activity recorded for the selected filter.</span>
          )}
        </div>
        <span style={styles.totalBadge}>
          {totalMatchingEvents.toLocaleString()} events analyzed
        </span>
      </div>

      {/* Heatmap Grid Container with Full Width & Horizontal Scroll if needed */}
      <div style={styles.gridScrollContainer}>
        <div style={styles.heatmapTable}>
          {/* X-Axis Hours Header */}
          <div style={styles.headerRow}>
            <div style={styles.dayLabelHeader}>Day / Hour</div>
            {HOURS.map((h) => (
              <div key={h} style={styles.hourLabel}>
                {h}
              </div>
            ))}
          </div>

          {/* 7 Days Grid Rows */}
          {DAYS.map((day) => (
            <div key={day} style={styles.dayRow}>
              <div style={styles.dayLabel}>{day.slice(0, 3)}</div>
              {HOURS.map((hour) => {
                const cellData = matrix[day][hour];
                const count = cellData.count;
                const cellStyle = getCellStyles(count);
                const isHovered =
                  hoveredCell && hoveredCell.day === day && hoveredCell.hour === hour;

                return (
                  <div
                    key={hour}
                    style={{
                      ...styles.gridCell,
                      ...cellStyle,
                      transform: isHovered ? 'scale(1.12)' : 'none',
                      zIndex: isHovered ? 10 : 1
                    }}
                    onMouseEnter={() => setHoveredCell({ day, hour, ...cellData })}
                    onMouseLeave={() => setHoveredCell(null)}
                    onClick={() => {
                      if (onSelectTimeSlot) onSelectTimeSlot(day, hour);
                    }}
                  >
                    <span style={styles.cellCount}>{count}</span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>
      </div>

      {/* Tooltip & Legend Row */}
      <div style={styles.footerRow}>
        {/* Active Tooltip Drawer */}
        {hoveredCell ? (
          <div style={styles.activeTooltip}>
            <Info size={13} color="var(--color-accent)" />
            <span>
              <strong>{hoveredCell.day}</strong> ({hoveredCell.hour}:00–
              {String(Number(hoveredCell.hour) + 1).padStart(2, '0')}:00):{' '}
              <strong style={{ color: 'var(--color-accent)' }}>{hoveredCell.count} events</strong>
              {' ('}
              <span style={{ color: 'var(--color-critical)' }}>Crit: {hoveredCell.critical}</span> |{' '}
              <span style={{ color: 'var(--color-high)' }}>High: {hoveredCell.high}</span> |{' '}
              <span style={{ color: 'var(--color-medium)' }}>Med: {hoveredCell.medium}</span> |{' '}
              <span style={{ color: 'var(--color-low)' }}>Low: {hoveredCell.low}</span>
              {')'}
            </span>
          </div>
        ) : (
          <div style={styles.tooltipPlaceholder}>
            <span style={styles.mutedText}>Hover over any cell to view hourly security event breakdown</span>
          </div>
        )}

        {/* Heat Intensity Legend */}
        <div style={styles.legendGroup}>
          <span style={styles.legendLabel}>Less Activity</span>
          <div style={styles.legendScale}>
            <div style={{ ...styles.legendBox, backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>0</div>
            <div style={{ ...styles.legendBox, backgroundColor: 'rgba(6, 182, 212, 0.25)', color: 'var(--text-primary)' }}>Low</div>
            <div style={{ ...styles.legendBox, backgroundColor: 'rgba(6, 182, 212, 0.75)', color: '#fff' }}>Med</div>
            <div style={{ ...styles.legendBox, backgroundColor: 'rgba(245, 158, 11, 0.85)', color: '#fff' }}>High</div>
            <div style={{ ...styles.legendBox, backgroundColor: 'rgba(244, 63, 94, 0.9)', color: '#fff' }}>Peak</div>
          </div>
          <span style={styles.legendLabel}>More Activity</span>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem',
    padding: '1.25rem',
    width: '100%',
    boxSizing: 'border-box'
  },
  statePanel: {
    minHeight: '140px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    width: '100%'
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem'
  },
  titleGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem'
  },
  title: {
    fontSize: '1rem',
    fontWeight: '600',
    margin: 0,
    color: 'var(--text-primary)'
  },
  subtitle: {
    fontSize: '0.75rem',
    margin: 0
  },
  toolbar: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    flexWrap: 'wrap'
  },
  toggleGroup: {
    display: 'flex',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '2px',
    gap: '2px',
    flexWrap: 'wrap'
  },
  toggleBtn: {
    fontSize: '0.72rem',
    padding: '0.25rem 0.55rem',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'all 0.15s ease'
  },
  insightBanner: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    padding: '0.5rem 0.85rem',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  insightLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem'
  },
  insightText: {
    fontSize: '0.78rem',
    color: 'var(--text-primary)'
  },
  totalBadge: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    fontFamily: 'var(--font-mono)'
  },
  gridScrollContainer: {
    width: '100%',
    overflowX: 'auto',
    paddingBottom: '0.5rem'
  },
  heatmapTable: {
    display: 'flex',
    flexDirection: 'column',
    gap: '4px',
    minWidth: '720px',
    width: '100%'
  },
  headerRow: {
    display: 'flex',
    gap: '4px',
    alignItems: 'center',
    marginBottom: '2px'
  },
  dayLabelHeader: {
    width: '44px',
    fontSize: '0.68rem',
    fontWeight: '600',
    color: 'var(--text-muted)',
    textTransform: 'uppercase'
  },
  hourLabel: {
    flex: 1,
    textAlign: 'center',
    fontSize: '0.68rem',
    fontFamily: 'var(--font-mono)',
    color: 'var(--text-muted)'
  },
  dayRow: {
    display: 'flex',
    gap: '4px',
    alignItems: 'center'
  },
  dayLabel: {
    width: '44px',
    fontSize: '0.73rem',
    fontWeight: '600',
    color: 'var(--text-secondary)'
  },
  gridCell: {
    flex: 1,
    height: '28px',
    borderRadius: '3px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
    userSelect: 'none'
  },
  cellCount: {
    fontSize: '0.7rem',
    fontWeight: '600',
    fontFamily: 'var(--font-mono)'
  },
  footerRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingTop: '0.4rem',
    borderTop: '1px solid var(--border-color)',
    flexWrap: 'wrap',
    gap: '0.75rem'
  },
  activeTooltip: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.78rem',
    color: 'var(--text-primary)'
  },
  tooltipPlaceholder: {
    display: 'flex',
    alignItems: 'center'
  },
  mutedText: {
    fontSize: '0.73rem',
    color: 'var(--text-muted)'
  },
  legendGroup: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  legendLabel: {
    fontSize: '0.72rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  legendScale: {
    display: 'flex',
    gap: '3px'
  },
  legendBox: {
    padding: '0.15rem 0.4rem',
    borderRadius: '3px',
    fontSize: '0.68rem',
    fontWeight: '600',
    border: '1px solid var(--border-color)'
  }
};

export default AttackHeatmap;
