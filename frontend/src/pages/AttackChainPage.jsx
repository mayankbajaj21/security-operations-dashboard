import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { getAttackChains } from '../services/api';
import Badge from '../components/Badge';
import { 
  GitCommit, 
  Layers, 
  ShieldAlert, 
  Activity, 
  Clock, 
  RefreshCw, 
  Cpu, 
  Flame, 
  Target, 
  User, 
  Server, 
  Globe, 
  ChevronRight, 
  ArrowRight,
  ShieldCheck,
  Sliders,
  CheckCircle2,
  AlertOctagon
} from 'lucide-react';

/**
 * Standard MITRE Attack Progression Defined by Milestone 3:
 * 1. Initial Access
 * 2. Credential Access
 * 3. Privilege Escalation
 * 4. Lateral Movement
 * 5. Exfiltration
 */
const MITRE_KILL_CHAIN_STAGES = [
  { id: 'Initial Access', label: 'Initial Access', color: '#38bdf8' },
  { id: 'Credential Access', label: 'Credential Access', color: '#facc15' },
  { id: 'Privilege Escalation', label: 'Privilege Escalation', color: '#fbbf24' },
  { id: 'Lateral Movement', label: 'Lateral Movement', color: '#fb923c' },
  { id: 'Exfiltration', label: 'Exfiltration', color: '#f43f5e' }
];

const AttackChainPage = () => {
  const [windowMinutes, setWindowMinutes] = useState(15);
  const [chainsData, setChainsData] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Selected Attack Chain for Expanded Deep-Dive
  const [selectedChainId, setSelectedChainId] = useState(null);

  const fetchAttackChains = useCallback(async (isManual = false) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getAttackChains({ window_minutes: windowMinutes }, { noCache: isManual });
      const rawChains = Array.isArray(res?.data) ? res.data : Array.isArray(res) ? res : [];
      setChainsData(rawChains);

      const resMetrics = res?.metrics || {
        total_events_analyzed: res?.total_events_analyzed ?? 0,
        suspicious_events_count: res?.suspicious_events_count ?? 0,
        attack_chains_count: res?.total ?? rawChains.length
      };
      setMetrics(resMetrics);

      if (rawChains.length > 0) {
        setSelectedChainId((prev) => (prev && rawChains.some((c) => c.attack_chain_id === prev) ? prev : rawChains[0].attack_chain_id));
      } else {
        setSelectedChainId(null);
      }
    } catch (err) {
      console.error('Failed to load attack chains from API:', err);
      setError('Unable to correlate multi-stage attack chains from the backend.');
    } finally {
      setLoading(false);
    }
  }, [windowMinutes]);

  useEffect(() => {
    fetchAttackChains();
  }, [fetchAttackChains]);

  const selectedChain = useMemo(() => {
    if (!chainsData.length) return null;
    return chainsData.find((c) => c.attack_chain_id === selectedChainId) || chainsData[0] || null;
  }, [chainsData, selectedChainId]);

  return (
    <div style={styles.container}>
      {/* 1. STANDARDIZED PAGE HEADER & ACTION CONTROLS */}
      <div style={styles.headerRow}>
        <div>
          <h2 className="section-title" style={styles.pageHeading}>
            <GitCommit size={20} color="var(--color-accent)" />
            <span>Correlated Attack Chains & Multi-Stage Progression</span>
          </h2>
          <p className="muted" style={styles.pageSubtitle}>
            M3 Event Correlation Engine detecting multi-stage MITRE kill chain attack patterns across time windows
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.65rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Sliding Time Window Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', backgroundColor: 'var(--bg-secondary)', padding: '0.25rem 0.65rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <Clock size={13} color="var(--color-accent)" />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Sliding Window:</span>
            <select
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value))}
              style={{ ...styles.selectFilter, border: 'none', padding: '0.15rem 0.4rem', background: 'transparent' }}
            >
              <option value={15}>15 Minutes</option>
              <option value={30}>30 Minutes</option>
              <option value={60}>60 Minutes</option>
              <option value={120}>120 Minutes</option>
            </select>
          </div>

          <button
            className="soc-button"
            onClick={() => fetchAttackChains(true)}
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
            title="Re-run Correlation Engine"
          >
            <RefreshCw size={14} />
            <span>Re-Correlate</span>
          </button>
        </div>
      </div>

      {/* 2. CORRELATION METRICS KPI GRID */}
      <div style={styles.kpiGrid}>
        <div className="panel" style={{ ...styles.kpiCard, borderLeft: '3px solid var(--color-accent)' }}>
          <span style={styles.kpiLabel}>CORRELATED ATTACK CHAINS</span>
          <div style={{ ...styles.kpiValue, color: 'var(--color-accent)' }}>
            {metrics?.attack_chains_count ?? chainsData.length}
          </div>
          <span style={styles.kpiSubtitle}>Multi-stage attack pathways</span>
        </div>

        <div className="panel" style={{ ...styles.kpiCard, borderLeft: '3px solid var(--color-critical)' }}>
          <span style={styles.kpiLabel}>SUSPICIOUS / ANOMALY EVENTS</span>
          <div style={{ ...styles.kpiValue, color: 'var(--color-critical)' }}>
            {(metrics?.suspicious_events_count ?? 0).toLocaleString()}
          </div>
          <span style={styles.kpiSubtitle}>Candidate chain telemetry</span>
        </div>

        <div className="panel" style={{ ...styles.kpiCard, borderLeft: '3px solid var(--color-high)' }}>
          <span style={styles.kpiLabel}>TOTAL TELEMETRY ANALYZED</span>
          <div style={{ ...styles.kpiValue, color: 'var(--text-primary)' }}>
            {(metrics?.total_events_analyzed ?? 0).toLocaleString()}
          </div>
          <span style={styles.kpiSubtitle}>Evaluated event records</span>
        </div>

        <div className="panel" style={{ ...styles.kpiCard, borderLeft: '3px solid var(--color-warning)' }}>
          <span style={styles.kpiLabel}>CORRELATION WINDOW</span>
          <div style={{ ...styles.kpiValue, color: 'var(--color-warning)' }}>
            {windowMinutes} min
          </div>
          <span style={styles.kpiSubtitle}>Sliding time grouping</span>
        </div>
      </div>

      {/* 3. MITRE ATT&CK 5-STAGE PROGRESSION REFERENCE STRIP */}
      <div className="panel" style={{ padding: '0.85rem 1.15rem', backgroundColor: 'var(--bg-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
          <span style={{ fontSize: '0.72rem', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
            STANDARD M3 MITRE ATT&CK PROGRESSION PATHWAY
          </span>
          <span style={{ fontSize: '0.68rem', color: 'var(--color-accent)' }}>Deterministic Kill Chain Mapping</span>
        </div>

        <div style={styles.progressionStrip}>
          {MITRE_KILL_CHAIN_STAGES.map((stage, idx) => (
            <React.Fragment key={stage.id}>
              <div style={{ ...styles.stageBadge, borderColor: stage.color, color: stage.color }}>
                <span style={{ fontSize: '0.68rem', fontWeight: '800' }}>0{idx + 1}</span>
                <span style={{ fontSize: '0.75rem', fontWeight: '700' }}>{stage.label}</span>
              </div>
              {idx < MITRE_KILL_CHAIN_STAGES.length - 1 && (
                <ChevronRight size={16} color="var(--border-color)" style={{ flexShrink: 0 }} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {loading && (
        <div className="panel" style={styles.statePanel}>
          <p className="muted">Running event correlation algorithm and mapping attack chains...</p>
        </div>
      )}

      {error && !loading && (
        <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
          <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
        </div>
      )}

      {!loading && !error && chainsData.length === 0 && (
        <div className="panel" style={styles.statePanel}>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={36} color="var(--color-success)" />
            <h4 style={{ margin: 0, color: 'var(--text-primary)' }}>No Multi-Stage Attack Chains Detected</h4>
            <p className="muted" style={{ margin: 0, fontSize: '0.82rem', maxWidth: '480px' }}>
              The correlation engine evaluated all {metrics?.total_events_analyzed ?? 0} events across the {windowMinutes}-minute window. Zero multi-stage progression signatures breached the correlation threshold.
            </p>
          </div>
        </div>
      )}

      {!loading && !error && chainsData.length > 0 && (
        <div style={styles.twoColumnLayout}>
          {/* Left Column: Attack Chains List Cards */}
          <div style={styles.chainsListColumn}>
            <span style={{ fontSize: '0.75rem', fontWeight: '700', color: 'var(--text-muted)', marginBottom: '0.25rem', display: 'block' }}>
              DETECTED ATTACK PATHWAYS ({chainsData.length})
            </span>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', maxHeight: '640px', overflowY: 'auto' }}>
              {chainsData.map((chain) => {
                const isSelected = chain.attack_chain_id === selectedChain?.attack_chain_id;
                const stagesList = chain.stages || [];
                const eventsList = chain.events || chain.related_events || [];

                return (
                  <div
                    key={chain.attack_chain_id}
                    onClick={() => setSelectedChainId(chain.attack_chain_id)}
                    className="panel"
                    style={{
                      ...styles.chainCard,
                      borderColor: isSelected ? 'var(--color-accent)' : 'var(--border-color)',
                      backgroundColor: isSelected ? 'rgba(6, 182, 212, 0.05)' : 'var(--bg-card)'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: '800', fontSize: '0.85rem', color: isSelected ? 'var(--color-accent)' : 'var(--text-primary)' }}>
                        {chain.attack_chain_id}
                      </span>
                      <Badge type="severity" value={chain.risk_level || 'High'} />
                    </div>

                    <div style={{ fontSize: '0.75rem', fontWeight: '600', color: 'var(--text-primary)', marginBottom: '0.35rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {chain.name || `Correlated Attack Campaign (${chain.stage || 'Multi-Stage'})`}
                    </div>

                    <div style={{ display: 'flex', gap: '0.6rem', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '0.45rem', flexWrap: 'wrap' }}>
                      <span><strong>{stagesList.length}</strong> Stages</span>
                      <span>•</span>
                      <span><strong>{eventsList.length}</strong> Events</span>
                      <span>•</span>
                      <span>Risk: <strong style={{ color: 'var(--color-critical)' }}>{chain.risk_score || 85}</strong>/100</span>
                      <span>•</span>
                      <span>Conf: <strong>{chain.confidence || chain.ml_confidence || 80}%</strong></span>
                    </div>

                    {/* Visual mini stage progression tags */}
                    <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap' }}>
                      {stagesList.map((stg, sIdx) => {
                        const stageName = typeof stg === 'string' ? stg : stg.stage_name || stg.stage;
                        return (
                          <span key={sIdx} className="badge severity-high" style={{ fontSize: '0.65rem' }}>
                            {stageName}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Selected Attack Chain Deep-Dive Workspace */}
          {selectedChain && (
            <div style={styles.deepDiveColumn}>
              <div className="panel" style={styles.deepDivePanel}>
                <div style={styles.deepDiveHeader}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <h3 className="section-title" style={{ fontSize: '1.1rem', margin: 0 }}>
                        {selectedChain.attack_chain_id}
                      </h3>
                      <Badge type="severity" value={selectedChain.risk_level || 'High'} />
                    </div>
                    <p className="muted" style={{ fontSize: '0.75rem', margin: '0.2rem 0 0 0' }}>
                      {selectedChain.name || 'Correlated Entity Timeline & Multi-Stage Kill Chain Mapping'}
                    </p>
                  </div>

                  <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>CHAIN RISK SCORE</span>
                      <span style={{ fontSize: '1.25rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-critical)' }}>
                        {selectedChain.risk_score || 85} <span style={{ fontSize: '0.7rem', opacity: 0.7 }}>/ 100</span>
                      </span>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', display: 'block', fontWeight: '700' }}>ML CONFIDENCE</span>
                      <span style={{ fontSize: '1.25rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                        {selectedChain.confidence || selectedChain.ml_confidence || 88}%
                      </span>
                    </div>
                  </div>
                </div>

                {/* Participating Entities Grid */}
                <div style={styles.entitiesGrid}>
                  <div style={styles.entityItem}>
                    <User size={14} color="var(--color-accent)" />
                    <span style={styles.entityLabel}>Target User:</span>
                    <span style={styles.entityVal}>
                      {selectedChain.target_user || selectedChain.username || selectedChain.participating_entities?.username || 'analyst'}
                    </span>
                  </div>
                  <div style={styles.entityItem}>
                    <Server size={14} color="var(--color-accent)" />
                    <span style={styles.entityLabel}>Target Host:</span>
                    <span style={styles.entityVal}>
                      {selectedChain.affected_asset || selectedChain.asset_name || selectedChain.participating_entities?.asset_name || 'Production Server'}
                    </span>
                  </div>
                  <div style={styles.entityItem}>
                    <Globe size={14} color="var(--color-accent)" />
                    <span style={styles.entityLabel}>Source IP:</span>
                    <span style={styles.entityValMono}>
                      {selectedChain.source_ip || selectedChain.participating_entities?.source_ip || '192.168.1.50'}
                    </span>
                  </div>
                  <div style={styles.entityItem}>
                    <Globe size={14} color="var(--color-accent)" />
                    <span style={styles.entityLabel}>Current Stage:</span>
                    <span style={styles.entityVal}>
                      {selectedChain.stage || 'Credential Access'}
                    </span>
                  </div>
                </div>

                {/* Correlation Rules Satisfied */}
                {selectedChain.correlation_rules && selectedChain.correlation_rules.length > 0 && (
                  <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: '700' }}>CORRELATION RULES:</span>
                    {selectedChain.correlation_rules.map((rule, rIdx) => (
                      <span key={rIdx} className="badge status-detected" style={{ fontSize: '0.68rem' }}>
                        {rule}
                      </span>
                    ))}
                  </div>
                )}

                {/* Multi-Stage Visual Timeline Flow */}
                <div style={{ marginTop: '0.75rem' }}>
                  <span style={{ fontSize: '0.78rem', fontWeight: '700', color: 'var(--text-primary)', display: 'block', marginBottom: '0.75rem' }}>
                    CHRONOLOGICAL ATTACK STAGE PROGRESSION ({(selectedChain.event_details || selectedChain.events || []).length} EVENTS)
                  </span>

                  <div style={styles.stageTimelineFlow}>
                    {(selectedChain.event_details && selectedChain.event_details.length > 0
                      ? selectedChain.event_details
                      : (selectedChain.events || []).map((eId, idx) => ({
                          event_id: eId,
                          event_type: selectedChain.name || 'Threat Event',
                          stage: (selectedChain.stages || [])[idx] || selectedChain.stage
                        }))
                    ).map((item, idx) => {
                      const eventId = item.event_id || item;
                      const eventType = item.event_type || item.threat_type || 'Security Event';
                      const stageName = item.stage || (selectedChain.stages || [])[idx] || 'Active Attack Step';
                      const eventTime = item.timestamp ? String(item.timestamp).replace('T', ' ').slice(0, 19) : null;
                      const user = item.username || item.user_id;
                      const asset = item.asset_name || item.asset_id;

                      return (
                        <div key={idx} style={styles.stageTimelineItem}>
                          <div style={styles.stageStepMarker}>
                            <span style={{ fontSize: '0.72rem', fontWeight: '800', color: '#000' }}>{idx + 1}</span>
                          </div>

                          <div style={styles.stageStepContent}>
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <strong style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                                  {eventType}
                                </strong>
                                <span className="badge severity-high" style={{ fontSize: '0.68rem' }}>
                                  {stageName}
                                </span>
                              </div>

                              <span className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem' }}>
                                {eventId}
                              </span>
                            </div>

                            <div style={{ display: 'flex', gap: '0.75rem', fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem', flexWrap: 'wrap' }}>
                              {eventTime && <span>Time: <strong style={{ color: 'var(--text-secondary)' }}>{eventTime}</strong></span>}
                              {user && <span>User: <strong style={{ color: 'var(--text-secondary)' }}>{user}</strong></span>}
                              {asset && <span>Asset: <strong style={{ color: 'var(--text-secondary)' }}>{asset}</strong></span>}
                              {item.confidence_score !== undefined && (
                                <span>Confidence: <strong style={{ color: 'var(--color-accent)' }}>{item.confidence_score}%</strong></span>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Correlated Event IDs List */}
                {(selectedChain.events || selectedChain.related_events) && (
                  <div style={{ marginTop: '1rem', paddingTop: '0.75rem', borderTop: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.72rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block', marginBottom: '0.4rem' }}>
                      CORRELATED EVENT IDENTIFIERS ({(selectedChain.events || selectedChain.related_events).length})
                    </span>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      {(selectedChain.events || selectedChain.related_events).map((evtId, idx) => (
                        <span key={idx} className="badge status-detected" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>
                          {evtId}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
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
  kpiCard: {
    padding: '0.85rem 1rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  kpiLabel: {
    fontSize: '0.68rem',
    fontWeight: '700',
    letterSpacing: '0.05em',
    color: 'var(--text-muted)'
  },
  kpiValue: {
    fontSize: '1.45rem',
    fontWeight: '800',
    fontFamily: 'var(--font-mono)',
    lineHeight: 1.1
  },
  kpiSubtitle: {
    fontSize: '0.72rem',
    color: 'var(--text-secondary)'
  },
  progressionStrip: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    overflowX: 'auto',
    padding: '0.25rem 0'
  },
  stageBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    padding: '0.35rem 0.65rem',
    borderRadius: '6px',
    border: '1px solid',
    backgroundColor: 'var(--bg-primary)',
    whiteSpace: 'nowrap'
  },
  selectFilter: {
    fontSize: '0.75rem',
    color: 'var(--text-primary)',
    backgroundColor: 'transparent',
    cursor: 'pointer'
  },
  twoColumnLayout: {
    display: 'grid',
    gridTemplateColumns: '320px 1fr',
    gap: '1.25rem',
    alignItems: 'start'
  },
  chainsListColumn: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.5rem'
  },
  chainCard: {
    padding: '0.85rem 1rem',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
    display: 'flex',
    flexDirection: 'column'
  },
  deepDiveColumn: {
    display: 'flex',
    flexDirection: 'column'
  },
  deepDivePanel: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  deepDiveHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem',
    paddingBottom: '0.75rem',
    borderBottom: '1px solid var(--border-subtle)'
  },
  entitiesGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
    gap: '0.75rem',
    padding: '0.85rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)'
  },
  entityItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem'
  },
  entityLabel: {
    fontSize: '0.7rem',
    color: 'var(--text-muted)',
    fontWeight: '600'
  },
  entityVal: {
    fontSize: '0.78rem',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  entityValMono: {
    fontSize: '0.78rem',
    fontFamily: 'var(--font-mono)',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  stageTimelineFlow: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem',
    position: 'relative',
    paddingLeft: '1.5rem',
    borderLeft: '2px solid var(--border-color)',
    marginLeft: '0.75rem'
  },
  stageTimelineItem: {
    position: 'relative',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  stageStepMarker: {
    position: 'absolute',
    left: '-2.05rem',
    top: '0',
    width: '18px',
    height: '18px',
    borderRadius: '50%',
    backgroundColor: 'var(--color-accent)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  stageStepContent: {
    padding: '0.75rem 1rem',
    backgroundColor: 'var(--bg-secondary)',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  statePanel: {
    minHeight: '200px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  }
};

export default AttackChainPage;
