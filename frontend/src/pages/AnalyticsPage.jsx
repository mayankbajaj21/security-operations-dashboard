import React, { useState, useEffect } from 'react';
import RiskPrioritizationPage from './RiskPrioritizationPage';
import IncidentResponsePage from './IncidentResponsePage';
import AttackChainPage from './AttackChainPage';
import SecurityIntelligencePage from './SecurityIntelligencePage';
import MitreCoveragePage from './MitreCoveragePage';
import AiThreatDetectionPage from './AiThreatDetectionPage';
import AssetRiskPage from './AssetRiskPage';
import { 
  Flame, 
  AlertOctagon, 
  GitCommit, 
  Radar, 
  Target, 
  Cpu, 
  Server 
} from 'lucide-react';

/**
 * Analytics Hub Page
 * Houses M3 Analytical and Security Intelligence Modules:
 * 1. Risk Prioritization & Overview (M3 Risk Engine & 5-tier distribution)
 * 2. Incident Response & Investigation (M3 Priority Incidents & Lifecycle State Machine)
 * 3. Attack Chain (M3 Correlated multi-stage kill chain progression)
 * 4. Security Intelligence (M3 IoC, MITRE, CVE, and Risk contribution)
 * 5. MITRE ATT&CK Coverage (M1/M2 coverage matrix)
 * 6. AI Threat Detection & Model Diagnostics (M2 Isolation Forest)
 * 7. Asset Risk Exposure (M1/M2 asset telemetry)
 */
const AnalyticsPage = ({ allEvents = null, initialSubTab = 'risk' }) => {
  const [activeSubTab, setActiveSubTab] = useState(initialSubTab);

  useEffect(() => {
    if (initialSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);

  const subTabs = [
    { id: 'risk', label: 'Risk Overview', icon: Flame },
    { id: 'incidents', label: 'Priority Incidents', icon: AlertOctagon },
    { id: 'attack-chain', label: 'Attack Chain', icon: GitCommit },
    { id: 'security-intel', label: 'Security Intelligence', icon: Radar },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Target },
    { id: 'ai-detection', label: 'AI Threat Detection', icon: Cpu },
    { id: 'assets', label: 'Asset Risk', icon: Server }
  ];

  return (
    <div style={styles.container}>
      {/* Sleek Sub-Navigation Tab Bar */}
      <div style={styles.tabBar}>
        {subTabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSubTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveSubTab(tab.id)}
              style={{
                ...styles.tabButton,
                backgroundColor: isActive ? 'var(--bg-card)' : 'transparent',
                borderColor: isActive ? 'var(--color-accent)' : 'transparent',
                color: isActive ? 'var(--color-accent)' : 'var(--text-secondary)'
              }}
              className={`analytics-subtab-btn ${isActive ? 'active' : ''}`}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* Sub-Tab Page Content */}
      <div style={styles.subContent}>
        {activeSubTab === 'risk' && <RiskPrioritizationPage />}
        {activeSubTab === 'incidents' && <IncidentResponsePage />}
        {activeSubTab === 'attack-chain' && <AttackChainPage />}
        {activeSubTab === 'security-intel' && <SecurityIntelligencePage />}
        {activeSubTab === 'mitre' && <MitreCoveragePage />}
        {activeSubTab === 'ai-detection' && <AiThreatDetectionPage />}
        {activeSubTab === 'assets' && <AssetRiskPage allEvents={allEvents} />}
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  tabBar: {
    display: 'flex',
    gap: '0.5rem',
    padding: '0.4rem',
    backgroundColor: 'var(--bg-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    overflowX: 'auto',
    alignItems: 'center'
  },
  tabButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem',
    padding: '0.5rem 0.85rem',
    borderRadius: '6px',
    border: '1px solid transparent',
    fontSize: '0.8rem',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'all 0.15s ease',
    whiteSpace: 'nowrap'
  },
  subContent: {
    display: 'flex',
    flexDirection: 'column'
  }
};

export default AnalyticsPage;
