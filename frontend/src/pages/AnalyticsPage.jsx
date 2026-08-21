import React, { useState, useEffect } from 'react';
import RiskPrioritizationPage from './RiskPrioritizationPage';
import IncidentResponsePage from './IncidentResponsePage';
import MitreCoveragePage from './MitreCoveragePage';
import AiThreatDetectionPage from './AiThreatDetectionPage';
import AssetRiskPage from './AssetRiskPage';
import { Flame, AlertOctagon, Target, Cpu, Server } from 'lucide-react';

/**
 * Analytics Hub Page
 * Houses existing analytical modules with sub-tab switching:
 * - Risk Prioritization
 * - Incident Response
 * - MITRE ATT&CK Coverage
 * - AI Threat Detection & Model Diagnostics
 * - Asset Risk Exposure
 * (Old Threat Intelligence is removed as it is now primary navigation #3)
 */
const AnalyticsPage = ({ allEvents = null, initialSubTab = 'risk' }) => {
  const [activeSubTab, setActiveSubTab] = useState(initialSubTab);

  useEffect(() => {
    if (initialSubTab) {
      setActiveSubTab(initialSubTab);
    }
  }, [initialSubTab]);

  const subTabs = [
    { id: 'risk', label: 'Risk Prioritization', icon: Flame },
    { id: 'incidents', label: 'Incident Response', icon: AlertOctagon },
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
        {activeSubTab === 'risk' && <RiskPrioritizationPage allEvents={allEvents} />}
        {activeSubTab === 'incidents' && <IncidentResponsePage allEvents={allEvents} />}
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
