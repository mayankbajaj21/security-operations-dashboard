import React from 'react';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Radar, 
  Server,
  Target,
  AlertOctagon,
  Flame,
  Shield,
  X
} from 'lucide-react';

const Sidebar = ({ isOpen, onClose, activeTab, onSelectTab }) => {
  const sections = [
    {
      title: null,
      items: [
        { id: 'overview', label: 'Overview', icon: LayoutDashboard }
      ]
    },
    {
      title: 'MONITORING',
      items: [
        { id: 'events', label: 'Security Events', icon: ShieldAlert },
        { id: 'threat-intel', label: 'Threat Intelligence', icon: Radar },
        { id: 'assets', label: 'Vulnerabilities', icon: Server }
      ]
    },
    {
      title: 'ANALYTICS',
      items: [
        { id: 'risk', label: 'Risk Prioritization', icon: Flame },
        { id: 'incidents', label: 'Incident Response', icon: AlertOctagon },
        { id: 'mitre', label: 'MITRE ATT&CK', icon: Target }
      ]
    }
  ];

  return (
    <aside 
      style={{
        ...styles.sidebar,
        transform: isOpen ? 'translateX(0)' : 'translateX(-100%)'
      }}
    >
      {/* Sidebar Header with Brand & Close Button */}
      <div style={styles.sidebarHeader}>
        <div style={styles.brandTitle}>
          <Shield size={18} color="var(--color-accent)" />
          <span style={styles.brandText}>SOC Navigation</span>
        </div>
        <button 
          onClick={onClose} 
          style={styles.closeBtn} 
          title="Close Sidebar" 
          aria-label="Close Sidebar"
        >
          <X size={16} color="var(--text-muted)" />
        </button>
      </div>

      <nav style={styles.nav}>
        {sections.map((section, idx) => (
          <div key={section.title || `section-${idx}`} style={styles.sectionGroup}>
            {section.title && (
              <div style={styles.sectionHeader}>
                <span style={styles.sectionTitle}>{section.title}</span>
              </div>
            )}

            <div style={styles.itemList}>
              {section.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;

                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      onSelectTab(item.id);
                    }}
                    style={{
                      ...styles.navButton,
                      ...(isActive ? styles.activeNavButton : {})
                    }}
                  >
                    <Icon 
                      size={16} 
                      color={isActive ? 'var(--color-accent)' : 'var(--text-muted)'} 
                    />
                    <span style={{
                      ...styles.navLabel,
                      ...(isActive ? styles.activeNavLabel : {})
                    }}>
                      {item.label}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
    </aside>
  );
};

const styles = {
  sidebar: {
    position: 'fixed',
    top: 0,
    left: 0,
    height: '100vh',
    width: '260px',
    maxWidth: '85vw',
    backgroundColor: 'var(--bg-secondary)',
    borderRight: '1px solid var(--border-color)',
    display: 'flex',
    flexDirection: 'column',
    padding: '0.85rem 0.75rem',
    zIndex: 999,
    boxShadow: '4px 0 24px rgba(0, 0, 0, 0.5)',
    transition: 'transform 280ms cubic-bezier(0.4, 0, 0.2, 1)',
    overflowY: 'auto'
  },
  sidebarHeader: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingBottom: '0.75rem',
    marginBottom: '0.5rem',
    borderBottom: '1px solid var(--border-color)'
  },
  brandTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  brandText: {
    fontSize: '0.9rem',
    fontWeight: '700',
    color: 'var(--text-primary)'
  },
  closeBtn: {
    backgroundColor: 'transparent',
    border: 'none',
    cursor: 'pointer',
    padding: '0.2rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '4px'
  },
  nav: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.1rem'
  },
  sectionGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  sectionHeader: {
    padding: '0 0.75rem 0.2rem 0.75rem'
  },
  sectionTitle: {
    fontSize: '0.66rem',
    fontWeight: '700',
    color: 'var(--text-muted)',
    letterSpacing: '0.08em',
    textTransform: 'uppercase'
  },
  itemList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.2rem'
  },
  navButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.65rem',
    width: '100%',
    padding: '0.5rem 0.75rem',
    backgroundColor: 'transparent',
    border: '1px solid transparent',
    borderRadius: '6px',
    color: 'var(--text-secondary)',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all 0.15s ease',
    outline: 'none'
  },
  activeNavButton: {
    backgroundColor: 'var(--bg-card)',
    border: '1px solid var(--border-subtle)',
    color: 'var(--text-primary)'
  },
  navLabel: {
    fontSize: '0.81rem',
    fontWeight: '500',
    color: 'var(--text-secondary)'
  },
  activeNavLabel: {
    fontWeight: '600',
    color: 'var(--text-primary)'
  }
};

export default Sidebar;
