import React from 'react';
import { Shield, Activity, User, LogOut, Menu, X, Sun, Moon } from 'lucide-react';

const Header = ({ 
  currentUser, 
  onLogout, 
  isSidebarOpen, 
  onToggleSidebar,
  theme = 'dark',
  onToggleTheme
}) => {
  const displayName = typeof currentUser === 'object'
    ? (currentUser.name || currentUser.email)
    : (currentUser || 'SOC Analyst');

  const isDark = theme === 'dark';

  return (
    <header style={styles.header}>
      <div style={styles.leftSection}>
        <button
          onClick={onToggleSidebar}
          className="soc-button"
          style={styles.toggleBtn}
          title={isSidebarOpen ? 'Close Menu' : 'Open Navigation Menu'}
          aria-label={isSidebarOpen ? 'Close Menu' : 'Open Navigation Menu'}
        >
          {isSidebarOpen ? <X size={18} /> : <Menu size={18} />}
        </button>

        <div style={styles.logoContainer}>
          <Shield size={24} color="var(--color-accent)" />
          <span style={styles.logoText}>SOC Operations</span>
        </div>
        <span style={styles.divider}>|</span>
        <span style={styles.subtitle}>Security Operations Center</span>
      </div>

      <div style={styles.rightSection}>
        {/* Compact Theme Pill Toggle */}
        <div style={styles.themePillGroup} role="group" aria-label="Theme selector">
          <button
            type="button"
            onClick={() => onToggleTheme && onToggleTheme('light')}
            style={{
              ...styles.themePillBtn,
              backgroundColor: !isDark ? 'var(--color-accent)' : 'transparent',
              color: !isDark ? '#ffffff' : 'var(--text-secondary)',
              fontWeight: !isDark ? '700' : '500'
            }}
            title="Switch to light mode"
            aria-label="Switch to light mode"
          >
            <Sun size={12} />
            <span>Light</span>
          </button>
          <button
            type="button"
            onClick={() => onToggleTheme && onToggleTheme('dark')}
            style={{
              ...styles.themePillBtn,
              backgroundColor: isDark ? 'var(--bg-card-hover)' : 'transparent',
              color: isDark ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderLeft: '1px solid var(--border-color)',
              fontWeight: isDark ? '700' : '500'
            }}
            title="Switch to dark mode"
            aria-label="Switch to dark mode"
          >
            <Moon size={12} />
            <span>Dark</span>
          </button>
        </div>

        <div style={styles.healthStatus}>
          <Activity size={16} color="var(--color-low)" />
          <span style={styles.statusText}>System Status: <strong style={{ color: 'var(--color-low)' }}>ONLINE</strong></span>
        </div>

        {currentUser && (
          <>
            <span style={styles.divider}>|</span>
            <div style={styles.userBadge}>
              <User size={14} color="var(--color-accent)" />
              <span>{displayName}</span>
            </div>
            <button 
              onClick={onLogout} 
              className="soc-button" 
              style={styles.logoutBtn}
              title="Sign Out"
            >
              <LogOut size={14} />
              <span>Logout</span>
            </button>
          </>
        )}
      </div>
    </header>
  );
};

const styles = {
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '0.75rem 1.5rem',
    backgroundColor: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border-color)',
    height: '60px',
    boxSizing: 'border-box',
    zIndex: 100
  },
  leftSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem'
  },
  toggleBtn: {
    padding: '0.35rem 0.55rem',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    color: 'var(--text-primary)',
    borderRadius: '4px',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  logoContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem'
  },
  logoText: {
    fontSize: '1.1rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    letterSpacing: '0.02em'
  },
  divider: {
    color: 'var(--border-subtle)',
    fontSize: '0.9rem'
  },
  subtitle: {
    fontSize: '0.85rem',
    color: 'var(--text-muted)',
    fontWeight: '500'
  },
  rightSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem'
  },
  themePillGroup: {
    display: 'flex',
    alignItems: 'center',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    padding: '1px',
    overflow: 'hidden'
  },
  themePillBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    padding: '0.2rem 0.45rem',
    fontSize: '0.72rem',
    border: 'none',
    borderRadius: '3px',
    cursor: 'pointer',
    transition: 'all 0.15s ease'
  },
  healthStatus: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    fontSize: '0.8rem',
    color: 'var(--text-secondary)'
  },
  statusText: {
    fontSize: '0.8rem'
  },
  userBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.78rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    backgroundColor: 'var(--bg-primary)',
    padding: '0.3rem 0.6rem',
    borderRadius: '4px',
    border: '1px solid var(--border-color)'
  },
  logoutBtn: {
    fontSize: '0.75rem',
    padding: '0.3rem 0.6rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem'
  }
};

export default Header;
