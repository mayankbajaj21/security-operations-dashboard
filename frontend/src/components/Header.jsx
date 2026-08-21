import React from 'react';
import { Menu, Activity, User, LogOut, Sun, Moon } from 'lucide-react';
import InfosysLogo from './InfosysLogo';

/**
 * Top Bar / Header Component for SOC Dashboard
 * Contains:
 * - Brand & Title: "Security Operations Center" (no hamburger on desktop)
 * - System Status: ONLINE
 * - Theme Toggle: Light ↔ Dark
 * - Authenticated Admin / User Badge (clickable)
 * - Sign Out / Logout
 */
const Header = ({ 
  currentUser, 
  onLogout, 
  isSidebarOpen, 
  onToggleSidebar, 
  onNavigateLanding,
  theme,
  onToggleTheme,
  onNavigateAdmin,
  activeTab
}) => {
  const displayName = typeof currentUser === 'object' && currentUser !== null
    ? (currentUser.name || currentUser.displayName || currentUser.email)
    : (currentUser || 'SOC Analyst');

  const isDark = theme === 'dark';
  const isAdminActive = activeTab === 'admin';

  return (
    <header style={styles.header}>
      {/* LEFT SECTION: BRAND & TITLE (NO HAMBURGER ON DESKTOP) */}
      <div style={styles.leftSection}>
        {/* Mobile-only hamburger button */}
        <button
          onClick={onToggleSidebar}
          className="soc-header-hamburger"
          style={styles.hamburgerBtn}
          title={isSidebarOpen ? "Close Navigation Menu" : "Open Navigation Menu"}
          aria-label="Toggle Navigation Sidebar"
        >
          <Menu size={18} color="var(--text-primary)" />
        </button>

        <div 
          style={{ ...styles.logoContainer, cursor: onNavigateLanding ? 'pointer' : 'default' }}
          onClick={onNavigateLanding}
          title={onNavigateLanding ? "Return to Landing Page" : undefined}
        >
          <InfosysLogo height={24} />
          <span style={styles.divider}>|</span>
          <h1 style={styles.logoText}>Security Operations Center</h1>
        </div>
      </div>

      {/* RIGHT SECTION: SYSTEM STATUS, THEME TOGGLE, ADMIN PROFILE, LOGOUT */}
      <div style={styles.rightSection}>
        {/* System Status Indicator */}
        <div style={styles.healthStatus}>
          <Activity size={15} color="var(--color-success)" className="spin-icon-subtle" />
          <span style={styles.statusText}>
            System Status: <strong style={{ color: 'var(--color-success)' }}>ONLINE</strong>
          </span>
        </div>

        <span style={styles.divider}>|</span>

        {/* Theme Toggle Button */}
        {onToggleTheme && (
          <button
            onClick={onToggleTheme}
            className="soc-button"
            style={styles.themeToggleBtn}
            title={`Switch to ${isDark ? 'Light' : 'Dark'} Mode`}
            aria-label="Toggle Theme"
          >
            {isDark ? <Sun size={15} color="var(--color-warning)" /> : <Moon size={15} color="var(--color-accent)" />}
            <span style={{ fontSize: '0.78rem' }}>{isDark ? 'Light' : 'Dark'}</span>
          </button>
        )}

        {currentUser && (
          <>
            <span style={styles.divider}>|</span>

            {/* Clickable Admin / User Profile Badge */}
            <div 
              style={{
                ...styles.userBadge,
                borderColor: isAdminActive ? 'var(--color-accent)' : 'var(--border-color)',
                backgroundColor: isAdminActive ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-primary)',
                cursor: onNavigateAdmin ? 'pointer' : 'default'
              }}
              onClick={onNavigateAdmin}
              title="View Admin Profile"
            >
              <User size={14} color="var(--color-accent)" />
              <span>{displayName}</span>
            </div>

            {/* Logout Button */}
            <button
              onClick={onLogout}
              className="soc-button"
              style={styles.logoutBtn}
              title="Sign Out"
              aria-label="Logout"
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
    padding: '0 1.25rem',
    backgroundColor: 'var(--bg-secondary)',
    borderBottom: '1px solid var(--border-color)',
    height: '56px',
    minHeight: '56px',
    boxSizing: 'border-box',
    width: '100%',
    flexShrink: 0
  },
  leftSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.85rem'
  },
  hamburgerBtn: {
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    borderRadius: '4px',
    padding: '0.35rem 0.45rem',
    cursor: 'pointer',
    alignItems: 'center',
    justifyContent: 'center',
    transition: 'all 0.15s ease'
  },
  logoContainer: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
  logoText: {
    fontSize: '0.95rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    letterSpacing: '-0.01em',
    margin: 0
  },
  divider: {
    color: 'var(--border-subtle)',
    fontSize: '0.85rem'
  },
  rightSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem',
    flexWrap: 'nowrap'
  },
  healthStatus: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.45rem',
    fontSize: '0.78rem',
    color: 'var(--text-secondary)'
  },
  statusText: {
    fontSize: '0.78rem',
    whiteSpace: 'nowrap'
  },
  themeToggleBtn: {
    padding: '0.3rem 0.55rem',
    fontSize: '0.75rem',
    display: 'flex',
    alignItems: 'center',
    gap: '0.35rem'
  },
  userBadge: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    fontSize: '0.78rem',
    fontWeight: '600',
    color: 'var(--text-primary)',
    padding: '0.3rem 0.6rem',
    borderRadius: '4px',
    border: '1px solid var(--border-color)',
    transition: 'all 0.15s ease',
    whiteSpace: 'nowrap'
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
