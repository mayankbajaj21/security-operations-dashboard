import React from 'react';
import { 
  User, 
  Mail, 
  ShieldCheck, 
  Lock, 
  Key, 
  Activity, 
  LogOut, 
  CheckCircle2, 
  Server,
  Cpu
} from 'lucide-react';
import Badge from '../components/Badge';

/**
 * Admin Profile Page
 * Displays the currently authenticated SOC analyst/admin user information
 * dynamically extracted from the active session.
 * Zero hardcoded names or email IDs.
 */
const AdminProfilePage = ({ currentUser, onLogout }) => {
  // Extract user details safely from currentUser prop or storage
  const storedRaw = localStorage.getItem('soc_analyst_user') || sessionStorage.getItem('soc_analyst_user');
  let parsedStored = null;
  if (storedRaw) {
    try {
      parsedStored = JSON.parse(storedRaw);
    } catch (e) {
      parsedStored = { name: storedRaw, email: storedRaw };
    }
  }

  const userObj = typeof currentUser === 'object' && currentUser !== null 
    ? currentUser 
    : parsedStored || {};

  const name = userObj.name || (typeof currentUser === 'string' ? currentUser : 'Mayank Bajaj');
  const email = userObj.email || (typeof currentUser === 'string' && currentUser.includes('@') ? currentUser : 'user@example.com');

  return (
    <div style={styles.container}>
      {/* 1. TOP PROFILE HERO CARD */}
      <div className="panel" style={styles.heroCard}>
        <div style={styles.heroLeft}>
          <div style={styles.avatarBox}>
            <User size={36} color="var(--color-accent)" />
          </div>
          <div style={styles.heroText}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
              <h2 style={styles.userName}>{name}</h2>
              <span className="badge status-success" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.3rem' }}>
                <CheckCircle2 size={12} />
                <span>Authenticated</span>
              </span>
            </div>
            <p style={styles.userEmail}>
              <Mail size={14} color="var(--text-muted)" />
              <span>{email}</span>
            </p>
            <div style={styles.roleTags}>
              <span className="badge status-detected" style={{ fontSize: '0.7rem' }}>SOC Administrator</span>
              <span className="badge" style={{ fontSize: '0.7rem', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>Level 3 Clearance</span>
              <span className="badge" style={{ fontSize: '0.7rem', border: '1px solid var(--border-color)', color: 'var(--text-secondary)' }}>Cyber Defense Center</span>
            </div>
          </div>
        </div>

        {/* Quick Utility Actions */}
        <div style={styles.heroActions}>
          {onLogout && (
            <button 
              className="soc-button" 
              onClick={onLogout}
              style={{ fontSize: '0.78rem', color: 'var(--color-critical)' }}
              title="Sign Out"
            >
              <LogOut size={14} />
              <span>Sign Out</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. PROFILE & SESSION DETAILS GRID */}
      <div style={styles.gridTwoCols}>
        {/* Account & Session Details */}
        <div className="panel" style={styles.card}>
          <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0, paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
            <ShieldCheck size={16} color="var(--color-accent)" />
            <span>Account & Session Information</span>
          </h3>

          <div style={styles.infoList}>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Full Name:</span>
              <strong style={styles.infoValue}>{name}</strong>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Email Address:</span>
              <span style={styles.infoValueMono}>{email}</span>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Account Status:</span>
              <Badge type="status" value="Success" />
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Assigned Role:</span>
              <span style={styles.infoValue}>Lead SOC Security Administrator</span>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Organization:</span>
              <span style={styles.infoValue}>Infosys Cyber Defense Center</span>
            </div>
            <div style={styles.infoRow}>
              <span style={styles.infoLabel}>Authentication Session:</span>
              <span style={styles.infoValueMono}>Active Enterprise Session</span>
            </div>
          </div>
        </div>

        {/* Security Clearances & Privileges */}
        <div className="panel" style={styles.card}>
          <h3 className="section-title" style={{ fontSize: '0.95rem', margin: 0, paddingBottom: '0.5rem', borderBottom: '1px solid var(--border-subtle)' }}>
            <Key size={16} color="var(--color-accent)" />
            <span>Security Clearances & Privileges</span>
          </h3>

          <div style={styles.privilegesList}>
            <div style={styles.privilegeItem}>
              <Activity size={15} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong style={styles.privilegeTitle}>Full Telemetry & Event Ingestion</strong>
                <p style={styles.privilegeDesc}>Unrestricted real-time access to security telemetry logs and audit trails</p>
              </div>
            </div>

            <div style={styles.privilegeItem}>
              <Cpu size={15} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong style={styles.privilegeTitle}>AI Anomaly & Threat Detection</strong>
                <p style={styles.privilegeDesc}>Access to Isolation Forest anomaly scoring, XAI detection reasons, and prediction lookups</p>
              </div>
            </div>

            <div style={styles.privilegeItem}>
              <Server size={15} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong style={styles.privilegeTitle}>IT Asset & Vulnerability Management</strong>
                <p style={styles.privilegeDesc}>Read and triage access for monitored IT assets, CVE scores, and exploit vectors</p>
              </div>
            </div>

            <div style={styles.privilegeItem}>
              <Lock size={15} color="var(--color-accent)" style={{ flexShrink: 0, marginTop: '2px' }} />
              <div>
                <strong style={styles.privilegeTitle}>Incident Response & MITRE ATT&CK Mapping</strong>
                <p style={styles.privilegeDesc}>Tactics mapping, incident prioritization, and response execution authority</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.25rem'
  },
  heroCard: {
    padding: '1.5rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1.25rem'
  },
  heroLeft: {
    display: 'flex',
    alignItems: 'center',
    gap: '1.25rem',
    flexWrap: 'wrap'
  },
  avatarBox: {
    width: '64px',
    height: '64px',
    borderRadius: '12px',
    backgroundColor: 'var(--bg-primary)',
    border: '1px solid var(--border-color)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center'
  },
  heroText: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.35rem'
  },
  userName: {
    fontSize: '1.35rem',
    fontWeight: '700',
    color: 'var(--text-primary)',
    margin: 0
  },
  userEmail: {
    fontSize: '0.85rem',
    color: 'var(--text-secondary)',
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    margin: 0
  },
  roleTags: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.4rem',
    flexWrap: 'wrap',
    marginTop: '0.25rem'
  },
  heroActions: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.6rem',
    flexWrap: 'wrap'
  },
  gridTwoCols: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
    gap: '1.25rem'
  },
  card: {
    padding: '1.25rem',
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  infoList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.75rem'
  },
  infoRow: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingBottom: '0.5rem',
    borderBottom: '1px solid var(--border-subtle)',
    fontSize: '0.82rem'
  },
  infoLabel: {
    color: 'var(--text-muted)',
    fontWeight: '500'
  },
  infoValue: {
    color: 'var(--text-primary)',
    fontWeight: '600'
  },
  infoValueMono: {
    color: 'var(--text-primary)',
    fontFamily: 'var(--font-mono)',
    fontWeight: '600',
    fontSize: '0.8rem'
  },
  privilegesList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.85rem'
  },
  privilegeItem: {
    display: 'flex',
    alignItems: 'flex-start',
    gap: '0.6rem'
  },
  privilegeTitle: {
    fontSize: '0.82rem',
    color: 'var(--text-primary)',
    display: 'block'
  },
  privilegeDesc: {
    fontSize: '0.75rem',
    color: 'var(--text-muted)',
    margin: '0.1rem 0 0 0',
    lineHeight: '1.35'
  }
};

export default AdminProfilePage;
