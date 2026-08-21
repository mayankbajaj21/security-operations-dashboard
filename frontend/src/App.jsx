import React, { useState, useEffect, useRef, useCallback } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MetricCard from './components/MetricCard';
import SeverityPieChart from './charts/SeverityPieChart';
import TopAttackTypesChart from './charts/TopAttackTypesChart';
import ThreatTimeline from './components/ThreatTimeline';
import AssetRiskOverviewCard from './components/AssetRiskOverviewCard';
import AutoRefreshControl from './components/AutoRefreshControl';
import LoginPage from './pages/LoginPage';
import LandingPage from './pages/LandingPage';
import SecurityEventsPage from './pages/SecurityEventsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import EventInvestigationPage from './pages/EventInvestigationPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import AnalyticsPage from './pages/AnalyticsPage';
import AdminProfilePage from './pages/AdminProfilePage';
import { getMetrics, getEventTrend, getEvents, getThreatSummary, getAssets, clearApiCache } from './services/api';
import { 
  Activity, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  AlertOctagon, 
  Cpu, 
  Radar, 
  LayoutDashboard, 
  Search, 
  BarChart2, 
  User 
} from 'lucide-react';

/**
 * Safely parse stored analyst user session from localStorage or sessionStorage
 */
const getInitialUser = () => {
  try {
    let raw = localStorage.getItem('soc_analyst_user');
    if (!raw) {
      raw = sessionStorage.getItem('soc_analyst_user');
    }

    if (raw && typeof raw === 'string' && raw.trim() !== '' && raw !== 'null' && raw !== 'undefined') {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') return parsed;
      } catch (e) {
        return { name: raw.trim(), email: raw.trim() };
      }
    }
  } catch (err) {
    console.error('Failed to read auth session:', err);
  }
  return null;
};

const getInitialTheme = () => {
  try {
    const saved = localStorage.getItem('soc_theme');
    if (saved === 'light' || saved === 'dark') return saved;
  } catch (err) {
    console.error('Failed to read theme preference:', err);
  }
  return 'dark';
};

function App() {
  // Client-side demo login state initialized from storage
  const [currentUser, setCurrentUser] = useState(getInitialUser);

  // Global SOC Theme (default 'dark')
  const [theme, setTheme] = useState(getInitialTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem('soc_theme', theme);
    } catch (err) {
      console.error('Failed to save theme preference:', err);
    }
  }, [theme]);

  const handleToggleTheme = (newTheme) => {
    if (newTheme === 'light' || newTheme === 'dark') {
      setTheme(newTheme);
    } else {
      setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
    }
  };

  // Navigation view mode ('landing', 'login', 'dashboard')
  const [currentView, setCurrentView] = useState('landing');

  // Primary 6 navigation tabs: overview, events, threat-intel, investigation, vulnerabilities, analytics
  const [activeTab, setActiveTab] = useState('overview');
  const [analyticsSubTab, setAnalyticsSubTab] = useState('risk');
  const [investigationEventId, setInvestigationEventId] = useState('');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [overviewAssets, setOverviewAssets] = useState(null);
  const [threatSummary, setThreatSummary] = useState(null);
  const [trendData, setTrendData] = useState([]);
  const [allOverviewEvents, setAllOverviewEvents] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Auto-Refresh state & concurrency control
  const [lastUpdated, setLastUpdated] = useState(null);
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState(null);
  const isRefreshingRef = useRef(false);

  // View Navigation Handlers
  const handleEnterSOC = () => {
    if (currentUser) {
      setCurrentView('dashboard');
    } else {
      setCurrentView('login');
    }
  };

  const handleNavigateLogin = () => {
    setCurrentView('login');
  };

  const handleNavigateLanding = () => {
    setCurrentView('landing');
  };

  // Handle Login Success
  const handleLoginSuccess = (userData, rememberMe = true) => {
    if (userData) {
      const payload = typeof userData === 'string' ? { name: userData, email: userData } : userData;
      const jsonStr = JSON.stringify(payload);

      try {
        if (rememberMe) {
          localStorage.setItem('soc_analyst_user', jsonStr);
          sessionStorage.removeItem('soc_analyst_user');
        } else {
          sessionStorage.setItem('soc_analyst_user', jsonStr);
          localStorage.removeItem('soc_analyst_user');
        }
      } catch (err) {
        console.error('Failed to save session storage:', err);
      }

      setCurrentUser(payload);
      setCurrentView('dashboard');
    }
  };

  // Handle Logout
  const handleLogout = () => {
    clearApiCache();
    try {
      localStorage.removeItem('soc_analyst_user');
      sessionStorage.removeItem('soc_analyst_user');
    } catch (err) {
      console.error('Failed to clear session storage:', err);
    }
    setCurrentUser(null);
    setActiveTab('overview');
    setCurrentView('landing');
  };

  // Centralized telemetry data fetching with batching & concurrency lock
  const fetchDashboardData = useCallback(async (isManualRefresh = false) => {
    if (isRefreshingRef.current) return;
    isRefreshingRef.current = true;
    setIsRefreshing(true);
    setRefreshError(null);

    const startTime = performance.now();

    try {
      if (isManualRefresh) {
        clearApiCache();
      }

      // Concurrently fetch overview KPI metrics, M2 threat summary, trend data, and asset exposure
      const [metricsRes, trendRes, threatSummaryRes, assetsRes] = await Promise.all([
        getMetrics({ forceRefresh: isManualRefresh }),
        getEventTrend({ forceRefresh: isManualRefresh }),
        getThreatSummary({ forceRefresh: isManualRefresh }).catch(() => null),
        getAssets({ forceRefresh: isManualRefresh }).catch(() => null)
      ]);
      setMetrics(metricsRes);
      setTrendData(trendRes?.trend || []);
      if (threatSummaryRes) {
        setThreatSummary(threatSummaryRes);
      }
      if (assetsRes) {
        setOverviewAssets(assetsRes);
      }

      // Controlled batch fetching for complete event dataset (4 concurrent requests max)
      const firstPage = await getEvents({ page: 1, limit: 100 }, { forceRefresh: isManualRefresh });
      const totalPages = firstPage?.pagination?.total_pages || 1;
      let records = [...(firstPage?.data || [])];

      if (totalPages > 1) {
        const batchSize = 4;
        for (let p = 2; p <= totalPages; p += batchSize) {
          const batchPromises = [];
          for (let b = p; b < Math.min(p + batchSize, totalPages + 1); b++) {
            batchPromises.push(getEvents({ page: b, limit: 100 }, { forceRefresh: isManualRefresh }));
          }
          const batchResults = await Promise.all(batchPromises);
          batchResults.forEach((res) => {
            if (res?.data) records = records.concat(res.data);
          });
        }
      }

      setAllOverviewEvents(records);
      setLastUpdated(new Date());
      setError(null);

      if (import.meta.env.DEV) {
        const duration = (performance.now() - startTime).toFixed(1);
        console.log(`[PERF] Telemetry load completed in ${duration}ms (${records.length} records processed)`);
      }
    } catch (err) {
      console.error('Failed to refresh dashboard telemetry:', err);
      setRefreshError('Refresh failed — showing last known telemetry');
    } finally {
      isRefreshingRef.current = false;
      setIsRefreshing(false);
      setLoading(false);
    }
  }, []);

  // 60-second controlled auto-refresh interval lifecycle
  useEffect(() => {
    if (!currentUser || currentView !== 'dashboard') return;

    // Initial load on mount or user login
    fetchDashboardData();

    if (!autoRefreshEnabled) return;

    const timerId = setInterval(() => {
      fetchDashboardData();
    }, 60000);

    return () => {
      clearInterval(timerId);
    };
  }, [currentUser, currentView, autoRefreshEnabled, fetchDashboardData]);

  // Render LandingPage when currentView is 'landing'
  if (currentView === 'landing') {
    return (
      <LandingPage 
        onEnterSOC={handleEnterSOC}
        onNavigateLogin={handleNavigateLogin}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        currentUser={currentUser}
        onLoginSuccess={handleLoginSuccess}
        initialMode="landing"
      />
    );
  }

  // Render unified LandingPage in 'signin' mode when currentView is 'login' or no user session exists
  if (currentView === 'login' || !currentUser) {
    return (
      <LandingPage 
        onEnterSOC={handleEnterSOC}
        onNavigateLogin={handleNavigateLanding}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        currentUser={currentUser}
        onLoginSuccess={handleLoginSuccess}
        initialMode="signin"
      />
    );
  }

  const getSectionHeader = () => {
    switch (activeTab) {
      case 'overview':
        return {
          title: 'Overview',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: LayoutDashboard
        };
      case 'events':
        return {
          title: 'Security Events',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: Activity
        };
      case 'threat-intel':
        return {
          title: 'Threat Intelligence',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: Radar
        };
      case 'investigation':
        return {
          title: 'Event Investigation',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: Search
        };
      case 'vulnerabilities':
        return {
          title: 'Vulnerabilities',
          subtitle: 'Real-time vulnerability exposure and asset risk monitoring',
          icon: ShieldAlert
        };
      case 'analytics':
        return {
          title: 'Analytics',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: BarChart2
        };
      case 'admin':
        return {
          title: 'Admin',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: User
        };
      default:
        return {
          title: 'Security Operations Center',
          subtitle: 'Real-time threat telemetry and security risk analytics monitoring',
          icon: LayoutDashboard
        };
    }
  };

  const sectionInfo = getSectionHeader();
  const SectionIcon = sectionInfo.icon;

  return (
    <div style={styles.appContainer}>
      <div style={styles.appShell}>
        {/* Dark translucent backdrop when sidebar is open on mobile */}
        {isSidebarOpen && (
          <div 
            onClick={() => setIsSidebarOpen(false)}
            style={styles.backdrop}
          />
        )}

        {/* 1. LEFT: SIDEBAR */}
        <Sidebar 
          isOpen={isSidebarOpen} 
          onClose={() => setIsSidebarOpen(false)}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
          activeTab={activeTab} 
          onSelectTab={(tabId) => {
            setActiveTab(tabId);
            setIsSidebarOpen(false);
          }}
        />

        {/* 2. RIGHT: TOP BAR (HEADER) + MAIN CONTENT AREA */}
        <div style={styles.contentColumn}>
          <Header 
            currentUser={currentUser} 
            onLogout={handleLogout} 
            isSidebarOpen={isSidebarOpen}
            onToggleSidebar={() => setIsSidebarOpen((prev) => !prev)}
            theme={theme}
            onToggleTheme={handleToggleTheme}
            onNavigateLanding={handleNavigateLanding}
            onNavigateAdmin={() => setActiveTab('admin')}
            activeTab={activeTab}
          />
          
          <main className="soc-main-content-layout">
            <div style={styles.headerSection}>
              <div>
                <h2 className="section-title" style={{ fontSize: '1.85rem', fontWeight: '700', margin: 0, display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
                  {SectionIcon && <SectionIcon size={28} color="var(--color-accent)" style={{ flexShrink: 0 }} />}
                  <span>{sectionInfo.title}</span>
                </h2>
                <p className="muted" style={{ fontSize: '0.85rem', marginTop: '0.25rem' }}>
                  {sectionInfo.subtitle}
                </p>
              </div>

              {activeTab === 'overview' && (
                <AutoRefreshControl
                  isRefreshing={isRefreshing}
                  lastUpdated={lastUpdated}
                  autoRefreshEnabled={autoRefreshEnabled}
                  onRefresh={() => fetchDashboardData(true)}
                  onToggle={() => setAutoRefreshEnabled((prev) => !prev)}
                  refreshError={refreshError}
                />
              )}
            </div>

          {/* 1. OVERVIEW PAGE */}
          {activeTab === 'overview' && (
            <div>
              {loading && (
                <div className="panel" style={styles.statePanel}>
                  <p className="muted">Loading dashboard metrics and trend data...</p>
                </div>
              )}

              {error && (
                <div className="panel" style={{ ...styles.statePanel, borderColor: 'var(--color-critical)' }}>
                  <p style={{ color: 'var(--color-critical)', fontWeight: '600' }}>{error}</p>
                </div>
              )}

              {!loading && !error && metrics && (
                <div style={styles.dashboardSection}>
                  {/* KPI Cards: EXACTLY 5 Required Cards */}
                  <div style={styles.kpiGrid}>
                    <MetricCard
                      title="Total Events"
                      value={metrics.overview?.total_events ?? 0}
                      subtitle="Monitored event logs"
                      icon={Activity}
                      variant="accent"
                    />
                    <MetricCard
                      title="Critical Threats"
                      value={metrics.overview?.critical_events ?? 0}
                      subtitle="Immediate attention required"
                      icon={AlertTriangle}
                      variant="critical"
                    />
                    <MetricCard
                      title="High Severity Alerts"
                      value={metrics.overview?.high_events ?? 0}
                      subtitle="High-risk threat telemetry"
                      icon={ShieldAlert}
                      variant="high"
                    />
                    <MetricCard
                      title="Vulnerabilities"
                      value={metrics.security_indicators?.events_with_vulnerability_id ?? 0}
                      subtitle="Events linked to vuln IDs"
                      icon={ShieldCheck}
                      variant="warning"
                    />
                    <MetricCard
                      title="Active Incidents"
                      value={metrics.security_indicators?.incident_matches ?? 0}
                      subtitle="Incident-linked events"
                      icon={AlertOctagon}
                      variant="high"
                    />
                  </div>

                  {/* Milestone 2 AI Threat Detection Overview Banner */}
                  {threatSummary && (
                    <div className="panel" style={{ padding: '0.85rem 1.25rem', backgroundColor: 'var(--bg-card)', border: '1px solid var(--border-color)', borderRadius: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Cpu size={18} color="var(--color-accent)" />
                          <div>
                            <span style={{ fontSize: '0.85rem', fontWeight: '700', color: 'var(--text-primary)' }}>
                              AI THREAT DETECTION OVERVIEW
                            </span>
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block' }}>
                              Isolation Forest ML & Threat Classification (Step 8 APIs)
                            </span>
                          </div>
                        </div>

                        <div style={{ display: 'flex', gap: '1.25rem', flexWrap: 'wrap' }}>
                          <div>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block' }}>TOTAL EVENTS</span>
                            <span style={{ fontSize: '0.95rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                              {threatSummary.total_events?.toLocaleString()}
                            </span>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block' }}>ANOMALIES DETECTED</span>
                            <span style={{ fontSize: '0.95rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-critical)' }}>
                              {threatSummary.anomalies_detected?.toLocaleString()}
                            </span>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block' }}>NORMAL EVENTS</span>
                            <span style={{ fontSize: '0.95rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-accent)' }}>
                              {threatSummary.normal_events?.toLocaleString()}
                            </span>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block' }}>HIGH / CRITICAL THREATS</span>
                            <span style={{ fontSize: '0.95rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-high)' }}>
                              {(threatSummary.threat_levels?.['High Threat'] || 0) + (threatSummary.threat_levels?.['Critical Threat'] || 0)}
                            </span>
                          </div>
                          <div>
                            <span style={{ fontSize: '0.68rem', fontWeight: '700', color: 'var(--text-muted)', display: 'block' }}>AVG CONFIDENCE SCORE</span>
                            <span style={{ fontSize: '0.95rem', fontWeight: '800', fontFamily: 'var(--font-mono)', color: 'var(--color-warning)' }}>
                              {threatSummary.average_confidence_score?.toFixed(1)}%
                            </span>
                          </div>
                        </div>

                        <button 
                          className="soc-button" 
                          onClick={() => {
                            setInvestigationEventId('EVT00034');
                            setActiveTab('investigation');
                          }}
                          style={{ fontSize: '0.75rem', padding: '0.3rem 0.6rem' }}
                        >
                          Investigate Events →
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Charts Grid: Severity Donut + Attack Types */}
                  <div style={styles.chartsGrid}>
                    <SeverityPieChart overviewData={metrics.overview} />
                    <TopAttackTypesChart allEvents={allOverviewEvents} />
                  </div>

                  {/* Asset Risk & Exposure Compact Overview Component */}
                  <div>
                    <AssetRiskOverviewCard
                      allEvents={allOverviewEvents}
                      onNavigateToAssetRisk={() => {
                        setAnalyticsSubTab('assets');
                        setActiveTab('analytics');
                      }}
                    />
                  </div>

                  {/* Chronological Threat Telemetry Timeline (KEPT ON OVERVIEW) */}
                  <div>
                    <ThreatTimeline allEvents={allOverviewEvents} />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* 2. SECURITY EVENTS PAGE */}
          {activeTab === 'events' && <SecurityEventsPage />}

          {/* 3. THREAT INTELLIGENCE PAGE */}
          {activeTab === 'threat-intel' && (
            <ThreatIntelPage 
              allEvents={allOverviewEvents} 
              trendData={trendData} 
              onInvestigateEvent={(eventId) => {
                setInvestigationEventId(eventId);
                setActiveTab('investigation');
              }}
            />
          )}

          {/* 4. EVENT INVESTIGATION PAGE (NEW DEDICATED PAGE) */}
          {activeTab === 'investigation' && (
            <EventInvestigationPage 
              initialEventId={investigationEventId}
            />
          )}

          {/* 5. VULNERABILITIES PAGE (NEW DEDICATED PAGE) */}
          {activeTab === 'vulnerabilities' && <VulnerabilitiesPage />}

          {/* 6. ANALYTICS HUB */}
          {activeTab === 'analytics' && (
            <AnalyticsPage 
              allEvents={allOverviewEvents} 
              initialSubTab={analyticsSubTab}
            />
          )}

          {/* 7. ADMIN PROFILE PAGE */}
          {activeTab === 'admin' && (
            <AdminProfilePage 
              currentUser={currentUser} 
              onLogout={handleLogout}
            />
          )}
        </main>
      </div>
    </div>
  </div>
  );
}

const styles = {
  appContainer: {
    height: '100vh',
    width: '100vw',
    overflow: 'hidden',
    backgroundColor: 'var(--bg-primary)'
  },
  appShell: {
    display: 'flex',
    height: '100vh',
    width: '100vw',
    overflow: 'hidden',
    position: 'relative'
  },
  contentColumn: {
    display: 'flex',
    flexDirection: 'column',
    flex: 1,
    minWidth: 0,
    height: '100vh',
    overflow: 'hidden'
  },
  backdrop: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0, 0, 0, 0.65)',
    backdropFilter: 'blur(2px)',
    zIndex: 998,
    transition: 'opacity 0.25s ease'
  },
  headerSection: {
    marginBottom: '1.25rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexWrap: 'wrap',
    gap: '1rem'
  },
  dashboardSection: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1.5rem'
  },
  kpiGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))',
    gap: '1.25rem'
  },
  chartsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
    gap: '1.25rem'
  },
  statePanel: {
    minHeight: '160px',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    textAlign: 'center'
  }
};

export default App;
