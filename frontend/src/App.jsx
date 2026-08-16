import React, { useState, useEffect, useRef, useCallback } from 'react';
import Header from './components/Header';
import Sidebar from './components/Sidebar';
import MetricCard from './components/MetricCard';
import SeverityPieChart from './charts/SeverityPieChart';
import ThreatTrendChart from './charts/ThreatTrendChart';
import TopAttackTypesChart from './charts/TopAttackTypesChart';
import TopAffectedAssetsChart from './charts/TopAffectedAssetsChart';
import IncidentTable from './components/IncidentTable';
import ThreatTimeline from './components/ThreatTimeline';
import AttackHeatmap from './components/AttackHeatmap';
import AutoRefreshControl from './components/AutoRefreshControl';
import LoginPage from './pages/LoginPage';
import SecurityEventsPage from './pages/SecurityEventsPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import AssetRiskPage from './pages/AssetRiskPage';
import MitreCoveragePage from './pages/MitreCoveragePage';
import IncidentResponsePage from './pages/IncidentResponsePage';
import RiskPrioritizationPage from './pages/RiskPrioritizationPage';
import { getMetrics, getEventTrend, getEvents, clearApiCache } from './services/api';
import { Activity, AlertTriangle, ShieldAlert, Bug, ShieldCheck, AlertOctagon } from 'lucide-react';

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

  const [activeTab, setActiveTab] = useState('overview');
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [metrics, setMetrics] = useState(null);
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

      // Concurrently fetch overview KPI metrics and time-series trend data
      const [metricsRes, trendRes] = await Promise.all([
        getMetrics({ forceRefresh: isManualRefresh }),
        getEventTrend({ forceRefresh: isManualRefresh })
      ]);
      setMetrics(metricsRes);
      setTrendData(trendRes?.trend || []);

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
    if (!currentUser) return;

    // Initial load on mount or user login
    fetchDashboardData();

    if (!autoRefreshEnabled) return;

    const timerId = setInterval(() => {
      fetchDashboardData();
    }, 60000);

    return () => {
      clearInterval(timerId);
    };
  }, [currentUser, autoRefreshEnabled, fetchDashboardData]);

  // Render LoginPage immediately if no valid user session exists
  if (!currentUser) {
    return <LoginPage onLoginSuccess={handleLoginSuccess} />;
  }

  const getSectionTitle = () => {
    switch (activeTab) {
      case 'overview':
        return 'Security Operations Overview';
      case 'events':
        return 'Security Events Log';
      case 'risk':
        return 'Security Risk & Alert Prioritization';
      case 'mitre':
        return 'MITRE ATT&CK Framework Coverage';
      case 'incidents':
        return 'Incident & Response Intelligence';
      case 'threat-intel':
        return 'Threat Intelligence & Indicators';
      case 'assets':
        return 'Vulnerabilities & Asset Risk Coverage';
      default:
        return 'Security Operations Center';
    }
  };

  return (
    <div style={styles.appContainer}>
      <Header 
        currentUser={currentUser} 
        onLogout={handleLogout} 
        isSidebarOpen={isSidebarOpen}
        onToggleSidebar={() => setIsSidebarOpen((prev) => !prev)}
        theme={theme}
        onToggleTheme={handleToggleTheme}
      />
      
      <div style={styles.bodyLayout}>
        {/* Dark translucent backdrop when sidebar is open */}
        {isSidebarOpen && (
          <div 
            onClick={() => setIsSidebarOpen(false)}
            style={styles.backdrop}
          />
        )}

        <Sidebar 
          isOpen={isSidebarOpen} 
          onClose={() => setIsSidebarOpen(false)}
          activeTab={activeTab} 
          onSelectTab={(tabId) => {
            setActiveTab(tabId);
            setIsSidebarOpen(false);
          }} 
        />
        
        <main style={styles.mainContent}>
          <div style={styles.headerSection}>
            <div>
              <h2 className="section-title" style={{ fontSize: '1.25rem', margin: 0 }}>
                {getSectionTitle()}
              </h2>
              <p className="muted" style={{ fontSize: '0.8rem', marginTop: '0.15rem' }}>
                Real-time threat telemetry and security risk analytics monitoring
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
                  {/* KPI Cards 6-card Row */}
                  <div style={styles.kpiGrid}>
                    <MetricCard
                      title="Total Security Events"
                      value={metrics.overview?.total_events ?? 0}
                      subtitle="Monitored event logs"
                      icon={Activity}
                      variant="accent"
                    />
                    <MetricCard
                      title="Critical Events"
                      value={metrics.overview?.critical_events ?? 0}
                      subtitle="Immediate attention required"
                      icon={AlertTriangle}
                      variant="critical"
                    />
                    <MetricCard
                      title="High Severity Events"
                      value={metrics.overview?.high_events ?? 0}
                      subtitle="High-risk threat telemetry"
                      icon={ShieldAlert}
                      variant="high"
                    />
                    <MetricCard
                      title="Vulnerability Events"
                      value={metrics.security_indicators?.events_with_vulnerability_id ?? 0}
                      subtitle="Events linked to vuln IDs"
                      icon={ShieldCheck}
                      variant="warning"
                    />
                    <MetricCard
                      title="Malware Detected"
                      value={metrics.security_indicators?.malware_detected ?? 0}
                      subtitle="Malware flag occurrences"
                      icon={Bug}
                      variant="critical"
                    />
                    <MetricCard
                      title="Active Incidents"
                      value={metrics.security_indicators?.incident_matches ?? 0}
                      subtitle="Incident-linked events"
                      icon={AlertOctagon}
                      variant="high"
                    />
                  </div>

                  {/* Charts Grid Row: Severity Donut + Threat Trend */}
                  <div style={styles.chartsGrid}>
                    <SeverityPieChart overviewData={metrics.overview} />
                    <ThreatTrendChart trendData={trendData} />
                  </div>

                  {/* Dynamic Top Attack Types Bar Chart Row */}
                  <div>
                    <TopAttackTypesChart allEvents={allOverviewEvents} />
                  </div>

                  {/* Dynamic Top Affected Assets Bar Chart Row */}
                  <div>
                    <TopAffectedAssetsChart allEvents={allOverviewEvents} />
                  </div>

                  {/* Recent & Active Incidents Compact Overview Widget */}
                  <div>
                    <IncidentTable
                      allEvents={allOverviewEvents}
                      onNavigateToIncidents={() => setActiveTab('incidents')}
                    />
                  </div>

                  {/* Chronological Threat Telemetry Timeline */}
                  <div>
                    <ThreatTimeline allEvents={allOverviewEvents} />
                  </div>

                  {/* SOC Attack Activity Heatmap (7 Days x 24 Hours) */}
                  <div>
                    <AttackHeatmap allEvents={allOverviewEvents} />
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'events' && <SecurityEventsPage />}

          {activeTab === 'risk' && <RiskPrioritizationPage allEvents={allOverviewEvents} />}

          {activeTab === 'mitre' && <MitreCoveragePage />}

          {activeTab === 'incidents' && <IncidentResponsePage allEvents={allOverviewEvents} />}

          {activeTab === 'threat-intel' && <ThreatIntelPage />}

          {activeTab === 'assets' && <AssetRiskPage />}
        </main>
      </div>
    </div>
  );
}

const styles = {
  appContainer: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    width: '100vw',
    overflow: 'hidden',
    backgroundColor: 'var(--bg-primary)'
  },
  bodyLayout: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden',
    position: 'relative'
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
  mainContent: {
    flex: 1,
    padding: '1.25rem 1.5rem',
    overflowY: 'auto',
    backgroundColor: 'var(--bg-primary)'
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
