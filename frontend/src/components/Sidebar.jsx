import React, { useState } from 'react';
import {
  LayoutDashboard,
  Activity,
  Radar,
  Search,
  ShieldAlert,
  BarChart2,
  ChevronLeft,
  ChevronRight,
  User,
  X
} from 'lucide-react';

/**
 * Clean SOC Navigation Sidebar Component
 * - Top Header: "NAVIGATION" text on the left + Compact Collapse Arrow (< / >) on the right
 * - Navigation: Overview, Security Events, Threat Intel, Event Investigation, Vulnerabilities, Analytics
 * - Bottom: Admin Profile Item
 */
const Sidebar = ({
  isOpen,
  onClose,
  isCollapsed,
  onToggleCollapse,
  activeTab,
  onSelectTab
}) => {
  const [hoveredTab, setHoveredTab] = useState(null);

  const navItems = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'events', label: 'Security Events', icon: Activity },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Radar },
    { id: 'investigation', label: 'Event Investigation', icon: Search },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
    { id: 'analytics', label: 'Analytics', icon: BarChart2 }
  ];

  return (
    <aside className={`soc-sidebar-root ${isCollapsed ? 'collapsed' : 'expanded'} ${isOpen ? 'mobile-open' : ''}`}>
      {/* 1. TOP SIDEBAR HEADER: "NAVIGATION" + COLLAPSE ARROW */}
      <div className="soc-sidebar-toggle-row">
        {!isCollapsed && (
          <span className="soc-sidebar-header-title">NAVIGATION</span>
        )}

        <button
          onClick={onToggleCollapse}
          className="soc-sidebar-toggle-btn"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <ChevronRight size={18} /> : <ChevronLeft size={18} />}
        </button>

        {/* Mobile Close Button (visible only on small screens) */}
        <button
          onClick={onClose}
          className="soc-sidebar-mobile-close"
          title="Close Navigation"
          aria-label="Close Navigation"
        >
          <X size={18} />
        </button>
      </div>

      {/* 2. NAVIGATION LINKS */}
      <nav className="soc-sidebar-nav">
        <div className="soc-nav-group">
          <div className="soc-nav-items-list">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;

              return (
                <div
                  key={item.id}
                  className="soc-nav-item-wrapper"
                  onMouseEnter={() => setHoveredTab(item.id)}
                  onMouseLeave={() => setHoveredTab(null)}
                >
                  <button
                    onClick={() => {
                      onSelectTab(item.id);
                      if (onClose) onClose();
                    }}
                    className={`soc-nav-btn ${isActive ? 'active' : ''}`}
                    aria-label={item.label}
                  >
                    <span className="soc-nav-icon-box">
                      <Icon size={20} />
                    </span>

                    {!isCollapsed && <span className="soc-nav-label">{item.label}</span>}
                    {isActive && <span className="soc-active-indicator" />}
                  </button>

                  {/* Collapsed Mode Tooltip */}
                  {isCollapsed && hoveredTab === item.id && (
                    <div className="soc-sidebar-tooltip" role="tooltip">
                      {item.label}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </nav>

      {/* 3. BOTTOM UTILITY FOOTER — ADMIN ITEM */}
      <div className="soc-sidebar-footer">
        <div
          className="soc-nav-item-wrapper"
          onMouseEnter={() => setHoveredTab('admin')}
          onMouseLeave={() => setHoveredTab(null)}
        >
          <button
            onClick={() => {
              onSelectTab('admin');
              if (onClose) onClose();
            }}
            className={`soc-nav-btn ${activeTab === 'admin' ? 'active' : ''}`}
            aria-label="Admin"
          >
            <span className="soc-nav-icon-box">
              <User size={20} />
            </span>
            {!isCollapsed && <span className="soc-nav-label">Admin</span>}
            {activeTab === 'admin' && <span className="soc-active-indicator" />}
          </button>

          {/* Collapsed Mode Tooltip */}
          {isCollapsed && hoveredTab === 'admin' && (
            <div className="soc-sidebar-tooltip" role="tooltip">
              Admin
            </div>
          )}
        </div>
      </div>
    </aside>
  );
};

export default Sidebar;
