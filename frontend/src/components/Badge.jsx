import React from 'react';

/**
 * Reusable Security & Operational Status Badge Component
 * @param {string} type - "severity" | "status"
 * @param {string} value - Value string (e.g., "Critical", "High", "Success", "Blocked")
 */
const Badge = ({ type = 'severity', value }) => {
  if (!value) return null;

  const normalizedVal = String(value).toLowerCase();
  
  let colorClass = 'badge';
  
  if (type === 'severity') {
    switch (normalizedVal) {
      case 'critical':
        colorClass += ' severity-critical';
        break;
      case 'high':
        colorClass += ' severity-high';
        break;
      case 'medium':
        colorClass += ' severity-medium';
        break;
      case 'low':
        colorClass += ' severity-low';
        break;
      default:
        colorClass += ' muted';
    }
  } else if (type === 'status') {
    switch (normalizedVal) {
      case 'success':
        colorClass += ' status-success';
        break;
      case 'failed':
        colorClass += ' status-failed';
        break;
      case 'blocked':
        colorClass += ' status-blocked';
        break;
      case 'detected':
        colorClass += ' status-detected';
        break;
      default:
        colorClass += ' muted';
    }
  }

  return (
    <span className={colorClass}>
      {value}
    </span>
  );
};

export default Badge;
