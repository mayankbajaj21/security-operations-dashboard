import React from 'react';

/**
 * Reusable Security & Operational Status Badge Component
 * @param {string} type - "severity" | "status"
 * @param {string} value - Value string (e.g., "Critical", "High", "Success", "Blocked")
 */
const Badge = ({ type = 'severity', value }) => {
  if (!value) return null;

  const normalizedVal = String(value).toLowerCase().trim();
  
  let colorClass = 'badge';
  
  if (type === 'severity') {
    switch (normalizedVal) {
      case 'critical':
      case 'critical threat':
        colorClass += ' severity-critical';
        break;
      case 'high':
      case 'high threat':
        colorClass += ' severity-high';
        break;
      case 'moderate':
        colorClass += ' severity-moderate';
        break;
      case 'medium':
      case 'medium threat':
        colorClass += ' severity-medium';
        break;
      case 'low':
      case 'low threat':
        colorClass += ' severity-low';
        break;
      default:
        colorClass += ' muted';
    }
  } else if (type === 'status') {
    switch (normalizedVal) {
      case 'open':
        colorClass += ' status-open';
        break;
      case 'investigating':
      case 'in progress':
        colorClass += ' status-investigating';
        break;
      case 'resolved':
      case 'closed':
        colorClass += ' status-resolved';
        break;
      case 'false positive':
      case 'false_positive':
        colorClass += ' status-false-positive';
        break;
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

