import React from 'react';
import CriticalThreatPanel from './CriticalThreatPanel';

/**
 * Backward-compatible wrapper aliasing IncidentTable to the authoritative
 * Milestone 4 Critical Threat Panel component.
 */
const IncidentTable = (props) => {
  return (
    <CriticalThreatPanel
      incidents={props.incidents}
      onInvestigateIncident={props.onSelectIncident || props.onInvestigateIncident}
      onViewAllIncidents={props.onNavigateToIncidents || props.onViewAllIncidents}
      {...props}
    />
  );
};

export default IncidentTable;
