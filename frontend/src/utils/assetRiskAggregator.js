/**
 * Shared Asset Risk Aggregation Utility
 * 
 * Authoritative source: Security Events Dataset (GET /events)
 * Every unique asset_name in the security events is treated as a monitored inventory asset.
 * Dynamically computes event metrics, risk scores, normalized exposure levels, and vulnerability breakdowns.
 */
export const aggregateAssetRisk = (events) => {
  if (!events || !Array.isArray(events) || events.length === 0) {
    return [];
  }

  const assetMap = {};

  events.forEach((evt) => {
    const rawAsset = evt.asset_name;
    if (!rawAsset || typeof rawAsset !== 'string' || !rawAsset.trim() || rawAsset.trim().toLowerCase() === 'null') {
      return;
    }

    const assetName = rawAsset.trim();
    const severityStr = evt.event_severity?.toLowerCase() || '';
    const isCritical = severityStr === 'critical';
    const isHigh = severityStr === 'high';
    const isMedium = severityStr === 'medium';
    const isLow = severityStr === 'low';
    const isMalware = Boolean(evt.malware_detected);
    const isThreatIntel = Boolean(evt.threat_intel_match);
    const hasIncident = Boolean(evt.incident_id && String(evt.incident_id).trim() !== '');

    const vulnId = evt.vulnerability_id && String(evt.vulnerability_id).trim() !== '' && String(evt.vulnerability_id).toLowerCase() !== 'none'
      ? String(evt.vulnerability_id).trim()
      : null;

    const cvssScore = Number(evt.cvss_score) || 0;
    const osName = evt.os || 'Linux';
    const deptName = evt.department || 'IT';

    if (!assetMap[assetName]) {
      assetMap[assetName] = {
        asset_name: assetName,
        totalEvents: 0,
        criticalEvents: 0,
        highEvents: 0,
        mediumEvents: 0,
        lowEvents: 0,
        malwareEvents: 0,
        vulnerabilityEvents: 0,
        maxCvss: 0,
        threatIntelMatches: 0,
        incidentEvents: 0,
        osCounts: {},
        deptCounts: {},
        vulnerabilitiesMap: {}
      };
    }

    const item = assetMap[assetName];
    item.totalEvents += 1;
    if (isCritical) item.criticalEvents += 1;
    if (isHigh) item.highEvents += 1;
    if (isMedium) item.mediumEvents += 1;
    if (isLow) item.lowEvents += 1;
    if (isMalware) item.malwareEvents += 1;
    if (isThreatIntel) item.threatIntelMatches += 1;
    if (hasIncident) item.incidentEvents += 1;

    if (cvssScore > item.maxCvss) {
      item.maxCvss = cvssScore;
    }

    if (vulnId) {
      item.vulnerabilityEvents += 1;
      if (!item.vulnerabilitiesMap[vulnId]) {
        item.vulnerabilitiesMap[vulnId] = {
          cve_id: vulnId,
          count: 0,
          maxCvss: cvssScore,
          severity: cvssScore >= 9.0 ? 'Critical' : cvssScore >= 7.0 ? 'High' : cvssScore >= 4.0 ? 'Medium' : 'Low'
        };
      }
      item.vulnerabilitiesMap[vulnId].count += 1;
      if (cvssScore > item.vulnerabilitiesMap[vulnId].maxCvss) {
        item.vulnerabilitiesMap[vulnId].maxCvss = cvssScore;
      }
    }

    item.osCounts[osName] = (item.osCounts[osName] || 0) + 1;
    item.deptCounts[deptName] = (item.deptCounts[deptName] || 0) + 1;
  });

  const list = Object.values(assetMap);
  if (list.length === 0) {
    return [];
  }

  // 1. Calculate raw exposure score
  list.forEach((item) => {
    item.rawScore =
      item.criticalEvents * 5 +
      item.highEvents * 3 +
      item.malwareEvents * 4 +
      item.vulnerabilityEvents * 2 +
      item.threatIntelMatches * 3 +
      item.incidentEvents * 4 +
      item.totalEvents * 0.1;
  });

  // 2. Relative normalization (0-100)
  const maxRawScore = Math.max(...list.map((a) => a.rawScore), 0);

  list.forEach((item) => {
    item.normalizedScore = maxRawScore > 0 ? Math.round((item.rawScore / maxRawScore) * 100) : 0;

    if (item.normalizedScore >= 80) {
      item.risk_level = 'Critical';
    } else if (item.normalizedScore >= 60) {
      item.risk_level = 'High';
    } else if (item.normalizedScore >= 40) {
      item.risk_level = 'Medium';
    } else {
      item.risk_level = 'Low';
    }

    item.primaryOs = Object.keys(item.osCounts).sort((a, b) => item.osCounts[b] - item.osCounts[a])[0] || 'Linux';
    item.primaryDept = Object.keys(item.deptCounts).sort((a, b) => item.deptCounts[b] - item.deptCounts[a])[0] || 'IT';

    // Convert vulnerabilities map to array sorted by severity & count
    item.vulnerabilities = Object.values(item.vulnerabilitiesMap).sort(
      (a, b) => b.maxCvss - a.maxCvss || b.count - a.count
    );
  });

  // 3. Sort assets by normalizedScore desc, criticalEvents desc, totalEvents desc
  list.sort((a, b) => {
    if (b.normalizedScore !== a.normalizedScore) return b.normalizedScore - a.normalizedScore;
    if (b.criticalEvents !== a.criticalEvents) return b.criticalEvents - a.criticalEvents;
    return b.totalEvents - a.totalEvents;
  });

  return list;
};
