// CASA Comprehensive Report Merger — n8n Code Node
// Place this after the Merge node that collects all sub-workflow results.
// Combines multiple sub-workflow reports into one unified report.
//
// Input: Multiple items from different sub-workflow executions,
//        each containing an investigation_report field.
// Output: Single item with a merged comprehensive report.

const items = $input.all();
const timestamp = new Date().toISOString().replace('T', ' ').split('.')[0] + ' UTC';

// Collect all reports and metadata
const reports = [];
const allTechniques = [];
const allNistFunctions = [];
const allCisControls = [];
const allCoverageGaps = [];
const investigationTypes = [];
let originalQuery = '';
let highestRisk = 'LOW';

const riskOrder = { 'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3 };

for (const item of items) {
  const data = item.json;

  if (data.investigation_report) {
    reports.push({
      type: data.investigation_type || 'unknown',
      report: data.investigation_report,
      risk_level: data.risk_level || 'MEDIUM',
      confidence: data.confidence || 'MEDIUM'
    });

    investigationTypes.push(data.investigation_type || 'unknown');

    // Track highest risk
    if ((riskOrder[data.risk_level] || 0) > (riskOrder[highestRisk] || 0)) {
      highestRisk = data.risk_level;
    }
  }

  // Collect MITRE techniques (deduplicate by ID)
  if (data.mitre_techniques) {
    for (const t of data.mitre_techniques) {
      if (!allTechniques.find(e => e.id === t.id)) {
        allTechniques.push(t);
      }
    }
  }

  // Collect NIST functions (deduplicate)
  if (data.nist_csf_functions) {
    for (const f of data.nist_csf_functions) {
      if (!allNistFunctions.includes(f)) {
        allNistFunctions.push(f);
      }
    }
  }

  // Collect CIS controls (deduplicate by ID)
  if (data.cis_controls) {
    for (const c of data.cis_controls) {
      if (!allCisControls.find(e => e.control_id === c.control_id)) {
        allCisControls.push(c);
      }
    }
  }

  // Collect coverage gaps (deduplicate)
  if (data.coverage_gaps) {
    for (const g of data.coverage_gaps) {
      if (!allCoverageGaps.includes(g)) {
        allCoverageGaps.push(g);
      }
    }
  }

  if (data.query && !originalQuery) {
    originalQuery = data.query;
  }
}

// If only one report came back, just pass it through
if (reports.length <= 1 && reports.length > 0) {
  return items;
}

// If no reports, return an error
if (reports.length === 0) {
  return [{
    json: {
      status: 'error',
      investigation_report: `CASA Comprehensive Analysis returned no results.\n\nNo sub-workflows produced output. Check n8n Executions for details.`,
      query: originalQuery,
      timestamp: timestamp
    }
  }];
}

// Build the comprehensive merged report
const report = `
================================================================================
CASA COMPREHENSIVE INVESTIGATION REPORT
================================================================================
Generated: ${timestamp}
Analysis Mode: Comprehensive (${reports.length} investigation paths analyzed)
Investigation Types: ${investigationTypes.join(', ')}
Overall Risk Level: ${highestRisk}
MITRE Techniques (combined): ${allTechniques.length}
NIST CSF Functions: ${allNistFunctions.join(', ') || 'N/A'}
CIS Controls: ${allCisControls.length}
Detection Gaps: ${allCoverageGaps.length}
================================================================================

0. COMPREHENSIVE ANALYSIS SUMMARY
--------------------------------------------------------------------------------
| This report combines findings from ${reports.length} parallel investigation paths.
| Each path analyzed the provided data through its specialized lens:
|
${reports.map((r, i) => `| ${i + 1}. ${r.type.toUpperCase()} analysis — Risk: ${r.risk_level} | Confidence: ${r.confidence}`).join('\n')}
|
| Highest risk finding: ${highestRisk}
| Combined MITRE ATT&CK techniques: ${allTechniques.length}
| Combined CIS Controls recommendations: ${allCisControls.length}
|
| When multiple investigation paths flag findings, it increases confidence
| that the observed activity is genuinely malicious rather than benign.
${reports.length > 1 ? `| Cross-correlation: ${investigationTypes.join(' + ')} perspectives provide multi-dimensional analysis.` : ''}

${reports.map((r, i) => {
  return `
${'='.repeat(80)}
INVESTIGATION PATH ${i + 1}: ${r.type.toUpperCase()}
${'='.repeat(80)}

${r.report}
`;
}).join('\n')}

================================================================================
END OF COMPREHENSIVE REPORT | CASA CyberAnalysis System | ${timestamp}
| Analysis paths: ${investigationTypes.join(', ')}
| Combined techniques: ${allTechniques.length} | Combined controls: ${allCisControls.length}
================================================================================
`.trim();

return [{
  json: {
    status: 'complete',
    investigation_report: report,
    risk_level: highestRisk,
    investigation_type: 'comprehensive',
    investigation_types_analyzed: investigationTypes,
    mitre_techniques: allTechniques,
    nist_csf_functions: allNistFunctions,
    cis_controls: allCisControls,
    coverage_gaps: allCoverageGaps,
    query: originalQuery,
    reports_merged: reports.length,
    timestamp: timestamp
  }
}];
