// NIST SP 800-92 Aligned Report Formatter for n8n
// Paste this code into an n8n Code node
// Takes synthesizer output + MITRE + NIST + CIS Controls + CAR coverage data
// and produces standardized investigation report
//
// v2.0.0 — Added CIS Controls v8.1.2 and MITRE CAR analytic coverage sections

// Gather data from upstream nodes
const synthesizerOutput = $input.first().json;

let techniques      = [];
let nistMappings    = [];
let cisMappings     = [];
let cisQuickWins    = [];
let coverageGaps    = [];
let lowCoverage     = [];
let analystFindings = '';
let investigationType = 'general';
let originalQuery   = '';

try {
  const mitreData     = $('MITRE Lookup').first().json;
  techniques          = mitreData.techniques        || [];
  analystFindings     = mitreData.analyst_findings  || '';
  investigationType   = mitreData.investigation_type || 'general';
} catch (e) {
  techniques = synthesizerOutput.techniques || [];
}

try {
  const carData  = $('CAR Coverage Lookup').first().json;
  techniques     = carData.techniques    || techniques;  // enriched with coverage
  coverageGaps   = carData.coverage_gaps || [];
  lowCoverage    = carData.low_coverage  || [];
  analystFindings = carData.analyst_findings || analystFindings;
} catch (e) {
  // CAR node may not be in pipeline yet — degrade gracefully
}

try {
  const nistData = $('NIST CSF Mapper').first().json;
  nistMappings   = nistData.nist_csf_mappings || [];
} catch (e) {
  nistMappings = synthesizerOutput.nist_csf_mappings || [];
}

try {
  const cisData  = $('CIS Controls Mapper').first().json;
  cisMappings    = cisData.cis_mappings    || [];
  cisQuickWins   = cisData.cis_quick_wins  || [];
} catch (e) {
  // CIS node may not be in pipeline yet — degrade gracefully
}

try {
  originalQuery = $('Execute Workflow Trigger').first().json.query ||
                  $('Webhook Trigger').first().json.body.query || '';
} catch (e) {
  originalQuery = synthesizerOutput.query || 'N/A';
}

// Extract synthesizer response text
const synthResponse = synthesizerOutput.response || JSON.stringify(synthesizerOutput);

// ── Helper Functions ─────────────────────────────────────────────────────────

function extractRiskLevel(text) {
  const n = text.toLowerCase();
  if (n.includes('critical')) return 'CRITICAL';
  if (n.includes('high risk') || n.includes('high severity')) return 'HIGH';
  if (n.includes('medium risk') || n.includes('medium severity') || n.includes('moderate')) return 'MEDIUM';
  if (n.includes('low risk') || n.includes('low severity')) return 'LOW';
  return 'MEDIUM';
}

function extractConfidence(text) {
  const n = text.toLowerCase();
  if (n.includes('high confidence')) return 'HIGH';
  if (n.includes('low confidence')) return 'LOW';
  return 'MEDIUM';
}

function formatMitreMappings(techs) {
  if (!techs || techs.length === 0) return '| No specific MITRE ATT&CK techniques identified.';
  return techs.map(t => {
    const covLine = t.coverage
      ? `|   Coverage: CAR=${t.coverage.car} Sigma=${t.coverage.sigma} ES_SIEM=${t.coverage.es_siem} Splunk=${t.coverage.splunk} Total=${t.coverage.total}`
      : '';
    return [
      `| ${t.id} | ${t.name} | ${(t.tactics || []).join(', ')} |`,
      `|   Description: ${t.description || ''}`,
      `|   Detection: ${t.detection || ''}`,
      covLine,
    ].filter(Boolean).join('\n');
  }).join('\n');
}

function formatNistMappings(mappings) {
  if (!mappings || mappings.length === 0) return '| No specific NIST CSF 2.0 mappings identified.';
  return mappings.map(func => {
    const cats = (func.categories || []).map(cat => {
      const subs = (cat.relevant_subcategories || [])
        .slice(0, 3)
        .map(s => `|     - ${s.id}: ${s.description}`)
        .join('\n');
      return `|   ${cat.category_id} - ${cat.category_name}\n|     ${cat.description}${subs ? '\n' + subs : ''}`;
    }).join('\n');
    return `| ${func.function_id} (${func.function_name}):\n${cats}`;
  }).join('\n\n');
}

function formatDetectionGaps(techs, gaps, low) {
  const lines = ['| Based on identified techniques, the following detection capabilities should be verified:'];

  for (const t of techs.slice(0, 5)) {
    lines.push(`| - ${t.id} (${t.name}): ${t.detection || 'See MITRE ATT&CK for detection guidance'}`);
  }

  if (gaps && gaps.length > 0) {
    lines.push('|');
    lines.push(`| ⚠️  ZERO-COVERAGE TECHNIQUES (${gaps.length}) — no community detection rules exist:`);
    for (const g of gaps) {
      lines.push(`|   ⚠️  ${g.id} (${g.name}): CAR=0 Sigma=0 ES SIEM=0 Splunk=0 — custom detection rules required`);
    }
  }

  if (low && low.length > 0) {
    lines.push('|');
    lines.push(`| ⚠️  LOW-COVERAGE TECHNIQUES (${low.length}) — very few community detections (total < 5):`);
    for (const l of low) {
      lines.push(`|   ${l.id} (${l.name}): Total=${l.coverage.total} (CAR=${l.coverage.car} Sigma=${l.coverage.sigma})`);
    }
  }

  return lines.join('\n');
}

function formatAnalyticCoverage(techs) {
  if (!techs || !techs.some(t => t.coverage)) {
    return '| CAR analytic coverage data not available for this pipeline run.';
  }
  const lines = ['| Analytic coverage per identified technique (CAR / Sigma / ES SIEM / Splunk):'];
  for (const t of techs) {
    if (!t.coverage) continue;
    const total   = t.coverage.total;
    const flag    = total === 0 ? ' ⚠️  NO DETECTIONS' : total < 5 ? ' ⚠️  LOW COVERAGE' : '';
    lines.push(`| ${t.id} (${t.name}): CAR=${t.coverage.car} Sigma=${t.coverage.sigma} ES SIEM=${t.coverage.es_siem} Splunk=${t.coverage.splunk} — Total: ${total}${flag}`);
  }
  return lines.join('\n');
}

function formatCisControls(mappings, quickWins) {
  const lines = [];

  if (quickWins && quickWins.length > 0) {
    lines.push('| Quick Wins — Implementation Group 1 (applicable to all organizations):');
    for (const sg of quickWins) {
      const igs = (sg.implementation_groups || ['IG1']).join('/');
      lines.push(`|   [${sg.id}] ${sg.title} [${igs}] — CIS Control ${sg.control_id}: ${sg.control_title}`);
    }
  }

  if (mappings && mappings.length > 0) {
    lines.push('|');
    lines.push('| Recommended controls by CIS Control number:');
    for (const ctrl of mappings) {
      lines.push(`| CIS Control ${ctrl.control_id} — ${ctrl.control_title}:`);
      for (const sg of (ctrl.safeguards || [])) {
        const igs = (sg.implementation_groups || []).join('/');
        const fn  = sg.security_function ? ` [${sg.security_function}]` : '';
        lines.push(`|   [${sg.id}] ${sg.title} [${igs}]${fn}`);
        if (sg.description) {
          lines.push(`|         ${sg.description.slice(0, 120)}...`);
        }
      }
    }
  }

  if (lines.length === 0) {
    return '| CIS Controls mapping not available for this pipeline run.';
  }

  return lines.join('\n');
}

// ── Report Assembly ───────────────────────────────────────────────────────────

const typeDisplayNames = {
  'auth_anomaly':    'Authentication Anomaly Investigation',
  'beaconing':       'Beaconing / C2 Communication Investigation',
  'exfiltration':    'Data Exfiltration Investigation',
  'lateral_movement':'Lateral Movement Investigation',
  'general':         'General Security Investigation',
};

const riskLevel  = extractRiskLevel(synthResponse);
const confidence = extractConfidence(synthResponse);
const timestamp  = new Date().toISOString();

const report = `
================================================================================
NIST SP 800-92 ALIGNED INVESTIGATION REPORT
Generated: ${timestamp}
Frameworks: MITRE ATT&CK | NIST CSF 2.0 | CIS Controls v8.1.2 | MITRE CAR Coverage
================================================================================

1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
| Query: ${originalQuery}
| Investigation Type: ${typeDisplayNames[investigationType] || investigationType}
| Risk Level: ${riskLevel}
| Confidence: ${confidence}
| MITRE Techniques Identified: ${techniques.length}
| NIST CSF Functions Mapped: ${nistMappings.length}
| CIS Controls Recommended: ${cisMappings.length} controls, ${cisQuickWins.length} quick wins
| Detection Coverage Gaps: ${coverageGaps.length} techniques with zero detections
|
| Summary:
${synthResponse.split('\n').slice(0, 5).map(l => '| ' + l).join('\n')}

2. INCIDENT CLASSIFICATION (NIST CSF 2.0)
--------------------------------------------------------------------------------
${formatNistMappings(nistMappings)}

3. TECHNICAL FINDINGS
--------------------------------------------------------------------------------
${synthResponse.split('\n').map(l => '| ' + l).join('\n')}

4. MITRE ATT&CK MAPPING
--------------------------------------------------------------------------------
${formatMitreMappings(techniques)}

5. DETECTION GAPS & RECOMMENDATIONS
--------------------------------------------------------------------------------
${formatDetectionGaps(techniques, coverageGaps, lowCoverage)}

5.5 ANALYTIC COVERAGE (MITRE CAR / Sigma / ES SIEM / Splunk)
--------------------------------------------------------------------------------
${formatAnalyticCoverage(techniques)}

5.6 CIS CONTROLS v8.1.2 RECOMMENDATIONS
--------------------------------------------------------------------------------
${formatCisControls(cisMappings, cisQuickWins)}

6. RECOMMENDED ACTIONS
--------------------------------------------------------------------------------
| Priority actions based on risk level (${riskLevel}):
| [See detailed recommendations in Technical Findings section above]
| [See CIS Controls quick wins in Section 5.6 for implementation guidance]

7. CONFIDENCE ASSESSMENT
--------------------------------------------------------------------------------
| Overall Confidence: ${confidence}
| Techniques Matched: ${techniques.length} (deterministic lookup against MITRE ATT&CK database)
| NIST Functions Covered: ${nistMappings.map(m => m.function_id).join(', ') || 'None'}
| CIS Controls Matched: ${cisMappings.map(c => 'CIS-' + c.control_id).join(', ') || 'None'}
| Coverage Gaps Identified: ${coverageGaps.length} techniques with no community detections
| Data Gaps: [See analyst findings for specific data gap notes]

8. EVIDENCE CHAIN
--------------------------------------------------------------------------------
| Investigation Flow:
| 1. Query received and classified as: ${investigationType}
| 2. Routed to specialized analyst agents
| 3. Findings matched against ${techniques.length > 0 ? techniques.length : 'N/A'} MITRE ATT&CK techniques
| 4. Detection coverage enriched from MITRE CAR analytic coverage dataset
| 5. Mapped to ${nistMappings.length} NIST CSF 2.0 function areas
| 6. Mapped to ${cisMappings.length} CIS Controls v8.1.2 control groups
| 7. Purple team validation and synthesis completed
| 8. Report generated per NIST SP 800-92 guidelines

================================================================================
END OF REPORT | CASA CyberAnalysis System | ${timestamp}
================================================================================
`.trim();

return [{
  json: {
    status: 'complete',
    investigation_report: report,
    risk_level: riskLevel,
    confidence: confidence,
    mitre_techniques:    techniques.map(t => ({ id: t.id, name: t.name, tactics: t.tactics, coverage: t.coverage || null })),
    nist_csf_functions:  nistMappings.map(m => m.function_id),
    cis_controls:        cisMappings.map(c => ({ control_id: c.control_id, control_title: c.control_title })),
    coverage_gaps:       coverageGaps.map(g => g.id),
    query:               originalQuery,
    investigation_type:  investigationType,
    timestamp:           timestamp,
  }
}];
