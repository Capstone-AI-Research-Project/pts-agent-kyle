// CIS Controls v8.1.2 Mapper Node for n8n
// Paste this code into an n8n Code node
// Maps analyst findings and MITRE technique data to CIS Controls v8.1.2 safeguards
// Follows the same pattern as nist-csf-mapper.js
//
// Position: Insert AFTER "NIST CSF Mapper" node, BEFORE "Synthesizer" node

const fs = require('fs');

// Read the CIS Controls v8.1.2 framework data
const cisData = JSON.parse(
  fs.readFileSync('/home/node/assets/cis-controls-v8.1.2.json', 'utf8')
);

// Get data from upstream (NIST CSF Mapper passes through findings + techniques)
const inputData = $input.first().json;
const findings      = inputData.analyst_findings  || JSON.stringify(inputData);
const techniques    = inputData.techniques        || [];
const nistMappings  = inputData.nist_csf_mappings || [];
const coverageGaps  = inputData.coverage_gaps     || [];
const lowCoverage   = inputData.low_coverage      || [];

// Normalize findings text for keyword matching
const normalizedFindings = findings.toLowerCase()
  .replace(/[^a-z0-9\s\-\.]/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();

// MITRE tactic → CIS security function correlation
// Used to boost safeguards relevant to the observed attack tactics
const tacticToCisFunction = {
  'Initial Access':        ['Protect'],
  'Execution':             ['Protect', 'Detect'],
  'Persistence':           ['Protect', 'Detect'],
  'Privilege Escalation':  ['Protect', 'Identify'],
  'Defense Evasion':       ['Detect', 'Protect'],
  'Credential Access':     ['Protect', 'Identify'],
  'Discovery':             ['Identify', 'Detect'],
  'Lateral Movement':      ['Protect', 'Detect'],
  'Collection':            ['Protect', 'Detect'],
  'Command and Control':   ['Detect', 'Respond'],
  'Exfiltration':          ['Detect', 'Respond', 'Protect'],
  'Impact':                ['Respond', 'Recover'],
};

// Collect all tactics present in matched techniques
const observedTactics = new Set();
for (const tech of techniques) {
  for (const tactic of (tech.tactics || [])) {
    observedTactics.add(tactic);
  }
}

// Score each safeguard against findings and technique data
const safeguardScores = [];

for (const control of cisData.controls) {
  for (const safeguard of control.safeguards) {
    let score = 0;

    // Keyword matching against analyst findings
    for (const kw of (safeguard.keywords || [])) {
      if (normalizedFindings.includes(kw.toLowerCase())) {
        score += 1;
      }
    }

    // Title-level matching (higher weight)
    if (normalizedFindings.includes(safeguard.title.toLowerCase())) {
      score += 3;
    }

    // Boost if safeguard security function correlates with observed tactics
    const secFunc = safeguard.security_function || '';
    for (const tactic of observedTactics) {
      const correlatedFunctions = tacticToCisFunction[tactic] || [];
      if (correlatedFunctions.some(f => f.toLowerCase() === secFunc.toLowerCase())) {
        score += 0.5;
      }
    }

    // Boost for coverage gaps: safeguards whose function is Detect get a boost
    // when we have techniques with no detection rules
    if (coverageGaps.length > 0 && secFunc.toLowerCase() === 'detect') {
      score += coverageGaps.length * 0.25;
    }

    if (score > 0) {
      safeguardScores.push({
        control_id:    control.id,
        control_title: control.title,
        safeguard_id:  safeguard.id,
        safeguard_title: safeguard.title,
        description:   safeguard.description,
        asset_type:    safeguard.asset_type,
        security_function: safeguard.security_function,
        nist_csf_function: safeguard.nist_csf_function,
        implementation_groups: safeguard.implementation_groups,
        score,
      });
    }
  }
}

// Sort by score descending, take top 12
safeguardScores.sort((a, b) => b.score - a.score);
const topSafeguards = safeguardScores.slice(0, 12);

// Group top safeguards by CIS Control number for readable output
const byControl = {};
for (const sg of topSafeguards) {
  const key = sg.control_id;
  if (!byControl[key]) {
    byControl[key] = {
      control_id:    sg.control_id,
      control_title: sg.control_title,
      safeguards:    [],
    };
  }
  byControl[key].safeguards.push({
    id:                   sg.safeguard_id,
    title:                sg.safeguard_title,
    description:          sg.description,
    asset_type:           sg.asset_type,
    security_function:    sg.security_function,
    nist_csf_function:    sg.nist_csf_function,
    implementation_groups: sg.implementation_groups,
  });
}

const cisMappings = Object.values(byControl).sort((a, b) => a.control_id - b.control_id);

// Extract IG1 quick wins from the top results (most accessible controls)
const quickWins = topSafeguards
  .filter(sg => sg.implementation_groups.includes('IG1'))
  .slice(0, 6)
  .map(sg => ({
    id:                   sg.safeguard_id,
    title:                sg.safeguard_title,
    control_id:           sg.control_id,
    control_title:        sg.control_title,
    security_function:    sg.security_function,
    implementation_groups: sg.implementation_groups,
  }));

return [{
  json: {
    // CIS Controls mappings grouped by control number
    cis_mappings: cisMappings,

    // IG1 quick wins — easiest to implement
    cis_quick_wins: quickWins,

    // Total matched safeguards
    cis_safeguard_count: topSafeguards.length,

    // Pass-through for downstream nodes
    techniques:       techniques,
    nist_csf_mappings: nistMappings,
    analyst_findings: findings,
    coverage_gaps:    coverageGaps,
    low_coverage:     lowCoverage,
  }
}];
